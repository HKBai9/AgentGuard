import asyncio
import json
import pytest
import httpx
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.shared.exceptions import McpError
from agentguard.v2.contracts import *
from agentguard.v2.common import canonical, RuntimeFault
from agentguard.v2.gateway.app import create_app
from agentguard.v2.adapters.python import PythonSDK
from agentguard.v2.adapters.mcp import create_mcp_server, MCPToolBackend
from conftest import proposal

@pytest.mark.asyncio
async def test_http_full_protocol_and_ui_redaction(harness):
    h=harness
    app=create_app(h.runtime,host_token='host-credential',ui_token='ui-credential')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://local') as client:
        host={'Authorization':'Bearer host-credential'}
        ui={'Authorization':'Bearer ui-credential'}
        assert (await client.post('/v2/sessions',json=h.request.model_dump(mode='json'))).status_code==401
        assert (await client.post('/v2/sessions',headers=ui,json=h.request.model_dump(mode='json'))).status_code==403
        response=await client.post('/v2/sessions',headers=host,json=h.request.model_dump(mode='json'))
        assert response.status_code==200, response.text
        sid=response.json()['session_id']
        prep=make(PrepareTurnRequest,session_id=sid,messages=[],model_destination_id='agent')
        response=await client.post(f'/v2/sessions/{sid}/model-turns/prepare',headers=host,json=prep.model_dump(mode='json'))
        p=PreparedTurn.model_validate_json(response.content)
        request=make(ModelOutputRequest,session_id=sid,model_call_id=p.model_call_id,context_version=p.context_version,content='answer',tool_proposals=[proposal()])
        response=await client.post(f'/v2/sessions/{sid}/model-outputs',headers=host,json=request.model_dump(mode='json'))
        out=ProposedTurn.model_validate_json(response.content)
        req=make(BatchRequest,session_id=sid,turn_id=p.turn_id,context_version=p.context_version,calls=out.calls)
        response=await client.post(f'/v2/sessions/{sid}/batches',headers=host,json=req.model_dump(mode='json'))
        batch=BatchResult.model_validate_json(response.content)
        r=batch.results[out.calls[0].call_id]
        assert r.status=='RELEASED'
        events=(await client.get(f'/v2/sessions/{sid}/events',headers=ui)).json()
        review_id=next(e['review_id'] for e in events if e['review_id'])
        for suffix in ['', '/policy','/graph','/metrics',f'/reviews/{review_id}',
            f'/artifacts/{r.artifact_ref.artifact_id}/versions/1/comparison']:
            response=await client.get(f'/v2/sessions/{sid}{suffix}',headers=ui)
            assert response.status_code==200, response.text
            assert 'document:docs' not in response.text and 'storage_ref' not in response.text
        bad=await client.post(f'/v2/sessions/{sid}/batches',headers=host,content='{"schema_version":"0.1","schema_version":"0.2"}')
        assert bad.status_code==422 and 'DUPLICATE_JSON_KEY' in bad.text
        bad=await client.post('/v2/sessions/wrong/batches',headers=host,json=req.model_dump(mode='json'))
        assert bad.status_code==409
        final=make(FinalizeRequest,session_id=sid,turn_id=p.turn_id,context_version=p.context_version,output_ref=out.output_ref)
        assert (await client.post(f'/v2/sessions/{sid}/finalize',headers=host,json=final.model_dump(mode='json'))).json()['content']=='answer'
        assert (await client.get('/v2/openapi.json',headers=ui)).status_code==200

@pytest.mark.asyncio
async def test_python_and_mcp_share_executor(harness):
    h=harness
    s=await h.session()
    p,out=await h.propose(s.session_id,[proposal()])
    wrapper=PythonSDK(h.runtime).wrap(h.handlers['read_document'],out.calls[0])
    r=await wrapper('docs')
    assert r.status=='RELEASED'
    with pytest.raises(RuntimeFault):
        await wrapper('reports')
    server=create_mcp_server(h.runtime,session_id=s.session_id)
    async with create_connected_server_and_client_session(server) as client:
        assert [t.name for t in (await client.list_tools()).tools]==['agentguard.execute_batch']
        request=make(BatchRequest,session_id=s.session_id,turn_id=p.turn_id,context_version=p.context_version,calls=out.calls)
        result=await client.call_tool('agentguard.execute_batch',request.model_dump(mode='json'))
        parsed=BatchResult.model_validate_json(canonical(result.structuredContent))
        assert parsed.results[out.calls[0].call_id]==r and h.reads==['docs']
        unknown=await client.call_tool('unsupported',{'private':'SYNTHETIC_PRIVATE'})
        assert unknown.isError and 'SYNTHETIC_PRIVATE' not in str(unknown)
        malformed=await client.call_tool('agentguard.execute_batch',{'private':'SYNTHETIC_PRIVATE'})
        assert malformed.isError and 'SYNTHETIC_PRIVATE' not in str(malformed)
        with pytest.raises(McpError):
            await client.list_resources()

@pytest.mark.asyncio
async def test_mcp_backend_all_content_quarantined(harness):
    from mcp.server.lowlevel import Server
    from mcp.types import Tool, TextContent, CallToolResult
    remote=Server('fake-backend')
    @remote.list_tools()
    async def listing():
        return [Tool(name='read',inputSchema={'type':'object'})]
    @remote.call_tool()
    async def call(name,args):
        return CallToolResult(content=[TextContent(type='text',text='SYNTHETIC_PRIVATE'),TextContent(type='text',text='second block')],structuredContent={'value':'third'},isError=False)
    h=harness
    async with create_connected_server_and_client_session(remote) as client:
        entry=h.runtime.registry.get('read_document')
        backend=MCPToolBackend(client,'read')
        h.runtime.registry.register(entry.manifest.model_copy(update={'manifest_version':'v2','return_media_type':'application/json'}),backend)
        h.request=h.request.model_copy(update={'tool_manifests':h.runtime.registry.manifests()})
        h.guard.mode='BLOCK'
        s=await h.session()
        _,out,batch=await h.run(s.session_id,[proposal().model_copy(update={'manifest_version':'v2'})])
        r=batch.results[out.calls[0].call_id]
        assert r.status=='BLOCKED' and r.content is None and 'SYNTHETIC_PRIVATE' not in canonical(r)
        raw=h.runtime.artifacts.read(s.session_id,r.receipt.artifact_ref)
        assert raw=={'content':['SYNTHETIC_PRIVATE','second block'],'structured':{'value':'third'}}


def test_sync_wrapper(harness):
    h=harness
    async def prepare():
        s=await h.session()
        return await h.propose(s.session_id,[proposal()])
    _,out=asyncio.run(prepare())
    wrapped=PythonSDK(h.runtime).wrap_sync(h.handlers['read_document'],out.calls[0])
    assert wrapped('docs').status=='RELEASED'
    assert wrapped('docs').status=='RELEASED' and h.reads==['docs']

@pytest.mark.asyncio
async def test_four_tool_types_same_runtime(harness):
    h=harness
    s=await h.session()
    for prop in [proposal(),proposal('write_report',{'resource':'reports','body':'report'},use='write'),
        proposal('send_report',{'destination':'receiver','body':'report'},use='send'),proposal('query_rows')]:
        _,out,batch=await h.run(s.session_id,[prop])
        assert batch.results[out.calls[0].call_id].status=='RELEASED'
    assert len(h.effects)==2

@pytest.mark.asyncio
async def test_real_loopback_http_service(harness):
    import socket
    import uvicorn
    h=harness
    app=create_app(h.runtime,host_token='host',ui_token='ui')
    sock=socket.socket()
    sock.bind(('127.0.0.1',0))
    sock.listen(128)
    port=sock.getsockname()[1]
    server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=port,log_level='error',access_log=False))
    task=asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(200):
            if server.started: break
            await asyncio.sleep(0.01)
        assert server.started
        async with httpx.AsyncClient(base_url=f'http://127.0.0.1:{port}',trust_env=False) as client:
            response=await client.post('/v2/sessions',headers={'Authorization':'Bearer host'},json=h.request.model_dump(mode='json'))
            assert response.status_code==200
            sid=response.json()['session_id']
            assert (await client.get('/v2/sessions/'+sid,headers={'Authorization':'Bearer ui'})).json()['status']=='ACTIVE'
    finally:
        server.should_exit=True
        await asyncio.wait_for(task,5)
        sock.close()

@pytest.mark.asyncio
async def test_mcp_error_body_quarantined(harness):
    from mcp.types import CallToolResult,TextContent
    class Backend:
        async def call_tool(self,name,kwargs):
            return CallToolResult(content=[TextContent(type='text',text='PRIVATE_BACKEND_ERROR')],isError=True)
    h=harness
    entry=h.runtime.registry.get('read_document')
    h.runtime.registry.register(entry.manifest.model_copy(update={'manifest_version':'v2','return_media_type':'application/json'}),MCPToolBackend(Backend(),'read'))
    h.request=h.request.model_copy(update={'tool_manifests':h.runtime.registry.manifests()})
    s=await h.session()
    _,out,b=await h.run(s.session_id,[proposal().model_copy(update={'manifest_version':'v2'})])
    r=b.results[out.calls[0].call_id]
    assert r.status=='UNKNOWN' and 'PRIVATE_BACKEND_ERROR' not in canonical(r)
    raw=h.runtime.artifacts.read(s.session_id,r.receipt.artifact_ref)
    assert raw['result']['content'][0]['text']=='PRIVATE_BACKEND_ERROR'
