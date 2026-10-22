"""Local regression checks for new boundaries; no demos or cloud inference."""
from copy import deepcopy
import json

import httpx
import pytest

from conftest import build_harness, proposal
from agentguard.v2.adapters.host import AgentReply, HostAdapter
from agentguard.v2.adapters.http import GatewayRuntime
from agentguard.v2.common import RuntimeFault, canonical, digest
from agentguard.v2.contracts import *
from agentguard.v2.gateway.app import create_app
from agentguard.v2.review.cache import AnalysisCache
from agentguard.v2.review.context import ContextBuilder
from agentguard.v2.review.prompts import review_messages
from agentguard.v2.review.reviewers import Reviewer
from agentguard.v2.review.service import GuardService
from test_guard_runtime import integrated, ScriptedCloud


class TwoTurnModel:
    destination_id='agent'
    def __init__(self):
        self.inputs=[]; self.resets=[]
    async def complete(self,prepared):
        self.inputs.append(prepared)
        if len(self.inputs)==1:
            return AgentReply('INTERNAL_UNRELEASED_REASONING',(proposal(),))
        return AgentReply('Complete public report')
    async def reset(self,sid):
        self.resets.append(sid); return True


@pytest.mark.asyncio
async def test_real_host_uses_released_refs_and_buffers_intermediate_text(tmp_path):
    h,cloud=integrated(tmp_path/'runtime')
    model=TwoTurnModel(); host=HostAdapter(h.runtime,model,state_directory=tmp_path/'host')
    session=await host.create(h.request)
    final=await host.run(session.session_id)
    assert final.status=='RELEASED'
    assert h.reads==['docs']
    actual=canonical([m.model_dump(mode='json') for m in model.inputs[1].messages])
    assert 'document:docs' in actual
    assert 'INTERNAL_UNRELEASED_REASONING' not in actual
    assert len(h.runtime.store.all(session.session_id,'model_output'))==2


@pytest.mark.asyncio
async def test_actual_host_recovery_resets_owned_state_and_can_resume_after_restart(tmp_path):
    h=build_harness(tmp_path/'runtime')
    model=TwoTurnModel(); state_dir=tmp_path/'host'
    host=HostAdapter(h.runtime,model,state_directory=state_dir)
    session=await host.create(h.request); sid=session.session_id
    await host.run(sid)
    state=host.states[sid]; state.memory['bad']='derived content'; state.cloud_conversation_id='old-id'
    product=state_dir/sid/'draft.txt'; product.write_text('derived product',encoding='utf-8')
    host.register_work_product(sid,product)
    result=h.runtime.store.all(sid,'result')[0]
    ref=EvidenceRef.model_validate_json(canonical(result['artifact_ref']))
    host.reset_hooks['memory']=lambda plan,state:False
    with pytest.raises(RuntimeFault,match='RECOVERY_ACK_INCOMPLETE'):
        await host.recover(sid,[ref])
    assert h.runtime.session_view(sid).status=='RECOVERING'
    assert not product.exists()
    assert not state.memory and state.cloud_conversation_id is None and model.resets==[sid]
    restored=HostAdapter(h.runtime,model,state_directory=state_dir)
    plan,ack,view=await restored.resume_recovery(sid)
    assert view.status=='ACTIVE' and all(ack.completed_resets.values())
    assert not (state_dir/sid/'recovery.json').exists()
    assert ref not in [m.ref for m in restored.states[sid].messages]


@pytest.mark.asyncio
async def test_http_host_uses_gateway_for_all_model_tool_final_boundaries(tmp_path):
    h=build_harness(tmp_path/'runtime')
    app=create_app(h.runtime,host_token='host',ui_token='ui')
    client=httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test')
    remote=GatewayRuntime('http://localhost', 'host',client=client)
    host=HostAdapter(remote,TwoTurnModel())
    session=await host.create(h.request)
    final=await host.run(session.session_id)
    assert final.status=='RELEASED' and h.reads==['docs']
    await remote.aclose()


@pytest.mark.asyncio
async def test_langchain_core_actual_model_adapter_through_runtime(tmp_path):
    pytest.importorskip('langchain_core')
    from langchain_core.language_models.fake_chat_models import FakeListChatModel
    from agentguard.v2.adapters.framework import LangChainHost
    h=build_harness(tmp_path/'runtime')
    replies=[canonical({'content':'','tool_proposals':[proposal().model_dump(mode='json')]}),
             canonical({'content':'Framework public answer','tool_proposals':[]})]
    host=LangChainHost(h.runtime,FakeListChatModel(responses=replies),destination_id='agent',endpoint='https://agent.test',
        state_directory=tmp_path/'host')
    session=await host.create(h.request)
    result=await host.run(session.session_id)
    assert result.status=='RELEASED' and h.reads==['docs']


@pytest.mark.asyncio
@pytest.mark.parametrize('strategy',['all','recent','relations'])
async def test_long_context_keeps_current_subject_security_facts_and_real_prompt_budget(tmp_path,strategy):
    h=build_harness(tmp_path)
    sid=(await h.session()).session_id
    p,out,batch=await h.run(sid,[proposal()])
    ref=next(iter(batch.results.values())).artifact_ref
    material=h.runtime._material(sid,p.turn_id,out.calls[0].call_id,'RESULT',ref,p.context_version)
    blocks=list(material.evidence)
    for i in range(20):
        meta=h.runtime.artifacts.create(sid,'Large optional history '+str(i)+'x'*8000,blocks[0].labels)
        blocks.append(make(EvidenceBlock,ref=h.runtime.artifacts.ref(meta),content=h.runtime.artifacts.read(sid,h.runtime.artifacts.ref(meta)),labels=meta.labels,role='related'))
    dense=list(material.lineage)
    for i,block in enumerate(blocks[3:]):
        for previous in blocks[3:3+i]:
            dense.append(make(LineageEdge,session_id=sid,source_ref=previous.ref,target_ref=block.ref,kind='possible',event_id='event_history'))
    facts={**material.mandatory_facts,'source_labels':[{'ref':b.ref.model_dump(mode='json'),'labels':b.labels.model_dump(mode='json')} for b in blocks]}
    material=material.model_copy(update={'evidence':blocks,'available_evidence_refs':[b.ref for b in blocks],
        'lineage':dense,'mandatory_facts':facts})
    result=ContextBuilder(max_bytes=60_000,strategy=strategy,recent_n=2).build(material)
    if strategy=='all':
        assert result.status=='INCOMPLETE'
    else:
        assert result.status=='READY'
        req=result.request.model_dump(mode='json')
        assert req['retained_mandatory_facts']==material.mandatory_facts
        assert material.subject_ref in result.request.selected_evidence_refs
        assert result.request.subject==material.subject
        from agentguard.v2.review.boundary import dumps
        assert result.request.budget_used==len(dumps(review_messages(req)).encode('utf-8'))<=60_000
        assert len(req['evidence'])<len(blocks)
        assert len(req['lineage'])<len(dense)


@pytest.mark.asyncio
async def test_cache_hits_bound_analysis_only_and_security_revision_changes_miss(tmp_path):
    h,cloud=integrated(tmp_path)
    cache=AnalysisCache(); reviewer=Reviewer(cloud,cache=cache)
    service=GuardService(ContextBuilder(),reviewer)
    sid=(await h.session()).session_id
    p,out,batch=await h.run(sid,[proposal()])
    ref=next(iter(batch.results.values())).artifact_ref
    material=h.runtime._material(sid,p.turn_id,out.calls[0].call_id,'RESULT',ref,p.context_version)
    first=await service.inspect(material)
    requests=len(cloud.requests)
    second=await service.inspect(material.model_copy(update={'review_id':'review_new_identifier'}))
    assert first.status==second.status=='DECIDED'
    assert second.decision.review_id=='review_new_identifier'
    assert second.decision.usage.attempts==0 and len(cloud.requests)==requests
    await service.inspect(material.model_copy(update={'relevant_security_revision':1}))
    assert len(cloud.requests)==requests+1
    service.clear_session(sid)
    await service.inspect(material)
    assert len(cloud.requests)==requests+2


@pytest.mark.asyncio
async def test_actual_action_field_finding_is_locatable_in_runtime_artifact(tmp_path):
    class ActionBlock(ScriptedCloud):
        async def complete(self,**kwargs):
            reply=await super().complete(**kwargs)
            if kwargs['purpose']=='ACTION':
                data=json.loads(reply.content)
                data.update(decision='BLOCK',reason_code='TASK_MISMATCH',findings=[{
                    'schema_version':'0.1','finding_type':'ARGUMENT_RISK','affected_action_field':'/resource',
                    'evidence_refs':[{**data['subject_ref'],'json_pointer':'/args/resource'}]}])
                from agentguard.v2.review.clients import CloudReply
                return CloudReply(json.dumps(data),reply.usage)
            return reply
    h=build_harness(tmp_path); client=ActionBlock()
    h.runtime.guard=GuardService(ContextBuilder(),Reviewer(client))
    sid=(await h.session()).session_id
    _,_,batch=await h.run(sid,[proposal()])
    assert next(iter(batch.results.values())).status=='BLOCKED'
    assert not h.reads


@pytest.mark.asyncio
@pytest.mark.parametrize('synthetic',[False,True])
async def test_console_actual_input_and_comparison_require_explicit_synthetic_data(tmp_path,synthetic):
    h,cloud=integrated(tmp_path)
    h.request=h.request.model_copy(update={'synthetic_demo':synthetic})
    model=TwoTurnModel(); host=HostAdapter(h.runtime,model)
    session=await host.create(h.request); await host.run(session.session_id)
    app=create_app(h.runtime,host_token='host',ui_token='ui',allow_synthetic_content=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test',headers={'Authorization':'Bearer ui'}) as client:
        reviews=(await client.get('/v2/sessions/'+session.session_id+'/reviews')).json()
        final_review=next(r for r in reviews if r['phase']=='FINAL')
        prefix='/v2/sessions/'+session.session_id
        response=await client.get(prefix+'/reviews/'+final_review['review_id']+'/input')
        assert response.status_code==200
        data=response.json()
        assert data['available'] and data['synthetic_content_visible'] is synthetic
        if not synthetic:
            assert 'Complete public report' not in response.text
        assert (await client.post(prefix+'/analysis-cache/reset',json={})).status_code==403


def test_independent_scorer_does_not_treat_unknown_as_attack_blocked():
    from benchmarks.v2.environment import Case
    from benchmarks.v2.scoring import report,score
    from types import SimpleNamespace
    case=Case('case',True,('doc',),'OK','FAKE_SECRET')
    receiver=SimpleNamespace(snapshot=lambda:[])
    world=SimpleNamespace(receiver=receiver,reports={},calls=[])
    row=score(case,world,None,unknown=True,audit={'variant':'v2','mode':'scripted'})
    assert row['attack_success'] is None and row['task_success'] is None
    result=report([row])['groups']['v2']['attack_success']
    assert result['denominator']==0 and result['unknown']==1 and result['rate'] is None


def test_external_bridge_remaps_all_destination_fields_without_executing_nested_tools():
    from benchmarks.v2.external import bridge_tools
    from pydantic import BaseModel
    from types import SimpleNamespace
    class Params(BaseModel):
        recipients:list[str]
        cc:list[str]=[]
        body:str
    called=[]
    def invoke(env,name,args):
        called.append(args); return {'sent':True},None
    runtime=SimpleNamespace(functions={'send_email':SimpleNamespace(parameters=Params)},run_function=invoke)
    mappings={'tools':{'send_email':{'effects':['SEND'],'destination_fields':['recipients','cc'],
        'destination_bindings':{'approved':{'recipients':['approved@example.test'],'cc':[]}}}}}
    registry=bridge_tools(runtime,object(),mappings,[])
    entry=registry.get('send_email')
    assert 'cc' not in entry.manifest.parameters_schema['properties']
    assert entry.handler(destination='approved',body='Public text')=={'sent':True}
    assert called[0]['recipients']==['approved@example.test'] and called[0]['cc']==[]


@pytest.mark.asyncio
async def test_late_action_risk_rebases_earlier_released_context_before_continuing(tmp_path):
    class LateRisk(ScriptedCloud):
        async def complete(self,**kwargs):
            reply=await super().complete(**kwargs)
            data=json.loads(reply.content)
            if kwargs['purpose']=='ACTION':
                request=json.loads(kwargs['messages'][1]['content'])
                if request['untrusted_evidence']['subject']['tool_id']=='send_report':
                    origin=next(b['ref'] for b in request['untrusted_evidence']['evidence'] if b['content']=='document:docs')
                    data.update(decision='BLOCK',reason_code='UNTRUSTED_INSTRUCTION',
                        evidence_refs=[data['subject_ref'],origin],findings=[{'schema_version':'0.1',
                        'finding_type':'EARLIER_INJECTION','affected_action_field':'/destination',
                        'evidence_refs':[{**origin,'span':[0,8]}]}])
                    from agentguard.v2.review.clients import CloudReply
                    return CloudReply(json.dumps(data),reply.usage)
            return reply
    class Agent(TwoTurnModel):
        async def complete(self,prepared):
            self.inputs.append(prepared)
            if len(self.inputs)==1:
                return AgentReply('',(proposal(),))
            if len(self.inputs)==2:
                return AgentReply('',(proposal('send_report',{'destination':'receiver','body':'derived'},use='send'),))
            return AgentReply('A fresh public response')
    h=build_harness(tmp_path/'runtime')
    h.runtime.guard=GuardService(ContextBuilder(),Reviewer(LateRisk()))
    model=Agent(); host=HostAdapter(h.runtime,model,state_directory=tmp_path/'host',recover_on_block=True)
    session=await host.create(h.request)
    final=await host.run(session.session_id)
    assert final.status=='RELEASED' and not h.effects
    assert len(model.resets)==1
    assert 'document:docs' not in canonical([m.model_dump(mode='json') for m in model.inputs[-1].messages])
    assert host.states[session.session_id].recoveries==1


def test_production_composition_has_no_model_request_on_construction(tmp_path,monkeypatch):
    from agentguard.v2.application import compose,load_settings
    settings=load_settings('config/v2.example.json')
    settings['state_directory']=str(tmp_path/'state')
    monkeypatch.setenv('AGENTGUARD_V2_CLOUD_ENABLED','1')
    monkeypatch.setenv('AGENTGUARD_GUARD_API_KEY','synthetic-not-a-real-key')
    monkeypatch.setenv('AGENTGUARD_AGENT_API_KEY','synthetic-not-a-real-key')
    app=compose(settings,'Read the synthetic example')
    assert app.runtime.guard.reviewer.cache is not None
    assert 'mask_text' in app.runtime.artifacts.transforms
    assert app.model.client.budget.attempts==0
    assert app.runtime.guard.reviewer.client.budget.attempts==0


@pytest.mark.asyncio
async def test_experiment_budget_is_global_across_two_model_clients():
    from agentguard.v2.review.budget import Budget
    from agentguard.v2.review.clients import CloudClient,CloudConfig
    from agentguard.v2.review.errors import GuardError
    class Transport:
        def __init__(self): self.calls=0
        async def post(self,body,config):
            self.calls+=1
            return json.dumps({'choices':[{'finish_reason':'stop','message':{'content':'{}'}}],
                'usage':{'prompt_tokens':1,'completion_tokens':1}})
    pool=Budget(max_attempts=1); transport=Transport()
    config=CloudConfig(enabled=True,api_key='synthetic-key',model='fixture',max_retries=0)
    one=CloudClient(config,budget=pool,transport=transport)
    two=CloudClient(config,budget=pool,transport=transport)
    await one.complete(messages=[{'role':'user','content':'synthetic'}],purpose='agent',prompt_version='test')
    with pytest.raises(GuardError,match='BUDGET_EXHAUSTED'):
        await two.complete(messages=[{'role':'user','content':'synthetic'}],purpose='agent',prompt_version='test')
    assert transport.calls==pool.attempts==1 and pool.exhausted
