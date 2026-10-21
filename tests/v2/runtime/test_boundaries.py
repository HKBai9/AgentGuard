import asyncio
from datetime import timedelta
import pytest
from agentguard.v2.contracts import *
from agentguard.v2.common import RuntimeFault, utcnow, canonical
from agentguard.v2.state.lineage import public_labels
from agentguard.v2.execution.executor import ToolResult
from conftest import proposal, build_harness

@pytest.mark.asyncio
async def test_immutable_capabilities_and_bytes(harness,tmp_path):
    h=harness
    entry=h.runtime.registry.get('send_report')
    manifest=entry.manifest.model_copy(update={'manifest_version':'v2','artifact_parameters':{'/body':'send'}})
    h.runtime.registry.register(manifest,entry.handler)
    h.request=h.request.model_copy(update={'tool_manifests':h.runtime.registry.manifests()})
    s=await h.session()
    ref=h.runtime.ingest(s.session_id,'frozen report',public_labels(),resource_scope_ids=['docs'])
    token=h.runtime.artifacts.issue_ref(s.session_id,ref,['send'],['send_report'],['receiver'],utcnow()+timedelta(seconds=60))
    prop=proposal('send_report',{'destination':'receiver','body':token.ref_id},[token],use='send').model_copy(update={'manifest_version':'v2'})
    p,out=await h.propose(s.session_id,[prop])
    call=out.calls[0]
    permit=h.runtime.permits.issue(call,[ref])
    # Replacing storage bytes after approval fails the digest check in claim.
    meta=h.runtime.artifacts.metadata(s.session_id,ref)
    blob=h.runtime.artifacts.directory/meta.storage_ref
    blob.write_text('"replaced"')
    with pytest.raises(RuntimeFault,match='ARTIFACT_INTEGRITY_FAILED'):
        h.runtime.permits.claim(permit,call)
    blob.write_text('"frozen report"')
    result=await h.runtime.execute_call(call)
    assert result.status=='RELEASED' and h.effects==[('send','receiver','frozen report')]
    b=await h.session()
    with pytest.raises(RuntimeFault,match='INVALID_ARTIFACT_CAPABILITY'):
        h.runtime.artifacts.resolve_ref(b.session_id,token,'send','send_report','receiver',None)

@pytest.mark.asyncio
@pytest.mark.parametrize('mutate',['version','use','tool','destination','expiry'])
async def test_capability_bindings(harness,mutate):
    h=harness
    s=await h.session()
    ref=h.runtime.ingest(s.session_id,'frozen report',public_labels())
    expires=utcnow()-timedelta(seconds=1) if mutate=='expiry' else utcnow()+timedelta(seconds=60)
    token=h.runtime.artifacts.issue_ref(s.session_id,ref,['send'],['send_report'],['receiver'],expires)
    from agentguard.v2.registry import Catalog
    catalog=Catalog(h.request.resource_catalog)
    args=[s.session_id,token,'send','send_report','receiver',catalog]
    if mutate=='version': args[1]=token.model_copy(update={'version':2})
    if mutate=='use': args[2]='reply'
    if mutate=='tool': args[3]='read_document'
    if mutate=='destination': args[4]='user'
    with pytest.raises(RuntimeFault):
        h.runtime.artifacts.resolve_ref(*args)

@pytest.mark.asyncio
async def test_guard_and_agent_destination_independent(tmp_path):
    labels=public_labels('external').model_copy(update={'model_destination_ids':['agent']})
    h=build_harness(tmp_path,output_labels=labels)
    s=await h.session()
    _,out,batch=await h.run(s.session_id,[proposal()])
    r=batch.results[out.calls[0].call_id]
    assert r.status=='REVIEW_PENDING' and r.reason_code=='DATA_DESTINATION_DENIED'
    assert not any(m.phase=='RESULT' for m in h.guard.materials)
    denied=h.runtime.ingest(s.session_id,'restricted',public_labels().model_copy(update={'model_destination_ids':['guard']}))
    with pytest.raises(RuntimeFault,match='DATA_DESTINATION_DENIED'):
        await h.propose(s.session_id,messages=[make(Message,role='tool',ref=denied)])

@pytest.mark.asyncio
async def test_size_limit_does_not_truncate(harness):
    h=harness
    h.request=h.request.model_copy(update={'host_policy':h.request.host_policy.model_copy(update={'max_review_bytes':100})})
    s=await h.session()
    _,out,batch=await h.run(s.session_id,[proposal()])
    r=batch.results[out.calls[0].call_id]
    assert r.reason_code=='CONTENT_TOO_LARGE' and h.reads==[] and h.guard.materials==[]

@pytest.mark.asyncio
async def test_stderr_and_structured_results_all_reviewed(harness):
    h=harness
    entry=h.runtime.registry.get('read_document')
    async def noisy(resource):
        return ToolResult('visible',stderr='PRIVATE_STDERR')
    h.runtime.registry.register(entry.manifest.model_copy(update={'manifest_version':'v2'}),noisy)
    h.request=h.request.model_copy(update={'tool_manifests':h.runtime.registry.manifests()})
    h.guard.mode='BLOCK'
    s=await h.session()
    _,out,batch=await h.run(s.session_id,[proposal().model_copy(update={'manifest_version':'v2'})])
    r=batch.results[out.calls[0].call_id]
    assert r.status=='BLOCKED' and 'PRIVATE_STDERR' not in canonical(r)
    assert next(m for m in h.guard.materials if m.phase=='RESULT').subject=={'content':'visible','stderr':'PRIVATE_STDERR'}

@pytest.mark.asyncio
async def test_claimed_write_serializes_shared_resource(harness):
    h=harness
    entry=h.runtime.registry.get('write_report')
    started,finish=asyncio.Event(),asyncio.Event()
    async def write(resource,body):
        started.set()
        await finish.wait()
        h.effects.append(body)
        return 'written'
    h.runtime.registry.register(entry.manifest.model_copy(update={'manifest_version':'v2'}),write)
    h.request=h.request.model_copy(update={'tool_manifests':h.runtime.registry.manifests()})
    s1,s2=await h.session(),await h.session()
    prop=proposal('write_report',{'resource':'reports','body':'report'},use='write').model_copy(update={'manifest_version':'v2'})
    _,o1=await h.propose(s1.session_id,[prop])
    _,o2=await h.propose(s2.session_id,[prop])
    task=asyncio.create_task(h.runtime.execute_call(o1.calls[0]))
    await started.wait()
    with pytest.raises(RuntimeFault,match='BATCH_BARRIER_PENDING'):
        await h.propose(s1.session_id)
    denied=await h.runtime.execute_call(o2.calls[0])
    assert denied.status=='BLOCKED' and denied.reason_code=='RESOURCE_BUSY'
    finish.set()
    assert (await task).status=='RELEASED'
    assert (await h.runtime.execute_call(o2.calls[0])).status=='RELEASED'
    assert len(h.effects)==2

@pytest.mark.asyncio
async def test_20_reordered_results_and_one_block(harness):
    h=harness
    entry=h.runtime.registry.get('read_document')
    props={**entry.manifest.parameters_schema['properties'],'index':{'type':'integer'}}
    schema={**entry.manifest.parameters_schema,'properties':props,'required':['resource','index']}
    completed=[]
    started=[]
    gates=[asyncio.Event() for _ in range(20)]
    async def read(resource,index):
        started.append(index)
        if len(started)==20:
            gates[19].set()
        await gates[index].wait()
        completed.append(index)
        if index:
            gates[index-1].set()
        return f'row-{index}'
    h.runtime.registry.register(entry.manifest.model_copy(update={'manifest_version':'v2','parameters_schema':schema}),read)
    h.request=h.request.model_copy(update={'tool_manifests':h.runtime.registry.manifests()})
    original=h.guard.inspect
    async def review(material):
        result=await original(material)
        if material.phase=='RESULT' and material.subject=='row-7':
            return result.model_copy(update={'decision':result.decision.model_copy(update={'decision':'BLOCK'})})
        return result
    h.guard.inspect=review
    s=await h.session()
    _,out,batch=await h.run(s.session_id,[proposal(args={'resource':'docs','index':i}).model_copy(update={'manifest_version':'v2'}) for i in range(20)])
    assert len(completed)==20 and completed != list(range(20))
    for i,call in enumerate(out.calls):
        r=batch.results[call.call_id]
        assert r.status==('BLOCKED' if i==7 else 'RELEASED')
        assert r.content==(None if i==7 else f'row-{i}')

@pytest.mark.asyncio
async def test_final_concurrent_redaction_idempotent(harness):
    h=harness
    s=await h.session()
    p,out=await h.propose(s.session_id,content='result')
    req=make(FinalizeRequest,session_id=s.session_id,turn_id=p.turn_id,context_version=p.context_version,output_ref=out.output_ref)
    results=await asyncio.gather(h.runtime.finalize(req),h.runtime.finalize(req))
    assert results[0]==results[1]
    assert len([e for e in h.runtime.store.events(s.session_id) if e.event_type=='FINAL_RELEASED'])==1

@pytest.mark.asyncio
@pytest.mark.parametrize('binding',['session_id','turn_id','review_id','call_id','policy_version','context_version'])
async def test_guard_wrong_binding_never_releases(harness,binding):
    h=harness
    original=h.guard.inspect
    async def review(material):
        outcome=await original(material)
        if material.phase=='RESULT':
            return outcome.model_copy(update={'decision':outcome.decision.model_copy(update={binding:'forged'})})
        return outcome
    h.guard.inspect=review
    s=await h.session()
    _,out,batch=await h.run(s.session_id,[proposal()])
    r=batch.results[out.calls[0].call_id]
    assert r.status=='REVIEW_PENDING' and r.reason_code=='INVALID_REFERENCE' and r.content is None

@pytest.mark.asyncio
async def test_unicode_span_redaction(harness):
    from agentguard.v2.state.artifacts import TransformSpec
    h=harness
    h.runtime.artifacts.transforms['mask_span']=TransformSpec('mask_span','mask_span')
    entry=h.runtime.registry.get('read_document')
    h.runtime.registry.register(entry.manifest.model_copy(update={'manifest_version':'v2'}),lambda resource:'中😀秘密尾')
    h.request=h.request.model_copy(update={'tool_manifests':h.runtime.registry.manifests()})
    original=h.guard.inspect
    async def review(material):
        outcome=await original(material)
        if material.phase=='RESULT':
            target=make(RedactionTarget,evidence_ref=material.subject_ref.model_copy(update={'span':(2,4)}),transform_id='mask_span')
            return outcome.model_copy(update={'decision':outcome.decision.model_copy(update={'decision':'REDACT','redaction_targets':[target]})})
        return outcome
    h.guard.inspect=review
    s=await h.session()
    _,out,batch=await h.run(s.session_id,[proposal().model_copy(update={'manifest_version':'v2'})])
    assert batch.results[out.calls[0].call_id].content=='中😀[REDACTED]尾'

@pytest.mark.asyncio
async def test_guard_cannot_copy_secret_into_public_reason_or_usage(harness):
    h=harness
    original=h.guard.inspect
    async def review(material):
        outcome=await original(material)
        return outcome.model_copy(update={'decision':outcome.decision.model_copy(update={'reason_code':'PRIVATE_SECRET',
            'reason_summary':'PRIVATE_SECRET','usage':outcome.decision.usage.model_copy(update={'provider':'PRIVATE_SECRET','model':'PRIVATE_SECRET'})})})
    h.guard.inspect=review
    s=await h.session()
    _,out,batch=await h.run(s.session_id,[proposal()])
    assert 'PRIVATE_SECRET' not in canonical(batch)
    assert 'PRIVATE_SECRET' not in canonical(h.runtime.store.all(s.session_id,'review'))
    assert 'PRIVATE_SECRET' not in canonical([e.model_dump(mode='json') for e in h.runtime.store.events(s.session_id)])

@pytest.mark.asyncio
async def test_missing_services_have_no_allow_fallback(harness):
    h=harness
    h.runtime.generator=None
    with pytest.raises(RuntimeFault,match='SERVICE_UNAVAILABLE'):
        await h.session()

@pytest.mark.asyncio
async def test_barrier_includes_result_review(harness):
    h=harness
    arrived,release=asyncio.Event(),asyncio.Event()
    original=h.guard.inspect
    async def review(material):
        if material.phase=='RESULT':
            arrived.set()
            await release.wait()
        return await original(material)
    h.guard.inspect=review
    s=await h.session()
    p,out=await h.propose(s.session_id,[proposal()])
    req=make(BatchRequest,session_id=s.session_id,turn_id=p.turn_id,context_version=p.context_version,calls=out.calls)
    task=asyncio.create_task(h.runtime.execute_batch(req))
    await arrived.wait()
    with pytest.raises(RuntimeFault,match='BATCH_BARRIER_PENDING'):
        await h.propose(s.session_id)
    release.set()
    result=await task
    assert result.results[out.calls[0].call_id].status=='RELEASED'
    await h.propose(s.session_id)

@pytest.mark.asyncio
async def test_policy_change_invalidates_cached_final(harness):
    h=harness
    s=await h.session()
    p,out=await h.propose(s.session_id)
    req=make(FinalizeRequest,session_id=s.session_id,turn_id=p.turn_id,context_version=p.context_version,output_ref=out.output_ref)
    assert (await h.runtime.finalize(req)).status=='RELEASED'
    _,_,old=h.runtime.components(s.session_id)
    await h.runtime.apply_policy(make(PolicyCandidate,session_id=s.session_id,base_policy_version=old.policy_version,rules=[],
        model_destination_ids=old.model_destination_ids,rationale='tightening',evidence_refs=[],unresolved_requirements=[]))
    with pytest.raises(RuntimeFault,match='STALE_CONTEXT'):
        await h.runtime.finalize(req)
