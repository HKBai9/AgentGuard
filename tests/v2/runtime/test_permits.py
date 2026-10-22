import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import pytest
from agentguard.v2.common import RuntimeFault, utcnow, canonical
from agentguard.v2.contracts import *
from agentguard.v2.execution.executor import KnownToolFailure, ToolResult
from agentguard.v2.bootstrap import build_runtime
from conftest import proposal, build_harness

async def prepare(h):
    s=await h.session()
    p,out=await h.propose(s.session_id,[proposal()])
    call=out.calls[0]
    return s,call,h.runtime.permits.issue(call,[])

@pytest.mark.asyncio
@pytest.mark.parametrize('two',[False,True])
async def test_atomic_competing_claims(harness,two):
    h=harness
    s,call,p1=await prepare(h)
    p2=h.runtime.permits.issue(call,[]) if two else p1
    def claim(p):
        try:
            h.runtime.permits.claim(p,call)
            return 'claimed'
        except RuntimeFault as e:
            return e.code
    with ThreadPoolExecutor(8) as pool:
        results=list(pool.map(claim,[p1,p2]*12))
    assert results.count('claimed')==1
    with h.runtime.store.connect() as conn:
        assert conn.execute('SELECT COUNT(*) FROM claims').fetchone()[0]==1
        assert conn.execute('SELECT used FROM quotas').fetchone()[0]==1

@pytest.mark.asyncio
async def test_two_runtimes_actual_dispatch_once(harness,tmp_path):
    h=harness
    s=await h.session()
    _,out=await h.propose(s.session_id,[proposal()])
    second=build_runtime(tmp_path,policy_generator=h.runtime.generator,guard_service=h.guard,registry=h.runtime.registry)
    results=await asyncio.gather(h.runtime.execute_call(out.calls[0]),second.execute_call(out.calls[0]))
    assert len(h.reads)==1
    assert sum(r.status=='RELEASED' for r in results)>=1
    assert (await second.execute_call(out.calls[0])).status=='RELEASED'
    assert len(h.reads)==1

@pytest.mark.asyncio
@pytest.mark.parametrize('change',['args','tool','policy','context','ttl','security'])
async def test_stale_permit_fails(harness,change):
    h=harness
    s,call,p=await prepare(h)
    if change=='args':
        call=call.model_copy(update={'args':{'resource':'reports'}})
    elif change=='tool':
        entry=h.runtime.registry.get('read_document')
        h.runtime.registry.register(entry.manifest.model_copy(update={'manifest_version':'v2'}),entry.handler)
    elif change=='policy':
        _,_,old=h.runtime.components(s.session_id)
        c=make(PolicyCandidate,session_id=s.session_id,base_policy_version=old.policy_version,rules=[],model_destination_ids=old.model_destination_ids,
            rationale='tighten',evidence_refs=[],unresolved_requirements=[])
        await h.runtime.apply_policy(c)
    elif change=='context':
        await h.propose(s.session_id)
    elif change=='security':
        with h.runtime.store.transaction() as conn:
            state=h.runtime.store.session(s.session_id,conn)
            state['security_revision']+=1
            h.runtime.store.save_session(s.session_id,state,conn)
    else:
        p=p.model_copy(update={'expires_at':utcnow()-timedelta(seconds=1)})
        with h.runtime.store.transaction() as conn:
            conn.execute('UPDATE permits SET data=? WHERE id=?',(canonical(p),p.permit_id))
    with pytest.raises(RuntimeFault):
        h.runtime.permits.claim(p,call)
    assert h.reads==[]

@pytest.mark.asyncio
@pytest.mark.parametrize('known',[False,True])
async def test_exception_effect_not_retried(tmp_path,known):
    h=build_harness(tmp_path)
    entry=h.runtime.registry.get('send_report')
    async def faulty(destination,body):
        if not known:
            h.effects.append(body)
        raise KnownToolFailure('PRIVATE_ERROR_BODY') if known else ValueError('PRIVATE_ERROR_BODY')
    h.runtime.registry.register(entry.manifest.model_copy(update={'manifest_version':'v2'}),faulty)
    h.request=h.request.model_copy(update={'tool_manifests':h.runtime.registry.manifests()})
    s=await h.session()
    prop=proposal('send_report',{'destination':'receiver','body':'report'},use='send').model_copy(update={'manifest_version':'v2'})
    _,out,b=await h.run(s.session_id,[prop])
    r=b.results[out.calls[0].call_id]
    assert r.status==('FAILED_KNOWN' if known else 'UNKNOWN') and r.content is None
    assert 'PRIVATE_ERROR_BODY' not in canonical(r)
    await h.runtime.execute_call(out.calls[0])
    assert h.effects==([] if known else ['report'])
    assert h.runtime.artifacts.read(s.session_id,r.receipt.artifact_ref)['error']=='PRIVATE_ERROR_BODY'

@pytest.mark.asyncio
async def test_crash_after_claim_requires_unknown(harness,tmp_path):
    h=harness
    s,call,p=await prepare(h)
    h.runtime.permits.claim(p,call)
    restarted=build_runtime(tmp_path,policy_generator=h.runtime.generator,guard_service=h.guard,registry=h.runtime.registry)
    assert restarted.permits.recover_abandoned()==1
    result=await restarted.execute_call(call)
    assert result.status=='UNKNOWN' and result.receipt.reason_code=='WORKER_LOST_AFTER_CLAIM'
    assert h.reads==[]

@pytest.mark.asyncio
async def test_atomic_quota_reservation(harness):
    h=harness
    rules=[r.model_copy(update={'max_calls':1}) for r in h.request.host_policy.rules]
    h.request=h.request.model_copy(update={'host_policy':h.request.host_policy.model_copy(update={'rules':rules})})
    s=await h.session()
    _,out,b=await h.run(s.session_id,[proposal() for _ in range(8)])
    assert len(h.reads)==1
    assert sum(r.status=='RELEASED' for r in b.results.values())==1
    assert all(r.status=='RELEASED' or r.reason_code=='QUOTA_EXHAUSTED' for r in b.results.values())

@pytest.mark.asyncio
async def test_review_does_not_hold_sqlite_transaction(harness):
    h=harness
    original=h.guard.inspect
    async def inspect(material):
        with h.runtime.store.transaction() as conn:
            h.runtime.store.event(material.session_id,'INDEPENDENT_WRITE',{},conn)
        return await original(material)
    h.guard.inspect=inspect
    s=await h.session()
    _,out,b=await h.run(s.session_id,[proposal()])
    assert b.results[out.calls[0].call_id].status=='RELEASED'
