import asyncio
import pytest
from agentguard.v2.contracts import *
from agentguard.v2.common import RuntimeFault, canonical
from agentguard.v2.state.lineage import public_labels
from conftest import build_harness, proposal

@pytest.mark.asyncio
async def test_full_lifecycle(harness):
    h = harness
    s = await h.session()
    p, out, batch = await h.run(s.session_id, [proposal()])
    result = batch.results[out.calls[0].call_id]
    assert result.status == 'RELEASED'
    assert result.content == 'document:docs'
    assert h.reads == ['docs']
    again = await h.runtime.execute_call(out.calls[0])
    assert again == result and len(h.reads) == 1
    p2, out2 = await h.propose(s.session_id, messages=[make(Message, role='tool', ref=result.artifact_ref)], content='finished report')
    final = await h.runtime.finalize(make(FinalizeRequest, session_id=s.session_id, turn_id=p2.turn_id,
        context_version=p2.context_version, output_ref=out2.output_ref))
    assert final.status == 'RELEASED' and final.content == 'finished report'
    events = h.runtime.store.events(s.session_id)
    kinds = [e.event_type for e in events]
    assert kinds.index('PERMIT_CLAIMED') < kinds.index('RESULT_QUARANTINED') < kinds.index('RESULT_RELEASED')
    assert len({e.seq for e in events}) == len(events)

@pytest.mark.asyncio
@pytest.mark.parametrize('mode,code', [('BLOCK','GUARD_DECISION'),('timeout','MODEL_TIMEOUT'),('malformed','INVALID_SCHEMA'),
    ('forged','INVALID_REFERENCE'),('exception','SERVICE_UNAVAILABLE'),('NEEDS_CONTEXT','MISSING_EVIDENCE')])
async def test_fail_closed(tmp_path,mode,code):
    h = build_harness(tmp_path,mode=mode)
    s = await h.session()
    _,out,batch = await h.run(s.session_id,[proposal()])
    r = batch.results[out.calls[0].call_id]
    assert r.status in ('BLOCKED','REVIEW_PENDING') and r.content is None and r.artifact_ref is None
    assert r.reason_code == code
    assert 'document:docs' not in canonical(r)
    assert 'PRIVATE_IN_EXCEPTION' not in canonical([e.model_dump(mode='json') for e in h.runtime.store.events(s.session_id)])
    assert len(h.reads) == 1
    assert len([m for m in h.guard.materials if m.phase=='RESULT']) <= 2

@pytest.mark.asyncio
async def test_redaction_keeps_original_quarantined(tmp_path):
    field = make(Restrictions,confidentiality=['private'],allowed_uses=None,destination_ids=None,model_destination_ids=['guard'])
    labels = public_labels('external').model_copy(update={'field_restrictions':{'/secret':field}})
    h = build_harness(tmp_path,mode='REDACT',output_labels=labels,secret=True)
    s = await h.session()
    _,out,batch = await h.run(s.session_id,[proposal()])
    r = batch.results[out.calls[0].call_id]
    assert r.status == 'RELEASED', r
    assert r.content['secret'] == '[REDACTED]' and r.artifact_ref.version == 2
    original = r.receipt.artifact_ref
    assert not h.runtime.artifacts.is_released(s.session_id,original)
    assert h.runtime.artifacts.read(s.session_id,original)['secret'] == 'SYNTHETIC_PRIVATE'
    assert h.runtime.lineage.edges(s.session_id)[-1].kind == 'exact'

@pytest.mark.asyncio
async def test_document_restriction_survives_field_redaction(tmp_path):
    labels = public_labels('external').model_copy(update={'model_destination_ids':['guard']})
    h = build_harness(tmp_path,mode='REDACT',output_labels=labels,secret=True)
    s = await h.session()
    _,out,batch = await h.run(s.session_id,[proposal()])
    r = batch.results[out.calls[0].call_id]
    assert r.status == 'BLOCKED' and r.reason_code=='DATA_DESTINATION_DENIED'

@pytest.mark.asyncio
async def test_local_policy_cannot_send(tmp_path):
    h=build_harness(tmp_path,send=False)
    s=await h.session()
    _,out,batch=await h.run(s.session_id,[proposal('send_report',{'destination':'receiver','body':'report'},use='send')])
    assert batch.results[out.calls[0].call_id].status=='BLOCKED' and h.effects==[]

@pytest.mark.asyncio
@pytest.mark.parametrize('steps',[10,30,60])
async def test_long_history_sticky_data_restrictions(tmp_path,steps):
    h=build_harness(tmp_path)
    s=await h.session()
    restricted=public_labels('external').model_copy(update={'confidentiality':['private'],'allowed_uses':['model','review','analyze'],
        'destination_ids':[], 'model_destination_ids':['agent','guard']})
    secret=h.runtime.ingest(s.session_id,'SYNTHETIC_PRIVATE',restricted,resource_scope_ids=['docs'])
    for step in range(steps):
        messages=[make(Message,role='tool',ref=secret)] if step==2 else []
        p,out=await h.propose(s.session_id,messages=messages,content='summary')
    _,out,batch=await h.run(s.session_id,[proposal('send_report',{'destination':'receiver','body':'encoded summary'},use='send')])
    result=batch.results[out.calls[0].call_id]
    assert result.status=='BLOCKED' and result.reason_code=='DATA_USE_DENIED' and h.effects==[]
    final=await h.runtime.finalize(make(FinalizeRequest,session_id=s.session_id,turn_id=out.turn_id,
        context_version=out.calls[0].input_context_version,output_ref=out.output_ref))
    assert final.status=='BLOCKED' and final.content is None

@pytest.mark.asyncio
async def test_20_out_of_order_calls(harness):
    h=harness
    s=await h.session()
    _,out,batch=await h.run(s.session_id,[proposal() for _ in range(20)])
    assert len(batch.results)==len(h.reads)==20
    assert all(r.call_id==k and r.status=='RELEASED' for k,r in batch.results.items())
    assert len({r.artifact_ref.artifact_id for r in batch.results.values()})==20
