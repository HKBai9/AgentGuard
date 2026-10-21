"""Explicit OFFLINE installation smoke. No paid models or production defaults."""
import asyncio
import json
import tempfile
from pathlib import Path
import agentguard.v2
from agentguard.v2.contracts import *
from agentguard.v2.ports import RuntimePort
from agentguard.v2.bootstrap import build_runtime
from agentguard.v2.registry import ToolRegistry
from agentguard.v2.schema import load
from agentguard.v2.state.lineage import public_labels


class OfflinePolicy:
    async def generate(self, req):
        return make(PolicyCandidate, session_id=req.session_id, base_policy_version=None,
            rules=req.host_policy.rules, model_destination_ids=req.host_policy.model_destination_ids,
            rationale='explicit installation smoke', evidence_refs=[], unresolved_requirements=[])


class OfflineGuard:
    async def inspect(self, m):
        decision=make(ReviewDecision, review_id=m.review_id, session_id=m.session_id, turn_id=m.turn_id, call_id=m.call_id,
            phase=m.phase, policy_version=m.policy.policy_version, context_version=m.context_version, subject_ref=m.subject_ref,
            decision='ALLOW', reason_code='OFFLINE_SMOKE', reason_summary='synthetic', evidence_refs=[m.subject_ref], findings=[],
            redaction_targets=[], requested_evidence_refs=[], usage=make(Usage, provider=None, model=None,
                input_tokens=None, output_tokens=None, latency_ms=None, attempts=1))
        return make(ReviewOutcome,status='DECIDED',decision=decision,failure=None)


async def main():
    labels=public_labels()
    registry=ToolRegistry()
    manifest=make(ToolManifest,tool_id='echo',manifest_version='v1',parameters_schema={'type':'object','properties':{},'additionalProperties':False},
        effects=['READ'],resource_parameter=None,destination_parameter=None,artifact_parameters={},return_media_type='text/plain',
        supports_idempotency_key=False,output_labels=labels)
    registry.register(manifest,lambda:'installed smoke')
    grant=make(ModelDestinationGrant,destination_id='model',resource_scope_ids=[])
    request=make(SessionRequest,trusted_task='installation smoke',confirmed_authorizations=[],tool_manifests=[manifest],
        resource_catalog=make(ResourceCatalog,resources=[],destinations=[
            make(Destination,destination_id='model',kind='model',address='https://offline.invalid',allowed_confidentiality=[]),
            make(Destination,destination_id='user',kind='user',address='local',allowed_confidentiality=[])]),
        host_policy=make(HostPolicy,rules=[make(PolicyRule,tool_id='echo',effect='READ',resource_scope_ids=[],destination_ids=[],allowed_uses=['analyze'],max_calls=1)],
            model_destination_ids=[grant],guard_destination_id='model',final_destination_id='user',final_use='reply',max_review_bytes=100000,
            permit_ttl_seconds=60,review_timeout_seconds=1.0))
    with tempfile.TemporaryDirectory() as directory:
        runtime=build_runtime(directory,policy_generator=OfflinePolicy(),guard_service=OfflineGuard(),registry=registry)
        assert isinstance(runtime,RuntimePort)
        s=await runtime.create_session(request)
        p=await runtime.prepare_model_turn(make(PrepareTurnRequest,session_id=s.session_id,messages=[],model_destination_id='model'))
        out=await runtime.record_model_output(make(ModelOutputRequest,session_id=s.session_id,model_call_id=p.model_call_id,context_version=p.context_version,
            content='report',tool_proposals=[make(ToolProposal,tool_id='echo',manifest_version='v1',args={},artifact_refs=[],use='analyze')]))
        result=await runtime.execute_batch(make(BatchRequest,session_id=s.session_id,turn_id=p.turn_id,context_version=p.context_version,calls=out.calls))
        assert result.results[out.calls[0].call_id].content=='installed smoke'
        final=await runtime.finalize(make(FinalizeRequest,session_id=s.session_id,turn_id=p.turn_id,context_version=p.context_version,output_ref=out.output_ref))
        assert final.content=='report'
    assert load('Permit')['properties']['schema_version']['const']=='0.1'
    print(json.dumps({'installed_module':str(Path(agentguard.v2.__file__).resolve()),'schema':'0.1','runtime_smoke':'passed'}))


if __name__=='__main__':
    asyncio.run(main())
