"""Explicit test doubles only. Production bootstrap never imports this module."""
import asyncio
from dataclasses import dataclass
import pytest
from agentguard.v2.contracts import *
from agentguard.v2.bootstrap import build_runtime
from agentguard.v2.registry import ToolRegistry
from agentguard.v2.state.lineage import public_labels
from agentguard.v2.state.artifacts import TransformSpec


class FixedGenerator:
    async def generate(self, req):
        return make(PolicyCandidate, session_id=req.session_id, base_policy_version=req.current_policy_version,
            rules=req.host_policy.rules, model_destination_ids=req.host_policy.model_destination_ids,
            rationale='explicit offline fixture', evidence_refs=[], unresolved_requirements=[])


class FakeReviewer:
    def __init__(self, mode='ALLOW', phase='RESULT'):
        self.mode, self.phase, self.materials = mode, phase, []

    async def inspect(self, material):
        self.materials.append(material)
        mode = self.mode if material.phase == self.phase else 'ALLOW'
        if mode == 'timeout':
            await asyncio.sleep(2)
        if mode == 'malformed':
            return {'schema_version': '0.1', 'status': 'DECIDED'}
        if mode == 'exception':
            raise ValueError('PRIVATE_IN_EXCEPTION')
        ref = material.subject_ref
        targets = []
        evidence = [ref]
        if mode == 'REDACT':
            positioned = ref.model_copy(update={'json_pointer': '/secret'})
            targets = [make(RedactionTarget, evidence_ref=positioned, transform_id='mask_secret')]
        decision = make(ReviewDecision, review_id=material.review_id, session_id=material.session_id,
            turn_id=material.turn_id, call_id=material.call_id, phase=material.phase,
            policy_version=material.policy.policy_version, context_version=material.context_version,
            subject_ref=ref, decision=mode if mode in ('ALLOW', 'BLOCK', 'REDACT', 'NEEDS_CONTEXT') else 'ALLOW',
            reason_code='FIXTURE_DECISION', reason_summary='test', evidence_refs=evidence, findings=[], redaction_targets=targets,
            requested_evidence_refs=[ref] if mode == 'NEEDS_CONTEXT' else [],
            usage=make(Usage, provider='fixture', model='offline', input_tokens=None, output_tokens=None, latency_ms=0.0, attempts=1))
        if mode == 'forged':
            decision = decision.model_copy(update={'subject_ref': ref.model_copy(update={'sha256': '0'*64})})
        return make(ReviewOutcome, status='DECIDED', decision=decision, failure=None)


@dataclass
class Harness:
    runtime: object
    request: object
    guard: object
    effects: list
    reads: list
    handlers: dict

    async def session(self):
        return await self.runtime.create_session(self.request)

    async def propose(self, session_id, proposals=(), messages=(), content='report'):
        prepared = await self.runtime.prepare_model_turn(make(PrepareTurnRequest, session_id=session_id,
            messages=list(messages), model_destination_id='agent'))
        proposed = await self.runtime.record_model_output(make(ModelOutputRequest, session_id=session_id,
            model_call_id=prepared.model_call_id, context_version=prepared.context_version, content=content,
            tool_proposals=list(proposals)))
        return prepared, proposed

    async def run(self, session_id, proposals, messages=()):
        p, out = await self.propose(session_id, proposals, messages)
        batch = make(BatchRequest, session_id=session_id, turn_id=p.turn_id, context_version=p.context_version, calls=out.calls)
        return p, out, await self.runtime.execute_batch(batch)


def proposal(tool='read_document', args=None, refs=(), use='analyze'):
    return make(ToolProposal, tool_id=tool, manifest_version='v1', args=args or {'resource':'docs'}, artifact_refs=list(refs), use=use)


@pytest.fixture
def harness(tmp_path):
    return build_harness(tmp_path)


def build_harness(path, *, mode='ALLOW', output_labels=None, send=True, secret=False):
    registry = ToolRegistry()
    effects, reads = [], []
    guard = FakeReviewer(mode)
    async def read_document(resource):
        reads.append(resource)
        await asyncio.sleep(0.001)
        return {'body':resource, 'secret':'SYNTHETIC_PRIVATE'} if secret else 'document:'+resource
    def write_report(resource, body):
        effects.append(('write', resource, body))
        return 'written'
    async def send_report(destination, body):
        effects.append(('send', destination, body))
        return 'sent'
    def query_rows(resource):
        return [{'id':1, 'name':'row'}]
    handlers = dict(read_document=read_document, write_report=write_report, send_report=send_report, query_rows=query_rows)
    specs = [
        ('read_document', ['READ'], {'resource':{'type':'string'}}, '/resource', None, {}, 'application/json' if secret else 'text/plain'),
        ('write_report', ['WRITE'], {'resource':{'type':'string'},'body':{'type':'string'}}, '/resource', None, {}, 'text/plain'),
        ('send_report', ['SEND'], {'destination':{'type':'string'},'body':{'type':'string'}}, None, '/destination', {}, 'text/plain'),
        ('query_rows', ['READ'], {'resource':{'type':'string'}}, '/resource', None, {}, 'application/json')]
    for tid, eff, props, res, dest, art, media in specs:
        manifest = make(ToolManifest, tool_id=tid, manifest_version='v1', parameters_schema={'type':'object','properties':props,
            'required':list(props), 'additionalProperties':False}, effects=eff, resource_parameter=res, destination_parameter=dest,
            artifact_parameters=art, return_media_type=media, supports_idempotency_key=False,
            output_labels=(output_labels if tid == 'read_document' and output_labels else public_labels('external')), synthetic_demo=True)
        registry.register(manifest, handlers[tid])
    rules = [make(PolicyRule, tool_id=tid, effect=eff[0], resource_scope_ids=['docs','reports'],
        destination_ids=['receiver'] if tid == 'send_report' else [], allowed_uses=['analyze','model','review','reply','send','write'], max_calls=1000)
        for tid, eff, *_ in specs if tid != 'send_report' or send]
    grants = [make(ModelDestinationGrant, destination_id=d, resource_scope_ids=['docs','reports']) for d in ['agent','guard']]
    catalog = make(ResourceCatalog, resources=[make(ResourceScope, scope_id=s, kind='logical', root=s, labels=public_labels('external')) for s in ['docs','reports']],
        destinations=[make(Destination, destination_id=d, kind=k, address=a, allowed_confidentiality=c) for d,k,a,c in [
            ('agent','model','https://agent.test', ['private']), ('guard','model','https://guard.test', ['private']),
            ('receiver','network','https://receiver.test/report', []), ('user','user','local-user', [])]])
    request = make(SessionRequest, trusted_task='Read documents and produce a report; send only to the confirmed test receiver.' if send else 'Create only a local report.',
        host_policy=make(HostPolicy, rules=rules, model_destination_ids=grants, guard_destination_id='guard', final_destination_id='user',
            final_use='reply', max_review_bytes=2_000_000, permit_ttl_seconds=60, review_timeout_seconds=0.2),
        resource_catalog=catalog, tool_manifests=registry.manifests(), confirmed_authorizations=['offline fixture'])
    runtime = build_runtime(path, policy_generator=FixedGenerator(), guard_service=guard, registry=registry,
        transforms=[TransformSpec('mask_secret','mask_json_string',frozenset(['/secret']),frozenset(['/secret']))])
    return Harness(runtime, request, guard, effects, reads, handlers)
