"""Real A runtime + real B compiler/service; only cloud inference is scripted.

These are integration assertions, not model accuracy or attack-rate evidence.
"""
import json

import pytest

from conftest import build_harness, proposal
from agentguard.v2.common import RuntimeFault
from agentguard.v2.contracts import BatchRequest, FinalizeRequest, make
from agentguard.v2.policy.compiler import PolicyCompiler
from agentguard.v2.review.clients import CloudReply
from agentguard.v2.review.context import ContextBuilder
from agentguard.v2.review.errors import GuardError
from agentguard.v2.review.reviewers import Reviewer
from agentguard.v2.review.service import GuardService


class ScriptedCloud:
    provider = 'integration-fixture'
    model = 'scripted-no-inference'
    destination_id = 'guard'

    def __init__(self, mode='ALLOW', phase='RESULT', over_quota=False):
        self.mode, self.phase, self.over_quota = mode, phase, over_quota
        self.requests = []

    async def complete(self, *, messages, purpose, prompt_version):
        self.requests.append((purpose, messages))
        req = json.loads(messages[1]['content'])
        usage = {'provider': self.provider, 'model': self.model, 'input_tokens': 'unavailable',
                 'output_tokens': 'unavailable', 'latency_ms': 0.0, 'attempts': 1}
        if purpose == 'policy':
            # Preselected fixture permissions; no claim of semantic inference.
            response = {'schema_version': '0.1', 'session_id': req['session_id'],
                        'base_policy_version': req['current_policy_version'],
                        'rules': req['host_policy']['rules'],
                        'model_destination_ids': req['host_policy']['model_destination_ids'],
                        'rationale': 'Explicit fixture policy', 'evidence_refs': [], 'unresolved_requirements': []}
            if self.over_quota:
                response['rules'][0]['max_calls'] += 1
        else:
            boundary = req['trusted_boundary']
            mode = self.mode if purpose == self.phase else 'ALLOW'
            if mode == 'TIMEOUT':
                raise GuardError('MODEL_TIMEOUT')
            if mode == 'MALFORMED':
                return CloudReply('{invalid', usage)
            keys = ('schema_version', 'review_id', 'session_id', 'turn_id', 'call_id', 'phase',
                    'policy_version', 'context_version', 'subject_ref')
            response = {key: boundary[key] for key in keys}
            response.update(decision=mode, reason_code='NORMAL_CONTENT' if mode == 'ALLOW' else 'INJECTION_DETECTED',
                            reason_summary='Scripted integration outcome', evidence_refs=[boundary['subject_ref']],
                            findings=[], redaction_targets=[], requested_evidence_refs=[])
            if mode in ('BLOCK', 'REDACT'):
                position = dict(boundary['subject_ref'])
                if mode == 'REDACT':
                    position['json_pointer'] = '/secret'
                    response['redaction_targets'] = [{'schema_version': '0.1', 'evidence_ref': position,
                                                      'transform_id': 'mask_secret'}]
                else:
                    position['span'] = [0, len(req['untrusted_evidence']['subject'])]
                response['findings'] = [{'schema_version': '0.1', 'finding_type': 'SYNTHETIC_RISK',
                                         'affected_action_field': None, 'evidence_refs': [position]}]
        return CloudReply(json.dumps(response), usage)


def integrated(path, *, mode='ALLOW', phase='RESULT', secret=False, over_quota=False):
    h = build_harness(path, secret=secret)
    cloud = ScriptedCloud(mode, phase, over_quota)
    h.runtime.generator = PolicyCompiler(cloud)
    h.runtime.guard = GuardService(ContextBuilder(), Reviewer(cloud))
    return h, cloud


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,status', [('ALLOW', 'RELEASED'), ('BLOCK', 'BLOCKED'),
                                        ('REDACT', 'RELEASED'), ('MALFORMED', 'REVIEW_PENDING'),
                                        ('TIMEOUT', 'REVIEW_PENDING')])
async def test_real_compiler_and_guard_connect_to_quarantine(tmp_path, mode, status):
    h, cloud = integrated(tmp_path, mode=mode, secret=mode == 'REDACT')
    s = await h.session()
    prepared, output, batch = await h.run(s.session_id, [proposal()])
    result = next(iter(batch.results.values()))
    assert result.status == status
    assert h.reads == ['docs']
    assert [p for p, _ in cloud.requests] == ['policy', 'ACTION', 'RESULT']
    raw_ref = result.receipt.artifact_ref
    if mode == 'REDACT':
        assert result.content['secret'] != 'SYNTHETIC_PRIVATE'
        assert result.artifact_ref != raw_ref
        assert not h.runtime.artifacts.is_released(s.session_id, raw_ref)
    elif status != 'RELEASED':
        assert result.content is None and result.artifact_ref is None
        assert not h.runtime.artifacts.is_released(s.session_id, raw_ref)
    else:
        assert result.content == 'document:docs'
        final = await h.runtime.finalize(make(FinalizeRequest, session_id=s.session_id,
            turn_id=prepared.turn_id, context_version=prepared.context_version, output_ref=output.output_ref))
        assert final.status == 'RELEASED' and cloud.requests[-1][0] == 'FINAL'


@pytest.mark.asyncio
async def test_guard_failure_before_execution_has_no_tool_effect(tmp_path):
    h, cloud = integrated(tmp_path, mode='MALFORMED', phase='ACTION')
    s = await h.session()
    _, _, batch = await h.run(s.session_id, [proposal()])
    assert next(iter(batch.results.values())).status == 'REVIEW_PENDING'
    assert h.reads == [] and h.effects == []
    assert [p for p, _ in cloud.requests] == ['policy', 'ACTION']


@pytest.mark.asyncio
async def test_model_policy_cannot_exceed_host_quota(tmp_path):
    h, _ = integrated(tmp_path, over_quota=True)
    with pytest.raises(RuntimeFault, match='HOST_POLICY_EXCEEDED'):
        await h.session()
    assert not h.reads and not h.effects


@pytest.mark.asyncio
async def test_wrong_guard_destination_never_receives_content(tmp_path):
    h, cloud = integrated(tmp_path)
    s = await h.session()
    cloud.destination_id = 'unauthorized-cloud'
    _, _, batch = await h.run(s.session_id, [proposal()])
    result = next(iter(batch.results.values()))
    assert result.status == 'REVIEW_PENDING' and result.reason_code == 'MODEL_DESTINATION_DENIED'
    assert [p for p, _ in cloud.requests] == ['policy']
    assert not h.reads


@pytest.mark.asyncio
async def test_final_output_error_stays_unreleased(tmp_path):
    h, _ = integrated(tmp_path, mode='TIMEOUT', phase='FINAL')
    s = await h.session()
    prepared, output = await h.propose(s.session_id, content='unreleased answer')
    final = await h.runtime.finalize(make(FinalizeRequest, session_id=s.session_id,
        turn_id=prepared.turn_id, context_version=prepared.context_version, output_ref=output.output_ref))
    assert final.status == 'REVIEW_PENDING' and final.content is None
    assert not h.runtime.artifacts.is_released(s.session_id, output.output_ref)
