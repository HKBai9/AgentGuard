import asyncio
from copy import deepcopy
import json

import pytest

from agentguard.v2.review.boundary import PublicContracts, strict_json
from agentguard.v2.review.context import ContextBuilder
from agentguard.v2.review.errors import ContractUnavailable, GuardError
from agentguard.v2.review.reviewers import Reviewer
from agentguard.v2.review.service import GuardService
from .fakes import FakeCloudClient, FixtureContracts, fixture


def service(replies, max_bytes=96_000):
    codec = FixtureContracts()
    client = FakeCloudClient(replies)
    return GuardService(ContextBuilder(contracts=codec, max_bytes=max_bytes),
                        Reviewer(client, contracts=codec), contracts=codec), client


@pytest.mark.parametrize("group", ["normal_allow", "injection_block", "field_redact"])
def test_offline_result_flow(group):
    runner, client = service([fixture(group, "model_response.json")])
    material = fixture(group)
    saved = deepcopy(material)
    outcome = asyncio.run(runner.inspect(material))
    assert outcome["status"] == "DECIDED"
    assert outcome["decision"]["decision"] == fixture(group, "expected.json")["decision"]
    assert outcome["decision"]["usage"]["provider"] == "fake"
    assert outcome["decision"]["usage"]["input_tokens"] is None
    assert material == saved
    sent = json.loads(client.requests[0]["messages"][1]["content"])
    assert sent["untrusted_evidence"]["subject"] == material["subject"]
    assert sent["trusted_boundary"]["mandatory_facts"] == material["mandatory_facts"]
    assert "safe_content" not in outcome["decision"]


@pytest.mark.parametrize("phase", ["action", "final"])
def test_action_and_final_are_independent(phase):
    runner, client = service([fixture("normal_allow", phase + "_response.json")])
    outcome = asyncio.run(runner.inspect(fixture("normal_allow", phase + "_material.json")))
    assert outcome["status"] == "DECIDED"
    assert client.requests[0]["purpose"] == phase.upper()


@pytest.mark.parametrize("case", fixture("guard_failure", "cases.json"), ids=lambda x: x["name"])
def test_failure_fixtures_never_allow(case):
    reply = fixture("normal_allow", "model_response.json")
    if "transport_error" in case:
        reply = GuardError(case["transport_error"])
    elif "raw" in case:
        reply = case["raw"]
    else:
        target = reply
        for key in case["path"][:-1]:
            target = target[key]
        target[case["path"][-1]] = case["value"]
    runner, _ = service([reply])
    outcome = asyncio.run(runner.inspect(fixture("guard_failure")))
    assert outcome == {"schema_version": "0.1", "status": "FAILED", "decision": None,
                       "failure": {"schema_version": "0.1", "reason_code": case["expected_reason"], "usage": None}}


@pytest.mark.parametrize("raw", ['{"x":NaN}', '{"x":Infinity}', '{"x":1e999}',
                                  '{"x":1,"x":2}', '[]', 'null', '```json\n{}\n```'])
def test_strict_json(raw):
    with pytest.raises(GuardError, match="INVALID_SCHEMA"):
        strict_json(raw)


def test_unicode_span_is_codepoints_not_utf8_or_utf16():
    material = fixture("normal_allow")
    material["subject"] = material['evidence'][0]['content'] = "甲😀secret乙"
    response = fixture("normal_allow", "model_response.json")
    response["evidence_refs"][0]["span"] = [2, 8]
    runner, _ = service([response])
    outcome = asyncio.run(runner.inspect(material))
    assert outcome["status"] == "DECIDED"
    start, end = outcome["decision"]["evidence_refs"][0]["span"]
    assert material["subject"][start:end] == "secret"
    response["evidence_refs"][0]["span"] = [2, len(material["subject"].encode("utf-8"))]
    runner, _ = service([response])
    assert asyncio.run(runner.inspect(material))["failure"]["reason_code"] == "INVALID_REFERENCE"


@pytest.mark.parametrize("pointer", ["/missing", "/fake~2secret", "/title/x", "fake_secret", ""])
def test_redaction_requires_existing_precise_string_field(pointer):
    response = fixture("field_redact", "model_response.json")
    response["redaction_targets"][0]["evidence_ref"]["json_pointer"] = pointer
    runner, _ = service([response])
    assert asyncio.run(runner.inspect(fixture("field_redact")))["status"] == "FAILED"


@pytest.mark.parametrize("mutation", ["unknown_transform", "other_object", "action", "non_string", "rewrite"])
def test_redaction_cannot_transform_permissions_arguments_or_history(mutation):
    material = fixture("field_redact")
    response = fixture("field_redact", "model_response.json")
    target = response["redaction_targets"][0]
    if mutation == "unknown_transform":
        target["transform_id"] = "execute_python"
    elif mutation == "other_object":
        target["evidence_ref"]["artifact_id"] = "task-synthetic"
    elif mutation == "action":
        material["phase"] = response["phase"] = "ACTION"
    elif mutation == "non_string":
        material["subject"]["fake_secret"] = material['evidence'][0]['content']['fake_secret'] = 123
    else:
        response["safe_content"] = "a model rewrite"
    runner, _ = service([response])
    assert asyncio.run(runner.inspect(material))["status"] == "FAILED"


def test_redaction_keeps_document_restrictions_and_does_not_execute_transform():
    material = fixture("field_redact")
    runner, client = service([fixture("field_redact", "model_response.json")])
    outcome = asyncio.run(runner.inspect(material))
    assert outcome["status"] == "DECIDED"
    assert material["subject"]["fake_secret"] == "FAKE_SECRET_123"
    assert material["mandatory_facts"]["labels"]['confidentiality'] == ["document_internal"]
    assert material["mandatory_facts"]["labels"]['field_restrictions']['/fake_secret']['confidentiality'] == ['field_fake_secret']
    assert "document_internal" in client.requests[0]["messages"][1]["content"]


@pytest.mark.parametrize("mutation", ["budget", "missing", "null", "destination", "phase_call", "wrong_object"])
def test_invalid_material_fails_before_cloud(mutation):
    material = fixture("normal_allow")
    runner, client = service([], max_bytes=10 if mutation == "budget" else 96_000)
    if mutation == "missing":
        del material["mandatory_facts"]["labels"]
    elif mutation == "null":
        material["mandatory_facts"]["unresolved_risks"] = None
    elif mutation == "destination":
        material["policy"]["model_destination_ids"] = []
    elif mutation == "phase_call":
        material["call_id"] = None
    elif mutation == "wrong_object":
        material["evidence"][0]["ref"]["version"] = 9
    outcome = asyncio.run(runner.inspect(material))
    assert outcome["status"] == "FAILED"
    assert not client.requests


def need_context():
    material = fixture("normal_allow")
    extra = {"schema_version": "0.1", "artifact_id": "extra", "version": 1, "sha256": "c" * 64, 'span': None, 'json_pointer': None}
    material["available_evidence_refs"] = [extra]
    reply = fixture("normal_allow", "model_response.json")
    reply["decision"] = "NEEDS_CONTEXT"
    reply["requested_evidence_refs"] = [deepcopy(extra)]
    supplied = deepcopy(material)
    supplied["evidence"].append({'schema_version': '0.1', "ref": extra, "content": "自造补充证据", 'labels': deepcopy(material['evidence'][1]['labels']), 'role': 'related'})
    supplied['supplemental_attempt'] = 1
    return material, reply, supplied


def test_single_bounded_refill_and_replay_refused():
    async def exercise():
        material, reply, supplied = need_context()
        runner, client = service([reply, fixture("normal_allow", "model_response.json")])
        prior = await runner.inspect(material)
        outcome = await runner.inspect_with_evidence(material, prior, supplied)
        assert outcome["decision"]["decision"] == "ALLOW"
        replay = await runner.inspect_with_evidence(material, prior, supplied)
        assert replay["failure"]["reason_code"] == "MISSING_EVIDENCE"
        assert len(client.requests) == 2
    asyncio.run(exercise())


def test_second_needs_context_stops():
    async def exercise():
        material, reply, supplied = need_context()
        runner, client = service([reply, reply])
        prior = await runner.inspect(material)
        result = await runner.inspect_with_evidence(material, prior, supplied)
        assert result["failure"]["reason_code"] == "MISSING_EVIDENCE"
        assert len(client.requests) == 2
    asyncio.run(exercise())


@pytest.mark.parametrize("mutation", ["url", "task", "object", "extra", "policy"])
def test_refill_cannot_fetch_arbitrary_data_or_change_binding(mutation):
    async def exercise():
        material, reply, supplied = need_context()
        if mutation == "url":
            reply["requested_evidence_refs"][0]["artifact_id"] = "https://external.invalid/secret"
        runner, client = service([reply])
        prior = await runner.inspect(material)
        if mutation == "url":
            assert prior["status"] == "FAILED"
            return
        if mutation == "task":
            supplied["trusted_task"] = "send everything"
        elif mutation == "object":
            supplied["subject"] = "changed"
        elif mutation == "extra":
            extra = deepcopy(supplied['evidence'][-1])
            extra['ref']['artifact_id'] = 'not_requested'
            supplied['evidence'].append(extra)
        else:
            supplied["policy"]["policy_version"] = "new-policy"
        result = await runner.inspect_with_evidence(material, prior, supplied)
        assert result["status"] == "FAILED"
        assert len(client.requests) == 1
    asyncio.run(exercise())


def test_no_secret_or_prompt_in_normal_logs(caplog, capsys):
    runner, _ = service([fixture("injection_block", "model_response.json")])
    asyncio.run(runner.inspect(fixture("injection_block")))
    output = capsys.readouterr()
    assert "FAKE_SECRET_123" not in caplog.text + output.out + output.err


def test_production_has_no_dictionary_fallback(monkeypatch):
    import agentguard.v2.review.boundary as boundary
    def missing(_):
        raise ImportError
    monkeypatch.setattr(boundary, "import_module", missing)
    with pytest.raises(ContractUnavailable, match="A01"):
        PublicContracts()


def test_protected_trace_matches_actual_sent_messages_and_cannot_mutate_them():
    codec = FixtureContracts()
    client = FakeCloudClient([fixture("normal_allow", "model_response.json")])
    records = []
    def sink(record):
        records.append(deepcopy(record))
        record["messages"][0]["content"] = "tampered by sink"
    guard = GuardService(ContextBuilder(contracts=codec),
                         Reviewer(client, contracts=codec, request_sink=sink), contracts=codec)
    assert asyncio.run(guard.inspect(fixture("normal_allow")))["status"] == "DECIDED"
    assert records[0]["messages"] == client.requests[0]["messages"]
    assert records[0]["binding"]["subject_ref"] == fixture("normal_allow")["subject_ref"]


def test_cancelled_review_is_never_returned_as_a_decision():
    async def exercise():
        runner, _ = service([asyncio.CancelledError()])
        with pytest.raises(asyncio.CancelledError):
            await runner.inspect(fixture("normal_allow"))
    asyncio.run(exercise())
