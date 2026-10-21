"""This is deliberately skipped until A01 supplies the one shared model module."""

from importlib.util import find_spec

import pytest

from agentguard.v2.review.boundary import PublicContracts
from agentguard.v2.review.context import ContextBuilder
from .fakes import fixture


def test_public_models_parse_the_same_fixtures_when_a01_is_available():
    if find_spec("agentguard.v2.contracts") is None:
        pytest.skip("A01 pending: no shared contracts/ports; dictionary tests are not contract parity")
    contracts = PublicContracts()
    for group in ("normal_allow", "injection_block", "field_redact"):
        material = contracts.parse("ContextMaterial", fixture(group))
        ContextBuilder(contracts=contracts).build(material)
        decision = fixture(group, "model_response.json")
        decision["usage"] = {"provider": "fake", "model": "scripted-offline",
                             "input_tokens": "unavailable", "output_tokens": "unavailable",
                             "latency_ms": 0.0, "attempts": 1}
        contracts.parse("ReviewDecision", decision)
    for task in ("local", "send"):
        contracts.parse("PolicyGenerationRequest", fixture("policy_local_vs_send", task + "_request.json"))
        contracts.parse("PolicyCandidate", fixture("policy_local_vs_send", task + "_candidate.json"))
