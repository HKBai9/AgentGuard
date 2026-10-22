"""Both teams' fixtures must parse with the shared production models."""

from agentguard.v2.review.boundary import PublicContracts
from agentguard.v2.review.context import ContextBuilder
from .fakes import fixture


def test_public_models_parse_the_same_fixtures():
    contracts = PublicContracts()
    for group in ("normal_allow", "injection_block", "field_redact"):
        material = contracts.parse("ContextMaterial", fixture(group))
        ContextBuilder(contracts=contracts).build(material)
        decision = fixture(group, "model_response.json")
        decision["usage"] = {"schema_version": "0.1", "provider": "fake", "model": "scripted-offline",
                             "input_tokens": None, "output_tokens": None,
                             "latency_ms": 0.0, "attempts": 1}
        contracts.parse("ReviewDecision", decision)
    for task in ("local", "send"):
        contracts.parse("PolicyGenerationRequest", fixture("policy_local_vs_send", task + "_request.json"))
        contracts.parse("PolicyCandidate", fixture("policy_local_vs_send", task + "_candidate.json"))
