"""Policy candidate producer. Does not implement A's validator or version store."""

from agentguard.v2.review.boundary import PublicContracts, dumps, payload, strict_json, versioned
from agentguard.v2.review.errors import GuardError
from agentguard.v2.review.evidence import check_ref, identity
from agentguard.v2.review.reviewers import authorize_destination
from .templates import POLICY_PROMPT_VERSION, POLICY_SYSTEM


def _strings(value):
    if (not isinstance(value, list) or any(not isinstance(v, str) or not v for v in value) or
        len(value) != len(set(value))):
        raise GuardError("INVALID_SCHEMA")
    return set(value)


def validate_candidate(candidate, req):
    expected = {"schema_version", "session_id", "base_policy_version", "rules",
                "model_destination_ids", "rationale", "evidence_refs", "unresolved_requirements"}
    if set(candidate) != expected or candidate["schema_version"] != "0.1":
        raise GuardError("INVALID_SCHEMA")
    if any(candidate[k] != req[k] for k in ("session_id", "base_policy_version")):
        raise GuardError("INVALID_REFERENCE")
    if not isinstance(candidate["rules"], list) or not isinstance(candidate["rationale"], str):
        raise GuardError("INVALID_SCHEMA")
    _strings(candidate["unresolved_requirements"])
    catalog = req["resource_catalog"]
    scopes = {item["resource_scope_id"] for item in catalog["resource_scopes"]}
    destinations = {item["destination_id"] for item in catalog["destinations"]}
    models = {item["destination_id"] for item in catalog["model_destinations"]}
    uses = set(catalog["allowed_uses"])
    manifests = {item["tool_id"]: item for item in req["tool_manifests"]}
    if not _strings(candidate["model_destination_ids"]) <= models & set(req["authorized_model_destination_ids"]):
        raise GuardError("INVALID_REFERENCE")
    for rule in candidate["rules"]:
        if (not isinstance(rule, dict) or set(rule) != {"tool_id", "effect", "resource_scope_ids",
            "destination_ids", "allowed_uses", "max_calls"} or
            rule["effect"] not in ("READ", "WRITE", "SEND", "DELETE") or
            type(rule["max_calls"]) is not int or rule["max_calls"] < 1):
            raise GuardError("INVALID_SCHEMA")
        if not isinstance(rule["tool_id"], str) or rule["tool_id"] not in manifests:
            raise GuardError("INVALID_REFERENCE")
        if (rule["effect"] not in manifests[rule["tool_id"]]["effects"] or
            not _strings(rule["resource_scope_ids"]) <= scopes or
            not _strings(rule["destination_ids"]) <= destinations or
            not _strings(rule["allowed_uses"]) <= uses):
            raise GuardError("INVALID_REFERENCE")
        if not rule["resource_scope_ids"] or not rule["allowed_uses"]:
            raise GuardError("INVALID_SCHEMA")
        if rule["effect"] == "SEND" and not rule["destination_ids"]:
            raise GuardError("INVALID_SCHEMA")
    if not isinstance(candidate["evidence_refs"], list) or not candidate["evidence_refs"]:
        raise GuardError("INVALID_REFERENCE")
    index = {identity(block["ref"]): block["content"] for block in req["trusted_evidence"]}
    for ref in candidate["evidence_refs"]:
        check_ref(ref, index)
    # Host quotas, permission containment and expansion/commit remain A's job.


class PolicyCompiler:
    def __init__(self, client, *, contracts=None, request_sink=None):
        self.client = client
        self.contracts = contracts if contracts is not None else PublicContracts()
        self.usage_records = []
        self.request_sink = request_sink

    async def generate(self, req):
        data = versioned(self.contracts.parse("PolicyGenerationRequest", payload(req)))
        authorize_destination(data, self.client)
        # Whitelist input fields; neither tool results nor arbitrary extra strings
        # become policy authority if a caller passes them alongside the request.
        selected = {key: data[key] for key in (
            "schema_version", "session_id", "base_policy_version", "trusted_task", "host_policy",
            "tool_manifests", "resource_catalog", "confirmed_authorizations", "trusted_evidence",
            "authorized_model_destination_ids",
        )}
        example = {"schema_version": "0.1", "session_id": data["session_id"],
                   "base_policy_version": data["base_policy_version"], "rules": [],
                   "model_destination_ids": [], "rationale": "Insufficient authorization.",
                   "evidence_refs": [b["ref"] for b in data["trusted_evidence"]],
                   "unresolved_requirements": ["Specify the required registered scope."]}
        messages = [{"role": "system", "content": POLICY_SYSTEM + "\nJSON example: " + dumps(example)},
                    {"role": "user", "content": dumps(selected)}]
        if self.request_sink is not None:
            self.request_sink(payload({"session_id": data["session_id"],
                                       "base_policy_version": data["base_policy_version"],
                                       "prompt_version": POLICY_PROMPT_VERSION, "model": self.client.model,
                                       "destination_id": self.client.destination_id, "messages": messages}))
        reply = await self.client.complete(
            messages=messages,
            purpose="policy", prompt_version=POLICY_PROMPT_VERSION,
        )
        self.usage_records.append({"session_id": data["session_id"],
                                   "base_policy_version": data["base_policy_version"],
                                   "usage": payload(reply.usage)})
        candidate = strict_json(reply.content)
        validate_candidate(candidate, data)
        return self.contracts.parse("PolicyCandidate", candidate)
