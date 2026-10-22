"""Policy candidate producer. Does not implement A's validator or version store."""

from agentguard.v2.review.boundary import PublicContracts, dumps, payload, strict_json, versioned, wire_usage
from agentguard.v2.review.errors import GuardError
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
    if (candidate['session_id'] != req['session_id'] or
        candidate['base_policy_version'] != req['current_policy_version']):
        raise GuardError("INVALID_REFERENCE")
    if not isinstance(candidate["rules"], list) or not isinstance(candidate["rationale"], str):
        raise GuardError("INVALID_SCHEMA")
    _strings(candidate["unresolved_requirements"])
    catalog = req["resource_catalog"]
    scopes = {item["scope_id"] for item in catalog["resources"]}
    destinations = {item["destination_id"] for item in catalog["destinations"]}
    models = {item["destination_id"] for item in catalog["destinations"] if item['kind'] == 'model'}
    uses = {use for rule in req['host_policy']['rules'] for use in rule['allowed_uses']}
    manifests = {item["tool_id"]: item for item in req["tool_manifests"]}
    authorized = {g['destination_id']: set(g['resource_scope_ids']) for g in req['host_policy']['model_destination_ids']}
    seen = set()
    for grant in candidate['model_destination_ids']:
        destination = grant['destination_id']
        if (destination in seen or destination not in models or destination not in authorized or
            not _strings(grant['resource_scope_ids']) <= scopes & authorized[destination]):
            raise GuardError('INVALID_REFERENCE')
        seen.add(destination)
    for rule in candidate["rules"]:
        if (not isinstance(rule, dict) or set(rule) != {"schema_version", "tool_id", "effect", "resource_scope_ids",
            "destination_ids", "allowed_uses", "max_calls"} or
            rule["effect"] not in ("READ", "WRITE", "SEND", "DELETE") or
            type(rule["max_calls"]) is not int or rule["max_calls"] < 0):
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
    # Initial compilation precedes artifact allocation: no fabricated task refs.
    if candidate['evidence_refs']:
        raise GuardError("INVALID_REFERENCE")
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
            "schema_version", "session_id", "current_policy_version", "trusted_task", "host_policy",
            "tool_manifests", "resource_catalog", "confirmed_authorizations",
        )}
        example = {"schema_version": "0.1", "session_id": data["session_id"],
                   "base_policy_version": data["current_policy_version"], "rules": [],
                   "model_destination_ids": [], "rationale": "Insufficient authorization.",
                   "evidence_refs": [],
                   "unresolved_requirements": ["Specify the required registered scope."]}
        messages = [{"role": "system", "content": POLICY_SYSTEM + "\nJSON example: " + dumps(example)},
                    {"role": "user", "content": dumps(selected)}]
        if self.request_sink is not None:
            self.request_sink(payload({"session_id": data["session_id"],
                                       "base_policy_version": data["current_policy_version"],
                                       "prompt_version": POLICY_PROMPT_VERSION, "model": self.client.model,
                                       "destination_id": self.client.destination_id, "messages": messages}))
        reply = await self.client.complete(
            messages=messages,
            purpose="policy", prompt_version=POLICY_PROMPT_VERSION,
        )
        self.usage_records.append({"session_id": data["session_id"],
                                   "base_policy_version": data["current_policy_version"],
                                   "usage": wire_usage(reply.usage)})
        candidate = strict_json(reply.content)
        candidate = payload(self.contracts.parse('PolicyCandidate', candidate))
        validate_candidate(candidate, data)
        return self.contracts.parse("PolicyCandidate", candidate)
