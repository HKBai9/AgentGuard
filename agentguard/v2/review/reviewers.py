"""Semantic review proposals; actual permission/release remains with Runtime."""

import re

from .boundary import PublicContracts, payload, strict_json, versioned, wire_usage
from .errors import GuardError
from .evidence import check_ref, check_requested, evidence_index, identity, pointer_value
from .prompts import BINDINGS, PROMPT_VERSION, review_messages, bindings


def authorize_destination(req, client):
    host = req["host_policy"]
    policy = req.get("policy", host)
    if (host["guard_destination_id"] != client.destination_id or
        client.destination_id not in {g['destination_id'] for g in host['model_destination_ids']} or
        client.destination_id not in {g['destination_id'] for g in policy['model_destination_ids']}):
        raise GuardError("MODEL_DESTINATION_DENIED")
    if 'resource_catalog' in req and hasattr(client, 'config'):
        from ..registry import normalize_endpoint
        destination = next((d for d in req['resource_catalog']['destinations']
                            if d['destination_id'] == client.destination_id), None)
        if destination is None or normalize_endpoint(destination['address']) != normalize_endpoint(client.config.endpoint):
            raise GuardError('MODEL_DESTINATION_DENIED')


def validate_analysis(data, req):
    fields = {*BINDINGS, "decision", "reason_code", "reason_summary", "evidence_refs",
              "findings", "redaction_targets", "requested_evidence_refs"}
    if set(data) != fields:
        raise GuardError("INVALID_SCHEMA")
    if data["schema_version"] != "0.1":
        raise GuardError("INVALID_SCHEMA")
    if any(data[k] != bindings(req)[k] for k in BINDINGS):
        raise GuardError("INVALID_REFERENCE")
    if data["decision"] not in ("ALLOW", "BLOCK", "REDACT", "NEEDS_CONTEXT"):
        raise GuardError("INVALID_SCHEMA")
    if (not isinstance(data["reason_code"], str) or
        re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", data["reason_code"]) is None or
        not isinstance(data["reason_summary"], str) or not 1 <= len(data["reason_summary"]) <= 1000):
        raise GuardError("INVALID_SCHEMA")
    for key in ("evidence_refs", "findings", "redaction_targets", "requested_evidence_refs"):
        if not isinstance(data[key], list):
            raise GuardError("INVALID_SCHEMA")
    index = evidence_index(req)
    for ref in data["evidence_refs"]:
        check_ref(ref, index)
    if not any(identity(r) == identity(req["subject_ref"]) for r in data["evidence_refs"]):
        raise GuardError("INVALID_REFERENCE")
    for finding in data["findings"]:
        if (not isinstance(finding, dict) or
            set(finding) != {"schema_version", "finding_type", "affected_action_field", "evidence_refs"} or
            finding['schema_version'] != '0.1' or
            not isinstance(finding["finding_type"], str) or not finding["finding_type"] or
            not isinstance(finding["evidence_refs"], list) or not finding["evidence_refs"]):
            raise GuardError("INVALID_SCHEMA")
        field = finding["affected_action_field"]
        if field is not None:
            # S1 uses a JSON pointer into the ACTION object; other phases use null.
            if req["phase"] != "ACTION" or not isinstance(field, str) or not field:
                raise GuardError("INVALID_REFERENCE")
            pointer_value(req["subject"]["args"], field)
        for ref in finding["evidence_refs"]:
            check_ref(ref, index, precise=True)
    if data["decision"] in ("BLOCK", "REDACT") and not data["findings"]:
        raise GuardError("INVALID_REFERENCE")
    if data["decision"] == "REDACT":
        if req["phase"] == "ACTION" or not data["redaction_targets"]:
            raise GuardError("INVALID_SCHEMA")
        for target in data["redaction_targets"]:
            if (not isinstance(target, dict) or set(target) != {"schema_version", "evidence_ref", "transform_id"}
                or target['schema_version'] != '0.1'):
                raise GuardError("INVALID_SCHEMA")
            if target["transform_id"] not in req["allowed_transform_ids"]:
                raise GuardError("INVALID_REFERENCE")
            if identity(target["evidence_ref"]) != identity(req["subject_ref"]):
                raise GuardError("INVALID_REFERENCE")
            check_ref(target["evidence_ref"], index, precise=True, string_target=True)
    elif data["redaction_targets"]:
        raise GuardError("INVALID_SCHEMA")
    check_requested(data["requested_evidence_refs"], req)
    if data["decision"] == "NEEDS_CONTEXT":
        if not data["requested_evidence_refs"]:
            raise GuardError("MISSING_EVIDENCE")
    elif data["requested_evidence_refs"]:
        raise GuardError("INVALID_SCHEMA")


class Reviewer:
    def __init__(self, client, *, contracts=None, request_sink=None, cache=None):
        self.client = client
        self.contracts = contracts if contracts is not None else PublicContracts()
        # Explicit host-owned protected trace sink, NEVER an ordinary logger.
        self.request_sink = request_sink
        self.cache = cache
        self._traces = {}

    def take_trace(self, review_id, supplemental_attempt):
        return self._traces.pop((review_id, supplemental_attempt), None)

    async def review(self, req):
        data = versioned(self.contracts.parse("ReviewRequest", payload(req)))
        if (data["phase"] not in ("ACTION", "RESULT", "FINAL") or
            (data["phase"] == "FINAL") != (data["call_id"] is None)):
            raise GuardError("INVALID_SCHEMA")
        evidence_index(data)
        authorize_destination(data, self.client)
        messages = review_messages(data)
        trace = {'request': data, 'binding': bindings(data), 'prompt_version': PROMPT_VERSION,
                 'model': self.client.model, 'destination_id': self.client.destination_id,
                 'messages': messages, 'cache_hit': False, 'submitted': False}
        self._traces[(data['review_id'], data['supplemental_attempt'])] = trace
        if len(self._traces) > 256:
            del self._traces[next(iter(self._traces))]
        model_identity = '|'.join((getattr(self.client, 'provider', ''), self.client.model,
                                  getattr(getattr(self.client, 'config', None), 'endpoint', '')))
        cache_key = self.cache.key(data, model=model_identity, destination_id=self.client.destination_id,
                                   prompt_version=PROMPT_VERSION) if self.cache else None
        cached = self.cache.get(cache_key) if self.cache else None
        if cached is not None:
            cached.update(bindings(data))
            validate_analysis(cached, data)
            trace['cache_hit'] = True
            cached['usage'] = wire_usage({'provider': 'cache', 'model': self.client.model,
                'input_tokens': 0, 'output_tokens': 0, 'latency_ms': 0.0, 'attempts': 0})
            return self.contracts.parse('ReviewDecision', cached)
        if self.request_sink is not None:
            self.request_sink(payload({"binding": bindings(data),
                                       "prompt_version": PROMPT_VERSION,
                                       "model": self.client.model,
                                       "destination_id": self.client.destination_id,
                                       "messages": messages}))
        trace['submitted'] = None  # Cancellation may leave transport state unknown.
        try:
            reply = await self.client.complete(messages=messages, purpose=data["phase"], prompt_version=PROMPT_VERSION)
        except GuardError as exc:
            if exc.usage:
                trace['usage'] = wire_usage(exc.usage)
                trace['submitted'] = exc.usage['attempts'] > 0
            elif exc.reason_code in ('CONTENT_TOO_LARGE','MODEL_CONFIGURATION_ERROR','MODEL_DESTINATION_DENIED'):
                trace['submitted'] = False
            raise
        trace['submitted'] = True
        trace['usage'] = wire_usage(reply.usage)
        analysis = strict_json(reply.content)
        validate_analysis(analysis, data)
        if self.cache and analysis['decision'] != 'NEEDS_CONTEXT':
            self.cache.put(cache_key, analysis)
        analysis["usage"] = wire_usage(reply.usage)
        return self.contracts.parse("ReviewDecision", analysis)
