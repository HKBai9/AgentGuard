"""S1 complete-object builder. No truncation, retrieval, summaries or IO.

S2 relation-based selection is intentionally not claimed by this implementation.
"""

from .boundary import PublicContracts, dumps, payload, versioned
from .errors import GuardError
from .evidence import evidence_index, identity
from .prompts import BINDINGS


class ContextBuilder:
    def __init__(self, *, contracts=None, max_bytes=96_000):
        self.contracts = contracts if contracts is not None else PublicContracts()
        if type(max_bytes) is not int or max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        self.max_bytes = max_bytes

    def build(self, material):
        data = versioned(self.contracts.parse("ContextMaterial", payload(material)))
        required = {*BINDINGS, "trusted_task", "task_policy", "host_constraints", "current_object",
                    "mandatory_facts", "evidence_blocks", "supplemental_history",
                    "available_evidence_refs", "allowed_transform_ids", "model_destination_id",
                    "authorized_model_destination_ids"}
        missing = sorted(required - data.keys())
        if missing or any(data.get(k) is None for k in required - {"call_id"}):
            return self._incomplete("MISSING_EVIDENCE", [])
        if not {"data_restrictions", "unresolved_risks", "lineage"} <= data["mandatory_facts"].keys():
            return self._incomplete("MISSING_EVIDENCE", [])
        if any(data["mandatory_facts"][k] is None for k in ("data_restrictions", "unresolved_risks", "lineage")):
            return self._incomplete("MISSING_EVIDENCE", [])
        evidence_index(data)
        for ref in data["available_evidence_refs"]:
            identity(ref)
        data["selected_evidence_refs"] = [data["subject_ref"], *[b["ref"] for b in data["evidence_blocks"]]]
        # Report bytes honestly. Provider token usage is recorded after inference.
        size = len(dumps(data).encode("utf-8"))
        if size > self.max_bytes:
            return self._incomplete("CONTENT_TOO_LARGE", [data["subject_ref"]])
        data["context_budget"] = {"unit": "utf8_bytes", "used": size, "limit": self.max_bytes,
                                  "truncated": False, "strategy": "complete_s1"}
        request = self.contracts.parse("ReviewRequest", data)
        return self.contracts.parse("ContextBuildResult", {
            "schema_version": "0.1", "status": "READY", "request": payload(request),
            "missing_evidence": [], "reason_code": None,
        })

    def _incomplete(self, code, missing):
        return self.contracts.parse("ContextBuildResult", {
            "schema_version": "0.1", "status": "INCOMPLETE", "request": None,
            "missing_evidence": missing, "reason_code": code,
        })
