"""Compose pure context building and review, with at most one supplied refill.

The service cannot fetch evidence. Only A may supply an authorized second package.
"""

from .boundary import PublicContracts, payload
from .errors import ContractUnavailable, GuardError
from .evidence import evidence_index, identity
from .prompts import bindings


class GuardService:
    supports_context_budgeting = True

    def __init__(self, builder, reviewer, *, contracts=None):
        self.builder = builder
        self.reviewer = reviewer
        self.contracts = contracts if contracts is not None else PublicContracts()
        self._refilled = set()

    def take_trace(self, review_id, supplemental_attempt):
        return self.reviewer.take_trace(review_id, supplemental_attempt)

    def clear_session(self, session_id):
        if self.reviewer.cache:
            self.reviewer.cache.clear_session(session_id)
        for key,value in list(self.reviewer._traces.items()):
            if value['binding']['session_id']==session_id:
                del self.reviewer._traces[key]

    async def inspect(self, material):
        return await self._inspect(material, second=False)

    async def _inspect(self, material, *, second):
        try:
            built = payload(self.builder.build(material))
            if built["status"] != "READY":
                raise GuardError(built["reason_code"])
            decision = payload(await self.reviewer.review(built["request"]))
            if (second or payload(material)['supplemental_attempt'] == 1) and decision["decision"] == "NEEDS_CONTEXT":
                raise GuardError("MISSING_EVIDENCE")
            return self.contracts.parse("ReviewOutcome", {
                "schema_version": "0.1", "status": "DECIDED", "decision": decision, "failure": None,
            })
        except GuardError as exc:
            return self._failure(exc.reason_code, exc.usage)
        except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
            return self._failure("INVALID_SCHEMA")
        except ContractUnavailable:
            raise
        except Exception:
            return self._failure("MODEL_UNAVAILABLE")

    async def inspect_with_evidence(self, original_material, previous_outcome, supplied_material):
        """A-controlled explicit second pass; no model-initiated IO or auto retry."""
        try:
            original, supplied, prior = map(payload, (original_material, supplied_material, previous_outcome))
            decision = prior["decision"]
            if prior["status"] != "DECIDED" or decision["decision"] != "NEEDS_CONTEXT":
                raise GuardError("MISSING_EVIDENCE")
            for key in (*bindings(original).keys() - {'policy_version'}, "trusted_task", "policy", "host_policy", "subject",
                        "mandatory_facts", "allowed_transform_ids", "lineage", "relevant_security_revision",
                        "recent_events", "available_evidence_refs", "task_ref"):
                if supplied[key] != original[key]:
                    raise GuardError("INVALID_REFERENCE")
            if any(decision[k] != value for k, value in bindings(original).items()):
                raise GuardError("INVALID_REFERENCE")
            requested = decision["requested_evidence_refs"]
            if not requested or any(ref not in original["available_evidence_refs"] for ref in requested):
                raise GuardError("INVALID_REFERENCE")
            old, new = evidence_index(original), evidence_index(supplied)
            if any(key not in new or new[key] != value for key, value in old.items()):
                raise GuardError("INVALID_REFERENCE")
            needed = {identity(ref) for ref in requested}
            if not needed <= new.keys() or new.keys() - old.keys() - needed:
                raise GuardError("INVALID_REFERENCE")
            key = tuple(bindings(original)[k] for k in ("session_id", "review_id", "policy_version", "context_version"))
            if key in self._refilled:
                raise GuardError("MISSING_EVIDENCE")
            # No eviction that might permit an old review's third pass. A must
            # also persist its retry limit across service/process restarts.
            if len(self._refilled) >= 1024:
                raise GuardError("BUDGET_EXHAUSTED")
            self._refilled.add(key)
        except GuardError as exc:
            return self._failure(exc.reason_code)
        except (KeyError, TypeError, ValueError):
            return self._failure("INVALID_SCHEMA")
        supplied['mandatory_facts'] = {**supplied['mandatory_facts'], 'requested_evidence_refs': requested}
        return await self._inspect(supplied, second=True)

    def _failure(self, code, usage=None):
        from .boundary import wire_usage
        failure = self.contracts.parse("ReviewFailure", {"schema_version": "0.1", "reason_code": code,
            "usage": wire_usage(usage) if usage else None})
        return self.contracts.parse("ReviewOutcome", {
            "schema_version": "0.1", "status": "FAILED", "decision": None, "failure": payload(failure),
        })
