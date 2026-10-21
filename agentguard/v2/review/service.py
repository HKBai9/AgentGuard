"""Compose pure context building and review, with at most one supplied refill.

The service cannot fetch evidence. Only A may supply an authorized second package.
"""

from .boundary import PublicContracts, payload
from .errors import ContractUnavailable, GuardError
from .evidence import evidence_index, identity
from .prompts import BINDINGS


class GuardService:
    def __init__(self, builder, reviewer, *, contracts=None):
        self.builder = builder
        self.reviewer = reviewer
        self.contracts = contracts if contracts is not None else PublicContracts()
        self._refilled = set()

    async def inspect(self, material):
        return await self._inspect(material, second=False)

    async def _inspect(self, material, *, second):
        try:
            built = payload(self.builder.build(material))
            if built["status"] != "READY":
                raise GuardError(built["reason_code"])
            decision = payload(await self.reviewer.review(built["request"]))
            if second and decision["decision"] == "NEEDS_CONTEXT":
                raise GuardError("MISSING_EVIDENCE")
            return self.contracts.parse("ReviewOutcome", {
                "schema_version": "0.1", "status": "DECIDED", "decision": decision, "failure": None,
            })
        except GuardError as exc:
            return self._failure(exc.reason_code)
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
            for key in (*BINDINGS, "trusted_task", "task_policy", "host_constraints", "current_object",
                        "mandatory_facts", "allowed_transform_ids", "model_destination_id",
                        "authorized_model_destination_ids", "supplemental_history", "available_evidence_refs"):
                if supplied[key] != original[key]:
                    raise GuardError("INVALID_REFERENCE")
            if any(decision[k] != original[k] for k in BINDINGS):
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
            key = tuple(original[k] for k in ("session_id", "review_id", "policy_version", "context_version"))
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
        return await self._inspect(supplied, second=True)

    def _failure(self, code):
        failure = self.contracts.parse("ReviewFailure", {"schema_version": "0.1", "reason_code": code})
        return self.contracts.parse("ReviewOutcome", {
            "schema_version": "0.1", "status": "FAILED", "decision": None, "failure": payload(failure),
        })
