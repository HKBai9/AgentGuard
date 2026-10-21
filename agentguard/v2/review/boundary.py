"""Consume A's models lazily. There is deliberately no fallback public schema.

Tests inject a dictionary-only codec, explicitly without claiming contract parity.
"""

from copy import deepcopy
from importlib import import_module
import json
import math

from .errors import ContractUnavailable, GuardError


def payload(value):
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if not isinstance(value, dict):
        raise GuardError("INVALID_SCHEMA")
    # Reject non-JSON values, non-string keys and bool masquerading as numbers.
    def check(item):
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) is float and math.isfinite(item):
            return
        if type(item) is list:
            for child in item:
                check(child)
            return
        if type(item) is dict and all(type(k) is str for k in item):
            for child in item.values():
                check(child)
            return
        raise GuardError("INVALID_SCHEMA")
    check(value)
    return deepcopy(value)


def dumps(value):
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError):
        raise GuardError("INVALID_SCHEMA") from None


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("nonfinite")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
        return payload(value)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise GuardError("INVALID_SCHEMA") from None


class PublicContracts:
    """The only production serializer; A owns every model referenced here."""

    def __init__(self):
        try:
            self.module = import_module("agentguard.v2.contracts")
        except ImportError:
            raise ContractUnavailable("A01 required: agentguard.v2.contracts") from None

    def parse(self, name, value):
        model = getattr(self.module, name, None)
        if model is None:
            raise ContractUnavailable("A01 missing public model: " + name)
        try:
            return model.model_validate(payload(value))
        except (ValueError, TypeError):
            raise GuardError("INVALID_SCHEMA") from None


def versioned(value):
    result = payload(value)
    if result.get("schema_version") != "0.1":
        raise GuardError("INVALID_SCHEMA")
    return result
