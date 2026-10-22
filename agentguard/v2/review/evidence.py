"""Validate locations in the evidence supplied by A, without resolving storage."""

import re

from .errors import GuardError


def identity(ref):
    if (not isinstance(ref, dict) or
        not {"schema_version", "artifact_id", "version", "sha256", "span", "json_pointer"} <= ref.keys() or
        ref["schema_version"] != "0.1" or
        set(ref) - {"schema_version", "artifact_id", "version", "sha256", "span", "json_pointer"} or
        not isinstance(ref["artifact_id"], str) or not ref["artifact_id"] or
        type(ref["version"]) is not int or ref["version"] < 1 or
        not isinstance(ref["sha256"], str) or
        re.fullmatch(r"[0-9a-f]{64}", ref["sha256"]) is None):
        raise GuardError("INVALID_REFERENCE")
    return ref["artifact_id"], ref["version"], ref["sha256"]


def pointer_value(content, pointer):
    if not isinstance(pointer, str) or (pointer != "" and not pointer.startswith("/")):
        raise GuardError("INVALID_REFERENCE")
    if pointer == "":
        return content
    value = content
    for part in pointer[1:].split("/"):
        if re.search(r"~(?![01])", part):
            raise GuardError("INVALID_REFERENCE")
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", part):
            index = int(part)
            if index >= len(value):
                raise GuardError("INVALID_REFERENCE")
            value = value[index]
        else:
            raise GuardError("INVALID_REFERENCE")
    return value


def evidence_index(req):
    blocks = [{"ref": req["subject_ref"], "content": req["subject"]}, *req["evidence"]]
    result = {}
    for block in blocks:
        key = identity(block["ref"])
        if block["ref"].get("span") is not None or block["ref"].get("json_pointer") is not None:
            raise GuardError("INVALID_REFERENCE")
        if key in result and result[key] != block["content"]:
            raise GuardError("INVALID_REFERENCE")
        result[key] = block["content"]
    if not any(block["ref"] == req["subject_ref"] for block in req["evidence"]):
        raise GuardError("INVALID_REFERENCE")
    return result


def check_ref(ref, index, *, precise=False, string_target=False):
    key = identity(ref)
    if key not in index:
        raise GuardError("INVALID_REFERENCE")
    content = index[key]
    pointer, span = ref.get("json_pointer"), ref.get("span")
    if pointer is not None and span is not None:
        raise GuardError("INVALID_REFERENCE")
    if pointer is not None:
        content = pointer_value(content, pointer)
        if precise and pointer == "":
            raise GuardError("INVALID_REFERENCE")
    elif span is not None:
        if (not isinstance(content, str) or not isinstance(span, list) or len(span) != 2 or
            any(type(n) is not int for n in span) or not 0 <= span[0] < span[1] <= len(content)):
            raise GuardError("INVALID_REFERENCE")
    elif precise:
        raise GuardError("INVALID_REFERENCE")
    if string_target and not isinstance(content, str):
        raise GuardError("INVALID_REFERENCE")


def check_requested(refs, req):
    if not isinstance(refs, list):
        raise GuardError("INVALID_SCHEMA")
    allowed = req["available_evidence_refs"]
    for ref in refs:
        identity(ref)
        if ref not in allowed:
            raise GuardError("INVALID_REFERENCE")
