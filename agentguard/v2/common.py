"""One JSON, digest, pointer, ID and public-error implementation."""
from __future__ import annotations
import hashlib
import json
import math
from datetime import datetime, timezone
from uuid import uuid4
from typing import Any
from pydantic import BaseModel


class RuntimeFault(Exception):
    def __init__(self, code: str, http_status: int = 409):
        self.code, self.http_status = code, http_status
        super().__init__(code)  # Never include tool or validation exception text.


def utcnow():
    return datetime.now(timezone.utc)


def new_id(prefix='id'):
    return prefix + '_' + uuid4().hex


def ensure_json(value):
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is list:
        for item in value:
            ensure_json(item)
        return
    if type(value) is dict and all(type(k) is str for k in value):
        for item in value.values():
            ensure_json(item)
        return
    raise RuntimeFault('INVALID_JSON', 422)


def canonical(value: Any) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode='json', warnings=False)
    ensure_json(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def strict_loads(raw):
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise RuntimeFault('DUPLICATE_JSON_KEY', 422)
            obj[key] = value
        return obj
    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        ensure_json(result)
        return result
    except RuntimeFault:
        raise
    except (ValueError, TypeError, UnicodeError):
        raise RuntimeFault('INVALID_JSON', 422) from None


def frozen_copy(cls, value):
    # Revalidation also defeats model_construct/model_copy(update=...) bypasses.
    try:
        raw = canonical(value)
        return cls.model_validate_json(raw)
    except RuntimeFault:
        raise
    except Exception:
        raise RuntimeFault('INVALID_SCHEMA', 422) from None


def pointer_parts(pointer):
    if pointer == '':
        return []
    if not pointer.startswith('/'):
        raise RuntimeFault('INVALID_REFERENCE')
    parts = pointer[1:].split('/')
    for part in parts:
        for pos, char in enumerate(part):
            if char == '~' and (pos + 1 == len(part) or part[pos + 1] not in '01'):
                raise RuntimeFault('INVALID_REFERENCE')
    return [p.replace('~1', '/').replace('~0', '~') for p in parts]


def at_pointer(value, pointer):
    try:
        for key in pointer_parts(pointer):
            if isinstance(value, list):
                if not key.isascii() or not key.isdigit() or (len(key) > 1 and key[0] == '0'):
                    raise KeyError()
                value = value[int(key)]
            else:
                value = value[key]
        return value
    except (KeyError, IndexError, TypeError, ValueError):
        raise RuntimeFault('INVALID_REFERENCE') from None
