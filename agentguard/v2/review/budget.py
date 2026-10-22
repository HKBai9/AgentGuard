"""Per-client attempt/token ceilings. Unavailable usage never means zero cost."""

import asyncio
from copy import deepcopy

from .errors import GuardError


class Budget:
    def __init__(self, max_attempts=20, max_tokens=None):
        if type(max_attempts) is not int or max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        if max_tokens is not None and (type(max_tokens) is not int or max_tokens < 1):
            raise ValueError("max_tokens must be positive or None")
        self.max_attempts = max_attempts
        self.max_tokens = max_tokens
        self.attempts = 0
        self.tokens = 0
        self.usage_unavailable = False
        self.exhausted = False
        self._reserved = 0
        self._lock = asyncio.Lock()
        self._records = []

    async def reserve(self, upper_bound):
        async with self._lock:
            if (self.attempts >= self.max_attempts or
                (self.max_tokens is not None and
                 (self.usage_unavailable or self.tokens + self._reserved + upper_bound > self.max_tokens))):
                self.exhausted = True
                raise GuardError("BUDGET_EXHAUSTED")
            self.attempts += 1
            self._reserved += upper_bound

    async def finish(self, reserved, record):
        async with self._lock:
            self._reserved -= reserved
            counts = (record["input_tokens"], record["output_tokens"])
            if any(type(n) is not int or n < 0 for n in counts):
                self.usage_unavailable = True
            else:
                self.tokens += sum(counts)
            self._records.append(deepcopy(record))

    @property
    def records(self):
        # Safe metadata only; no model text, HTTP bodies, keys, or source content.
        return deepcopy(self._records)
