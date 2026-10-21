"""Scripted test doubles only. No tool backend, database, permit or release engine."""

import asyncio
from collections import deque
from copy import deepcopy
import json
from pathlib import Path

from agentguard.v2.review.clients import CloudReply
from agentguard.v2.review.errors import GuardError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def fixture(group, filename="material.json"):
    return json.loads((FIXTURES / group / filename).read_text(encoding="utf-8"))


class FixtureContracts:
    """Explicit test-only identity codec; NOT Pydantic or a public schema clone.

    Tests verify B's behavior on provisional dictionaries. Never use in bootstrap.
    A01 must replace this injection with PublicContracts for joint acceptance.
    """

    def parse(self, name, value):
        return deepcopy(value)


class FakeCloudClient:
    provider = "fake"
    model = "scripted-offline"
    destination_id = "guard_cloud"

    def __init__(self, replies):
        self.replies = deque(replies)
        self.requests = []  # Synthetic test inputs only; never ordinary logs.

    async def complete(self, *, messages, purpose, prompt_version):
        self.requests.append(deepcopy({"messages": messages, "purpose": purpose,
                                       "prompt_version": prompt_version}))
        await asyncio.sleep(0)
        if not self.replies:
            raise GuardError("MODEL_UNAVAILABLE")
        reply = self.replies.popleft()
        if isinstance(reply, BaseException):
            raise reply
        return CloudReply(reply if isinstance(reply, str) else json.dumps(reply, ensure_ascii=False), {
            "provider": self.provider, "model": self.model, "input_tokens": "unavailable",
            "output_tokens": "unavailable", "latency_ms": 0.0, "attempts": 1,
        })


class FakeRuntime:
    """RuntimePort-shaped playback of pre-authored responses, never execution.

    All responses, including any RELEASED contents, must be scripted explicitly.
    Empty scripts fail closed. No interpretation of ALLOW or production releases.
    """

    def __init__(self, script):
        self.script = deque(deepcopy(script))
        self.calls = []

    async def _next(self, method, req):
        self.calls.append((method, deepcopy(req)))
        if not self.script:
            raise AssertionError("FakeRuntime script exhausted")
        step = self.script.popleft()
        if step["method"] != method or step["request"] != req:
            raise AssertionError("FakeRuntime request mismatch")
        return deepcopy(step["response"])

    async def create_session(self, req):
        return await self._next("create_session", req)

    async def prepare_model_turn(self, req):
        return await self._next("prepare_model_turn", req)

    async def record_model_output(self, req):
        return await self._next("record_model_output", req)

    async def execute_batch(self, req):
        return await self._next("execute_batch", req)

    async def finalize(self, req):
        return await self._next("finalize", req)

    async def prepare_recovery(self, req):
        return await self._next("prepare_recovery", req)

    async def complete_recovery(self, req):
        return await self._next("complete_recovery", req)
