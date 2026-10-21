import asyncio
import json

import pytest

from agentguard.v2.review.budget import Budget
from agentguard.v2.review.clients import CloudClient, CloudConfig, JsonHTTPTransport, TransportError, _NoRedirect
from agentguard.v2.review.errors import GuardError

MESSAGES = [{"role": "system", "content": "Return JSON."}, {"role": "user", "content": "Synthetic only."}]


def envelope(content='{"ok":true}', **kwargs):
    value = {"choices": [{"finish_reason": "stop", "message": {"content": content}}],
             "usage": {"prompt_tokens": 11, "completion_tokens": 7}}
    value.update(kwargs)
    return json.dumps(value)


class ScriptedTransport:
    def __init__(self, replies, delay=0):
        self.replies = list(replies)
        self.bodies = []
        self.delay = delay
        self.active = self.peak = 0

    async def post(self, body, config):
        self.bodies.append(body)
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            await asyncio.sleep(self.delay)
            reply = self.replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return reply
        finally:
            self.active -= 1


def client(replies, *, budget=None, **config):
    transport = ScriptedTransport(replies)
    settings = CloudConfig(model="fixture-model", api_key="FAKE_KEY_DO_NOT_USE", enabled=True,
                           retry_delay_seconds=0, **config)
    return CloudClient(settings, budget=budget, transport=transport), transport


async def complete(instance):
    return await instance.complete(messages=MESSAGES, purpose="RESULT", prompt_version="test-1")


def test_structured_request_has_no_tools_and_measured_usage():
    instance, transport = client([envelope()])
    reply = asyncio.run(complete(instance))
    body = transport.bodies[0]
    assert body["response_format"] == {"type": "json_object"}
    assert body["stream"] is False
    assert "tools" not in body and "functions" not in body and "tool_choice" not in body
    assert reply.usage["input_tokens"] == 11 and reply.usage["output_tokens"] == 7
    assert reply.usage["latency_ms"] >= 0
    assert "FAKE_KEY" not in repr(instance.config) + repr(reply) + json.dumps(instance.budget.records)


def test_retry_upper_bound_and_records():
    instance, transport = client([TransportError("MODEL_UNAVAILABLE", True)] * 5, max_retries=2)
    with pytest.raises(GuardError, match="MODEL_UNAVAILABLE"):
        asyncio.run(complete(instance))
    assert len(transport.bodies) == 3
    assert [r["attempt"] for r in instance.budget.records] == [1, 2, 3]


def test_retry_success_reports_unknown_prior_usage():
    instance, _ = client([TransportError("MODEL_TIMEOUT", True), envelope()])
    reply = asyncio.run(complete(instance))
    assert reply.usage["attempts"] == 2
    assert reply.usage["input_tokens"] == "unavailable"
    assert reply.usage["output_tokens"] == "unavailable"


def test_no_retry_auth_or_schema_failure():
    for response in (TransportError("MODEL_UNAVAILABLE", False), envelope("{")):
        instance, transport = client([response, envelope()], max_retries=3)
        with pytest.raises(GuardError):
            asyncio.run(complete(instance))
        assert len(transport.bodies) == 1


def test_timeout_is_failure_and_observable():
    instance, transport = client([envelope()], timeout_seconds=0.005, max_retries=0)
    transport.delay = 0.1
    with pytest.raises(GuardError, match="MODEL_TIMEOUT"):
        asyncio.run(complete(instance))
    assert instance.budget.records[0]["error"] == "MODEL_TIMEOUT"
    assert transport.active == 0


def test_concurrency_and_call_budget_are_atomic():
    async def exercise():
        instance, transport = client([envelope()] * 20, budget=Budget(max_attempts=5), max_concurrency=2)
        transport.delay = 0.005
        replies = await asyncio.gather(*(complete(instance) for _ in range(20)), return_exceptions=True)
        assert transport.peak == 2
        assert len(transport.bodies) == 5
        assert sum(isinstance(r, GuardError) and r.reason_code == "BUDGET_EXHAUSTED" for r in replies) == 15
        assert len(instance.budget.records) == 5
    asyncio.run(exercise())


def test_token_budget_blocks_before_request():
    instance, transport = client([envelope()], budget=Budget(max_tokens=1))
    with pytest.raises(GuardError, match="BUDGET_EXHAUSTED"):
        asyncio.run(complete(instance))
    assert not transport.bodies


def test_unknown_usage_is_unavailable_and_stops_finite_token_budget():
    instance, _ = client([envelope(usage=None)])
    reply = asyncio.run(complete(instance))
    assert reply.usage["input_tokens"] == "unavailable"
    async def exercise():
        instance, transport = client([envelope(usage=None), envelope()], budget=Budget(max_tokens=100_000))
        for _ in range(2):
            with pytest.raises(GuardError, match="BUDGET_EXHAUSTED"):
                await complete(instance)
        assert len(transport.bodies) == 1
    asyncio.run(exercise())


@pytest.mark.parametrize("value", ["length", "tool_calls", "refusal", "empty", "malformed", "wrong_usage", "many"])
def test_provider_response_failure_paths(value):
    response = json.loads(envelope())
    if value == "length":
        response["choices"][0]["finish_reason"] = "length"
    elif value == "tool_calls":
        response["choices"][0]["message"]["tool_calls"] = [{"name": "read_file"}]
    elif value == "refusal":
        response["choices"][0]["message"]["refusal"] = "refused"
    elif value == "empty":
        response["choices"][0]["message"]["content"] = ""
    elif value == "malformed":
        response["choices"] = None
    elif value == "wrong_usage":
        response["usage"] = "bad"
    else:
        response["choices"] *= 2
    instance, transport = client([json.dumps(response)], max_retries=3)
    with pytest.raises(GuardError, match="INVALID_SCHEMA"):
        asyncio.run(complete(instance))
    assert len(transport.bodies) == 1


def test_missing_key_and_disabled_cloud_fail_without_fakes(monkeypatch):
    for key in ("AGENTGUARD_V2_CLOUD_ENABLED", "AGENTGUARD_V2_API_KEY", "AGENTGUARD_V2_MODEL"):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(GuardError, match="MODEL_CONFIGURATION_ERROR"):
        CloudConfig.from_env()
    monkeypatch.setenv("AGENTGUARD_V2_CLOUD_ENABLED", "1")
    monkeypatch.setenv("AGENTGUARD_V2_MODEL", "fixture-model")
    with pytest.raises(GuardError, match="MODEL_CONFIGURATION_ERROR"):
        CloudConfig.from_env()


def test_json_http_transport_fixed_destination_and_no_redirect(monkeypatch):
    import agentguard.v2.review.clients as module
    captured = {}
    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read1(self, size):
            if captured.get("read"):
                return b""
            captured["read"] = True
            return envelope().encode()
    class Opener:
        def open(self, req, timeout):
            captured["url"] = req.full_url
            captured["headers"] = dict(req.header_items())
            captured["body"] = json.loads(req.data)
            return Response()
    monkeypatch.setattr(module.request, "build_opener", lambda *args: Opener())
    config = CloudConfig(model="fixture-model", api_key="fake", enabled=True)
    raw = asyncio.run(JsonHTTPTransport().post({"messages": MESSAGES}, config))
    assert json.loads(raw)["usage"]["prompt_tokens"] == 11
    assert captured["url"] == "https://api.deepseek.com/chat/completions"
    assert _NoRedirect().redirect_request(None, None, 307, "", {}, "https://external.invalid") is None


def test_budget_records_failure_without_http_body(caplog):
    instance, _ = client([RuntimeError("FAKE_SECRET_123 in provider exception")])
    with pytest.raises(GuardError) as exc:
        asyncio.run(complete(instance))
    assert str(exc.value) == "MODEL_UNAVAILABLE"
    assert "FAKE_SECRET_123" not in caplog.text + json.dumps(instance.budget.records)


def test_request_and_response_size_limits():
    instance, transport = client([envelope()], max_input_bytes=1)
    with pytest.raises(GuardError, match="CONTENT_TOO_LARGE"):
        asyncio.run(complete(instance))
    assert not transport.bodies
    instance, _ = client([envelope()], max_response_bytes=1)
    with pytest.raises(GuardError, match="INVALID_SCHEMA"):
        asyncio.run(complete(instance))


def test_cancelled_http_worker_finishes_before_freeing_concurrency_slot(monkeypatch):
    import threading
    import time
    active = 0
    peak = 0
    lock = threading.Lock()
    started = threading.Event()
    def post(body, config):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        started.set()
        time.sleep(0.02)
        with lock:
            active -= 1
        return envelope()
    monkeypatch.setattr(JsonHTTPTransport, "_post", staticmethod(post))
    async def exercise():
        config = CloudConfig(model="fixture-model", api_key="fake", enabled=True, max_concurrency=1)
        instance = CloudClient(config)
        first = asyncio.create_task(complete(instance))
        while not started.is_set():
            await asyncio.sleep(0.001)
        first.cancel()
        await asyncio.sleep(0.001)
        first.cancel()  # Repeated cancellation must not orphan the HTTP worker.
        second = asyncio.create_task(complete(instance))
        with pytest.raises(asyncio.CancelledError):
            await first
        await second
        assert peak == 1 and active == 0
        assert instance.budget.records[0]["error"] == "MODEL_CANCELLED"
    asyncio.run(exercise())


@pytest.mark.parametrize("status,retryable", [(401, False), (403, False), (302, False),
                                            (429, True), (503, True)])
def test_http_error_body_never_read_or_logged(monkeypatch, status, retryable, caplog):
    import agentguard.v2.review.clients as module
    from urllib.error import HTTPError
    class Body:
        closed = False
        def read(self, *args):
            raise AssertionError("Error body must not be read")
        def close(self):
            self.closed = True
    source = Body()
    class Opener:
        def open(self, *args, **kwargs):
            raise HTTPError("https://api.deepseek.com/chat/completions", status,
                            "FAKE_SECRET_123", {}, source)
    monkeypatch.setattr(module.request, "build_opener", lambda *args: Opener())
    config = CloudConfig(model="fixture-model", api_key="fake", enabled=True)
    with pytest.raises(TransportError) as exc:
        asyncio.run(JsonHTTPTransport().post({}, config))
    assert exc.value.retryable is retryable
    assert source.closed
    assert "FAKE_SECRET_123" not in str(exc.value) + caplog.text
