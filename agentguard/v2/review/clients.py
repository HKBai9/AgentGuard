"""Explicitly configured, tool-free DeepSeek JSON client (stdlib transport).

No automatic fake fallback, redirects, SDK agent loop, or conversation state.
The caller must authorize this destination for each evidence package.
"""

import asyncio
from dataclasses import dataclass, field
import os
import socket
import time
from urllib import error, request

from .boundary import dumps, payload, strict_json
from .budget import Budget
from .errors import GuardError


@dataclass(frozen=True)
class CloudConfig:
    model: str
    api_key: str = field(repr=False)
    enabled: bool = False
    destination_id: str = "guard_cloud"
    timeout_seconds: float = 30.0
    max_concurrency: int = 2
    max_retries: int = 1
    max_output_tokens: int = 2048
    max_input_bytes: int = 128_000
    max_response_bytes: int = 1_000_000
    retry_delay_seconds: float = 0.25

    def __post_init__(self):
        if self.enabled is not True or not self.api_key.strip() or not self.model.strip():
            raise GuardError("MODEL_CONFIGURATION_ERROR")
        if any(c in self.api_key for c in "\r\n") or not self.destination_id:
            raise GuardError("MODEL_CONFIGURATION_ERROR")
        if (type(self.max_retries) is not int or not 0 <= self.max_retries <= 3 or
            type(self.max_concurrency) is not int or not 1 <= self.max_concurrency <= 32):
            raise GuardError("MODEL_CONFIGURATION_ERROR")
        for number in (self.max_output_tokens, self.max_input_bytes, self.max_response_bytes):
            if type(number) is not int or number < 1:
                raise GuardError("MODEL_CONFIGURATION_ERROR")
        if not 0 < self.timeout_seconds <= 120 or not 0 <= self.retry_delay_seconds <= 5:
            raise GuardError("MODEL_CONFIGURATION_ERROR")

    @classmethod
    def from_env(cls):
        # No dotenv discovery and no endpoint controlled by task/model text.
        try:
            return cls(
                enabled=os.environ.get("AGENTGUARD_V2_CLOUD_ENABLED") == "1",
                api_key=os.environ.get("AGENTGUARD_V2_API_KEY", ""),
                model=os.environ.get("AGENTGUARD_V2_MODEL", ""),
                destination_id=os.environ.get("AGENTGUARD_V2_DESTINATION_ID", "guard_cloud"),
                timeout_seconds=float(os.environ.get("AGENTGUARD_V2_TIMEOUT_SECONDS", "30")),
                max_concurrency=int(os.environ.get("AGENTGUARD_V2_CONCURRENCY", "2")),
                max_retries=int(os.environ.get("AGENTGUARD_V2_RETRIES", "1")),
            )
        except ValueError:
            raise GuardError("MODEL_CONFIGURATION_ERROR") from None


@dataclass(frozen=True)
class CloudReply:
    content: str = field(repr=False)
    usage: dict


class TransportError(Exception):
    def __init__(self, code, retryable=False):
        self.code = code
        self.retryable = retryable
        super().__init__(code)


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class JsonHTTPTransport:
    """One HTTPS destination, no redirects/proxies; bounded bytes and read time."""

    async def post(self, body, config):
        task = asyncio.create_task(asyncio.to_thread(self._post, body, config))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            # Do not free the concurrency slot while the worker still sends data.
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            try:
                task.result()
            except Exception:
                pass
            raise

    def _post(self, body, config):
        opener = request.build_opener(request.ProxyHandler({}), _NoRedirect())
        req = request.Request(
            "https://api.deepseek.com/chat/completions",
            data=dumps(body).encode("utf-8"),
            headers={"Authorization": "Bearer " + config.api_key,
                     "Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            deadline = time.monotonic() + config.timeout_seconds
            with opener.open(req, timeout=config.timeout_seconds) as response:
                chunks, size = [], 0
                while True:
                    if time.monotonic() > deadline:
                        raise TransportError("MODEL_TIMEOUT", True)
                    chunk = response.read1(min(65536, config.max_response_bytes + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > config.max_response_bytes:
                        raise TransportError("INVALID_SCHEMA")
                return b"".join(chunks).decode("utf-8")
        except error.HTTPError as exc:
            # Never read/log an HTTP error body: it can reflect source text/keys.
            code = exc.code
            exc.close()
            raise TransportError("MODEL_UNAVAILABLE", code == 429 or 500 <= code < 600) from None
        except (TimeoutError, socket.timeout):
            raise TransportError("MODEL_TIMEOUT", True) from None
        except error.URLError as exc:
            timeout = isinstance(exc.reason, (TimeoutError, socket.timeout))
            raise TransportError("MODEL_TIMEOUT" if timeout else "MODEL_UNAVAILABLE", timeout) from None
        except (OSError, UnicodeError):
            raise TransportError("MODEL_UNAVAILABLE") from None


class CloudClient:
    provider = "deepseek"

    def __init__(self, config, *, budget=None, transport=None):
        self.config = config
        self.model = config.model
        self.destination_id = config.destination_id
        self.budget = budget if budget is not None else Budget()
        self.transport = transport if transport is not None else JsonHTTPTransport()
        self._semaphore = asyncio.Semaphore(config.max_concurrency)

    async def complete(self, *, messages, purpose, prompt_version):
        if purpose not in ("policy", "ACTION", "RESULT", "FINAL"):
            raise GuardError("INVALID_SCHEMA")
        if not messages or any(set(m) != {"role", "content"} or
                               m["role"] not in ("system", "user") or
                               not isinstance(m["content"], str) for m in messages):
            raise GuardError("INVALID_SCHEMA")
        body = {"model": self.model, "messages": payload({"messages": messages})["messages"], "stream": False,
                "response_format": {"type": "json_object"},
                "max_tokens": self.config.max_output_tokens}
        input_bytes = len(dumps(body).encode("utf-8"))
        if input_bytes > self.config.max_input_bytes:
            raise GuardError("CONTENT_TOO_LARGE")
        # Conservative reservation, not a claimed tokenizer or billed amount.
        reservation = input_bytes + 1024 + self.config.max_output_tokens
        total_in, total_out, unknown = 0, 0, False
        start = time.monotonic()
        for attempt in range(1, self.config.max_retries + 2):
            async with self._semaphore:
                await self.budget.reserve(reservation)
                tick = time.monotonic()
                record = {"provider": self.provider, "model": self.model,
                          "purpose": purpose, "prompt_version": prompt_version,
                          "attempt": attempt, "input_tokens": "unavailable",
                          "output_tokens": "unavailable", "error": None}
                retry = False
                try:
                    raw = await asyncio.wait_for(self.transport.post(body, self.config),
                                                 timeout=self.config.timeout_seconds)
                    if len(raw.encode("utf-8")) > self.config.max_response_bytes:
                        raise GuardError("INVALID_SCHEMA")
                    envelope = strict_json(raw)
                    usage = envelope.get("usage") or {}
                    for wire, local in (("prompt_tokens", "input_tokens"),
                                        ("completion_tokens", "output_tokens")):
                        count = usage.get(wire)
                        if type(count) is int and count >= 0:
                            record[local] = count
                    choices = envelope["choices"]
                    if len(choices) != 1 or choices[0]["finish_reason"] != "stop":
                        raise GuardError("INVALID_SCHEMA")
                    message = choices[0]["message"]
                    if message.get("tool_calls") or message.get("function_call") or message.get("refusal"):
                        raise GuardError("INVALID_SCHEMA")
                    content = message["content"]
                    if not isinstance(content, str) or not content.strip():
                        raise GuardError("INVALID_SCHEMA")
                    strict_json(content)
                except asyncio.CancelledError:
                    record["error"] = "MODEL_CANCELLED"
                    raise
                except (TimeoutError, TransportError) as exc:
                    record["error"] = exc.code if isinstance(exc, TransportError) else "MODEL_TIMEOUT"
                    retry = not isinstance(exc, TransportError) or exc.retryable
                except GuardError as exc:
                    record["error"] = exc.reason_code
                except (KeyError, IndexError, TypeError, ValueError, AttributeError):
                    record["error"] = "INVALID_SCHEMA"
                except Exception:
                    record["error"] = "MODEL_UNAVAILABLE"
                finally:
                    record["latency_ms"] = round((time.monotonic() - tick) * 1000, 3)
                    await self.budget.finish(reservation, record)
                counts = (record["input_tokens"], record["output_tokens"])
                if any(n == "unavailable" for n in counts):
                    unknown = True
                else:
                    total_in += counts[0]
                    total_out += counts[1]
                if record["error"] is None:
                    if self.budget.max_tokens is not None and (
                        unknown or self.budget.tokens > self.budget.max_tokens
                    ):
                        raise GuardError("BUDGET_EXHAUSTED")
                    return CloudReply(content, {
                        "provider": self.provider, "model": self.model,
                        "input_tokens": "unavailable" if unknown else total_in,
                        "output_tokens": "unavailable" if unknown else total_out,
                        "latency_ms": round((time.monotonic() - start) * 1000, 3),
                        "attempts": attempt,
                    })
                if not retry or attempt > self.config.max_retries:
                    raise GuardError(record["error"]) from None
            await asyncio.sleep(self.config.retry_delay_seconds)
        raise AssertionError("unreachable")
