"""Signature-aware SDK wrappers. Return CallResult, never unreviewed values."""
import asyncio
import inspect
from functools import wraps
from ..common import RuntimeFault, canonical
from ..contracts import ToolCall


class PythonSDK:
    def __init__(self, runtime):
        self.runtime = runtime

    def register(self, manifest, function):
        signature = inspect.signature(function)
        if any(p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD, p.POSITIONAL_ONLY) for p in signature.parameters.values()):
            raise RuntimeFault('UNSUPPORTED_PYTHON_SIGNATURE', 422)
        self.runtime.registry.register(manifest, function)
        return function

    def wrap(self, function, call: ToolCall):
        """Bind an existing Runtime-issued proposal, preserving its call_id on retry."""
        signature = inspect.signature(function)
        entry = self.runtime.registry.get(call.tool_id, call.manifest_version)
        if entry.handler is not function:
            raise RuntimeFault('TOOL_HANDLER_MISMATCH')

        @wraps(function)
        async def wrapped(*args, **kwargs):
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            if canonical(dict(bound.arguments)) != canonical(call.args):
                raise RuntimeFault('CALL_BINDING_MISMATCH')
            return await self.runtime.execute_call(call)
        return wrapped

    def wrap_sync(self, function, call):
        asynchronous = self.wrap(function, call)
        @wraps(function)
        def wrapped(*args, **kwargs):
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return asyncio.run(asynchronous(*args, **kwargs))
            raise RuntimeFault('USE_ASYNC_SDK_IN_EVENT_LOOP', 409)
        return wrapped
