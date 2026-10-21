"""Trusted handlers receive frozen JSON. Exceptions never become agent text."""
import asyncio
import inspect
from dataclasses import dataclass
from ..common import canonical, strict_loads


class KnownToolFailure(Exception):
    """A trusted adapter guarantees that no effect was committed."""


class ToolExecutionFailure(Exception):
    """An uncertain backend failure with content that MUST stay in quarantine."""
    def __init__(self, payload):
        self.payload = strict_loads(canonical(payload))
        super().__init__('TOOL_BACKEND_FAILURE')


@dataclass(frozen=True)
class ToolResult:
    content: object
    stderr: str | None = None


async def dispatch(handler, args):
    args = strict_loads(canonical(args))
    if inspect.iscoroutinefunction(handler):
        return await handler(**args)
    value = await asyncio.to_thread(handler, **args)
    if inspect.isawaitable(value):
        return await value
    return value
