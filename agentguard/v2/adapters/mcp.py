"""MCP 1.28.1: tools/list + tools/call, bound to one trusted host session.

No resources, prompts, sampling, elicitation, tasks, subscriptions or transparent
forwarding. The host must still prepare/record model turns and finalize output.
"""
from mcp.server.lowlevel import Server
from mcp.types import Tool, TextContent, CallToolResult
from ..common import RuntimeFault, canonical, frozen_copy
from ..contracts import BatchRequest
from ..execution.executor import ToolExecutionFailure


def create_mcp_server(runtime, *, session_id):
    runtime.session_view(session_id)
    server = Server('agentguard-v2')

    @server.list_tools()
    async def list_tools():
        return [Tool(name='agentguard.execute_batch', description='Execute Runtime-issued proposals after policy and review checks.',
                     inputSchema=BatchRequest.model_json_schema())]

    @server.call_tool(validate_input=False)
    async def call_tool(name, arguments):
        # Disable SDK's input error formatting: it can echo rejected raw values.
        try:
            if name != 'agentguard.execute_batch':
                raise RuntimeFault('UNSUPPORTED_MCP_TOOL')
            request = frozen_copy(BatchRequest, arguments)
            if request.session_id != session_id:
                raise RuntimeFault('SESSION_BINDING_MISMATCH')
            result = await runtime.execute_batch(request)
            value = result.model_dump(mode='json')
            return CallToolResult(content=[TextContent(type='text', text=canonical(value))], structuredContent=value, isError=False)
        except RuntimeFault as exc:
            return CallToolResult(content=[TextContent(type='text', text=exc.code)], isError=True)
        except Exception:
            return CallToolResult(content=[TextContent(type='text', text='SERVICE_UNAVAILABLE')], isError=True)

    return server


class MCPToolBackend:
    """Host-owned, already authenticated ClientSession and fixed remote tool name.

    Backend credentials/transport never come from remote descriptions or args.
    Unsupported results fail closed and are recorded UNKNOWN by the executor.
    """
    def __init__(self, client_session, remote_tool_name):
        self.client = client_session
        self.remote_tool_name = remote_tool_name

    async def __call__(self, **kwargs):
        result = await self.client.call_tool(self.remote_tool_name, kwargs)
        if result.isError:
            raise ToolExecutionFailure({'reason_code': 'MCP_BACKEND_ERROR', 'result': result.model_dump(mode='json')})
        if any(not isinstance(item, TextContent) for item in result.content):
            raise ToolExecutionFailure({'reason_code': 'UNSUPPORTED_MCP_CONTENT', 'result': result.model_dump(mode='json')})
        # All returned text blocks and structured data are quarantined together.
        return {'content': [item.text for item in result.content], 'structured': result.structuredContent}


async def serve_stdio(runtime, *, session_id):
    """For a trusted local host; stdout is reserved for MCP protocol frames."""
    from mcp.server.stdio import stdio_server
    server = create_mcp_server(runtime, session_id=session_id)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())
