"""LangChain Core model integration; Runtime owns the execution loop.

No AgentExecutor, ToolNode, callable tools, callbacks, streaming or hidden memory
are attached. A BaseChatModel proposes JSON tools using the native host protocol.
"""
from ..common import RuntimeFault, canonical, frozen_copy, strict_loads
from ..contracts import ToolProposal
from .host import AgentReply, HostAdapter

LANGCHAIN_CORE_VERSION = '1.6.13'


class LangChainModel:
    def __init__(self, model, *, destination_id, endpoint):
        from langchain_core.language_models.chat_models import BaseChatModel
        if not isinstance(model, BaseChatModel):
            raise TypeError('Use a stateless BaseChatModel, not a chain with hidden history')
        from langchain_core.globals import get_debug, get_verbose, get_llm_cache
        if get_debug() or get_verbose() or get_llm_cache() is not None:
            raise ValueError('Disable global LangChain debug, verbose output and caches')
        if model.callbacks or getattr(model, 'streaming', False) or model.cache:
            raise ValueError('Disable callbacks, streaming and provider caches for guarded execution')
        import os
        if any(os.environ.get(k, '').lower() in ('true', '1') for k in ('LANGCHAIN_TRACING_V2', 'LANGSMITH_TRACING')):
            raise ValueError('Disable external tracing before processing private model inputs')
        self.model = model.model_copy(update={'cache':False,'verbose':False,'disable_streaming':True})
        self.destination_id, self.endpoint = destination_id, endpoint

    async def complete(self, prepared):
        from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
        if prepared.model_destination_id != self.destination_id:
            raise RuntimeFault('MODEL_DESTINATION_DENIED')
        types = {'user': HumanMessage, 'system': SystemMessage, 'assistant': AIMessage}
        messages = []
        for m in prepared.messages:
            if m.role not in types:
                raise RuntimeFault('HOST_TOOL_MESSAGES_REQUIRE_ENVELOPE')
            messages.append(types[m.role](content=m.content if isinstance(m.content, str) else canonical(m.content)))
        response = await self.model.ainvoke(messages, config={'callbacks': [], 'tags': ['agentguard-v2']})
        if response.tool_calls or response.invalid_tool_calls or not isinstance(response.content, str):
            raise RuntimeFault('FRAMEWORK_EXPECTS_JSON_PROPOSALS')
        data = strict_loads(response.content)
        if not isinstance(data, dict) or set(data) != {'content', 'tool_proposals'} or not isinstance(data['content'], str):
            raise RuntimeFault('INVALID_MODEL_OUTPUT')
        usage = response.usage_metadata or {}
        return AgentReply(data['content'], tuple(frozen_copy(ToolProposal, p) for p in data['tool_proposals']),
            {'provider': 'langchain', 'model': self.model._llm_type, 'input_tokens': usage.get('input_tokens'),
             'output_tokens': usage.get('output_tokens'), 'latency_ms': None, 'attempts': 1})

    async def reset(self, session_id):
        # BaseChatModel has no conversational state in this adapter; all messages
        # are reconstructed each call. Persistent framework state belongs to Host.
        return True


class LangChainHost(HostAdapter):
    def __init__(self, runtime, chat_model, *, destination_id, endpoint, **kwargs):
        super().__init__(runtime, LangChainModel(chat_model, destination_id=destination_id, endpoint=endpoint), **kwargs)
