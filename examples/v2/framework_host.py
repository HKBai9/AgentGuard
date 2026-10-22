"""LangChain integration template; importing this file never invokes a model."""
from agentguard.v2.adapters.framework import LangChainHost


async def run_guarded(runtime, request, chat_model, *, endpoint, destination_id='agent', state_directory=None):
    """chat_model is a caller-configured, stateless BaseChatModel with no callbacks."""
    host = LangChainHost(runtime, chat_model, destination_id=destination_id,
                         endpoint=endpoint, state_directory=state_directory,
                         recover_on_block=True)
    session = await host.create(request)
    return await host.run(session.session_id)
