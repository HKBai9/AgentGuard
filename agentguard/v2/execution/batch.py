"""A barrier returns independently keyed results; completion order is not lineage."""
import asyncio
from ..common import RuntimeFault
from ..contracts import BatchResult, make


async def execute(runtime, req):
    if len({c.call_id for c in req.calls}) != len(req.calls):
        raise RuntimeFault('DUPLICATE_CALL_ID', 422)
    for call in req.calls:
        if (call.session_id, call.turn_id, call.input_context_version) != (req.session_id, req.turn_id, req.context_version):
            raise RuntimeFault('BATCH_BINDING_MISMATCH')
        runtime.action_state(call)
    results = await asyncio.gather(*(runtime.execute_call(call) for call in req.calls))
    return make(BatchResult, session_id=req.session_id, turn_id=req.turn_id, results={r.call_id: r for r in results})
