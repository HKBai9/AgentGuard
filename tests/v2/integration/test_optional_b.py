"""Opt-in real B integration. Missing B is reported as skipped, never simulated.

The trusted factory module:function receives a temporary path and returns
(runtime, SessionRequest, list[ToolProposal]). It must supply B's real generator
and GuardService and configure its own API credentials/budget. Default tests
never import the factory or make any paid API calls.
"""
import importlib
import os
import pytest
from agentguard.v2.contracts import *

@pytest.mark.asyncio
async def test_real_b_integration(tmp_path):
    factory=os.environ.get('AGENTGUARD_B_INTEGRATION_FACTORY')
    if not factory:
        pytest.skip('B implementation not provided; set AGENTGUARD_B_INTEGRATION_FACTORY explicitly for real integration')
    module,separator,name=factory.partition(':')
    assert separator
    runtime,request,proposals=getattr(importlib.import_module(module),name)(tmp_path)
    session=await runtime.create_session(request)
    destination=next(g.destination_id for g in request.host_policy.model_destination_ids if g.destination_id != request.host_policy.guard_destination_id)
    prepared=await runtime.prepare_model_turn(make(PrepareTurnRequest,session_id=session.session_id,messages=[],model_destination_id=destination))
    output=await runtime.record_model_output(make(ModelOutputRequest,session_id=session.session_id,model_call_id=prepared.model_call_id,
        context_version=prepared.context_version,content='integration report',tool_proposals=proposals))
    batch=await runtime.execute_batch(make(BatchRequest,session_id=session.session_id,turn_id=prepared.turn_id,
        context_version=prepared.context_version,calls=output.calls))
    assert batch.results and all(r.status=='RELEASED' for r in batch.results.values())
    final=await runtime.finalize(make(FinalizeRequest,session_id=session.session_id,turn_id=prepared.turn_id,
        context_version=prepared.context_version,output_ref=output.output_ref))
    assert final.status=='RELEASED'
