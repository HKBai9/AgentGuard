"""Real process termination after a visible effect, before receipt persistence."""
import asyncio
import os
from pathlib import Path
import subprocess
import sys
import pytest
from agentguard.v2.common import canonical
from agentguard.v2.contracts import *
from conftest import proposal

@pytest.mark.asyncio
async def test_process_dies_after_effect_no_redelivery(harness,tmp_path):
    h=harness
    entry=h.runtime.registry.get('send_report')
    h.runtime.registry.register(entry.manifest.model_copy(update={'manifest_version':'v2'}),entry.handler)
    h.request=h.request.model_copy(update={'tool_manifests':h.runtime.registry.manifests()})
    s=await h.session()
    _,out=await h.propose(s.session_id,[proposal('send_report',{'destination':'receiver','body':'report'},use='send').model_copy(update={'manifest_version':'v2'})])
    request=tmp_path/'call.json'
    request.write_text(canonical(out.calls[0]))
    receiver=tmp_path/'receiver.txt'
    code='''
import asyncio, os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from conftest import build_harness
from agentguard.v2.contracts import ToolCall
h=build_harness(Path(sys.argv[2]))
entry=h.runtime.registry.get('send_report')
def crash(destination,body):
    with open(sys.argv[4],'a') as receiver:
        receiver.write(body+'\\n')
        receiver.flush()
        os.fsync(receiver.fileno())
    os._exit(17)
h.runtime.registry.register(entry.manifest.model_copy(update={'manifest_version':'v2'}),crash)
call=ToolCall.model_validate_json(Path(sys.argv[3]).read_bytes())
asyncio.run(h.runtime.execute_call(call))
'''
    proc=await asyncio.to_thread(subprocess.run,[sys.executable,'-c',code,str(Path(__file__).resolve().parents[1]),str(tmp_path),str(request),str(receiver)],
        capture_output=True,text=True,timeout=20)
    assert proc.returncode==17,proc.stderr
    assert receiver.read_text()=='report\n'
    assert h.runtime.permits.recover_abandoned()==1
    result=await h.runtime.execute_call(out.calls[0])
    assert result.status=='UNKNOWN' and receiver.read_text()=='report\n' and h.effects==[]
