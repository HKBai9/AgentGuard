"""Generate A-owned synthetic contract examples, separate from B's fixtures."""
import asyncio
import json
from pathlib import Path
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tests/v2'))
from conftest import build_harness,proposal
from agentguard.v2.contracts import *
from agentguard.v2.state.lineage import public_labels

OUTPUT=ROOT/'docs/v2/examples'

def save(group,name,value):
    folder=OUTPUT/group
    folder.mkdir(parents=True,exist_ok=True)
    if isinstance(value,Wire):value=value.model_dump(mode='json')
    (folder/(name+'.json')).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

async def main():
    with tempfile.TemporaryDirectory() as directory:
        for send in [False,True]:
            h=build_harness(Path(directory)/str(send),send=send)
            save('policy_local_vs_send','send_request' if send else 'local_request',h.request)
        save('policy_local_vs_send','expected',{'local_allowed_effects':['READ','WRITE'],'local_send':False,'send_only_destinations':['receiver']})
        for group,mode,secret in [('normal_allow','ALLOW',False),('injection_block','BLOCK',False),('field_redact','REDACT',True),('guard_failure','forged',False)]:
            h=build_harness(Path(directory)/group,mode=mode,secret=secret)
            s=await h.session()
            p,out,b=await h.run(s.session_id,[proposal()])
            material=next(m for m in h.guard.materials if m.phase=='RESULT')
            outcome=await h.guard.inspect(material)
            save(group,'material',material)
            save(group,'outcome',outcome)
            save(group,'result',b)
            expected={'normal_allow':{'status':'RELEASED','content':'document:docs'},
                'injection_block':{'status':'BLOCKED','content':None},'field_redact':{'status':'RELEASED','secret':'[REDACTED]','version':2},
                'guard_failure':{'status':'REVIEW_PENDING','reason_code':'INVALID_REFERENCE','content':None}}[group]
            save(group,'expected',expected)
        bad=outcome.model_dump(mode='json')
        bad['schema_version']='unknown'
        save('guard_failure','invalid_schema',bad)

if __name__=='__main__':asyncio.run(main())
