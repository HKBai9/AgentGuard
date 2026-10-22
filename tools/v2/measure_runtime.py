"""Offline measurements of the same Runtime; no alternate benchmark executor."""
import argparse
import asyncio
from contextlib import contextmanager
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tests/v2'))
from conftest import build_harness,proposal

async def measure():
    with tempfile.TemporaryDirectory() as directory:
        h=build_harness(Path(directory))
        waits,held=[],[]
        original=h.runtime.store.transaction
        @contextmanager
        def transaction():
            start=time.perf_counter()
            with original() as conn:
                acquired=time.perf_counter()
                waits.append((acquired-start)*1000)
                try:
                    yield conn
                finally:
                    held.append((time.perf_counter()-acquired)*1000)
        h.runtime.store.transaction=transaction
        session=await h.session()
        start=time.perf_counter()
        _,out,batch=await h.run(session.session_id,[proposal() for _ in range(20)])
        assert len(h.reads)==20 and all(r.status=='RELEASED' for r in batch.results.values())
        def stats(items):
            ordered=sorted(items)
            return {'count':len(items),'median_ms':round(statistics.median(items),3),
                'p95_ms':round(ordered[min(len(ordered)-1,int(len(ordered)*0.95))],3),'max_ms':round(max(items),3)}
        return {'mode':'explicit offline fixture; same production Runtime', 'calls':20,'batch_seconds':round(time.perf_counter()-start,3),
            'transaction_acquisition':stats(waits),'transaction_body':stats(held),'model_cost':'unavailable (no model used)'}

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,default=ROOT.parent/'ai/artifacts/v2/performance.json')
    args=parser.parse_args()
    result=asyncio.run(measure())
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
