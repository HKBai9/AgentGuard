"""Offline release acceptance. Exit nonzero on tests, build or install failure."""
import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[2]


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,default=ROOT.parent/'ai'/'artifacts'/'v2'/'verification.json')
    parser.add_argument('--skip-install',action='store_true',help='Explicitly mark wheel install NOT VERIFIED')
    parser.add_argument('--powershell-version',default=None,help=argparse.SUPPRESS)
    args=parser.parse_args()
    args.output=args.output.resolve()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    report={'python':sys.version,'platform':platform.platform(),'contract':'0.1','paid_api_calls':0,
        'dependencies':{d.metadata['Name']:d.version for d in importlib.metadata.distributions()},'checks':[],
        'external_b_integration':'not_run: B implementation is not present; use the documented injected RuntimePort integration',
        'powershell_launcher':args.powershell_version or 'not_run (Python entry point)'}
    def run(name,command,cwd=ROOT,env=None):
        start=time.perf_counter()
        completed=subprocess.run(command,cwd=cwd,env=env,text=True,capture_output=True)
        log=args.output.parent/(name+'.log')
        log.write_text(completed.stdout+completed.stderr,encoding='utf-8')
        record={'name':name,'command':command,'exit_code':completed.returncode,'seconds':round(time.perf_counter()-start,3),'log':str(log)}
        report['checks'].append(record)
        print(name+': '+('PASS' if completed.returncode==0 else 'FAIL'),flush=True)
        if completed.returncode:
            raise RuntimeError(name+' failed; see '+str(log))
        return completed.stdout
    code=0
    try:
        if sys.version_info[:2] != (3,12):
            raise RuntimeError('Release verification requires Python 3.12')
        report['git_head']=run('git-head',['git','rev-parse','HEAD']).strip()
        report['git_status']=run('git-status',['git','status','--short'])
        for name,paths in [('legacy',['tests/test_capability.py','tests/test_guard.py','tests/test_sdk.py']),
            ('contracts-runtime',['tests/v2/contracts','tests/v2/runtime']),('integration',['tests/v2/integration'])]:
            junit=args.output.parent/(name+'.xml')
            offline_env={k:v for k,v in os.environ.items() if k != 'AGENTGUARD_B_INTEGRATION_FACTORY'}
            run(name,[sys.executable,'-m','pytest',*paths,'-o','addopts=','-q','--junitxml='+str(junit)],env=offline_env)
            tree=ET.parse(junit)
            report['checks'][-1]['test_counts']={key:sum(int(s.get(key,'0')) for s in tree.getroot().iter('testsuite')) for key in ['tests','failures','errors','skipped']}
        with tempfile.TemporaryDirectory(prefix='agentguard-install-') as temporary:
            temp=Path(temporary)
            dist=temp/'dist'
            run('wheel-build',[sys.executable,'-m','build','--wheel','--no-isolation','--outdir',str(dist)])
            wheel=next(dist.glob('*.whl'))
            shutil.copy2(wheel,args.output.parent/wheel.name)
            if args.skip_install:
                report['wheel_install']='NOT_VERIFIED (--skip-install)'
            else:
                target=temp/'installed'
                # --target gets a clean package location; pinned deps are provided by
                # the verified Python environment, no network used for this step.
                run('wheel-install',[sys.executable,'-m','pip','install','--no-deps','--target',str(target),str(wheel)],cwd=temp)
                smoke=temp/'smoke.py'
                shutil.copy2(ROOT/'tools/v2/installed_smoke.py',smoke)
                env={**os.environ,'PYTHONPATH':str(target),'PYTHONNOUSERSITE':'1'}
                smoke_output=run('installed-smoke',[sys.executable,str(smoke)],cwd=temp,env=env)
                info=json.loads(smoke_output.strip().splitlines()[-1])
                if not Path(info['installed_module']).is_relative_to(target):
                    raise RuntimeError('Installed smoke imported source checkout')
                report['wheel_install']=info
    except Exception as exc:
        report['failure']=str(exc)
        code=1
    report['success']=code==0
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Report: '+str(args.output))
    return code


if __name__=='__main__':
    raise SystemExit(main())
