"""Supervise localhost gateway + read-only console; no paid call until a task."""
import argparse
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

from .application import load_settings


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True)
    parser.add_argument('--task')
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--ui-port',type=int,default=8502)
    args=parser.parse_args()
    settings=load_settings(args.config)
    env=dict(os.environ)
    if env.get('AGENTGUARD_V2_CLOUD_ENABLED')!='1':
        parser.error('Enable cloud configuration explicitly; launching does not send task data')
    for role in ('guard','agent'):
        if not env.get(settings[role]['api_key_env']):
            parser.error('Set the configured '+role+' API key environment variable')
    env['AGENTGUARD_V2_CONFIG']=str(Path(args.config).resolve())
    env['AGENTGUARD_HOST_TOKEN']=env.get('AGENTGUARD_HOST_TOKEN') or secrets.token_urlsafe(32)
    env['AGENTGUARD_UI_TOKEN']=env.get('AGENTGUARD_UI_TOKEN') or secrets.token_urlsafe(32)
    env['AGENTGUARD_V2_GATEWAY']='http://127.0.0.1:'+str(args.port)
    env['AGENTGUARD_V2_UI_PORT']=str(args.ui_port)
    env.pop('AGENTGUARD_V2_REPLAY',None)
    logs=Path(settings['state_directory'])/'service-logs'; logs.mkdir(parents=True,exist_ok=True)
    handles=[]; processes=[]
    flags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0
    try:
        from . import console
        commands=[('gateway',[sys.executable,'-m','agentguard.v2.gateway.cli','--factory','agentguard.v2.application:factory',
            '--port',str(args.port)]),('console',[sys.executable,'-m','streamlit','run',str(Path(console.__file__).resolve()),
                '--server.address','127.0.0.1','--server.port',str(args.ui_port),'--browser.gatherUsageStats','false'])]
        for name,command in commands:
            handle=(logs/(name+'.log')).open('a',encoding='utf-8'); handles.append(handle)
            processes.append(subprocess.Popen(command,env=env,stdout=handle,stderr=subprocess.STDOUT,creationflags=flags))
        from .console import ConsoleReader
        reader=ConsoleReader(env['AGENTGUARD_V2_GATEWAY'],env['AGENTGUARD_UI_TOKEN'])
        ready=False
        for _ in range(40):
            if any(p.poll() is not None for p in processes):
                raise RuntimeError('A service exited; inspect '+str(logs))
            try:
                reader.get('/v2/sessions'); ready=True; break
            except Exception:
                time.sleep(.25)
        if not ready:
            raise RuntimeError('Gateway startup timed out; inspect '+str(logs))
        print('Gateway: '+env['AGENTGUARD_V2_GATEWAY'])
        print('Console: http://127.0.0.1:'+str(args.ui_port))
        print('Ctrl+C stops the services started by this command.')
        if args.task:
            subprocess.run([sys.executable,'-m','agentguard.v2.application','--config',args.config,'--task',args.task,
                            '--gateway',env['AGENTGUARD_V2_GATEWAY']],env=env,check=True)
        while all(p.poll() is None for p in processes):
            time.sleep(.5)
    except KeyboardInterrupt:
        pass
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
        for handle in handles:
            handle.close()


if __name__=='__main__':
    main()
