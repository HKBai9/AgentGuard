"""Local-first gateway launch with explicit host-owned composition factory."""
import argparse
import importlib
import os
import uvicorn
from .app import create_app


def main():
    parser = argparse.ArgumentParser(description='AgentGuard v2 authenticated gateway')
    parser.add_argument('--factory', required=True, help='Trusted module:function returning a configured Runtime')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8765)
    args = parser.parse_args()
    module, separator, name = args.factory.partition(':')
    if not separator:
        parser.error('--factory requires module:function')
    host_token = os.environ.get('AGENTGUARD_HOST_TOKEN')
    ui_token = os.environ.get('AGENTGUARD_UI_TOKEN')
    if not host_token or not ui_token or host_token == ui_token:
        parser.error('Set distinct AGENTGUARD_HOST_TOKEN and AGENTGUARD_UI_TOKEN')
    runtime = getattr(importlib.import_module(module), name)()
    app = create_app(runtime, host_token=host_token, ui_token=ui_token)
    # Host write bodies may contain private inputs; access logs omit payloads.
    uvicorn.run(app, host=args.host, port=args.port, access_log=False)


if __name__ == '__main__':
    main()
