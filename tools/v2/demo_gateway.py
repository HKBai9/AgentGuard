"""Explicit synthetic offline demo factory; NEVER the production default.

Run from the checkout with AGENTGUARD_OFFLINE_DEMO=1. Backend tools and Guard
are test fixtures; the security Runtime is exactly the production implementation.
"""
import os
from pathlib import Path
import sys


def build_demo_runtime():
    if os.environ.get('AGENTGUARD_OFFLINE_DEMO') != '1':
        raise RuntimeError('This factory requires explicit AGENTGUARD_OFFLINE_DEMO=1')
    root=Path(__file__).resolve().parents[2]
    sys.path.insert(0,str(root/'tests/v2'))
    from conftest import build_harness
    directory=os.environ.get('AGENTGUARD_DEMO_STATE')
    if not directory:
        raise RuntimeError('Set an explicit private AGENTGUARD_DEMO_STATE directory')
    return build_harness(Path(directory)).runtime
