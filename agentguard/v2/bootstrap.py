"""Explicit composition. Missing model services fail closed; no production fakes."""
from pathlib import Path
from .runtime import Runtime
from .registry import ToolRegistry
from .state.store import Store
from .state.artifacts import Artifacts
from .state.lineage import Lineage


def build_runtime(directory, *, policy_generator, guard_service, registry=None, transforms=()):
    directory = Path(directory)
    store = Store(directory / 'state.sqlite3')
    registry = registry if registry is not None else ToolRegistry()
    return Runtime(store=store, artifacts=Artifacts(store, directory / 'quarantine', transforms),
        lineage=Lineage(store), registry=registry, policy_generator=policy_generator, guard_service=guard_service)
