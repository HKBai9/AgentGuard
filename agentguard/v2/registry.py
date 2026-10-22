"""Host-owned tool registration. Remote descriptions cannot mutate grants."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from typing import Callable
from jsonschema import Draft202012Validator
from referencing import Registry as SchemaRegistry
from .contracts import ToolManifest, ResourceCatalog
from .common import RuntimeFault, frozen_copy, canonical, pointer_parts


def normalize_endpoint(address: str) -> str:
    try:
        if any(ord(char) <= 32 for char in address):
            raise ValueError()
        url = urlsplit(address)
        if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.fragment or url.query:
            raise ValueError()
        host = url.hostname.encode('idna').decode('ascii').lower().rstrip('.')
        if '*' in host:
            raise ValueError()
        if ':' in host:
            host = '[' + host + ']'
        port = url.port if url.port is not None else (443 if url.scheme == 'https' else 80)
        if port == 0:
            raise ValueError()
        path = url.path or '/'
        # Exact endpoints only. No wildcard, URL userinfo or redirect semantics.
        if '%' in path or '..' in path.split('/') or '\\' in path:
            raise ValueError()
        return urlunsplit((url.scheme, f'{host}:{port}', path, '', ''))
    except (ValueError, UnicodeError):
        raise RuntimeFault('INVALID_DESTINATION', 422) from None


@dataclass(frozen=True)
class RegisteredTool:
    manifest: ToolManifest
    handler: Callable


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, RegisteredTool] = {}
        self._versions: dict[tuple[str, str], str] = {}

    def register(self, manifest: ToolManifest, handler: Callable):
        manifest = frozen_copy(ToolManifest, manifest)
        if len(set(manifest.effects)) != len(manifest.effects):
            raise RuntimeFault('DUPLICATE_EFFECT', 422)
        for pointer in [manifest.resource_parameter, manifest.destination_parameter, *manifest.artifact_parameters]:
            if pointer is not None and len(pointer_parts(pointer)) != 1:
                raise RuntimeFault('UNSUPPORTED_PARAMETER_LOCATION', 422)
        # JSON Schema references are local-only: validation must never fetch URLs.
        def check_refs(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in ('$ref', '$dynamicRef') and (not isinstance(item, str) or not item.startswith('#')):
                        raise RuntimeFault('REMOTE_SCHEMA_REFERENCE_FORBIDDEN', 422)
                    check_refs(item)
            elif isinstance(value, list):
                for item in value:
                    check_refs(item)
        check_refs(manifest.parameters_schema)
        try:
            Draft202012Validator.check_schema(manifest.parameters_schema)
        except Exception:
            raise RuntimeFault('INVALID_TOOL_SCHEMA', 422) from None
        key = (manifest.tool_id, manifest.manifest_version)
        value = canonical(manifest)
        if key in self._versions:
            # Changing code without changing the manifest version is forbidden too.
            if self._versions[key] != value or self._tools.get(manifest.tool_id, None) is None or self._tools[manifest.tool_id].handler is not handler:
                raise RuntimeFault('MANIFEST_VERSION_REUSED')
            return
        self._versions[key] = value
        self._tools[manifest.tool_id] = RegisteredTool(manifest, handler)

    def get(self, tool_id, version=None):
        entry = self._tools.get(tool_id)
        if entry is None:
            raise RuntimeFault('UNKNOWN_TOOL')
        if version is not None and version != entry.manifest.manifest_version:
            raise RuntimeFault('TOOL_VERSION_CHANGED')
        return entry

    def manifests(self):
        return [frozen_copy(ToolManifest, entry.manifest) for entry in self._tools.values()]

    def validate_args(self, manifest, args):
        canonical(args)
        def no_remote(uri):
            raise RuntimeFault('REMOTE_SCHEMA_REFERENCE_FORBIDDEN', 422)
        try:
            valid = Draft202012Validator(manifest.parameters_schema, registry=SchemaRegistry(retrieve=no_remote)).is_valid(args)
        except Exception:
            raise RuntimeFault('INVALID_TOOL_SCHEMA', 422) from None
        if not valid:
            raise RuntimeFault('INVALID_ARGUMENTS', 422)


class Catalog:
    def __init__(self, value: ResourceCatalog):
        self.value = frozen_copy(ResourceCatalog, value)
        self.resources = {r.scope_id: r for r in self.value.resources}
        self.destinations = {d.destination_id: d for d in self.value.destinations}
        if len(self.resources) != len(self.value.resources) or len(self.destinations) != len(self.value.destinations):
            raise RuntimeFault('DUPLICATE_CATALOG_ID', 422)
        for r in self.resources.values():
            if r.kind == 'path' and not Path(r.root).is_absolute():
                raise RuntimeFault('INVALID_RESOURCE_ROOT', 422)
        for d in self.destinations.values():
            if d.kind in ('network', 'model'):
                normalize_endpoint(d.address)

    def matching_scopes(self, value):
        if not isinstance(value, str):
            raise RuntimeFault('INVALID_RESOURCE')
        result = []
        for rid, scope in self.resources.items():
            if scope.kind == 'logical' and value == scope.root:
                result.append(rid)
            if scope.kind == 'path':
                try:
                    path = Path(value)
                    if path.is_absolute() and path.resolve().is_relative_to(Path(scope.root).resolve()):
                        result.append(rid)
                except (ValueError, OSError):
                    pass
        if not result:
            raise RuntimeFault('RESOURCE_OUT_OF_SCOPE')
        return result

    def destination(self, value):
        if not isinstance(value, str):
            raise RuntimeFault('INVALID_DESTINATION')
        if value in self.destinations:
            return value
        normalized = normalize_endpoint(value)
        for did, dest in self.destinations.items():
            if dest.kind in ('network', 'model') and normalize_endpoint(dest.address) == normalized:
                return did
        raise RuntimeFault('DESTINATION_OUT_OF_SCOPE')
