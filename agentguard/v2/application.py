"""Production composition and a small, usable workspace tool pack.

Configuration is trusted host input. Neither tasks nor models may set endpoints,
import tool handlers, expand roots, or change labels.
"""
from dataclasses import dataclass
from pathlib import Path
import argparse
import asyncio
import os

from .bootstrap import build_runtime
from .common import RuntimeFault, canonical, frozen_copy, strict_loads
from .contracts import (DataLabels, Destination, HostPolicy, ModelDestinationGrant,
    PolicyRule, ResourceCatalog, ResourceScope, SessionRequest, ToolManifest, make)
from .registry import ToolRegistry
from .state.lineage import public_labels
from .state.artifacts import TransformSpec
from .review.budget import Budget
from .review.cache import AnalysisCache
from .review.clients import CloudClient, CloudConfig
from .review.context import ContextBuilder
from .review.reviewers import Reviewer
from .review.service import GuardService
from .policy.compiler import PolicyCompiler
from .adapters.host import CloudAgentModel, HostAdapter


@dataclass
class Application:
    runtime: object
    model: object
    settings: dict
    request: SessionRequest

    def host(self, runtime=None):
        return HostAdapter(runtime or self.runtime, self.model,
            state_directory=Path(self.settings['state_directory']) / 'host',
            max_turns=self.settings.get('max_turns', 60),
            recover_on_block=self.settings.get('recover_on_block', True))


def load_settings(path):
    path = Path(path).resolve()
    settings = strict_loads(path.read_text(encoding='utf-8'))
    allowed = {'workspace', 'state_directory', 'guard', 'agent', 'network_destinations',
        'max_turns', 'max_calls', 'max_review_bytes', 'context_strategy', 'recent_n',
        'max_attempts', 'max_tokens', 'recover_on_block', 'resources', 'tool_factory',
        'synthetic_demo', 'confirmed_authorizations'}
    allowed.add('transforms')
    if not isinstance(settings, dict) or set(settings) - allowed:
        raise ValueError('Unknown application configuration field')
    for key in ('workspace', 'state_directory'):
        value = Path(settings[key])
        settings[key] = str((path.parent / value).resolve() if not value.is_absolute() else value.resolve())
    return settings


def cloud(config, *, max_attempts=1000, max_tokens=None, budget=None):
    if os.environ.get('AGENTGUARD_V2_CLOUD_ENABLED') != '1':
        raise ValueError('Set AGENTGUARD_V2_CLOUD_ENABLED=1 explicitly')
    config = dict(config)
    key_env = config.pop('api_key_env')
    return CloudClient(CloudConfig(enabled=True, api_key=os.environ.get(key_env, ''), **config),
        budget=budget if budget is not None else Budget(max_attempts=max_attempts, max_tokens=max_tokens))


def workspace_tools(settings):
    root = Path(settings['workspace']).resolve()
    if not root.is_dir():
        raise ValueError('Configured workspace must already exist')
    registry = ToolRegistry()

    def checked(path):
        value = Path(path)
        resolved = (root / value).resolve() if not value.is_absolute() else value.resolve()
        if not resolved.is_relative_to(root) or resolved == root:
            raise RuntimeFault('RESOURCE_OUT_OF_SCOPE')
        return resolved

    def read_text(path):
        value = checked(path)
        if value.stat().st_size > settings.get('max_review_bytes', 96_000):
            raise RuntimeFault('CONTENT_TOO_LARGE')
        return value.read_text(encoding='utf-8')

    def write_text(path, body):
        value = checked(path)
        if not isinstance(body, str) or len(body.encode('utf-8')) > 1_000_000:
            raise RuntimeFault('CONTENT_TOO_LARGE')
        value.parent.mkdir(parents=True, exist_ok=True)
        value.write_text(body, encoding='utf-8')
        return 'written'

    def list_files(path):
        value = root if Path(path).resolve() == root else checked(path)
        return [str(p.resolve()) for p in sorted(value.iterdir()) if p.is_file() and p.resolve().is_relative_to(root)][:1000]

    destinations = {d['destination_id']: d['address'] for d in settings.get('network_destinations', [])}

    def send_http(destination, body):
        # No remote receiver is present by default. Only exact host catalog IDs.
        if destination not in destinations:
            raise RuntimeFault('DESTINATION_OUT_OF_SCOPE')
        from urllib import request
        from .review.clients import _NoRedirect
        opener = request.build_opener(request.ProxyHandler({}), _NoRedirect())
        raw = canonical({'body': body}).encode('utf-8')
        if len(raw) > 1_000_000:
            raise RuntimeFault('CONTENT_TOO_LARGE')
        req = request.Request(destinations[destination], data=raw, headers={'Content-Type': 'application/json'}, method='POST')
        with opener.open(req, timeout=15) as response:
            return {'status_code': response.status, 'response': response.read(65537).decode('utf-8', errors='replace')}

    specs = [
        ('read_text', read_text, 'READ', {'path': {'type': 'string'}}, '/path', None, 'text/plain'),
        ('list_files', list_files, 'READ', {'path': {'type': 'string'}}, '/path', None, 'application/json'),
        ('write_text', write_text, 'WRITE', {'path': {'type': 'string'}, 'body': {'type': 'string'}}, '/path', None, 'text/plain')]
    if destinations:
        specs.append(('send_http', send_http, 'SEND', {'destination': {'type': 'string', 'enum': list(destinations)},
                      'body': {'type': 'string'}}, None, '/destination', 'application/json'))
    for name, handler, effect, props, resource, destination, media in specs:
        registry.register(make(ToolManifest, tool_id=name, manifest_version='v1',
            parameters_schema={'type': 'object', 'properties': props, 'required': list(props), 'additionalProperties': False},
            effects=[effect], resource_parameter=resource, destination_parameter=destination, artifact_parameters={},
            return_media_type=media, supports_idempotency_key=False, output_labels=public_labels('external'),
            synthetic_demo=settings.get('synthetic_demo', False)), handler)
    return registry


def compose(settings, task=''):
    if settings.get('tool_factory'):
        # Explicit deployment configuration only; never passed by model/user task.
        import importlib
        module, function = settings['tool_factory'].split(':', 1)
        registry = getattr(importlib.import_module(module), function)(settings)
    else:
        registry = workspace_tools(settings)
    guard = cloud(settings['guard'], max_attempts=settings.get('max_attempts', 1000), max_tokens=settings.get('max_tokens'))
    agent = cloud(settings['agent'], max_attempts=settings.get('max_attempts', 1000), max_tokens=settings.get('max_tokens'))
    if guard.destination_id == agent.destination_id:
        raise ValueError('Use distinct catalog identities for Guard and task model')
    service = GuardService(ContextBuilder(max_bytes=settings.get('max_review_bytes', 96_000),
        strategy=settings.get('context_strategy', 'relations'), recent_n=settings.get('recent_n', 8)),
        Reviewer(guard, cache=AnalysisCache()))
    transforms = [TransformSpec(item['transform_id'],item['kind'],frozenset(item.get('allowed_pointers',[])),
        frozenset(item.get('declassify_fields',[]))) for item in settings.get('transforms',[])]
    runtime = build_runtime(settings['state_directory'], registry=registry,
        policy_generator=PolicyCompiler(guard), guard_service=service,transforms=transforms)
    resources = [make(ResourceScope, scope_id='workspace', kind='path', root=settings['workspace'], labels=public_labels('external'))]
    for resource in settings.get('resources', []):
        resources.append(frozen_copy(ResourceScope, resource))
    scopes = [r.scope_id for r in resources]
    destinations = [make(Destination, destination_id=c.destination_id, kind='model', address=c.config.endpoint,
                        allowed_confidentiality=['private', 'internal']) for c in (guard, agent)]
    destinations.append(make(Destination, destination_id='user', kind='user', address='local-user', allowed_confidentiality=[]))
    destinations.extend(frozen_copy(Destination, d) for d in settings.get('network_destinations', []))
    rules = [make(PolicyRule, tool_id=m.tool_id, effect=effect, resource_scope_ids=scopes,
        destination_ids=[d['destination_id'] for d in settings.get('network_destinations', [])] if effect == 'SEND' else [],
        allowed_uses=['analyze', 'write', 'send', 'reply', 'model', 'review'], max_calls=settings.get('max_calls', 200))
        for m in registry.manifests() for effect in m.effects]
    request = make(SessionRequest, trusted_task=task or 'Await a host-supplied task.',
        host_policy=make(HostPolicy, rules=rules, model_destination_ids=[make(ModelDestinationGrant,
            destination_id=c.destination_id, resource_scope_ids=scopes) for c in (guard, agent)],
            guard_destination_id=guard.destination_id, final_destination_id='user', final_use='reply',
            max_review_bytes=settings.get('max_review_bytes', 96_000), permit_ttl_seconds=60, review_timeout_seconds=120.0),
        resource_catalog=make(ResourceCatalog, resources=resources, destinations=destinations),
        tool_manifests=registry.manifests(), confirmed_authorizations=settings.get('confirmed_authorizations', []),
        synthetic_demo=settings.get('synthetic_demo', False))
    return Application(runtime, CloudAgentModel(agent), settings, request)


def factory():
    return compose(load_settings(os.environ['AGENTGUARD_V2_CONFIG'])).runtime


def main():
    parser = argparse.ArgumentParser(description='Run a buffered native Agent through AgentGuard v2')
    parser.add_argument('--config', required=True)
    parser.add_argument('--task', required=True)
    parser.add_argument('--gateway', help='Use gateway RuntimePort instead of local dispatch')
    args = parser.parse_args()

    async def run():
        app = compose(load_settings(args.config), args.task)
        remote = None
        try:
            if args.gateway:
                from .adapters.http import GatewayRuntime
                remote = GatewayRuntime(args.gateway, os.environ['AGENTGUARD_HOST_TOKEN'])
            host = app.host(remote)
            session = await host.create(app.request)
            result = await host.run(session.session_id)
            # No intermediate content, thoughts or tool bodies are printed.
            print(canonical({'session_id': session.session_id, 'status': result.status,
                'reason_code': result.reason_code, 'content': result.content if result.status == 'RELEASED' else None}))
        finally:
            if remote:
                await remote.aclose()
    try:
        asyncio.run(run())
    except Exception as exc:
        # Provider errors and tool errors may contain private content.
        from .review.errors import GuardError
        code = exc.code if isinstance(exc,RuntimeFault) else exc.reason_code if isinstance(exc,GuardError) else 'HOST_FAILED'
        print(canonical({'status': 'FAILED', 'reason_code': code}))
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
