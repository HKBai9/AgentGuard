"""Audit regressions: actual boundaries under restart and lost responses."""
from pathlib import Path
import httpx
import pytest

from conftest import build_harness, proposal
from agentguard.v2.adapters.host import AgentReply, HostAdapter
from agentguard.v2.common import RuntimeFault, canonical
from agentguard.v2.contracts import *
from agentguard.v2.gateway.app import create_app
from agentguard.v2.state.lineage import public_labels


class SendingModel:
    destination_id = 'agent'
    def __init__(self):
        self.calls = 0
        self.resets = 0

    async def complete(self, prepared):
        self.calls += 1
        if self.calls == 1:
            return AgentReply('', (proposal('send_report', {'destination': 'receiver', 'body': 'public'}, use='send'),))
        return AgentReply('finished')

    async def reset(self, sid):
        self.resets += 1
        return True


@pytest.mark.asyncio
async def test_lost_batch_response_cannot_replan_effect_after_host_restart(tmp_path, monkeypatch):
    h = build_harness(tmp_path / 'runtime')
    model = SendingModel()
    host = HostAdapter(h.runtime, model, state_directory=tmp_path / 'host')
    sid = (await host.create(h.request)).session_id
    execute = h.runtime.execute_batch

    async def lose_response(req):
        await execute(req)
        raise ConnectionError('response lost after the send')

    monkeypatch.setattr(h.runtime, 'execute_batch', lose_response)
    with pytest.raises(ConnectionError):
        await host.run(sid)
    assert len(h.effects) == 1
    restored = HostAdapter(h.runtime, model, state_directory=tmp_path / 'host')
    with pytest.raises(RuntimeFault, match='HOST_OPERATION_PENDING'):
        await restored.run(sid)
    assert model.calls == 1 and len(h.effects) == 1


@pytest.mark.asyncio
async def test_completed_host_and_turn_ceiling_survive_restart(tmp_path):
    h = build_harness(tmp_path / 'runtime')
    model = SendingModel()
    host = HostAdapter(h.runtime, model, state_directory=tmp_path / 'host', max_turns=1)
    sid = (await host.create(h.request)).session_id
    with pytest.raises(RuntimeFault, match='HOST_TURN_LIMIT'):
        await host.run(sid)
    restored = HostAdapter(h.runtime, model, state_directory=tmp_path / 'host', max_turns=1)
    with pytest.raises(RuntimeFault, match='HOST_TURN_LIMIT'):
        await restored.run(sid)
    assert model.calls == 1 and len(h.effects) == 1
    other = HostAdapter(h.runtime, model, state_directory=tmp_path / 'other')
    sid = (await other.create(h.request)).session_id
    assert (await other.run(sid)).status == 'RELEASED'
    with pytest.raises(RuntimeFault, match='HOST_TASK_COMPLETED'):
        await HostAdapter(h.runtime, model, state_directory=tmp_path / 'other').run(sid)


@pytest.mark.asyncio
async def test_committed_recovery_ack_lost_response_resumes_without_resetting_again(tmp_path, monkeypatch):
    h = build_harness(tmp_path / 'runtime')
    model = SendingModel()
    host = HostAdapter(h.runtime, model, state_directory=tmp_path / 'host')
    sid = (await host.create(h.request)).session_id
    await host.run(sid)
    ref = EvidenceRef.model_validate_json(canonical(h.runtime.store.all(sid, 'result')[0]['artifact_ref']))
    complete = h.runtime.complete_recovery

    async def lose_ack(req):
        await complete(req)
        raise ConnectionError('ACK response lost')

    monkeypatch.setattr(h.runtime, 'complete_recovery', lose_ack)
    with pytest.raises(ConnectionError):
        await host.recover(sid, [ref])
    assert h.runtime.session_view(sid).status == 'ACTIVE'
    monkeypatch.setattr(h.runtime, 'complete_recovery', complete)
    restored = HostAdapter(h.runtime, model, state_directory=tmp_path / 'host')
    with pytest.raises(RuntimeFault, match='HOST_RECOVERY_PENDING'):
        await restored.run(sid)
    plan, ack, view = await restored.resume_recovery(sid)
    assert view.status == 'ACTIVE' and model.resets == 1
    assert not (tmp_path / 'host' / sid / 'recovery.json').exists()
    with pytest.raises(RuntimeFault, match='RECOVERY_BINDING_MISMATCH'):
        await complete(ack.model_copy(update={'new_host_context_id': 'changed'}))
    await restored.run(sid)
    with pytest.raises(RuntimeFault, match='RECOVERY_BINDING_MISMATCH'):
        await complete(ack)


@pytest.mark.asyncio
@pytest.mark.parametrize('protection', ['confidentiality', 'destination_ids', 'allowed_uses', 'model_destination_ids'])
async def test_write_cannot_launder_restricted_context_into_public_resource(tmp_path, protection):
    h = build_harness(tmp_path)
    values = {'confidentiality': ['private'], 'destination_ids': ['user'],
              'allowed_uses': ['model', 'review', 'write'], 'model_destination_ids': ['agent', 'guard']}
    labels = public_labels('external').model_copy(update={protection: values[protection]})
    sid = (await h.session()).session_id
    ref = h.runtime.ingest(sid, 'PRIVATE_SOURCE', labels, resource_scope_ids=['docs'])
    _, out, batch = await h.run(sid, [proposal('write_report', {'resource': 'reports', 'body': 'PRIVATE_SOURCE'}, use='write')],
                              [make(Message, role='user', ref=ref)])
    result = batch.results[out.calls[0].call_id]
    assert result.status == 'BLOCKED' and result.reason_code == 'RESOURCE_LABEL_DOWNGRADE'
    assert h.effects == []


@pytest.mark.asyncio
async def test_write_to_host_protected_resource_retains_labels_on_next_session_read(tmp_path):
    h = build_harness(tmp_path)
    labels = public_labels('external').model_copy(update={'confidentiality': ['private']})
    catalog = h.request.resource_catalog
    h.request = h.request.model_copy(update={'resource_catalog': catalog.model_copy(update={
        'resources': [r.model_copy(update={'labels': labels}) if r.scope_id == 'reports' else r for r in catalog.resources]})})
    sid = (await h.session()).session_id
    ref = h.runtime.ingest(sid, 'PRIVATE_SOURCE', labels, resource_scope_ids=['docs'])
    _, out, batch = await h.run(sid, [proposal('write_report', {'resource': 'reports', 'body': 'PRIVATE_SOURCE'}, use='write')],
                              [make(Message, role='user', ref=ref)])
    assert batch.results[out.calls[0].call_id].status == 'RELEASED'
    sid2 = (await h.session()).session_id
    _, out, batch = await h.run(sid2, [proposal(args={'resource': 'reports'})])
    result = batch.results[out.calls[0].call_id]
    assert h.runtime.artifacts.metadata(sid2, result.artifact_ref).labels.confidentiality == ['private']


@pytest.mark.asyncio
async def test_synthetic_tool_cannot_expose_real_input_in_console_or_omitted_history(tmp_path):
    h = build_harness(tmp_path)
    h.request = h.request.model_copy(update={'synthetic_demo': True})
    entry = h.runtime.registry.get('write_report')
    h.runtime.registry.register(entry.manifest.model_copy(update={'manifest_version': 'v2'}), lambda resource, body: body)
    h.request = h.request.model_copy(update={'tool_manifests': h.runtime.registry.manifests()})
    sid = (await h.session()).session_id
    private = h.runtime.ingest(sid, 'NOT_SYNTHETIC_INPUT', public_labels(), synthetic_demo=False)
    _, out, batch = await h.run(sid, [proposal('write_report', {'resource': 'reports', 'body': 'NOT_SYNTHETIC_INPUT'}, use='write').model_copy(update={'manifest_version': 'v2'})],
                              [make(Message, role='user', ref=private)])
    ref = batch.results[out.calls[0].call_id].artifact_ref
    assert not h.runtime.artifacts.metadata(sid, ref).synthetic_demo
    _, derived = await h.propose(sid, content='NOT_SYNTHETIC_INPUT', messages=[])
    assert not h.runtime.artifacts.metadata(sid, derived.output_ref).synthetic_demo
    app = create_app(h.runtime, host_token='host', ui_token='ui', allow_synthetic_content=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test', headers={'Authorization': 'Bearer ui'}) as client:
        response = await client.get(f'/v2/sessions/{sid}/artifacts/{ref.artifact_id}/versions/1/comparison')
    assert response.status_code == 200 and 'NOT_SYNTHETIC_INPUT' not in response.text
    assert not response.json()['synthetic_content_visible']


@pytest.mark.parametrize('layout', ['inside', 'ancestor', 'extra_resource'])
def test_composition_rejects_state_exposed_to_tools_before_initialization(tmp_path, layout):
    from agentguard.v2.application import compose
    settings = {'workspace': str(tmp_path / 'workspace'), 'state_directory': str(tmp_path / 'private')}
    if layout == 'inside':
        settings['state_directory'] = str(tmp_path / 'workspace' / 'state')
    elif layout == 'ancestor':
        settings['state_directory'] = str(tmp_path)
    else:
        settings['resources'] = [{'kind': 'path', 'root': str(tmp_path / 'private' / 'quarantine')}]
    with pytest.raises(ValueError, match='disjoint'):
        compose(settings)
    assert not Path(settings['state_directory'], 'state.sqlite3').exists()


def test_remote_composition_does_not_create_local_runtime_database(tmp_path, monkeypatch):
    from agentguard.v2.application import compose, load_settings
    settings = load_settings('config/v2.example.json')
    settings['state_directory'] = str(tmp_path / 'private')
    monkeypatch.setenv('AGENTGUARD_V2_CLOUD_ENABLED', '1')
    monkeypatch.setenv('AGENTGUARD_GUARD_API_KEY', 'fixture')
    monkeypatch.setenv('AGENTGUARD_AGENT_API_KEY', 'fixture')
    remote = object()
    app = compose(settings, runtime=remote)
    assert app.runtime is remote
    assert not (tmp_path / 'private').exists()


@pytest.mark.asyncio
async def test_unexpected_gateway_exception_does_not_escape_to_server_logs(tmp_path, monkeypatch):
    h = build_harness(tmp_path)
    def fail(_):
        raise ValueError('PRIVATE_EXCEPTION_CONTENT')
    monkeypatch.setattr(h.runtime, 'session_view', fail)
    app = create_app(h.runtime, host_token='host', ui_token='ui')
    # ASGITransport defaults to raise_app_exceptions=True, like the server's
    # error logger. A sanitized response alone must not mask a re-raised error.
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        response = await client.get('/v2/sessions/test', headers={'Authorization': 'Bearer ui'})
    assert response.status_code == 503 and 'PRIVATE_EXCEPTION_CONTENT' not in response.text


@pytest.mark.asyncio
async def test_lost_recovery_plan_response_can_be_resumed(tmp_path, monkeypatch):
    h = build_harness(tmp_path / 'runtime')
    host = HostAdapter(h.runtime, SendingModel(), state_directory=tmp_path / 'host')
    sid = (await host.create(h.request)).session_id
    await host.run(sid)
    ref = EvidenceRef.model_validate_json(canonical(h.runtime.store.all(sid, 'result')[0]['artifact_ref']))
    prepare = h.runtime.prepare_recovery
    async def lose_plan(req):
        await prepare(req)
        raise ConnectionError('plan response lost')
    monkeypatch.setattr(h.runtime, 'prepare_recovery', lose_plan)
    with pytest.raises(ConnectionError):
        await host.recover(sid, [ref])
    assert h.runtime.session_view(sid).status == 'RECOVERING'
    monkeypatch.setattr(h.runtime, 'prepare_recovery', prepare)
    restored = HostAdapter(h.runtime, SendingModel(), state_directory=tmp_path / 'host')
    _, _, view = await restored.resume_recovery(sid)
    assert view.status == 'ACTIVE'
    assert len(h.runtime.store.all(sid, 'recovery')) == 1


def test_worker_lock_excludes_live_process_and_os_releases_after_crash(tmp_path):
    import os
    import subprocess
    import sys
    from agentguard.v2.state.ownership import exclusive_worker
    code = ('import sys\nfrom agentguard.v2.state.ownership import exclusive_worker\n'
            'with exclusive_worker(sys.argv[1]):\n print("owned",flush=True)\n sys.stdin.read()\n')
    worker = subprocess.Popen([sys.executable, '-c', code, str(tmp_path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    try:
        assert worker.stdout.readline().strip() == 'owned'
        with pytest.raises(RuntimeFault, match='RUNTIME_WORKER_ALREADY_RUNNING'):
            with exclusive_worker(tmp_path):
                pytest.fail('two active workers')
        worker.terminate()
        worker.wait(timeout=10)
        with exclusive_worker(tmp_path):
            pass
    finally:
        if worker.poll() is None:
            worker.kill()
            worker.wait(timeout=10)
        for stream in (worker.stdin, worker.stdout, worker.stderr):
            stream.close()


@pytest.mark.asyncio
async def test_gateway_startup_reconciles_abandoned_claim_under_worker_lock(tmp_path, monkeypatch):
    import sys
    from agentguard.v2.gateway import cli
    from agentguard.v2 import application
    from agentguard.v2.state.ownership import exclusive_worker
    h = build_harness(tmp_path)
    sid = (await h.session()).session_id
    _, out = await h.propose(sid, [proposal('send_report', {'destination': 'receiver', 'body': 'public'}, use='send')])
    permit = h.runtime.permits.issue(out.calls[0], [])
    h.runtime.permits.claim(permit, out.calls[0])
    h.runtime._begin_operation(sid, out.calls[0].input_context_version)
    monkeypatch.setattr(application, 'factory', lambda: h.runtime)
    monkeypatch.setenv('AGENTGUARD_HOST_TOKEN', 'host')
    monkeypatch.setenv('AGENTGUARD_UI_TOKEN', 'ui')
    monkeypatch.setattr(sys, 'argv', ['gateway', '--factory', 'agentguard.v2.application:factory'])
    def serve(*args, **kwargs):
        with h.runtime.store.connect() as conn:
            assert conn.execute('SELECT status FROM claims').fetchone()[0] == 'UNKNOWN'
        assert not h.runtime.store.all(sid, 'active_operation')
        with pytest.raises(RuntimeFault, match='RUNTIME_WORKER_ALREADY_RUNNING'):
            with exclusive_worker(tmp_path):
                pass
    monkeypatch.setattr(cli.uvicorn, 'run', serve)
    cli.main()
    result = await h.runtime.execute_call(out.calls[0])
    assert result.status == 'UNKNOWN' and h.effects == []


def test_long_experiment_audit_includes_events_after_first_page():
    from types import SimpleNamespace
    from benchmarks.v2.run import read_all_events
    events = [SimpleNamespace(seq=i) for i in range(1, 2014)]
    class Store:
        def events(self, sid, after, limit):
            return events[after:after + limit]
    assert read_all_events(Store(), 'session') == events


@pytest.mark.asyncio
async def test_sdk_session_cannot_expose_runtime_private_storage(tmp_path):
    h = build_harness(tmp_path / 'private')
    catalog = h.request.resource_catalog
    request = h.request.model_copy(update={'resource_catalog': catalog.model_copy(update={'resources': [
        make(ResourceScope, scope_id='docs', kind='path', root=str(tmp_path), labels=public_labels()),
        catalog.resources[1]]})})
    with pytest.raises(RuntimeFault, match='PRIVATE_STORAGE_EXPOSED'):
        await h.runtime.create_session(request)


@pytest.mark.asyncio
async def test_known_read_failure_allows_replanning_without_false_recovery(tmp_path):
    from agentguard.v2.application import workspace_tools
    from agentguard.v2.execution.executor import KnownToolFailure
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    tools = workspace_tools({'workspace': str(workspace), 'max_review_bytes': 8})
    with pytest.raises(KnownToolFailure):
        tools.get('read_text').handler(str(workspace / 'missing.txt'))
    large = workspace / 'large.txt'
    large.write_text('a' * 100, encoding='utf-8')
    with pytest.raises(KnownToolFailure, match='CONTENT_TOO_LARGE'):
        tools.get('read_text').handler(str(large))
    h = build_harness(tmp_path / 'runtime')
    def missing(resource):
        raise KnownToolFailure('FILE_MISSING')
    entry = h.runtime.registry.get('read_document')
    h.runtime.registry.register(entry.manifest.model_copy(update={'manifest_version': 'v2'}), missing)
    h.request = h.request.model_copy(update={'tool_manifests': h.runtime.registry.manifests()})
    class Agent(SendingModel):
        async def complete(self, prepared):
            self.calls += 1
            return AgentReply('', (proposal().model_copy(update={'manifest_version': 'v2'}),)) if self.calls == 1 else AgentReply('File unavailable')
    model = Agent()
    host = HostAdapter(h.runtime, model, recover_on_block=True)
    sid = (await host.create(h.request)).session_id
    assert (await host.run(sid)).status == 'RELEASED'
    assert model.resets == 0 and not h.runtime.store.all(sid, 'recovery')
