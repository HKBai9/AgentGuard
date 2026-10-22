"""Authenticated host writes and a separate metadata-only console boundary."""
import hmac
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from ..common import RuntimeFault, canonical, strict_loads, frozen_copy
from ..contracts import *


def create_app(runtime, *, host_token: str, ui_token: str, allow_synthetic_content=False):
    if not host_token or not ui_token or host_token == ui_token:
        raise ValueError('Distinct nonempty host and UI credentials are required')
    app = FastAPI(title='AgentGuard v2', version='0.1', docs_url=None, redoc_url=None, openapi_url=None)
    request_schemas = {}

    @app.middleware('http')
    async def contain_unexpected_errors(request, call_next):
        # Starlette's outer error handler re-raises after sending a response,
        # which lets the server print exception text containing private values.
        try:
            return await call_next(request)
        except Exception:
            return JSONResponse({'schema_version': '0.1', 'reason_code': 'SERVICE_UNAVAILABLE'}, status_code=503)

    def body_schema(cls):
        schema = cls.model_json_schema(ref_template='#/components/schemas/{model}')
        request_schemas.update(schema.pop('$defs', {}))
        request_schemas[cls.__name__] = schema
        return {'$ref': '#/components/schemas/'+cls.__name__}

    def authorize(request, write=False):
        auth = request.headers.get('authorization', '')
        if not auth.startswith('Bearer '):
            raise RuntimeFault('AUTHENTICATION_REQUIRED', 401)
        token = auth[7:]
        if write and not hmac.compare_digest(token, host_token):
            raise RuntimeFault('HOST_PERMISSION_REQUIRED', 403)
        if not write and not (hmac.compare_digest(token, host_token) or hmac.compare_digest(token, ui_token)):
            raise RuntimeFault('INVALID_CREDENTIAL', 401)

    @app.exception_handler(RuntimeFault)
    async def fault(request, exc):
        return JSONResponse({'schema_version': '0.1', 'reason_code': exc.code}, status_code=exc.http_status)

    @app.exception_handler(RequestValidationError)
    async def invalid(request, exc):
        return JSONResponse({'schema_version': '0.1', 'reason_code': 'INVALID_SCHEMA'}, status_code=422)

    @app.exception_handler(Exception)
    async def unavailable(request, exc):
        return JSONResponse({'schema_version': '0.1', 'reason_code': 'SERVICE_UNAVAILABLE'}, status_code=503)

    async def body(request, cls, sid=None):
        authorize(request, write=True)
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > 4 * 1024 * 1024:
                raise RuntimeFault('CONTENT_TOO_LARGE', 422)
            chunks.append(chunk)
        raw = b''.join(chunks)
        value = frozen_copy(cls, strict_loads(raw))
        if sid is not None and value.session_id != sid:
            raise RuntimeFault('SESSION_BINDING_MISMATCH')
        return value

    def add_write(path, cls, method, response):
        async def endpoint(request: Request, id: str):
            return await method(await body(request, cls, id))
        endpoint.__name__ = method.__name__
        app.add_api_route('/v2/sessions/{id}/'+path, endpoint, methods=['POST'], response_model=response,
            openapi_extra={'requestBody': {'required': True, 'content': {'application/json': {'schema': body_schema(cls)}}}})

    @app.post('/v2/sessions', response_model=SessionView,
              openapi_extra={'requestBody': {'required': True, 'content': {'application/json': {'schema': body_schema(SessionRequest)}}}})
    async def create(request: Request):
        return await runtime.create_session(await body(request, SessionRequest))

    for path, cls, method, response in [
        ('host-inputs', HostInputRequest, runtime.register_host_input, EvidenceRef),
        ('model-turns/prepare', PrepareTurnRequest, runtime.prepare_model_turn, PreparedTurn),
        ('model-outputs', ModelOutputRequest, runtime.record_model_output, ProposedTurn),
        ('batches', BatchRequest, runtime.execute_batch, BatchResult),
        ('finalize', FinalizeRequest, runtime.finalize, FinalizedOutput),
        ('recovery-plans', RecoveryRequest, runtime.prepare_recovery, RecoveryPlan),
        ('recovery-acks', RecoveryAck, runtime.complete_recovery, SessionView)]:
        add_write(path, cls, method, response)

    @app.post('/v2/sessions/{id}/analysis-cache/reset')
    async def reset_cache(id: str, request: Request):
        authorize(request, write=True)
        return {'schema_version': '0.1', 'cleared': await runtime.clear_analysis_cache(id)}

    @app.get('/v2/openapi.json')
    async def openapi(request: Request):
        authorize(request)
        return app.openapi()

    @app.get('/v2/sessions/{id}')
    async def session(id: str, request: Request):
        authorize(request)
        return runtime.session_view(id)

    @app.get('/v2/sessions')
    async def sessions(request: Request, offset: int = 0, limit: int = 100):
        authorize(request)
        if offset < 0 or not 1 <= limit <= 1000:
            raise RuntimeFault('INVALID_PAGINATION', 422)
        with runtime.store.connect() as conn:
            ids = [r[0] for r in conn.execute('SELECT id FROM sessions ORDER BY rowid DESC LIMIT ? OFFSET ?', (limit, offset))]
        return [runtime.session_view(sid) for sid in ids]

    @app.get('/v2/sessions/{id}/reviews')
    async def reviews(id: str, request: Request):
        authorize(request)
        runtime.session_view(id)
        return runtime.store.all(id, 'review_attempt')

    @app.get('/v2/sessions/{id}/events')
    async def events(id: str, request: Request, after_seq: int = 0, limit: int = 100):
        authorize(request)
        return runtime.store.events(id, after_seq, limit)

    @app.get('/v2/sessions/{id}/policy')
    async def policy(id: str, request: Request):
        authorize(request)
        _, _, policy = runtime.components(id)
        # Rationale may contain sensitive copied task text; only finite grants here.
        return policy.model_dump(exclude={'rationale', 'unresolved_requirements', 'evidence_refs'})

    @app.get('/v2/sessions/{id}/graph')
    async def graph(id: str, request: Request):
        authorize(request)
        runtime.session_view(id)
        return {'schema_version': '0.1', 'edges': runtime.lineage.edges(id)}

    @app.get('/v2/sessions/{id}/reviews/{review_id}')
    async def review(id: str, review_id: str, request: Request):
        authorize(request)
        runtime.session_view(id)
        value = runtime.store.get(id, 'review', review_id)
        if value is None:
            raise RuntimeFault('REVIEW_NOT_FOUND', 404)
        return value

    @app.get('/v2/sessions/{id}/reviews/{review_id}/input')
    async def review_input(id: str, review_id: str, request: Request, attempt: int = 0):
        authorize(request)
        runtime.session_view(id)
        summary = runtime.store.get(id, 'review_attempt', review_id+':'+str(attempt))
        if summary is None:
            raise RuntimeFault('REVIEW_NOT_FOUND', 404)
        ref = EvidenceRef.model_validate_json(canonical(summary['audit_ref']))
        audit = runtime.artifacts.read(id, ref)
        trace = audit.get('actual_request')
        if trace is None:
            return {'schema_version': '0.1', 'available': False, 'reason_code': 'NO_ACTUAL_REQUEST'}
        material = ContextMaterial.model_validate_json(canonical(audit['material']))
        _, host, _ = runtime.components(id)
        raw = bool(allow_synthetic_content and host.synthetic_demo and all(
            runtime.artifacts.metadata(id, b.ref).synthetic_demo for b in material.evidence))
        result = {'schema_version': '0.1', 'available': True, 'synthetic_content_visible': raw,
            'prompt_version': trace['prompt_version'], 'submitted': trace['submitted'],
            'cache_hit': trace['cache_hit'], 'budget_used': trace['request']['budget_used'],
            'selected_evidence_refs': trace['request']['selected_evidence_refs'],
            'retained_security_facts': {k: material.mandatory_facts[k] for k in
                ('labels', 'source_labels', 'unresolved_risks', 'ancestor_refs')},
            'messages': trace['messages'] if raw else [dict(role=m['role'], content='[REDACTED]') for m in trace['messages']]}
        if raw:
            result['request'] = trace['request']
        return result

    @app.get('/v2/sessions/{id}/metrics')
    async def metrics(id: str, request: Request):
        authorize(request)
        runtime.session_view(id)
        with runtime.store.connect() as conn:
            states = {r[0]: r[1] for r in conn.execute('SELECT status,COUNT(*) FROM claims WHERE session=? GROUP BY status', (id,))}
        return {'schema_version': '0.1', 'executions': states,
            'reviews': len(runtime.store.all(id, 'review')), 'review_attempts': len(runtime.store.all(id, 'review_attempt')),
            'usage': [r['usage'] for r in runtime.store.all(id, 'review_attempt')],
            'model_usage': runtime.store.all(id, 'model_usage'),
            'policy_usage': runtime.store.all(id, 'policy_usage'),
            'recovery_plans': runtime.store.all(id, 'recovery'), 'recovery_acks': runtime.store.all(id, 'recovery_ack_attempt')}

    @app.get('/v2/sessions/{id}/artifacts')
    async def artifacts(id: str, request: Request):
        authorize(request)
        runtime.session_view(id)
        with runtime.store.connect() as conn:
            metas = [ArtifactVersion.model_validate_json(r[0]) for r in
                conn.execute('SELECT meta FROM artifacts WHERE session=? ORDER BY rowid', (id,))]
        return [dict(artifact_id=m.artifact_id, version=m.version, sha256=m.sha256,
                     source_call_id=m.source_call_id, labels=m.labels.model_dump(mode='json'),
                     synthetic_demo=m.synthetic_demo, released=runtime.artifacts.is_released(id, runtime.artifacts.ref(m))) for m in metas]

    @app.get('/v2/sessions/{id}/artifacts/{artifact_id}/versions/{version}/comparison')
    async def comparison(id: str, artifact_id: str, version: int, request: Request):
        authorize(request)
        runtime.session_view(id)
        with runtime.store.connect() as conn:
            row = conn.execute('SELECT meta FROM artifacts WHERE session=? AND id=? AND version=?', (id, artifact_id, version)).fetchone()
        if not row:
            raise RuntimeFault('ARTIFACT_NOT_FOUND', 404)
        meta = ArtifactVersion.model_validate_json(row[0])
        visible = bool(allow_synthetic_content and meta.synthetic_demo)
        with runtime.store.connect() as conn:
            versions = [ArtifactVersion.model_validate_json(r[0]) for r in conn.execute(
                'SELECT meta FROM artifacts WHERE session=? AND id=? ORDER BY version', (id, artifact_id))]
        return {'schema_version': '0.1', 'artifact_id': meta.artifact_id, 'version': meta.version, 'sha256': meta.sha256,
            'released': runtime.artifacts.is_released(id, runtime.artifacts.ref(meta)),
            'synthetic_content_visible': visible,
            'content': runtime.artifacts.read(id, runtime.artifacts.ref(meta)) if visible else '[REDACTED]',
            'versions': [{'version': m.version, 'sha256': m.sha256,
                'released': runtime.artifacts.is_released(id, runtime.artifacts.ref(m)),
                'content': runtime.artifacts.read(id, runtime.artifacts.ref(m)) if allow_synthetic_content and m.synthetic_demo else '[REDACTED]'} for m in versions]}

    original_openapi = app.openapi
    def complete_openapi():
        result = original_openapi()
        result.setdefault('components', {}).setdefault('schemas', {}).update(request_schemas)
        return result
    app.openapi = complete_openapi
    return app
