"""RuntimePort over the authenticated gateway. Never dispatch tools client-side."""
from ..common import RuntimeFault, canonical
from ..contracts import (SessionView, PreparedTurn, ProposedTurn, BatchResult,
    FinalizedOutput, RecoveryPlan, EvidenceRef)


class GatewayRuntime:
    def __init__(self, base_url, host_token, *, timeout=150, client=None):
        from urllib.parse import urlsplit
        address = urlsplit(base_url)
        if (address.scheme not in ('http', 'https') or not address.hostname or address.username or
                address.password or address.query or address.fragment or
                (address.scheme == 'http' and address.hostname not in ('127.0.0.1', 'localhost', '::1'))):
            raise ValueError('Use HTTPS or a loopback gateway')
        if not host_token:
            raise ValueError('Host token required')
        import httpx
        self.client = client or httpx.AsyncClient(base_url=base_url.rstrip('/'), timeout=timeout,
            follow_redirects=False, trust_env=False)
        self.token = host_token

    async def _post(self, path, value, cls=None):
        response = await self.client.post(path, content=canonical(value),
            headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        if response.status_code != 200:
            # Only consume the finite error envelope; no raw server errors reach callers.
            from ..common import strict_loads
            try:
                code = strict_loads(response.content)['reason_code']
                if not isinstance(code, str) or not code.isascii() or len(code) > 80:
                    raise ValueError()
            except Exception:
                code = 'GATEWAY_UNAVAILABLE'
            raise RuntimeFault(code)
        if len(response.content) > 8 * 1024 * 1024:
            raise RuntimeFault('CONTENT_TOO_LARGE')
        return cls.model_validate_json(response.content) if cls else response.json()

    def _path(self, req, suffix):
        from urllib.parse import quote
        return '/v2/sessions/' + quote(req.session_id, safe='') + '/' + suffix

    async def create_session(self, req):
        return await self._post('/v2/sessions', req, SessionView)

    async def register_host_input(self, req):
        return await self._post(self._path(req, 'host-inputs'), req, EvidenceRef)

    async def prepare_model_turn(self, req):
        return await self._post(self._path(req, 'model-turns/prepare'), req, PreparedTurn)

    async def record_model_output(self, req):
        return await self._post(self._path(req, 'model-outputs'), req, ProposedTurn)

    async def execute_batch(self, req):
        return await self._post(self._path(req, 'batches'), req, BatchResult)

    async def finalize(self, req):
        return await self._post(self._path(req, 'finalize'), req, FinalizedOutput)

    async def prepare_recovery(self, req):
        return await self._post(self._path(req, 'recovery-plans'), req, RecoveryPlan)

    async def complete_recovery(self, req):
        return await self._post(self._path(req, 'recovery-acks'), req, SessionView)

    async def clear_analysis_cache(self, session_id):
        from urllib.parse import quote
        result = await self._post('/v2/sessions/' + quote(session_id, safe='') + '/analysis-cache/reset', {})
        return result.get('cleared') is True

    async def aclose(self):
        await self.client.aclose()
