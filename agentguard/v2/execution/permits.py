"""Durable authorization commit point. No remote work inside transactions."""
from datetime import timedelta
import sqlite3
from ..common import RuntimeFault, canonical, digest, new_id, utcnow
from ..contracts import Permit, Receipt, make


class Permits:
    def __init__(self, runtime):
        self.runtime = runtime
        self.store = runtime.store

    def issue(self, call, refs):
        with self.store.transaction() as conn:
            state, req, policy, context = self.runtime.action_state(call, conn)
            permit = make(Permit, permit_id=new_id('permit'), session_id=call.session_id,
                turn_id=call.turn_id, call_id=call.call_id, tool_id=call.tool_id,
                tool_manifest_version=call.manifest_version, args_digest=digest(call.args),
                artifact_versions=refs, policy_version=policy.policy_version,
                context_version=context.context_version, relevant_security_revision=state['security_revision'],
                expires_at=utcnow()+timedelta(seconds=req.host_policy.permit_ttl_seconds), status='APPROVED')
            conn.execute('INSERT INTO permits VALUES(?,?,?,?,?)',
                (permit.permit_id, call.session_id, call.call_id, permit.status, canonical(permit)))
            self.store.event(call.session_id, 'PERMIT_APPROVED', {'permit_id': permit.permit_id, 'permit': permit.model_dump(mode='json')}, conn,
                turn_id=call.turn_id, call_id=call.call_id)
        return permit

    def claim(self, permit, call):
        try:
            return self._claim(permit, call)
        except RuntimeFault as exc:
            if exc.code == 'PERMIT_EXPIRED':
                with self.store.transaction() as conn:
                    changed = conn.execute("UPDATE permits SET status='EXPIRED' WHERE id=? AND status='APPROVED'", (permit.permit_id,)).rowcount
                    if changed:
                        self.store.event(permit.session_id, 'PERMIT_EXPIRED', {'permit_id': permit.permit_id}, conn,
                            turn_id=permit.turn_id, call_id=permit.call_id)
            raise

    def _claim(self, permit, call):
        # Always use the immutable server copy; callers cannot mint their own permit.
        with self.store.transaction() as conn:
            row = conn.execute('SELECT status,data FROM permits WHERE id=?', (permit.permit_id,)).fetchone()
            if row is None or canonical(permit) != row['data'] or row['status'] != 'APPROVED':
                raise RuntimeFault('PERMIT_NOT_APPROVED')
            if permit.expires_at <= utcnow():
                raise RuntimeFault('PERMIT_EXPIRED')
            state, req, policy, context = self.runtime.action_state(call, conn)
            bindings = (call.session_id, call.turn_id, call.call_id, call.tool_id, call.manifest_version,
                        digest(call.args), policy.policy_version, context.context_version, state['security_revision'])
            expected = (permit.session_id, permit.turn_id, permit.call_id, permit.tool_id, permit.tool_manifest_version,
                        permit.args_digest, permit.policy_version, permit.context_version, permit.relevant_security_revision)
            if bindings != expected:
                raise RuntimeFault('PERMIT_BINDING_CHANGED')
            facts, artifacts = self.runtime.action_facts(call, req, policy, context, conn)
            refs = [self.runtime.artifacts.ref(a) for a in artifacts]
            if canonical(refs_to_json(refs)) != canonical(refs_to_json(permit.artifact_versions)):
                raise RuntimeFault('ARTIFACT_VERSION_CHANGED')
            for ref in refs:
                self.runtime.artifacts.read(call.session_id, ref, released=True, conn=conn)
            if conn.execute('SELECT 1 FROM claims WHERE session=? AND call_id=?', (call.session_id, call.call_id)).fetchone():
                raise RuntimeFault('CALL_ALREADY_CLAIMED')
            manifest = self.runtime.registry.get(call.tool_id, call.manifest_version).manifest
            if any(e in manifest.effects for e in ('WRITE', 'DELETE')):
                # Host catalog root identities serialize shared mutations across sessions/workers.
                from ..registry import Catalog
                from pathlib import Path
                catalog = Catalog(req.resource_catalog)
                locks = ['path:'+str(Path(catalog.resources[s].root).resolve()) if catalog.resources[s].kind == 'path'
                         else 'logical:'+catalog.resources[s].root for s in facts.scope_ids]
                if not locks:
                    locks = ['tool:'+call.tool_id]
                existing = [r[0] for r in conn.execute('SELECT resource FROM resource_locks')]
                for key in locks:
                    for held in existing:
                        overlap = key == held
                        if key.startswith('path:') and held.startswith('path:'):
                            a, b = Path(key[5:]), Path(held[5:])
                            overlap = a.is_relative_to(b) or b.is_relative_to(a)
                        if overlap:
                            raise RuntimeFault('RESOURCE_BUSY')
                try:
                    for key in sorted(set(locks)):
                        conn.execute('INSERT INTO resource_locks VALUES(?,?,?)', (key, call.session_id, call.call_id))
                except sqlite3.IntegrityError:
                    raise RuntimeFault('RESOURCE_BUSY') from None
            for key in facts.rule_keys:
                rule = next(r for r in policy.rules if r.tool_id+':'+r.effect == key)
                used = conn.execute('SELECT used FROM quotas WHERE session=? AND rule_key=?', (call.session_id, key)).fetchone()
                if (used[0] if used else 0) >= rule.max_calls:
                    raise RuntimeFault('QUOTA_EXHAUSTED')
                conn.execute('INSERT INTO quotas VALUES(?,?,1) ON CONFLICT(session,rule_key) DO UPDATE SET used=used+1', (call.session_id, key))
            conn.execute('INSERT INTO claims VALUES(?,?,?,?,NULL)', (call.session_id, call.call_id, permit.permit_id, 'CLAIMED'))
            conn.execute("UPDATE permits SET status='CLAIMED' WHERE id=?", (permit.permit_id,))
            self.store.event(call.session_id, 'PERMIT_CLAIMED', {'permit_id': permit.permit_id,
                'permit': permit.model_copy(update={'status': 'CLAIMED'}).model_dump(mode='json')}, conn, turn_id=call.turn_id, call_id=call.call_id)
        return facts

    def finish(self, permit, status, reason_code, artifact_ref, conn):
        receipt = make(Receipt, receipt_id=new_id('receipt'), permit_id=permit.permit_id,
            session_id=permit.session_id, turn_id=permit.turn_id, call_id=permit.call_id,
            status=status, reason_code=reason_code, effect_evidence={'dispatched': True},
            artifact_ref=artifact_ref, timestamp=utcnow())
        changed = conn.execute("UPDATE claims SET status=?,receipt=? WHERE session=? AND call_id=? AND status='CLAIMED'",
            (status, canonical(receipt), permit.session_id, permit.call_id)).rowcount
        if changed != 1:
            raise RuntimeFault('RECEIPT_ALREADY_RECORDED')
        conn.execute('UPDATE permits SET status=? WHERE id=?', (status, permit.permit_id))
        if status != 'UNKNOWN':
            conn.execute('DELETE FROM resource_locks WHERE session=? AND call_id=?', (permit.session_id, permit.call_id))
        self.store.event(permit.session_id, 'EXECUTION_'+status, {'permit_id': permit.permit_id, 'reason_code': reason_code,
            'receipt': receipt.model_dump(mode='json')}, conn,
            turn_id=permit.turn_id, call_id=permit.call_id)
        return receipt

    def recover_abandoned(self):
        """Host startup operation ONLY after exclusive worker ownership is established."""
        with self.store.transaction() as conn:
            rows = conn.execute("SELECT p.data FROM permits p JOIN claims c ON p.id=c.permit_id WHERE c.status='CLAIMED'").fetchall()
            for row in rows:
                permit = Permit.model_validate_json(row[0])
                self.finish(permit, 'UNKNOWN', 'WORKER_LOST_AFTER_CLAIM', None, conn)
            conn.execute("DELETE FROM records WHERE kind='active_operation'")
        return len(rows)


def refs_to_json(refs):
    return [r.model_dump(mode='json') for r in refs]
