"""Recovery is a host handshake; plans do not undo external effects."""
from ..common import RuntimeFault, canonical, new_id, utcnow
from ..contracts import ContextSnapshot, EvidenceRef, RecoveryPlan, Receipt, make
from ..state.lineage import inherit

RESETS = ['messages', 'cloud_conversation', 'framework_checkpoints', 'memory', 'analysis_cache', 'work_products']


def prepare(runtime, req):
    sid = req.session_id
    with runtime.store.transaction() as conn:
        state, host, policy = runtime.active(sid, conn=conn)
        for ref in req.risk_refs:
            runtime.artifacts.whole_ref(sid, ref, conn)
        affected = runtime.lineage.closure(sid, req.risk_refs)
        keys = {(r.artifact_id, r.version) for r in affected}
        for ref in affected:
            runtime.artifacts.revoke(sid, ref, conn)
        # Every old-context authorization is unusable during recovery, including
        # independent calls; their released inputs can be reproposed after ACK.
        revoked = [r[0] for r in conn.execute("SELECT id FROM permits WHERE session=? AND status='APPROVED'", (sid,))]
        conn.execute("UPDATE permits SET status='REVOKED' WHERE session=? AND status='APPROVED'", (sid,))
        messages = []
        if state['context_version']:
            old = runtime.snapshot(sid, state['context_version'], conn)
            messages = [m for m in old.messages if (m.ref.artifact_id, m.ref.version) not in keys
                        and runtime.artifacts.is_released(sid, m.ref, conn)]
            model_destination = old.model_destination_id
        else:
            model_destination = host.host_policy.guard_destination_id
        # Preserve independent released work as evidence, with its original role.
        from ..contracts import Message
        existing = {(m.ref.artifact_id, m.ref.version) for m in messages}
        for row in conn.execute('SELECT a.meta FROM artifacts a JOIN artifact_status s USING(session,id,version) WHERE a.session=? AND s.released=1 AND s.revoked=0', (sid,)):
            from ..contracts import ArtifactVersion
            meta = ArtifactVersion.model_validate_json(row[0])
            key = (meta.artifact_id, meta.version)
            if key not in keys and key not in existing:
                messages.append(make(Message, role='tool' if meta.source_call_id else 'user', ref=runtime.artifacts.ref(meta)))
                existing.add(key)
        metas = [runtime.artifacts.metadata(sid, m.ref, conn) for m in messages]
        safe = make(ContextSnapshot, session_id=sid, turn_id=new_id('turn'), context_version=new_id('context'),
            messages=messages, policy_version=policy.policy_version, relevant_security_revision=state['security_revision']+1,
            unresolved_risks=[], model_destination_id=model_destination, labels=inherit(a.labels for a in metas),
            resource_scope_ids=sorted({s for a in metas for s in a.resource_scope_ids}))
        irreversible, unknown = [], []
        for row in conn.execute("SELECT p.data FROM permits p JOIN claims c ON c.permit_id=p.id WHERE c.session=? AND c.status='CLAIMED'", (sid,)):
            from ..contracts import Permit
            permit = Permit.model_validate_json(row[0])
            unknown.append(make(Receipt, receipt_id=new_id('receipt'), permit_id=permit.permit_id,
                session_id=sid, turn_id=permit.turn_id, call_id=permit.call_id, status='UNKNOWN',
                reason_code='IN_FLIGHT_AT_RECOVERY', effect_evidence={'dispatched': True, 'in_flight': True},
                artifact_ref=None, timestamp=utcnow()))
        for row in conn.execute('SELECT receipt FROM claims WHERE session=? AND receipt IS NOT NULL', (sid,)):
            receipt = Receipt.model_validate_json(row[0])
            call = runtime.store.get(sid, 'call', receipt.call_id, conn)
            manifest = next((m for m in host.tool_manifests if m.tool_id == call['tool_id']), None)
            if receipt.status == 'UNKNOWN':
                unknown.append(receipt)
            elif receipt.status == 'SUCCEEDED' and manifest and any(e in manifest.effects for e in ['SEND', 'WRITE', 'DELETE']):
                irreversible.append(receipt)
        plan = make(RecoveryPlan, session_id=sid, recovery_id=new_id('recovery'), affected_refs=affected,
            revoked_permit_ids=revoked, safe_context_version=safe.context_version, rebuild_messages=messages,
            required_host_resets=RESETS, irreversible_receipts=irreversible,
            irreversible_final_refs=[EvidenceRef.model_validate_json(canonical(f['artifact_ref']))
                for f in runtime.store.all(sid, 'final', conn) if f['status'] == 'RELEASED'],
            unknown_receipts=unknown)
        runtime.store.put(sid, 'context', safe.context_version, safe, conn)
        runtime.store.put(sid, 'recovery', plan.recovery_id, plan, conn)
        state.update(status='RECOVERING', recovery_id=plan.recovery_id,
            security_revision=state['security_revision']+1, risks=[r.model_dump(mode='json') for r in req.risk_refs])
        runtime.store.save_session(sid, state, conn)
        runtime.store.event(sid, 'RECOVERY_PREPARED', {'recovery_id': plan.recovery_id,
            'affected_count': len(affected), 'unknown_count': len(unknown)}, conn)
    return plan


def complete(runtime, ack):
    sid = ack.session_id
    with runtime.store.transaction() as conn:
        state = runtime.store.session(sid, conn)
        if state['status'] != 'RECOVERING' or state['recovery_id'] != ack.recovery_id:
            raise RuntimeFault('RECOVERY_BINDING_MISMATCH')
        plan = RecoveryPlan.model_validate_json(canonical(runtime.store.get(sid, 'recovery', ack.recovery_id, conn)))
        # Record actual incomplete ACKs for the console; never label them recovered.
        runtime.store.put(sid, 'recovery_ack_attempt', new_id('ack'), ack, conn)
        incomplete = ack.unsupported or set(ack.completed_resets) != set(plan.required_host_resets) or not all(ack.completed_resets.values())
        if state.get('host_context_id') == ack.new_host_context_id:
            incomplete = True
        if conn.execute("SELECT 1 FROM claims WHERE session=? AND status='CLAIMED'", (sid,)).fetchone():
            incomplete = True
        if runtime.store.all(sid, 'active_operation', conn):
            incomplete = True
        if incomplete:
            runtime.store.event(sid, 'RECOVERY_ACK_INCOMPLETE', {'recovery_id': ack.recovery_id}, conn)
        else:
            state.update(status='ACTIVE', context_version=plan.safe_context_version,
                host_context_id=ack.new_host_context_id, risks=[], recovery_id=None,
                carry_refs=[m.ref.model_dump(mode='json') for m in plan.rebuild_messages])
            runtime.store.save_session(sid, state, conn)
            runtime.store.put(sid, 'recovery_ack', ack.recovery_id, ack, conn)
            runtime.store.event(sid, 'RECOVERY_COMPLETED', {'recovery_id': ack.recovery_id}, conn)
    if incomplete:
        raise RuntimeFault('RECOVERY_ACK_INCOMPLETE')
    return runtime.session_view(sid)
