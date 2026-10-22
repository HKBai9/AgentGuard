"""AgentGuard v2 runtime: all effect and delivery paths converge here."""
from __future__ import annotations

import asyncio
from pydantic import ValidationError

from .common import RuntimeFault, canonical, digest, frozen_copy, new_id, strict_loads, utcnow, at_pointer, pointer_parts
from .contracts import *
from .registry import Catalog
from .policy.validator import validate_candidate
from .policy.engine import PolicyEngine
from .state.lineage import public_labels, inherit, exact_labels, check_use
from .execution.permits import Permits
from .execution.executor import dispatch, KnownToolFailure, ToolExecutionFailure, ToolResult
from .execution.batch import execute as execute_batch


def safe_code(code):
    # Model-controlled strings (even uppercase ones) can contain copied secrets.
    return code if code in {
        'NORMAL_CONTENT', 'CONTENT_SAFE', 'INJECTION_DETECTED', 'POLICY_VIOLATION',
        'EXTERNAL_TEXT_CHANGES_DESTINATION', 'FIELD_REDACTED', 'MISSING_EVIDENCE',
        'TASK_MISMATCH', 'UNTRUSTED_INSTRUCTION', 'SENSITIVE_CONTENT',
    } else 'GUARD_DECISION'


class Runtime:
    def __init__(self, *, store, artifacts, lineage, registry, policy_generator, guard_service):
        self.store, self.artifacts, self.lineage = store, artifacts, lineage
        self.registry, self.generator, self.guard = registry, policy_generator, guard_service
        self.engine = PolicyEngine(registry)
        self.permits = Permits(self)

    def session_view(self, sid):
        s = self.store.session(sid)
        return make(SessionView, session_id=sid, status=s['status'], policy_version=s['policy_version'],
                    context_version=s['context_version'], relevant_security_revision=s['security_revision'])

    def components(self, sid, conn=None):
        state = self.store.session(sid, conn)
        req = SessionRequest.model_validate_json(canonical(state['request']))
        policy = TaskPolicy.model_validate_json(canonical(self.store.get(sid, 'policy', state['policy_version'], conn)))
        return state, req, policy

    def active(self, sid, context_version=None, conn=None):
        state, req, policy = self.components(sid, conn)
        if state['status'] != 'ACTIVE':
            raise RuntimeFault('SESSION_NOT_ACTIVE')
        if context_version is not None and context_version != state['context_version']:
            raise RuntimeFault('STALE_CONTEXT')
        return state, req, policy

    def snapshot(self, sid, version, conn=None):
        raw = self.store.get(sid, 'context', version, conn)
        if raw is None:
            raise RuntimeFault('UNKNOWN_CONTEXT')
        return ContextSnapshot.model_validate_json(canonical(raw))

    def _begin_operation(self, sid, context_version):
        operation_id = new_id('operation')
        with self.store.transaction() as conn:
            self.active(sid, context_version, conn)
            self.store.put(sid, 'active_operation', operation_id, {'context_version': context_version}, conn)
        return operation_id

    def _end_operation(self, sid, operation_id):
        with self.store.transaction() as conn:
            conn.execute("DELETE FROM records WHERE session=? AND kind='active_operation' AND id=?", (sid, operation_id))

    async def create_session(self, req):
        req = frozen_copy(SessionRequest, req)
        from pathlib import Path
        private_roots = (self.store.path.parent.resolve(), self.artifacts.directory.resolve())
        for resource in req.resource_catalog.resources:
            if resource.kind == 'path':
                root = Path(resource.root).resolve()
                if any(root.is_relative_to(private) or private.is_relative_to(root) for private in private_roots):
                    raise RuntimeFault('PRIVATE_STORAGE_EXPOSED', 422)
        if len({m.tool_id for m in req.tool_manifests}) != len(req.tool_manifests):
            raise RuntimeFault('DUPLICATE_TOOL', 422)
        for manifest in req.tool_manifests:
            if self.registry.get(manifest.tool_id, manifest.manifest_version).manifest != manifest:
                raise RuntimeFault('TOOL_NOT_HOST_CONFIRMED')
        reviewer = getattr(self.guard, 'reviewer', None)
        client = getattr(reviewer, 'client', None)
        if client is not None and hasattr(client, 'config'):
            from .review.reviewers import authorize_destination
            try:
                authorize_destination(req.model_dump(mode='json'), client)
            except Exception:
                raise RuntimeFault('MODEL_DESTINATION_DENIED') from None
        sid = new_id('session')
        generation = make(PolicyGenerationRequest, session_id=sid, trusted_task=req.trusted_task,
            host_policy=req.host_policy, tool_manifests=req.tool_manifests, resource_catalog=req.resource_catalog,
            confirmed_authorizations=req.confirmed_authorizations, current_policy_version=None)
        if self.generator is None or self.guard is None:
            raise RuntimeFault('SERVICE_UNAVAILABLE', 503)
        try:
            candidate = await asyncio.wait_for(self.generator.generate(generation), req.host_policy.review_timeout_seconds)
        except asyncio.TimeoutError:
            raise RuntimeFault('MODEL_TIMEOUT', 503) from None
        except Exception:
            raise RuntimeFault('POLICY_GENERATION_FAILED', 503) from None
        policy = validate_candidate(candidate, generation, self.registry)
        if candidate.evidence_refs:
            raise RuntimeFault('INVALID_REFERENCE')
        with self.store.transaction() as conn:
            task = self.artifacts.create(sid, req.trusted_task, public_labels('trusted_user'), synthetic_demo=req.synthetic_demo, conn=conn)
            task_ref = self.artifacts.ref(task)
            self.artifacts.release(sid, task_ref, conn)
            self.store.save_session(sid, {'request': req.model_dump(mode='json'), 'status': 'ACTIVE',
                'policy_version': policy.policy_version, 'context_version': None, 'security_revision': 0,
                'task_ref': task_ref.model_dump(mode='json'), 'carry_refs': [], 'risks': [], 'recovery_id': None}, conn)
            self.store.put(sid, 'policy', policy.policy_version, policy, conn)
            for index, item in enumerate(getattr(self.generator, 'usage_records', [])):
                if item.get('session_id') == sid:
                    self.store.put(sid, 'policy_usage', 'policy_'+str(index), item['usage'], conn)
            self.store.event(sid, 'SESSION_CREATED', {}, conn)
        return self.session_view(sid)

    async def apply_policy(self, candidate):
        candidate = frozen_copy(PolicyCandidate, candidate)
        sid = candidate.session_id
        with self.store.transaction() as conn:
            state, req, current = self.active(sid, conn=conn)
            generation = make(PolicyGenerationRequest, session_id=sid, trusted_task=req.trusted_task,
                host_policy=req.host_policy, tool_manifests=req.tool_manifests, resource_catalog=req.resource_catalog,
                confirmed_authorizations=req.confirmed_authorizations, current_policy_version=current.policy_version)
            policy = validate_candidate(candidate, generation, self.registry, current)
            for ref in candidate.evidence_refs:
                self.artifacts.read(sid, ref, conn=conn)
            self.store.put(sid, 'policy', policy.policy_version, policy, conn)
            state.update(policy_version=policy.policy_version, security_revision=state['security_revision']+1)
            self.store.save_session(sid, state, conn)
            conn.execute("UPDATE permits SET status='REVOKED' WHERE session=? AND status='APPROVED'", (sid,))
            self.store.event(sid, 'POLICY_COMMITTED', {'change_kind': policy.change_kind}, conn)
        return policy

    def ingest(self, sid, content, labels, *, resource_scope_ids=(), media_type='text/plain', synthetic_demo=False):
        """Trusted HOST input registration, never a model or UI capability."""
        _, req, _ = self.active(sid)
        labels = frozen_copy(DataLabels, labels)
        if not set(resource_scope_ids) <= Catalog(req.resource_catalog).resources.keys():
            raise RuntimeFault('UNKNOWN_RESOURCE')
        with self.store.transaction() as conn:
            meta = self.artifacts.create(sid, content, labels, resource_scope_ids=resource_scope_ids,
                media_type=media_type, synthetic_demo=synthetic_demo, conn=conn)
            self.artifacts.release(sid, self.artifacts.ref(meta), conn)
            self.store.event(sid, 'HOST_INPUT_REGISTERED', {'artifact_id': meta.artifact_id}, conn)
        return self.artifacts.ref(meta)

    async def register_host_input(self, req):
        req = frozen_copy(HostInputRequest, req)
        return self.ingest(req.session_id, req.content, req.labels, resource_scope_ids=req.resource_scope_ids,
            media_type=req.media_type, synthetic_demo=req.synthetic_demo)

    async def clear_analysis_cache(self, session_id):
        self.store.session(session_id)
        if hasattr(self.guard, 'clear_session'):
            self.guard.clear_session(session_id)
        return True

    async def prepare_model_turn(self, req):
        req = frozen_copy(PrepareTurnRequest, req)
        sid = req.session_id
        with self.store.transaction() as conn:
            state, host, policy = self.active(sid, conn=conn)
            if conn.execute("SELECT 1 FROM claims WHERE session=? AND status='CLAIMED'", (sid,)).fetchone():
                raise RuntimeFault('BATCH_BARRIER_PENDING')
            if self.store.all(sid, 'active_operation', conn):
                raise RuntimeFault('BATCH_BARRIER_PENDING')
            messages = list(req.messages)
            task_ref = EvidenceRef.model_validate_json(canonical(state['task_ref']))
            if not any(m.ref == task_ref for m in messages):
                messages.insert(0, make(Message, role='user', ref=task_ref))
            metas, prepared = [], []
            for msg in messages:
                meta = self.artifacts.whole_ref(sid, msg.ref, conn)
                content = self.artifacts.read(sid, msg.ref, released=True, conn=conn)
                if msg.role == 'system' and meta.labels.integrity != ['host']:
                    raise RuntimeFault('UNTRUSTED_SYSTEM_MESSAGE')
                metas.append(meta)
                prepared.append(make(PreparedMessage, role=msg.role, content=content, ref=msg.ref))
            # Sticky dependencies survive omitted history and model-side summaries.
            carry = [EvidenceRef.model_validate_json(canonical(r)) for r in state['carry_refs']]
            unique = {(r.artifact_id, r.version): r for r in carry + [m.ref for m in messages]}
            carry_metas = [self.artifacts.whole_ref(sid, r, conn) for r in unique.values()]
            for ref in unique.values():
                if not self.artifacts.is_released(sid, ref, conn):
                    raise RuntimeFault('REVOKED_CONTEXT_INPUT')
            self.engine.model(req.model_destination_id, policy, host, carry_metas)
            context = make(ContextSnapshot, session_id=sid, turn_id=new_id('turn'), context_version=new_id('context'),
                messages=messages, policy_version=policy.policy_version, relevant_security_revision=state['security_revision'],
                unresolved_risks=[EvidenceRef.model_validate_json(canonical(r)) for r in state['risks']],
                model_destination_id=req.model_destination_id, labels=inherit(a.labels for a in carry_metas),
                resource_scope_ids=sorted({s for a in carry_metas for s in a.resource_scope_ids}))
            model_id = new_id('model')
            self.store.put(sid, 'context', context.context_version, context, conn)
            self.store.put(sid, 'model_call', model_id, {'context_version': context.context_version, 'turn_id': context.turn_id,
                'input_refs': [r.model_dump(mode='json') for r in unique.values()]}, conn)
            state.update(context_version=context.context_version, carry_refs=[r.model_dump(mode='json') for r in unique.values()])
            self.store.save_session(sid, state, conn)
            self.store.event(sid, 'MODEL_TURN_PREPARED', {'model_call_id': model_id, 'input_count': len(messages)}, conn, turn_id=context.turn_id)
        return make(PreparedTurn, session_id=sid, turn_id=context.turn_id, model_call_id=model_id,
            context_version=context.context_version, messages=prepared, model_destination_id=req.model_destination_id)

    async def record_model_output(self, req):
        req = frozen_copy(ModelOutputRequest, req)
        sid = req.session_id
        with self.store.transaction() as conn:
            state, host, policy = self.active(sid, req.context_version, conn)
            model = self.store.get(sid, 'model_call', req.model_call_id, conn)
            if model is None or model['context_version'] != req.context_version:
                raise RuntimeFault('MODEL_CALL_BINDING_MISMATCH')
            prior = self.store.get(sid, 'model_output', req.model_call_id, conn)
            if prior is not None:
                if prior['request_digest'] != digest(req):
                    raise RuntimeFault('MODEL_OUTPUT_CHANGED')
                return ProposedTurn.model_validate_json(canonical(prior['proposal']))
            context = self.snapshot(sid, req.context_version, conn)
            if context.policy_version != policy.policy_version or context.relevant_security_revision != state['security_revision']:
                raise RuntimeFault('STALE_CONTEXT')
            output = self.artifacts.create(sid, req.content, context.labels.model_copy(update={'integrity': sorted(set(context.labels.integrity+['model']))}),
                resource_scope_ids=context.resource_scope_ids,
                synthetic_demo=host.synthetic_demo and all(self.artifacts.metadata(sid,
                    EvidenceRef.model_validate_json(canonical(r)), conn).synthetic_demo for r in model['input_refs']), conn=conn)
            output_ref = self.artifacts.ref(output)
            event = self.store.event(sid, 'MODEL_OUTPUT_RECORDED', {'artifact_id': output.artifact_id}, conn, turn_id=context.turn_id)
            for raw in model['input_refs']:
                self.lineage.add(sid, EvidenceRef.model_validate_json(canonical(raw)), output_ref, 'possible', event.event_id, conn)
            calls = []
            for proposal in req.tool_proposals:
                call = make(ToolCall, session_id=sid, turn_id=context.turn_id, call_id=new_id('call'),
                    input_context_version=context.context_version, **proposal.model_dump(exclude={'schema_version'}))
                action = self.artifacts.create(sid, {'tool_id': call.tool_id, 'manifest_version': call.manifest_version,
                    'args': call.args}, output.labels, media_type='application/json',
                    source_call_id=call.call_id, resource_scope_ids=context.resource_scope_ids,
                    synthetic_demo=output.synthetic_demo, conn=conn)
                action_ref = self.artifacts.ref(action)
                self.store.put(sid, 'call', call.call_id, call, conn)
                self.store.put(sid, 'action_ref', call.call_id, action_ref, conn)
                self.lineage.add(sid, output_ref, action_ref, 'possible', event.event_id, conn)
                calls.append(call)
            proposed = make(ProposedTurn, session_id=sid, turn_id=context.turn_id, output_ref=output_ref, calls=calls)
            self.store.put(sid, 'model_output', req.model_call_id, {'request_digest': digest(req), 'proposal': proposed.model_dump(mode='json')}, conn)
            if req.usage:
                self.store.put(sid, 'model_usage', req.model_call_id, req.usage, conn)
            self.store.put(sid, 'output_binding', output.artifact_id, {'turn_id': context.turn_id, 'context_version': context.context_version}, conn)
        return proposed

    def action_state(self, call, conn=None):
        state, host, policy = self.active(call.session_id, call.input_context_version, conn)
        saved = self.store.get(call.session_id, 'call', call.call_id, conn)
        if saved is None or canonical(saved) != canonical(call):
            raise RuntimeFault('CALL_BINDING_MISMATCH')
        context = self.snapshot(call.session_id, call.input_context_version, conn)
        if context.turn_id != call.turn_id or context.policy_version != policy.policy_version or context.relevant_security_revision != state['security_revision']:
            raise RuntimeFault('STALE_CONTEXT')
        return state, host, policy, context

    def action_facts(self, call, host, policy, context, conn=None):
        manifest = self.registry.get(call.tool_id, call.manifest_version).manifest
        catalog = Catalog(host.resource_catalog)
        destination = catalog.destination(at_pointer(call.args, manifest.destination_parameter)) if manifest.destination_parameter else None
        metas = []
        token_ids = {t.ref_id for t in call.artifact_refs}
        if len(token_ids) != len(call.artifact_refs):
            raise RuntimeFault('DUPLICATE_ARTIFACT_CAPABILITY')
        mapped = set()
        for pointer, use in manifest.artifact_parameters.items():
            token_id = at_pointer(call.args, pointer)
            token = next((t for t in call.artifact_refs if t.ref_id == token_id), None)
            if token is None or use != call.use:
                raise RuntimeFault('ARTIFACT_CAPABILITY_REQUIRED')
            mapped.add(token_id)
        if mapped != token_ids:
            raise RuntimeFault('UNBOUND_ARTIFACT_CAPABILITY')
        for token in call.artifact_refs:
            metas.append(self.artifacts.resolve_ref(call.session_id, token, call.use, call.tool_id, destination, catalog, conn))
        facts = self.engine.action(call, policy, host, context, metas)
        return facts, metas

    def _material(self, sid, turn_id, call_id, phase, subject_ref, context_version):
        state, host, policy = self.active(sid, context_version)
        context = self.snapshot(sid, context_version)
        if policy.policy_version != context.policy_version or state['security_revision'] != context.relevant_security_revision:
            raise RuntimeFault('STALE_CONTEXT')
        task_ref = EvidenceRef.model_validate_json(canonical(state['task_ref']))
        refs = self.lineage.closure(sid, [subject_ref], reverse=True)
        risk_refs = [EvidenceRef.model_validate_json(canonical(r)) for r in state['risks']]
        required_keys = {(r.artifact_id, r.version) for r in [task_ref, *refs, *risk_refs]}
        history = [EvidenceRef.model_validate_json(canonical(r)) for r in self.store.all(sid, 'action_ref')]
        history += [EvidenceRef.model_validate_json(canonical(o['proposal']['output_ref']))
                    for o in self.store.all(sid, 'model_output')]
        with self.store.connect() as conn:
            # Audits and arbitrary host-private blobs are not review history.
            history += [self.artifacts.ref(ArtifactVersion.model_validate_json(r[0])) for r in conn.execute(
                'SELECT meta FROM artifacts WHERE session=? ORDER BY rowid', (sid,))
                if strict_loads(r[0])['source_call_id'] is not None]
        unique = {(r.artifact_id, r.version): r for r in [*history, task_ref, *refs, *risk_refs]}
        evidence = []
        evidence_resources = []
        for ref in unique.values():
            meta = self.artifacts.whole_ref(sid, ref)
            # Guard itself is a data destination and never gets an implicit exemption.
            try:
                self.engine.model(host.host_policy.guard_destination_id, policy, host, [meta], use='review')
            except RuntimeFault:
                if (ref.artifact_id, ref.version) in required_keys:
                    raise
                continue
            evidence.append(make(EvidenceBlock, ref=ref, content=self.artifacts.read(sid, ref), labels=meta.labels,
                role='subject' if ref == subject_ref else ('task' if ref == task_ref else 'related')))
            evidence_resources.append({'ref': ref.model_dump(mode='json'), 'resource_scope_ids': meta.resource_scope_ids})
        subject = self.artifacts.read(sid, subject_ref)
        facts = {'labels': self.artifacts.metadata(sid, subject_ref).labels.model_dump(mode='json'),
            'source_labels': [{'ref': e.ref.model_dump(mode='json'), 'labels': e.labels.model_dump(mode='json')} for e in evidence],
            'unresolved_risks': state['risks'], 'ancestor_refs': [r.model_dump(mode='json') for r in refs],
            'evidence_resources': evidence_resources,
            'resource_scope_ids': context.resource_scope_ids, 'tool_id': None, 'use': None, 'destination_id': None}
        if call_id:
            saved = self.store.get(sid, 'call', call_id)
            call = ToolCall.model_validate_json(canonical(saved))
            manifest = self.registry.get(call.tool_id, call.manifest_version).manifest
            facts.update(tool_id=call.tool_id, use=call.use, manifest_version=call.manifest_version,
                destination_id=Catalog(host.resource_catalog).destination(at_pointer(call.args, manifest.destination_parameter)) if manifest.destination_parameter else None)
        keys = set(unique)
        return make(ContextMaterial, session_id=sid, turn_id=turn_id, call_id=call_id, review_id=new_id('review'), phase=phase,
            trusted_task=host.trusted_task, task_ref=task_ref, policy=policy, host_policy=host.host_policy,
            context_version=context_version, relevant_security_revision=state['security_revision'], subject_ref=subject_ref,
            subject=subject, mandatory_facts=facts, evidence=evidence,
            lineage=[e for e in self.lineage.edges(sid) if (e.target_ref.artifact_id, e.target_ref.version) in keys],
            recent_events=[e.model_dump(mode='json') for e in self.store.events(sid,
                max(0, self._event_count(sid)-12), 12)], supplemental_attempt=0,
            allowed_transform_ids=sorted(self.artifacts.transforms),
            available_evidence_refs=[e.ref for e in evidence])

    def _event_count(self, sid):
        with self.store.connect() as conn:
            return conn.execute('SELECT COALESCE(MAX(seq),0) FROM events WHERE session=?', (sid,)).fetchone()[0]

    def _validate_decision(self, decision, material):
        bindings = ['review_id', 'session_id', 'turn_id', 'call_id', 'phase', 'context_version', 'subject_ref']
        if any(getattr(decision, name) != getattr(material, name) for name in bindings) or decision.policy_version != material.policy.policy_version:
            raise RuntimeFault('INVALID_REFERENCE')
        allowed = {(e.ref.artifact_id, e.ref.version, e.ref.sha256) for e in material.evidence}
        def validate(ref, positioned=False):
            if (ref.artifact_id, ref.version, ref.sha256) not in allowed or (positioned and ref.span is None and ref.json_pointer is None):
                raise RuntimeFault('INVALID_REFERENCE')
            self.artifacts.read(material.session_id, ref)
        for ref in decision.evidence_refs:
            validate(ref)
        if decision.decision != 'NEEDS_CONTEXT' and not any((r.artifact_id, r.version, r.sha256) ==
            (material.subject_ref.artifact_id, material.subject_ref.version, material.subject_ref.sha256) for r in decision.evidence_refs):
            raise RuntimeFault('INVALID_REFERENCE')
        for finding in decision.findings:
            for ref in finding.evidence_refs:
                validate(ref, positioned=True)
            if finding.affected_action_field is not None:
                if material.call_id is None:
                    raise RuntimeFault('INVALID_REFERENCE')
                call = self.store.get(material.session_id, 'call', material.call_id)
                at_pointer(call['args'], finding.affected_action_field)
        if decision.decision == 'REDACT':
            if material.phase == 'ACTION' or not decision.redaction_targets:
                raise RuntimeFault('INVALID_REFERENCE')
        elif decision.redaction_targets:
            raise RuntimeFault('INVALID_REFERENCE')
        for target in decision.redaction_targets:
            validate(target.evidence_ref, positioned=True)
        if decision.decision != 'NEEDS_CONTEXT' and decision.requested_evidence_refs:
            raise RuntimeFault('INVALID_REFERENCE')
        for ref in decision.requested_evidence_refs:
            # Existing session evidence only, no URLs, tools, files or cross-session reads.
            if ref not in material.available_evidence_refs:
                raise RuntimeFault('INVALID_REFERENCE')
            self.artifacts.read(material.session_id, ref)

    async def inspect(self, sid, turn_id, call_id, phase, subject_ref, context_version):
        try:
            material = self._material(sid, turn_id, call_id, phase, subject_ref, context_version)
        except RuntimeFault as exc:
            self.store.event(sid, 'REVIEW_FAILED', {'reason_code': exc.code}, turn_id=turn_id, call_id=call_id)
            return None, exc.code
        for attempt in range(2):
            failure = None
            outcome = None
            if (not getattr(self.guard, 'supports_context_budgeting', False) and
                    len(canonical(material).encode('utf-8')) > material.host_policy.max_review_bytes):
                failure = 'CONTENT_TOO_LARGE'
            elif self.guard is None:
                failure = 'SERVICE_UNAVAILABLE'
            else:
                try:
                    value = await asyncio.wait_for(self.guard.inspect(frozen_copy(ContextMaterial, material)), material.host_policy.review_timeout_seconds)
                    outcome = frozen_copy(ReviewOutcome, value)
                    if outcome.status == 'FAILED':
                        failure = outcome.failure.reason_code
                    else:
                        self._validate_decision(outcome.decision, material)
                except asyncio.TimeoutError:
                    failure = 'MODEL_TIMEOUT'
                except RuntimeFault as exc:
                    failure = 'INVALID_REFERENCE' if exc.code == 'INVALID_REFERENCE' else 'INVALID_SCHEMA'
                except ValidationError:
                    failure = 'INVALID_SCHEMA'
                except Exception:
                    failure = 'SERVICE_UNAVAILABLE'
            trace = self.guard.take_trace(material.review_id, attempt) if hasattr(self.guard, 'take_trace') else None
            with self.store.transaction() as conn:
                usage = (outcome.decision.usage if outcome and outcome.decision and not failure else
                         outcome.failure.usage if outcome and outcome.failure else None)
                if usage is None and trace and trace.get('usage'):
                    usage = Usage.model_validate_json(canonical(trace['usage']))
                # Complete material/outcome live in the private immutable vault;
                # the console only sees IDs, positions and numeric usage.
                audit_labels = inherit([e.labels for e in material.evidence])
                audit = self.artifacts.create(sid, {'material': material.model_dump(mode='json'),
                    'outcome': outcome.model_dump(mode='json') if outcome else None, 'failure': failure,
                    'actual_request': trace},
                    audit_labels, media_type='application/json', conn=conn)
                # UI receives only this allowlisted summary, never free-form model text.
                summary = {'review_id': material.review_id, 'phase': phase, 'attempt': attempt,
                    'status': 'FAILED' if failure else 'DECIDED',
                    'decision': outcome.decision.decision if outcome and outcome.decision and not failure else None,
                    'reason_code': failure or safe_code(outcome.decision.reason_code),
                    'usage': usage.model_dump(mode='json', exclude={'provider', 'model'}) if usage else None,
                    'evidence_refs': (trace['request']['selected_evidence_refs'] if trace else
                        [e.ref.model_dump(mode='json') for e in material.evidence]),
                    'prompt_bytes': trace['request']['budget_used'] if trace else None,
                    'cache_hit': trace['cache_hit'] if trace else False,
                    'submitted': trace['submitted'] if trace else False,
                    'audit_ref': self.artifacts.ref(audit).model_dump(mode='json')}
                self.store.put(sid, 'review', material.review_id, summary, conn, replace=True)
                self.store.put(sid, 'review_attempt', material.review_id+':'+str(attempt), summary, conn)
                self.store.event(sid, 'REVIEW_FAILED' if failure else 'REVIEW_DECIDED',
                    {k: summary[k] for k in ('status', 'decision', 'reason_code', 'attempt')}, conn,
                    turn_id=turn_id, call_id=call_id, review_id=material.review_id)
            if failure:
                return None, failure
            decision = outcome.decision
            if decision.decision != 'NEEDS_CONTEXT':
                return decision, safe_code(decision.reason_code)
            if attempt == 1 or not decision.requested_evidence_refs:
                return None, 'MISSING_EVIDENCE'
            extra = list(material.evidence)
            _, host, _ = self.components(sid)
            try:
                for ref in decision.requested_evidence_refs:
                    meta = self.artifacts.metadata(sid, ref)
                    self.engine.model(host.host_policy.guard_destination_id, material.policy, host, [meta], use='review')
                    whole = self.artifacts.ref(meta)
                    if not any(e.ref == whole for e in extra):
                        extra.append(make(EvidenceBlock, ref=whole, content=self.artifacts.read(sid, whole), labels=meta.labels, role='related'))
            except RuntimeFault:
                return None, 'MISSING_EVIDENCE'
            material = material.model_copy(update={'supplemental_attempt': 1, 'evidence': extra,
                'mandatory_facts': {**material.mandatory_facts,
                    'requested_evidence_refs': [r.model_dump(mode='json') for r in decision.requested_evidence_refs]}})
        return None, 'MISSING_EVIDENCE'

    def _decision_risks(self, sid, decision):
        if decision is None or decision.decision != 'BLOCK':
            return []
        cited = [r for f in decision.findings for r in f.evidence_refs]
        subject = (decision.subject_ref.artifact_id, decision.subject_ref.version)
        origins = [r for r in cited if (r.artifact_id, r.version) != subject and
                   set(self.artifacts.metadata(sid, r).labels.integrity) & {'external', 'model'}]
        # When ACTION/FINAL locates only the derived subject, model provenance
        # cannot identify one causal token. Conservatively rebase all released
        # external ancestors; the host never treats this as an exact dependency.
        if not origins and decision.phase in ('ACTION', 'FINAL'):
            for ref in self.lineage.closure(sid, [decision.subject_ref], reverse=True):
                meta = self.artifacts.metadata(sid, ref)
                if 'external' in meta.labels.integrity and self.artifacts.is_released(sid, ref):
                    origins.append(ref)
        if not origins:
            origins = [decision.subject_ref]
        unique = {}
        for ref in origins:
            whole = self.artifacts.ref(self.artifacts.metadata(sid, ref))
            unique[(whole.artifact_id, whole.version)] = whole
        return list(unique.values())

    def _result(self, call, status, code, *, content=None, ref=None, receipt=None, risk_refs=()):
        return make(CallResult, session_id=call.session_id, turn_id=call.turn_id, call_id=call.call_id,
            status=status, reason_code=code, content=content, artifact_ref=ref, receipt=receipt, risk_refs=list(risk_refs))

    async def execute_batch(self, req):
        req = frozen_copy(BatchRequest, req)
        self.active(req.session_id, req.context_version)
        context = self.snapshot(req.session_id, req.context_version)
        if context.turn_id != req.turn_id:
            raise RuntimeFault('BATCH_BINDING_MISMATCH')
        operation = self._begin_operation(req.session_id, req.context_version)
        try:
            return await execute_batch(self, req)
        finally:
            self._end_operation(req.session_id, operation)

    async def execute_call(self, call):
        call = frozen_copy(ToolCall, call)
        try:
            operation = self._begin_operation(call.session_id, call.input_context_version)
        except RuntimeFault as exc:
            if exc.code == 'SESSION_NOT_FOUND':
                raise
            return self._result(call, 'BLOCKED', exc.code)
        try:
            return await self._execute_call_guarded(call)
        finally:
            self._end_operation(call.session_id, operation)

    async def _execute_call_guarded(self, call):
        try:
            return await self._execute_call(call)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # A local failure after claiming (including storage faults) must never
            # make a non-idempotent operation eligible for another dispatch.
            with self.store.connect() as conn:
                row = conn.execute('SELECT p.data,c.status,c.receipt FROM claims c JOIN permits p ON p.id=c.permit_id WHERE c.session=? AND c.call_id=?',
                    (call.session_id, call.call_id)).fetchone()
            if row and row['status'] == 'CLAIMED':
                with self.store.transaction() as conn:
                    receipt = self.permits.finish(Permit.model_validate_json(row['data']), 'UNKNOWN', 'EXECUTION_RECORD_FAILED', None, conn)
                return self._result(call, 'UNKNOWN', 'EXECUTION_RECORD_FAILED', receipt=receipt)
            if row:
                receipt = Receipt.model_validate_json(row['receipt']) if row['receipt'] else None
                return self._result(call, 'UNKNOWN' if row['status'] == 'UNKNOWN' else 'REVIEW_PENDING', 'RESULT_RECORD_FAILED', receipt=receipt)
            if isinstance(exc, RuntimeFault):
                raise exc from None
            raise RuntimeFault('SERVICE_UNAVAILABLE', 503) from None

    async def _execute_call(self, call):
        call = frozen_copy(ToolCall, call)
        sid = call.session_id
        try:
            state, host, policy, context = self.action_state(call)
            self.action_facts(call, host, policy, context)
            with self.store.connect() as conn:
                claimed = conn.execute('SELECT status,receipt FROM claims WHERE session=? AND call_id=?', (sid, call.call_id)).fetchone()
            if claimed:
                receipt = Receipt.model_validate_json(claimed['receipt']) if claimed['receipt'] else None
                saved = self.store.get(sid, 'result', call.call_id)
                if saved:
                    result = CallResult.model_validate_json(canonical(saved))
                    if result.artifact_ref and not self.artifacts.is_released(sid, result.artifact_ref):
                        return self._result(call, 'BLOCKED', 'ARTIFACT_REVOKED', receipt=receipt)
                    if result.artifact_ref:
                        self.artifacts.read(sid, result.artifact_ref, released=True)
                    return result
                return self._result(call, 'UNKNOWN' if claimed['status'] == 'UNKNOWN' else 'REVIEW_PENDING',
                    'EXECUTION_OUTCOME_UNKNOWN' if claimed['status'] == 'UNKNOWN' else 'CALL_ALREADY_CLAIMED', receipt=receipt)
            action_ref = EvidenceRef.model_validate_json(canonical(self.store.get(sid, 'action_ref', call.call_id)))
            facts, bound_inputs = self.action_facts(call, host, policy, context)
            if bound_inputs:
                with self.store.transaction() as conn:
                    self.action_state(call, conn)
                    event = self.store.event(sid, 'ACTION_INPUTS_BOUND', {'input_count': len(bound_inputs)}, conn,
                        turn_id=call.turn_id, call_id=call.call_id)
                    for meta in bound_inputs:
                        self.lineage.add(sid, self.artifacts.ref(meta), action_ref, 'possible', event.event_id, conn)
            decision, code = await self.inspect(sid, call.turn_id, call.call_id, 'ACTION', action_ref, call.input_context_version)
            if decision is None or decision.decision != 'ALLOW':
                return self._result(call, 'REVIEW_PENDING' if decision is None else 'BLOCKED', code,
                    risk_refs=self._decision_risks(sid, decision))
            # A fresh state read after the model wait prevents stale approvals.
            _, host, policy, context = self.action_state(call)
            facts, metas = self.action_facts(call, host, policy, context)
            permit = self.permits.issue(call, [self.artifacts.ref(a) for a in metas])
            # Bind the reviewed security state, not whichever state arrived during inspection.
            if permit.policy_version != decision.policy_version or permit.context_version != decision.context_version:
                raise RuntimeFault('STALE_REVIEW')
            facts = self.permits.claim(permit, call)
        except RuntimeFault as exc:
            if exc.code == 'SESSION_NOT_FOUND':
                raise
            self.store.event(sid, 'CALL_BLOCKED', {'reason_code': exc.code}, turn_id=call.turn_id, call_id=call.call_id)
            return self._result(call, 'BLOCKED', exc.code)
        entry = self.registry.get(call.tool_id, call.manifest_version)
        args = strict_loads(canonical(call.args))
        for pointer in entry.manifest.artifact_parameters:
            token = next(t for t in call.artifact_refs if t.ref_id == at_pointer(args, pointer))
            meta = next(a for a in metas if a.artifact_id == token.artifact_id and a.version == token.version)
            value = self.artifacts.read(sid, self.artifacts.ref(meta))
            parts = pointer_parts(pointer)
            if len(parts) != 1:
                # Registration rejects nested injection points; avoid changing unchecked structures.
                raise RuntimeFault('INVALID_ARTIFACT_PARAMETER')
            args[parts[0]] = value
        status, code, media = 'SUCCEEDED', 'TOOL_SUCCEEDED', entry.manifest.return_media_type
        try:
            raw = await dispatch(entry.handler, args)
            if isinstance(raw, ToolResult):
                if raw.stderr is not None:
                    raw, media = {'content': raw.content, 'stderr': raw.stderr}, 'application/json'
                else:
                    raw = raw.content
            canonical(raw)
            if media == 'text/plain' and not isinstance(raw, str):
                raise TypeError('invalid tool result')
        except asyncio.CancelledError:
            with self.store.transaction() as conn:
                self.permits.finish(permit, 'UNKNOWN', 'EXECUTION_CANCELLED', None, conn)
            raise
        except Exception as exc:
            raw = exc.payload if isinstance(exc, ToolExecutionFailure) else {'error_type': type(exc).__name__, 'error': str(exc)}
            media = 'application/json'
            status = 'FAILED_KNOWN' if isinstance(exc, KnownToolFailure) else 'UNKNOWN'
            code = 'TOOL_FAILED_BEFORE_EFFECT' if status == 'FAILED_KNOWN' else 'TOOL_OUTCOME_UNKNOWN'
        labels = exact_labels([facts.labels, entry.manifest.output_labels,
            *[Catalog(host.resource_catalog).resources[s].labels for s in facts.scope_ids]])
        scopes = sorted(set(facts.scope_ids + context.resource_scope_ids + [s for a in metas for s in a.resource_scope_ids]))
        with self.store.transaction() as conn:
            # A synthetic tool may echo real task/model input. Visibility follows
            # every sticky dependency, not just the tool's fixture declaration.
            synthetic = host.synthetic_demo and entry.manifest.synthetic_demo and all(
                self.artifacts.metadata(sid, EvidenceRef.model_validate_json(canonical(r)), conn).synthetic_demo
                for r in state['carry_refs']) and all(a.synthetic_demo for a in metas)
            meta = self.artifacts.create(sid, raw, labels, media_type=media, source_call_id=call.call_id,
                resource_scope_ids=scopes, synthetic_demo=synthetic, conn=conn)
            ref = self.artifacts.ref(meta)
            event = self.store.event(sid, 'RESULT_QUARANTINED', {'artifact_id': meta.artifact_id, 'version': meta.version}, conn,
                turn_id=call.turn_id, call_id=call.call_id)
            self.lineage.add(sid, action_ref, ref, 'possible', event.event_id, conn)
            for art in metas:
                self.lineage.add(sid, self.artifacts.ref(art), ref, 'possible', event.event_id, conn)
            receipt = self.permits.finish(permit, status, code, ref, conn)
        if status != 'SUCCEEDED':
            result = self._result(call, status, code, receipt=receipt)
        else:
            decision, code = await self.inspect(sid, call.turn_id, call.call_id, 'RESULT', ref, call.input_context_version)
            if decision is None or decision.decision == 'BLOCK':
                result = self._result(call, 'REVIEW_PENDING' if decision is None else 'BLOCKED', code, receipt=receipt,
                    risk_refs=self._decision_risks(sid, decision))
            else:
                try:
                    released, content = self._release(sid, ref, decision, call.input_context_version, final=False)
                    result = self._result(call, 'RELEASED', code, content=content, ref=released, receipt=receipt)
                except RuntimeFault as exc:
                    result = self._result(call, 'BLOCKED', exc.code, receipt=receipt)
        with self.store.transaction() as conn:
            self.store.put(sid, 'result', call.call_id, result, conn)
        return result

    def _release(self, sid, ref, decision, version, *, final):
        with self.store.transaction() as conn:
            state, host, policy = self.active(sid, version, conn)
            context = self.snapshot(sid, version, conn)
            if decision.policy_version != policy.policy_version or context.relevant_security_revision != state['security_revision']:
                raise RuntimeFault('STALE_REVIEW')
            release_key = ref.artifact_id+':'+str(ref.version)+('::final' if final else '::result')
            prior = self.store.get(sid, 'release', release_key, conn)
            if prior:
                target = EvidenceRef.model_validate_json(canonical(prior))
                return target, self.artifacts.read(sid, target, released=True, conn=conn)
            meta = self.artifacts.metadata(sid, ref, conn)
            if decision.decision == 'REDACT':
                meta = self.artifacts.redact(sid, ref, decision.redaction_targets, conn)
                target = self.artifacts.ref(meta)
                event = self.store.event(sid, 'ARTIFACT_REDACTED', {'artifact_id': meta.artifact_id, 'version': meta.version,
                    'targets': [t.model_dump(mode='json') for t in decision.redaction_targets]}, conn)
                self.lineage.add(sid, ref, target, 'exact', event.event_id, conn)
            elif decision.decision != 'ALLOW':
                raise RuntimeFault('CONTENT_NOT_APPROVED')
            if final:
                check_use(meta.labels, host.host_policy.final_use, host.host_policy.final_destination_id, catalog=Catalog(host.resource_catalog))
            else:
                self.engine.model(context.model_destination_id, policy, host, [meta])
            target = self.artifacts.ref(meta)
            self.artifacts.release(sid, target, conn)
            content = self.artifacts.read(sid, target, released=True, conn=conn)
            self.store.put(sid, 'release', release_key, target, conn)
            self.store.event(sid, 'FINAL_RELEASED' if final else 'RESULT_RELEASED',
                {'artifact_id': target.artifact_id, 'version': target.version}, conn, turn_id=context.turn_id, review_id=decision.review_id)
        return target, content

    async def finalize(self, req):
        req = frozen_copy(FinalizeRequest, req)
        operation = self._begin_operation(req.session_id, req.context_version)
        try:
            return await self._finalize(req)
        finally:
            self._end_operation(req.session_id, operation)

    async def _finalize(self, req):
        state, host, policy = self.active(req.session_id, req.context_version)
        context = self.snapshot(req.session_id, req.context_version)
        if context.policy_version != policy.policy_version or context.relevant_security_revision != state['security_revision']:
            raise RuntimeFault('STALE_CONTEXT')
        binding = self.store.get(req.session_id, 'output_binding', req.output_ref.artifact_id)
        if context.turn_id != req.turn_id or binding != {'turn_id': req.turn_id, 'context_version': req.context_version}:
            raise RuntimeFault('FINAL_BINDING_MISMATCH')
        self.artifacts.whole_ref(req.session_id, req.output_ref)
        prior = self.store.get(req.session_id, 'final', req.output_ref.artifact_id)
        if prior:
            result = FinalizedOutput.model_validate_json(canonical(prior))
            if result.artifact_ref and self.artifacts.is_released(req.session_id, result.artifact_ref):
                self.artifacts.read(req.session_id, result.artifact_ref, released=True)
                return result
            raise RuntimeFault('FINAL_ALREADY_REVIEWED')
        decision, code = await self.inspect(req.session_id, req.turn_id, None, 'FINAL', req.output_ref, req.context_version)
        content = target = None
        status = 'REVIEW_PENDING' if decision is None else 'BLOCKED'
        if decision is not None and decision.decision in ('ALLOW', 'REDACT'):
            try:
                target, content = self._release(req.session_id, req.output_ref, decision, req.context_version, final=True)
                status = 'RELEASED'
            except RuntimeFault as exc:
                code = exc.code
        result = make(FinalizedOutput, session_id=req.session_id, status=status, reason_code=code, content=content, artifact_ref=target,
            risk_refs=self._decision_risks(req.session_id, decision))
        with self.store.transaction() as conn:
            if self.store.get(req.session_id, 'final', req.output_ref.artifact_id, conn) is None:
                self.store.put(req.session_id, 'final', req.output_ref.artifact_id, result, conn)
        return result

    async def prepare_recovery(self, req):
        from .recovery.checkpoints import prepare
        return prepare(self, frozen_copy(RecoveryRequest, req))

    async def complete_recovery(self, req):
        from .recovery.checkpoints import complete
        return complete(self, frozen_copy(RecoveryAck, req))
