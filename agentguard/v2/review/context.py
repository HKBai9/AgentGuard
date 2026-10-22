"""Deterministic selection. Security facts and the current object are indivisible."""
from copy import deepcopy
from .boundary import PublicContracts, dumps, payload, versioned
from .evidence import evidence_index, identity
from .prompts import review_messages


class ContextBuilder:
    def __init__(self, *, contracts=None, max_bytes=96_000, strategy="relations",
                 recent_n=8, max_events=12, summary_chars=160):
        self.contracts = contracts if contracts is not None else PublicContracts()
        if type(max_bytes) is not int or max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        if strategy not in {"all", "recent", "relations"}:
            raise ValueError("Unknown context strategy")
        if any(type(n) is not int or n < 0 for n in (recent_n, max_events, summary_chars)):
            raise ValueError("Invalid context limits")
        self.max_bytes = max_bytes
        self.strategy, self.recent_n = strategy, recent_n
        self.max_events, self.summary_chars = max_events, summary_chars

    def build(self, material):
        data = versioned(self.contracts.parse("ContextMaterial", payload(material)))
        facts = data['mandatory_facts']
        if any(facts.get(k) is None for k in ("labels", "source_labels", "unresolved_risks", "ancestor_refs")):
            return self._incomplete("MISSING_EVIDENCE", [])
        evidence_index(data)
        for ref in data["available_evidence_refs"]:
            identity(ref)
        blocks = data['evidence']
        by_id = {identity(b['ref']): b for b in blocks}
        pinned = {identity(data['subject_ref']), identity(data['task_ref'])}
        pinned.update(identity(r) for r in facts['unresolved_risks'])
        pinned.update(identity(r) for r in facts.get('requested_evidence_refs', []))
        if not pinned <= by_id.keys():
            return self._incomplete('MISSING_EVIDENCE', [data['subject_ref']])
        chosen = [b for b in blocks if identity(b['ref']) in pinned]
        others = [b for b in blocks if identity(b['ref']) not in pinned]
        current = identity(data['subject_ref'])
        parents = {identity(e['source_ref']) for e in data['lineage'] if identity(e['target_ref']) == current}
        data['retained_mandatory_facts'] = deepcopy(facts)
        events = deepcopy(data['recent_events'][-self.max_events:]) if self.max_events else []

        def assemble(selected, summaries=True):
            # data is already an owned JSON copy. Do not copy the entire dense
            # historical DAG for every candidate body in the greedy selector.
            result = dict(data)
            ids = {identity(b['ref']) for b in selected}
            omitted = [b for b in blocks if identity(b['ref']) not in ids]
            result['evidence'] = selected
            result['selected_evidence_refs'] = [b['ref'] for b in selected]
            # Preserve real direct edges around the subject/parents/risks. The
            # complete DAG remains in Runtime; ancestor identities and all
            # restrictions stay in mandatory_facts. Never invent shortcut edges
            # or upgrade a possible dependency into exact causality.
            result['lineage'] = data['lineage'] if self.strategy=='all' else [e for e in data['lineage'] if
                identity(e['target_ref'])==current or
                (identity(e['target_ref']) in parents | pinned and identity(e['source_ref']) in ids)]
            # Excerpts are untrusted, incomplete data, never synthetic evidence
            # with the full object's hash. All labels/lineage remain mandatory.
            result['recent_events'] = events + [{
                'kind': 'context_selection', 'strategy': self.strategy,
                'selected': len(selected), 'omitted': len(omitted),
                'lineage_edges_retained':len(result['lineage']),
                'lineage_edges_omitted':len(data['lineage'])-len(result['lineage']),
                'history_summaries': [{'source_ref': b['ref'], 'labels': b['labels'],
                    'authoritative': False, 'complete': False,
                    'excerpt': (b['content'] if isinstance(b['content'], str) else dumps(b['content']))[:self.summary_chars]}
                    for b in omitted[-self.recent_n:]] if summaries and self.summary_chars and self.recent_n else [],
            }]
            result['budget_used'] = 0
            for _ in range(5):
                size = len(dumps(review_messages(result)).encode('utf-8'))
                if size == result['budget_used']:
                    break
                result['budget_used'] = size
            return result

        limit = min(self.max_bytes, data['host_policy']['max_review_bytes'])
        if assemble(chosen, False)['budget_used'] > limit:
            return self._incomplete("CONTENT_TOO_LARGE", [data["subject_ref"]])
        if self.strategy == 'all':
            result = assemble(blocks, False)
            if result['budget_used'] > limit:
                return self._incomplete('CONTENT_TOO_LARGE', [data['subject_ref']])
        else:
            if self.strategy == 'recent':
                ranked = list(reversed(others[-self.recent_n:])) if self.recent_n else []
            else:
                scopes = {identity(item['ref']): set(item['resource_scope_ids'])
                          for item in facts.get('evidence_resources', [])}
                current_scopes = scopes.get(identity(data['subject_ref']), set()) | set(facts.get('resource_scope_ids', []))
                ranked = [b for _, b in sorted(enumerate(others), key=lambda pair: (
                    identity(pair[1]['ref']) in parents,
                    bool(scopes.get(identity(pair[1]['ref']), set()) & current_scopes),
                    pair[1]['labels'] == facts['labels'], pair[0]), reverse=True)]
            for block in ranked:
                if assemble(chosen + [block], False)['budget_used'] <= limit:
                    chosen.append(block)
            result = assemble(chosen)
            if result['budget_used'] > limit:
                result = assemble(chosen, False)
        request = self.contracts.parse("ReviewRequest", result)
        return self.contracts.parse("ContextBuildResult", {
            "schema_version": "0.1", "status": "READY", "request": payload(request),
            "missing_evidence": [], "reason_code": "READY",
        })

    def _incomplete(self, code, missing):
        return self.contracts.parse("ContextBuildResult", {
            "schema_version": "0.1", "status": "INCOMPLETE", "request": None,
            "missing_evidence": missing, "reason_code": code,
        })
