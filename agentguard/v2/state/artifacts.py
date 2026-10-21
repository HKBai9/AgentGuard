"""Private immutable version store. All content reads are integrity checked."""
from __future__ import annotations
import os
from pathlib import Path
from dataclasses import dataclass
from ..contracts import ArtifactVersion, EvidenceRef, ArtifactRef, DataLabels, make
from ..common import canonical, digest, strict_loads, new_id, utcnow, at_pointer, pointer_parts, RuntimeFault
from .lineage import check_use


@dataclass(frozen=True)
class TransformSpec:
    transform_id: str
    kind: str  # mask_span | mask_json_string
    allowed_pointers: frozenset[str] = frozenset()
    declassify_fields: frozenset[str] = frozenset()


class Artifacts:
    def __init__(self, store, directory, transforms=()):
        self.store = store
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory.chmod(0o700)
        transforms = tuple(transforms)
        self.transforms = {t.transform_id: t for t in transforms}
        if len(self.transforms) != len(transforms):
            raise RuntimeFault('DUPLICATE_TRANSFORM')
        for spec in self.transforms.values():
            if spec.kind not in ('mask_span', 'mask_json_string') or not spec.declassify_fields <= spec.allowed_pointers:
                raise RuntimeFault('INVALID_TRANSFORM')

    def create(self, sid, content, labels, *, media_type='text/plain', source_call_id=None,
               resource_scope_ids=(), synthetic_demo=False, artifact_id=None, conn=None):
        raw = canonical(content)
        if media_type == 'text/plain' and not isinstance(content, str):
            raise RuntimeFault('INVALID_ARTIFACT_TYPE', 422)
        if conn is None:
            with self.store.transaction() as cx:
                return self.create(sid, content, labels, media_type=media_type, source_call_id=source_call_id,
                    resource_scope_ids=resource_scope_ids, synthetic_demo=synthetic_demo, artifact_id=artifact_id, conn=cx)
        aid = artifact_id or new_id('artifact')
        version = conn.execute('SELECT COALESCE(MAX(version),0)+1 FROM artifacts WHERE session=? AND id=?', (sid, aid)).fetchone()[0]
        # The path is a random store allocation, never derived from untrusted IDs.
        filename = new_id('blob') + '.json'
        path = self.directory / filename
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        meta = make(ArtifactVersion, session_id=sid, artifact_id=aid, version=version, sha256=digest(content),
            media_type=media_type, source_call_id=source_call_id, labels=labels,
            resource_scope_ids=sorted(set(resource_scope_ids)), storage_ref=filename,
            synthetic_demo=synthetic_demo, created_at=utcnow())
        conn.execute('INSERT INTO artifacts VALUES(?,?,?,?)', (sid, aid, version, canonical(meta)))
        conn.execute('INSERT INTO artifact_status(session,id,version) VALUES(?,?,?)', (sid, aid, version))
        return meta

    @staticmethod
    def ref(meta):
        return make(EvidenceRef, artifact_id=meta.artifact_id, version=meta.version, sha256=meta.sha256, json_pointer=None, span=None)

    def metadata(self, sid, ref, conn=None):
        if conn is None:
            with self.store.connect() as cx:
                return self.metadata(sid, ref, cx)
        row = conn.execute('SELECT meta FROM artifacts WHERE session=? AND id=? AND version=?', (sid, ref.artifact_id, ref.version)).fetchone()
        if row is None:
            raise RuntimeFault('INVALID_REFERENCE')
        meta = ArtifactVersion.model_validate_json(row[0])
        if meta.sha256 != ref.sha256:
            raise RuntimeFault('INVALID_REFERENCE')
        return meta

    def read(self, sid, ref, *, released=False, conn=None):
        meta = self.metadata(sid, ref, conn)
        if released and not self.is_released(sid, ref, conn):
            raise RuntimeFault('ARTIFACT_NOT_RELEASED')
        path = self.directory / meta.storage_ref
        try:
            content = strict_loads(path.read_bytes())
        except (OSError, RuntimeFault):
            raise RuntimeFault('ARTIFACT_INTEGRITY_FAILED') from None
        if digest(content) != ref.sha256:
            raise RuntimeFault('ARTIFACT_INTEGRITY_FAILED')
        if ref.json_pointer is not None:
            at_pointer(content, ref.json_pointer)
        if ref.span is not None and (not isinstance(content, str) or ref.span[1] > len(content)):
            raise RuntimeFault('INVALID_REFERENCE')
        return content

    def whole_ref(self, sid, ref, conn=None):
        if ref.span is not None or ref.json_pointer is not None:
            raise RuntimeFault('WHOLE_ARTIFACT_REQUIRED')
        return self.metadata(sid, ref, conn)

    def is_released(self, sid, ref, conn=None):
        if conn is None:
            with self.store.connect() as cx:
                return self.is_released(sid, ref, cx)
        row = conn.execute('SELECT released,revoked FROM artifact_status WHERE session=? AND id=? AND version=?', (sid, ref.artifact_id, ref.version)).fetchone()
        return bool(row and row[0] and not row[1])

    def release(self, sid, ref, conn):
        self.whole_ref(sid, ref, conn)
        cursor = conn.execute('UPDATE artifact_status SET released=1 WHERE session=? AND id=? AND version=? AND revoked=0', (sid, ref.artifact_id, ref.version))
        if cursor.rowcount != 1:
            raise RuntimeFault('ARTIFACT_REVOKED')

    def revoke(self, sid, ref, conn):
        conn.execute('UPDATE artifact_status SET revoked=1 WHERE session=? AND id=? AND version=?', (sid, ref.artifact_id, ref.version))

    def issue_ref(self, sid, ref, uses, tool_ids, destinations, expires_at):
        self.whole_ref(sid, ref)
        result = make(ArtifactRef, ref_id=new_id('ref'), session_id=sid, artifact_id=ref.artifact_id,
                      version=ref.version, allowed_uses=uses, tool_ids=tool_ids, destination_ids=destinations, expires_at=expires_at)
        with self.store.transaction() as conn:
            self.store.put(sid, 'artifact_ref', result.ref_id, result, conn)
        return result

    def resolve_ref(self, sid, token, use, tool_id, destination, catalog, conn=None):
        saved = self.store.get(sid, 'artifact_ref', token.ref_id, conn)
        if saved is None or canonical(saved) != canonical(token) or token.session_id != sid:
            raise RuntimeFault('INVALID_ARTIFACT_CAPABILITY')
        if token.expires_at <= utcnow():
            raise RuntimeFault('ARTIFACT_CAPABILITY_EXPIRED')
        if use not in token.allowed_uses or tool_id not in token.tool_ids or (destination is not None and destination not in token.destination_ids):
            raise RuntimeFault('ARTIFACT_CAPABILITY_DENIED')
        with self.store.connect() as cx:
            row = cx.execute('SELECT meta FROM artifacts WHERE session=? AND id=? AND version=?', (sid, token.artifact_id, token.version)).fetchone()
        if row is None:
            raise RuntimeFault('INVALID_REFERENCE')
        meta = ArtifactVersion.model_validate_json(row[0])
        ref = self.ref(meta)
        if not self.is_released(sid, ref, conn):
            raise RuntimeFault('ARTIFACT_NOT_RELEASED')
        self.read(sid, ref, conn=conn)
        check_use(meta.labels, use, destination, catalog=catalog)
        return meta

    def redact(self, sid, subject_ref, targets, conn):
        source = self.whole_ref(sid, subject_ref, conn)
        content = strict_loads(canonical(self.read(sid, subject_ref, conn=conn)))
        spans, pointers, cleared = [], set(), set()
        for target in targets:
            ref = target.evidence_ref
            if (ref.artifact_id, ref.version, ref.sha256) != (subject_ref.artifact_id, subject_ref.version, subject_ref.sha256):
                raise RuntimeFault('INVALID_REFERENCE')
            self.read(sid, ref, conn=conn)
            spec = self.transforms.get(target.transform_id)
            if spec is None:
                raise RuntimeFault('UNKNOWN_TRANSFORM')
            if spec.kind == 'mask_span' and ref.span is not None and ref.json_pointer is None:
                spans.append(ref.span)
            elif spec.kind == 'mask_json_string' and ref.json_pointer in spec.allowed_pointers and ref.span is None:
                pointer = ref.json_pointer
                if pointer in pointers or any(pointer.startswith(p + '/') or p.startswith(pointer + '/') for p in pointers):
                    raise RuntimeFault('OVERLAPPING_REDACTION')
                pointers.add(pointer)
                if not isinstance(at_pointer(content, pointer), str):
                    raise RuntimeFault('INVALID_REDACTION_TARGET')
                parts = pointer_parts(pointer)
                if not parts:
                    content = '[REDACTED]'
                else:
                    parent = at_pointer(content, '/' + '/'.join(p.replace('~', '~0').replace('/', '~1') for p in parts[:-1])) if len(parts) > 1 else content
                    parent[int(parts[-1]) if isinstance(parent, list) else parts[-1]] = '[REDACTED]'
                if pointer in spec.declassify_fields:
                    cleared.add(pointer)
            else:
                raise RuntimeFault('TRANSFORM_NOT_AUTHORIZED')
        spans.sort()
        if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
            raise RuntimeFault('OVERLAPPING_REDACTION')
        for start, end in reversed(spans):
            content = content[:start] + '[REDACTED]' + content[end:]
        labels = source.labels.model_copy(update={'field_restrictions': {p: v for p, v in source.labels.field_restrictions.items() if p not in cleared}})
        return self.create(sid, content, labels, media_type=source.media_type, source_call_id=source.source_call_id,
            resource_scope_ids=source.resource_scope_ids, synthetic_demo=source.synthetic_demo, artifact_id=source.artifact_id, conn=conn)
