"""Conservative data restrictions; summaries and renaming do not declassify."""
from ..contracts import DataLabels, Restrictions, LineageEdge, make
from ..common import RuntimeFault


def public_labels(integrity='host'):
    return make(DataLabels, confidentiality=[], allowed_uses=None, destination_ids=None,
                model_destination_ids=None, integrity=[integrity], field_restrictions={})


def _intersection(values):
    restricted = [set(v) for v in values if v is not None]
    return sorted(set.intersection(*restricted)) if restricted else None


def combine(labels):
    labels = list(labels)
    if not labels:
        return public_labels()
    return make(DataLabels,
        confidentiality=sorted({c for x in labels for c in x.confidentiality}),
        allowed_uses=_intersection([x.allowed_uses for x in labels]),
        destination_ids=_intersection([x.destination_ids for x in labels]),
        model_destination_ids=_intersection([x.model_destination_ids for x in labels]),
        integrity=sorted({c for x in labels for c in getattr(x, 'integrity', [])}),
        # Once derived through a model, fields lose their exact position. Fold them
        # into document restrictions; only exact approved transforms can drop fields.
        field_restrictions={})


def effective(labels):
    return combine([labels, *labels.field_restrictions.values()])


def inherit(labels):
    return combine(effective(x) for x in labels)


def check_use(labels, use, destination=None, model=False, catalog=None):
    labels = effective(labels)
    if labels.allowed_uses is not None and use not in labels.allowed_uses:
        raise RuntimeFault('DATA_USE_DENIED')
    allowed = labels.model_destination_ids if model else labels.destination_ids
    if destination is not None and allowed is not None and destination not in allowed:
        raise RuntimeFault('DATA_DESTINATION_DENIED')
    if destination is not None:
        dest = catalog.destinations.get(destination) if catalog else None
        if dest is None or not set(labels.confidentiality) <= set(dest.allowed_confidentiality):
            raise RuntimeFault('CONFIDENTIALITY_DENIED')


def check_write_labels(source, target):
    """A persistent resource must preserve restrictions on derived content.

    Without this check, a new session could read a private derived file with the
    public labels of its directory and silently lose its original restrictions.
    Resource labels are host-owned; a model cannot declassify by choosing a path.
    """
    source, target = effective(source), effective(target)
    if not set(source.confidentiality) <= set(target.confidentiality):
        raise RuntimeFault('RESOURCE_LABEL_DOWNGRADE')
    for name in ('allowed_uses', 'destination_ids', 'model_destination_ids'):
        restriction, retained = getattr(source, name), getattr(target, name)
        if restriction is not None and (retained is None or not set(retained) <= set(restriction)):
            raise RuntimeFault('RESOURCE_LABEL_DOWNGRADE')


class Lineage:
    def __init__(self, store):
        self.store = store

    def add(self, session_id, source, target, kind, event_id, conn=None):
        edge = make(LineageEdge, session_id=session_id, source_ref=source, target_ref=target, kind=kind, event_id=event_id)
        self.store.add_edge(edge, conn)

    def edges(self, session_id):
        return self.store.edges(session_id)

    def closure(self, session_id, refs, reverse=False):
        known = {(r.artifact_id, r.version): r for r in refs}
        edges = self.edges(session_id)
        changed = True
        while changed:
            changed = False
            for edge in edges:
                source, target = (edge.target_ref, edge.source_ref) if reverse else (edge.source_ref, edge.target_ref)
                if (source.artifact_id, source.version) in known and (target.artifact_id, target.version) not in known:
                    known[(target.artifact_id, target.version)] = target
                    changed = True
        return list(known.values())


def exact_labels(labels):
    """Combine document restrictions, retaining host-known structural fields."""
    labels = list(labels)
    document = combine(labels)
    fields = {}
    for label in labels:
        for pointer, restriction in label.field_restrictions.items():
            if pointer in fields:
                value = combine([fields[pointer], restriction])
                fields[pointer] = make(Restrictions, **value.model_dump(exclude={'schema_version', 'integrity', 'field_restrictions'}))
            else:
                fields[pointer] = restriction
    return document.model_copy(update={'field_restrictions': fields})
