"""Finite set/quota inclusion only. No execution of generated expressions."""
from ..contracts import PolicyCandidate, TaskPolicy, make
from ..common import RuntimeFault, frozen_copy, new_id
from ..registry import Catalog


def rule_key(rule):
    return rule.tool_id, rule.effect


def rule_subset(child, parent):
    return (rule_key(child) == rule_key(parent)
            and set(child.resource_scope_ids) <= set(parent.resource_scope_ids)
            and set(child.destination_ids) <= set(parent.destination_ids)
            and set(child.allowed_uses) <= set(parent.allowed_uses)
            and child.max_calls <= parent.max_calls)


def grants_subset(children, parents):
    mapping = {g.destination_id: g for g in parents}
    return all(g.destination_id in mapping and set(g.resource_scope_ids) <= set(mapping[g.destination_id].resource_scope_ids) for g in children)


def compare(candidate, current):
    old = {rule_key(r): r for r in current.rules}
    subset = all(rule_key(r) in old and rule_subset(r, old[rule_key(r)]) for r in candidate.rules)
    subset = subset and grants_subset(candidate.model_destination_ids, current.model_destination_ids)
    if not subset:
        return 'EXPANSION'
    new = {rule_key(r): r for r in candidate.rules}
    reverse = all(rule_key(r) in new and rule_subset(r, new[rule_key(r)]) for r in current.rules)
    if reverse and grants_subset(current.model_destination_ids, candidate.model_destination_ids):
        return 'UNCHANGED'
    return 'TIGHTENING'


def validate_candidate(candidate, request, registry, current=None):
    candidate = frozen_copy(PolicyCandidate, candidate)
    if candidate.session_id != request.session_id or candidate.base_policy_version != request.current_policy_version:
        raise RuntimeFault('POLICY_BINDING_MISMATCH')
    catalog = Catalog(request.resource_catalog)
    manifests = {m.tool_id: m for m in request.tool_manifests}
    host = {rule_key(r): r for r in request.host_policy.rules}
    if len(host) != len(request.host_policy.rules):
        raise RuntimeFault('DUPLICATE_HOST_RULE', 422)
    for rule in request.host_policy.rules + candidate.rules:
        if rule.tool_id not in manifests:
            raise RuntimeFault('UNKNOWN_TOOL')
        actual = registry.get(rule.tool_id, manifests[rule.tool_id].manifest_version).manifest
        if actual != manifests[rule.tool_id] or rule.effect not in actual.effects:
            raise RuntimeFault('UNKNOWN_EFFECT')
        if not set(rule.resource_scope_ids) <= catalog.resources.keys():
            raise RuntimeFault('UNKNOWN_RESOURCE')
        if not set(rule.destination_ids) <= catalog.destinations.keys():
            raise RuntimeFault('UNKNOWN_DESTINATION')
        if rule.effect == 'SEND' and not rule.destination_ids:
            raise RuntimeFault('DESTINATION_REQUIRED')
    if len({rule_key(r) for r in candidate.rules}) != len(candidate.rules):
        raise RuntimeFault('DUPLICATE_POLICY_RULE')
    for rule in candidate.rules:
        if rule_key(rule) not in host or not rule_subset(rule, host[rule_key(rule)]):
            raise RuntimeFault('HOST_POLICY_EXCEEDED')
    for grants in (request.host_policy.model_destination_ids, candidate.model_destination_ids):
        if len({g.destination_id for g in grants}) != len(grants):
            raise RuntimeFault('DUPLICATE_MODEL_GRANT')
        for grant in grants:
            dest = catalog.destinations.get(grant.destination_id)
            if dest is None or dest.kind != 'model' or not set(grant.resource_scope_ids) <= catalog.resources.keys():
                raise RuntimeFault('UNKNOWN_MODEL_DESTINATION')
    if not grants_subset(candidate.model_destination_ids, request.host_policy.model_destination_ids):
        raise RuntimeFault('HOST_POLICY_EXCEEDED')
    guard = catalog.destinations.get(request.host_policy.guard_destination_id)
    final = catalog.destinations.get(request.host_policy.final_destination_id)
    if guard is None or guard.kind != 'model' or final is None or final.kind != 'user':
        raise RuntimeFault('INVALID_HOST_DESTINATION')
    if candidate.unresolved_requirements:
        raise RuntimeFault('UNRESOLVED_REQUIREMENTS')
    kind = 'INITIAL' if current is None else compare(candidate, current)
    if kind in ('EXPANSION', 'UNKNOWN'):
        raise RuntimeFault('POLICY_EXPANSION_REQUIRES_AUTHORIZATION')
    return make(TaskPolicy, **candidate.model_dump(exclude={'schema_version'}), policy_version=new_id('policy'), change_kind=kind)
