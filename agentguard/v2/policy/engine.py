from dataclasses import dataclass
from ..common import RuntimeFault, at_pointer
from ..registry import Catalog
from ..state.lineage import check_use, check_write_labels, inherit, public_labels

@dataclass(frozen=True)
class ActionFacts:
    scope_ids: list[str]
    destination_id: str | None
    rule_keys: list[str]
    labels: object


class PolicyEngine:
    def __init__(self, registry):
        self.registry = registry

    def action(self, call, policy, host_request, context, artifacts):
        manifest = self.registry.get(call.tool_id, call.manifest_version).manifest
        if manifest not in host_request.tool_manifests:
            raise RuntimeFault('TOOL_NOT_HOST_CONFIRMED')
        self.registry.validate_args(manifest, call.args)
        catalog = Catalog(host_request.resource_catalog)
        scopes = catalog.matching_scopes(at_pointer(call.args, manifest.resource_parameter)) if manifest.resource_parameter else []
        destination = catalog.destination(at_pointer(call.args, manifest.destination_parameter)) if manifest.destination_parameter else None
        rules = []
        for effect in manifest.effects:
            matches = [r for r in policy.rules if r.tool_id == call.tool_id and r.effect == effect and call.use in r.allowed_uses]
            if len(matches) != 1:
                raise RuntimeFault('ACTION_NOT_AUTHORIZED')
            rule = matches[0]
            if manifest.resource_parameter and not set(scopes) & set(rule.resource_scope_ids):
                raise RuntimeFault('RESOURCE_OUT_OF_SCOPE')
            if destination is not None and destination not in rule.destination_ids:
                raise RuntimeFault('DESTINATION_OUT_OF_SCOPE')
            if effect == 'SEND' and destination is None:
                raise RuntimeFault('DESTINATION_REQUIRED')
            if effect in ('SEND', 'WRITE') and not set(context.resource_scope_ids) <= set(rule.resource_scope_ids):
                raise RuntimeFault('ARTIFACT_SCOPE_DENIED')
            # Artifact contents must fit each effect's registered data scope.
            for art in artifacts:
                if not set(art.resource_scope_ids) <= set(rule.resource_scope_ids):
                    raise RuntimeFault('ARTIFACT_SCOPE_DENIED')
            rules.append(rule.tool_id + ':' + rule.effect)
        labels = inherit([context.labels, *(a.labels for a in artifacts)])
        check_use(labels, call.use, destination, catalog=catalog)
        if 'WRITE' in manifest.effects and destination is None:
            target_labels = inherit(catalog.resources[s].labels for s in scopes) if scopes else public_labels()
            check_write_labels(labels, target_labels)
        # Never dereference a mutable file to send it under an earlier approval.
        if 'SEND' in manifest.effects and manifest.resource_parameter:
            raise RuntimeFault('IMMUTABLE_ARTIFACT_REQUIRED')
        return ActionFacts(scopes, destination, rules, labels)

    def model(self, destination_id, policy, host_request, artifacts, *, use='model'):
        catalog = Catalog(host_request.resource_catalog)
        grant = next((g for g in policy.model_destination_ids if g.destination_id == destination_id), None)
        if grant is None:
            raise RuntimeFault('MODEL_DESTINATION_DENIED')
        for art in artifacts:
            if not set(art.resource_scope_ids) <= set(grant.resource_scope_ids):
                raise RuntimeFault('MODEL_RESOURCE_DENIED')
            check_use(art.labels, use, destination_id, model=True, catalog=catalog)
