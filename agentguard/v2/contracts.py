"""Version 0.1 wire contract. Importing this module never starts a service.

All wire objects require schema_version. Optional security values use explicit
null (unrestricted) versus [] (deny all); missing required fields never grant.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

ID = Annotated[str, StringConstraints(min_length=1, max_length=200, pattern=r'^[A-Za-z0-9_.:-]+$')]
Digest = Annotated[str, StringConstraints(pattern=r'^[a-f0-9]{64}$')]
Effect = Literal['READ', 'WRITE', 'SEND', 'DELETE']
Phase = Literal['ACTION', 'RESULT', 'FINAL']
CallStatus = Literal['RELEASED', 'BLOCKED', 'REVIEW_PENDING', 'FAILED_KNOWN', 'UNKNOWN']
PermitStatus = Literal['PROPOSED', 'REVIEWED', 'APPROVED', 'CLAIMED', 'SUCCEEDED', 'FAILED_KNOWN', 'UNKNOWN', 'REVOKED', 'EXPIRED']
FailureCode = Literal['MODEL_TIMEOUT', 'INVALID_SCHEMA', 'INVALID_REFERENCE', 'CONTENT_TOO_LARGE', 'BUDGET_EXHAUSTED', 'MISSING_EVIDENCE', 'SERVICE_UNAVAILABLE', 'MODEL_CONFIGURATION_ERROR', 'MODEL_UNAVAILABLE', 'MODEL_DESTINATION_DENIED']


class Wire(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True, strict=True, hide_input_in_errors=True, allow_inf_nan=False)
    schema_version: Literal['0.1']

    @classmethod
    def model_validate_json(cls, json_data, **kwargs):
        from .common import strict_loads
        strict_loads(json_data)
        return super().model_validate_json(json_data, **kwargs)

    @model_validator(mode='after')
    def utc_dates(self):
        from .common import ensure_json
        for name in self.__class__.model_fields:
            value = getattr(self, name)
            if name in ('args', 'content', 'subject', 'parameters_schema', 'payload', 'mandatory_facts', 'retained_mandatory_facts', 'effect_evidence'):
                ensure_json(value)
            if isinstance(value, datetime) and (value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value)):
                raise ValueError('timestamps must be timezone-aware UTC')
        return self


def make(cls, **values):
    """Explicit convenience for Python integrations; wire parsing stays strict."""
    return cls(schema_version='0.1', **values)


class Restrictions(Wire):
    confidentiality: list[str]
    allowed_uses: list[str] | None
    destination_ids: list[ID] | None
    model_destination_ids: list[ID] | None


class DataLabels(Restrictions):
    integrity: list[Literal['trusted_user', 'host', 'external', 'model']]
    field_restrictions: dict[str, Restrictions]


class ResourceScope(Wire):
    scope_id: ID
    kind: Literal['path', 'logical']
    root: str
    labels: DataLabels


class Destination(Wire):
    destination_id: ID
    kind: Literal['network', 'model', 'user', 'local']
    address: str
    allowed_confidentiality: list[str]


class ResourceCatalog(Wire):
    resources: list[ResourceScope]
    destinations: list[Destination]


class ToolManifest(Wire):
    tool_id: ID
    manifest_version: ID
    parameters_schema: dict[str, Any]
    effects: list[Effect] = Field(min_length=1)
    resource_parameter: str | None
    destination_parameter: str | None
    artifact_parameters: dict[str, str]
    return_media_type: Literal['text/plain', 'application/json']
    supports_idempotency_key: bool
    output_labels: DataLabels
    synthetic_demo: bool = False


class PolicyRule(Wire):
    tool_id: ID
    effect: Effect
    resource_scope_ids: list[ID]
    destination_ids: list[ID]
    allowed_uses: list[str] = Field(min_length=1)
    max_calls: int = Field(ge=0)


class ModelDestinationGrant(Wire):
    destination_id: ID
    resource_scope_ids: list[ID]


class HostPolicy(Wire):
    rules: list[PolicyRule]
    model_destination_ids: list[ModelDestinationGrant]
    guard_destination_id: ID
    final_destination_id: ID
    final_use: str
    max_review_bytes: int = Field(gt=0)
    permit_ttl_seconds: int = Field(gt=0, le=3600)
    review_timeout_seconds: float = Field(gt=0, le=300)


class EvidenceRef(Wire):
    artifact_id: ID
    version: int = Field(ge=1)
    sha256: Digest
    json_pointer: str | None
    span: tuple[int, int] | None

    @model_validator(mode='after')
    def position(self):
        if self.json_pointer is not None and self.span is not None:
            raise ValueError('use pointer or code-point span, not both')
        if self.span is not None and not (0 <= self.span[0] < self.span[1]):
            raise ValueError('invalid half-open span')
        return self


class PolicyCandidate(Wire):
    session_id: ID
    base_policy_version: ID | None
    rules: list[PolicyRule]
    model_destination_ids: list[ModelDestinationGrant]
    rationale: str
    evidence_refs: list[EvidenceRef]
    unresolved_requirements: list[str]


class TaskPolicy(PolicyCandidate):
    policy_version: ID
    change_kind: Literal['INITIAL', 'UNCHANGED', 'TIGHTENING', 'EXPANSION', 'UNKNOWN']


class PolicyGenerationRequest(Wire):
    session_id: ID
    trusted_task: str
    host_policy: HostPolicy
    tool_manifests: list[ToolManifest]
    resource_catalog: ResourceCatalog
    confirmed_authorizations: list[str]
    current_policy_version: ID | None


class SessionRequest(Wire):
    trusted_task: str = Field(min_length=1)
    host_policy: HostPolicy
    resource_catalog: ResourceCatalog
    tool_manifests: list[ToolManifest]
    confirmed_authorizations: list[str]


class SessionView(Wire):
    session_id: ID
    status: Literal['ACTIVE', 'RECOVERING', 'CLOSED']
    policy_version: ID
    context_version: ID | None
    relevant_security_revision: int = Field(ge=0)


class ArtifactVersion(Wire):
    session_id: ID
    artifact_id: ID
    version: int = Field(ge=1)
    sha256: Digest
    media_type: Literal['text/plain', 'application/json']
    source_call_id: ID | None
    labels: DataLabels
    resource_scope_ids: list[ID]
    storage_ref: str
    synthetic_demo: bool
    created_at: datetime


class ArtifactRef(Wire):
    ref_id: ID
    session_id: ID
    artifact_id: ID
    version: int = Field(ge=1)
    allowed_uses: list[str]
    tool_ids: list[ID]
    destination_ids: list[ID]
    expires_at: datetime


class ToolCall(Wire):
    session_id: ID
    turn_id: ID
    call_id: ID
    tool_id: ID
    manifest_version: ID
    args: dict[str, Any]
    input_context_version: ID
    artifact_refs: list[ArtifactRef]
    use: str


class Message(Wire):
    role: Literal['system', 'user', 'assistant', 'tool']
    ref: EvidenceRef


class ContextSnapshot(Wire):
    session_id: ID
    turn_id: ID
    context_version: ID
    messages: list[Message]
    policy_version: ID
    relevant_security_revision: int
    unresolved_risks: list[EvidenceRef]
    model_destination_id: ID
    labels: DataLabels
    resource_scope_ids: list[ID]


class LineageEdge(Wire):
    session_id: ID
    source_ref: EvidenceRef
    target_ref: EvidenceRef
    kind: Literal['exact', 'possible']
    event_id: ID


class EvidenceBlock(Wire):
    ref: EvidenceRef
    content: Any
    labels: DataLabels
    role: Literal['task', 'subject', 'related', 'input']


class ContextMaterial(Wire):
    session_id: ID
    turn_id: ID
    call_id: ID | None
    review_id: ID
    phase: Phase
    trusted_task: str
    task_ref: EvidenceRef
    policy: TaskPolicy
    host_policy: HostPolicy
    context_version: ID
    relevant_security_revision: int
    subject_ref: EvidenceRef
    subject: Any
    mandatory_facts: dict[str, Any]
    evidence: list[EvidenceBlock]
    lineage: list[LineageEdge]
    recent_events: list[dict[str, Any]]
    supplemental_attempt: int = Field(ge=0, le=1)
    allowed_transform_ids: list[ID]
    available_evidence_refs: list[EvidenceRef]

    @model_validator(mode='after')
    def phase_binding(self):
        if (self.phase == 'FINAL') != (self.call_id is None):
            raise ValueError('FINAL has no call_id; ACTION/RESULT require call_id')
        return self


class ReviewRequest(ContextMaterial):
    selected_evidence_refs: list[EvidenceRef]
    retained_mandatory_facts: dict[str, Any]
    budget_used: int = Field(ge=0)


class ContextBuildResult(Wire):
    status: Literal['READY', 'INCOMPLETE']
    request: ReviewRequest | None
    missing_evidence: list[EvidenceRef]
    reason_code: str

    @model_validator(mode='after')
    def coherent(self):
        if (self.status == 'READY') != (self.request is not None):
            raise ValueError('READY requires request, INCOMPLETE forbids it')
        return self


class Usage(Wire):
    provider: str | None
    model: str | None
    input_tokens: int | None = Field(ge=0)
    output_tokens: int | None = Field(ge=0)
    latency_ms: float | None = Field(ge=0)
    attempts: int = Field(ge=0)


class Finding(Wire):
    finding_type: str
    affected_action_field: str | None
    evidence_refs: list[EvidenceRef] = Field(min_length=1)


class RedactionTarget(Wire):
    evidence_ref: EvidenceRef
    transform_id: ID


class ReviewDecision(Wire):
    review_id: ID
    session_id: ID
    turn_id: ID
    call_id: ID | None
    phase: Phase
    policy_version: ID
    context_version: ID
    subject_ref: EvidenceRef
    decision: Literal['ALLOW', 'BLOCK', 'REDACT', 'NEEDS_CONTEXT']
    reason_code: str
    reason_summary: str
    evidence_refs: list[EvidenceRef]
    findings: list[Finding]
    redaction_targets: list[RedactionTarget]
    requested_evidence_refs: list[EvidenceRef]
    usage: Usage

    @model_validator(mode='after')
    def phase_binding(self):
        if (self.phase == 'FINAL') != (self.call_id is None):
            raise ValueError('invalid phase/call binding')
        if self.decision != 'NEEDS_CONTEXT' and not self.evidence_refs:
            raise ValueError('decision requires subject evidence')
        return self


class ReviewFailure(Wire):
    reason_code: FailureCode
    usage: Usage | None


class ReviewOutcome(Wire):
    status: Literal['DECIDED', 'FAILED']
    decision: ReviewDecision | None
    failure: ReviewFailure | None

    @model_validator(mode='after')
    def coherent(self):
        if self.status == 'DECIDED' and (self.decision is None or self.failure is not None):
            raise ValueError('invalid DECIDED outcome')
        if self.status == 'FAILED' and (self.failure is None or self.decision is not None):
            raise ValueError('invalid FAILED outcome')
        return self


class Permit(Wire):
    permit_id: ID
    session_id: ID
    turn_id: ID
    call_id: ID
    tool_id: ID
    tool_manifest_version: ID
    args_digest: Digest
    artifact_versions: list[EvidenceRef]
    policy_version: ID
    context_version: ID
    relevant_security_revision: int
    expires_at: datetime
    status: PermitStatus


class Receipt(Wire):
    receipt_id: ID
    permit_id: ID
    session_id: ID
    turn_id: ID
    call_id: ID
    status: Literal['SUCCEEDED', 'FAILED_KNOWN', 'UNKNOWN']
    reason_code: str
    effect_evidence: dict[str, Any]
    artifact_ref: EvidenceRef | None
    timestamp: datetime


class PrepareTurnRequest(Wire):
    session_id: ID
    messages: list[Message]
    model_destination_id: ID


class PreparedMessage(Wire):
    role: Literal['system', 'user', 'assistant', 'tool']
    content: Any
    ref: EvidenceRef


class PreparedTurn(Wire):
    session_id: ID
    turn_id: ID
    model_call_id: ID
    context_version: ID
    messages: list[PreparedMessage]
    model_destination_id: ID


class ToolProposal(Wire):
    tool_id: ID
    manifest_version: ID
    args: dict[str, Any]
    artifact_refs: list[ArtifactRef]
    use: str


class ModelOutputRequest(Wire):
    session_id: ID
    model_call_id: ID
    context_version: ID
    content: str
    tool_proposals: list[ToolProposal]


class ProposedTurn(Wire):
    session_id: ID
    turn_id: ID
    output_ref: EvidenceRef
    calls: list[ToolCall]


class BatchRequest(Wire):
    session_id: ID
    turn_id: ID
    context_version: ID
    calls: list[ToolCall]


class CallResult(Wire):
    session_id: ID
    turn_id: ID
    call_id: ID
    status: CallStatus
    reason_code: str
    content: Any | None
    artifact_ref: EvidenceRef | None
    receipt: Receipt | None

    @model_validator(mode='after')
    def delivery(self):
        if self.status == 'RELEASED' and self.artifact_ref is None:
            raise ValueError('released result requires immutable reference')
        if self.status != 'RELEASED' and (self.content is not None or self.artifact_ref is not None):
            raise ValueError('unreleased result cannot carry content')
        return self


class BatchResult(Wire):
    session_id: ID
    turn_id: ID
    results: dict[ID, CallResult]

    @model_validator(mode='after')
    def bindings(self):
        for key, result in self.results.items():
            if (key, self.session_id, self.turn_id) != (result.call_id, result.session_id, result.turn_id):
                raise ValueError('batch result binding mismatch')
        return self


class FinalizeRequest(Wire):
    session_id: ID
    turn_id: ID
    context_version: ID
    output_ref: EvidenceRef


class FinalizedOutput(Wire):
    session_id: ID
    status: Literal['RELEASED', 'BLOCKED', 'REVIEW_PENDING']
    reason_code: str
    content: Any | None
    artifact_ref: EvidenceRef | None

    @model_validator(mode='after')
    def delivery(self):
        if self.status == 'RELEASED' and self.artifact_ref is None:
            raise ValueError('released output requires immutable reference')
        if self.status != 'RELEASED' and (self.content is not None or self.artifact_ref is not None):
            raise ValueError('unreleased output cannot carry content')
        return self


class RecoveryRequest(Wire):
    session_id: ID
    risk_refs: list[EvidenceRef] = Field(min_length=1)
    reason_code: str


class RecoveryPlan(Wire):
    session_id: ID
    recovery_id: ID
    affected_refs: list[EvidenceRef]
    revoked_permit_ids: list[ID]
    safe_context_version: ID
    rebuild_messages: list[Message]
    required_host_resets: list[str]
    irreversible_receipts: list[Receipt]
    irreversible_final_refs: list[EvidenceRef]
    unknown_receipts: list[Receipt]


class RecoveryAck(Wire):
    session_id: ID
    recovery_id: ID
    new_host_context_id: ID
    completed_resets: dict[str, bool]
    unsupported: list[str]


class Event(Wire):
    event_id: ID
    session_id: ID
    seq: int = Field(ge=1)
    timestamp: datetime
    event_type: str
    turn_id: ID | None
    call_id: ID | None
    review_id: ID | None
    policy_version: ID | None
    context_version: ID | None
    payload: dict[str, Any]
