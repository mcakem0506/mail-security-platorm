"""API request/response schemas (ТЗ 30: strict validation, no over-exposure)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from msp_contracts import (
    AnalysisStatus,
    AnalystClassification,
    CanaryScope,
    CanaryState,
    CandidateState,
    ExceptionType,
    FalseNegativeSource,
    FalsePositiveReason,
    GapStatus,
    IncidentStatus,
    IOCType,
    ReanalysisState,
    RemediationState,
    RemediationType,
    RiskLevel,
    Role,
    RootCause,
    RuleHealth,
    RuleStatus,
    Severity,
    SignalDisposition,
)
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ---------------------------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------------------------
class LoginRequest(ApiModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(ApiModel):
    user_id: str
    email: str
    display_name: str
    role: Role
    role_label: str
    permissions: list[str]
    csrf_token: str
    expires_at: datetime
    must_change_password: bool = False


class ChangePasswordRequest(ApiModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class MeResponse(ApiModel):
    user_id: str
    email: str
    display_name: str
    role: Role
    role_label: str
    permissions: list[str]
    organization_id: str
    csrf_token: str


# ---------------------------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------------------------
class AnalyzeRequest(ApiModel):
    """Submit a message for analysis. Either raw EML (base64) or an Exchange reference."""

    raw_eml_base64: str | None = Field(default=None, max_length=36_000_000)
    exchange_item_id: str | None = Field(default=None, max_length=512)
    internet_message_id: str | None = Field(default=None, max_length=998)
    mailbox: str | None = Field(default=None, max_length=320)
    report_as_phishing: bool = False
    note: str = Field(default="", max_length=2000)

    @field_validator("raw_eml_base64")
    @classmethod
    def _non_empty(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("raw_eml_base64 must not be empty")
        return value


class ReasonOut(ApiModel):
    title: str
    explanation: str
    severity: Severity


class AnalysisStatusResponse(ApiModel):
    """Employee-facing result (ТЗ 6.4): no internal rules, no raw provider output."""

    job_id: str
    status: AnalysisStatus
    classification: RiskLevel | None = None
    confidence: str | None = None
    recommendation: str | None = None
    reasons: list[ReasonOut] = Field(default_factory=list)
    analysis_incomplete: bool = False
    analyzed_at: datetime | None = None
    reported_to_security: bool = False
    ti_state: str | None = None
    message: str | None = None


class AnalystReasonOut(ReasonOut):
    signal_id: str
    source: str
    observed_at: datetime
    internal: bool = False
    recommendation: str | None = None


class SignalOut(ApiModel):
    signal_id: str
    rule_id: str | None
    rule_version: int | None
    category: str
    title: str
    explanation: str
    severity: Severity
    confidence: float
    weight: float
    source: str
    evidence: dict[str, Any]
    hard: bool
    internal: bool
    suppressed: bool
    suppressed_by: str | None


class AnalysisDetailResponse(ApiModel):
    """Analyst-facing result: full evidence, rule versions and provider lookups."""

    job_id: str
    message_id: str | None
    status: AnalysisStatus
    state: str
    ti_state: str
    classification: RiskLevel
    score: int
    confidence: str
    recommendation: str
    reasons: list[AnalystReasonOut]
    hard_signals: list[AnalystReasonOut]
    suppressed_signals: list[AnalystReasonOut]
    sources: list[str]
    missing_evidence: list[str]
    signals: list[SignalOut]
    engine_version: str
    risk_engine_version: str
    duration_ms: int | None
    campaign_id: str | None = None


# ---------------------------------------------------------------------------------------------
# Investigations
# ---------------------------------------------------------------------------------------------
class MessageSummary(ApiModel):
    message_id: str
    subject: str
    sender_address: str
    sender_display_name: str
    sender_domain: str
    recipient_count: int
    received_at: datetime
    classification: RiskLevel | None
    score: int | None
    has_attachments: bool
    url_count: int
    source: str
    reported_by: str | None
    campaign_id: str | None = None
    #: The analysis that produced ``classification``. The console needs it to fetch the
    #: detection signals behind the verdict — without it the message card can show a verdict
    #: but not the reasons for it.
    job_id: str | None = None


class MessageSearchQuery(ApiModel):
    sender: str | None = Field(default=None, max_length=320)
    recipient: str | None = Field(default=None, max_length=320)
    subject: str | None = Field(default=None, max_length=500)
    verdict: RiskLevel | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    domain: str | None = Field(default=None, max_length=255)
    url: str | None = Field(default=None, max_length=2048)
    campaign_id: str | None = Field(default=None, max_length=32)
    incident_id: str | None = Field(default=None, max_length=32)
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0, le=100_000)


class AttachmentOut(ApiModel):
    attachment_id: str
    filename: str
    detected_type: str
    size_bytes: int
    sha256: str
    depth: int
    is_archive: bool
    encrypted: bool
    flags: list[str]
    downloadable: bool
    scan_result: dict[str, Any] = Field(default_factory=dict)


class MessageDetailResponse(ApiModel):
    message: MessageSummary
    headers: list[dict[str, str]]
    recipients: list[dict[str, str]]
    attachments: list[AttachmentOut]
    urls: list[dict[str, Any]]
    auth_summary: dict[str, Any]
    #: Set when Authentication-Results were present but not believed. Without it an analyst
    #: cannot tell "the sender did not authenticate" from "we refused to read the claim".
    auth_note: str | None = None
    verdict: AnalysisDetailResponse | None
    preview_available: bool


class SafePreviewResponse(ApiModel):
    """Sanitised preview (ТЗ 22.3): links are non-clickable, remote content disabled."""

    message_id: str
    sanitized_html: str | None
    plain_text: str | None
    urls: list[dict[str, Any]]
    warning: str = (
        "Содержимое очищено: скрипты, внешние ресурсы и активные ссылки удалены. "
        "Ссылки показаны текстом и не являются кликабельными."
    )


# ---------------------------------------------------------------------------------------------
# Indicators / TI
# ---------------------------------------------------------------------------------------------
class IndicatorOut(ApiModel):
    indicator_id: str
    ioc_type: IOCType
    value: str
    first_seen: datetime
    last_seen: datetime
    sighting_count: int
    worst_status: str | None
    confirmed_malicious: bool


class ProviderLookupOut(ApiModel):
    provider_id: str
    ioc_type: IOCType
    indicator: str
    status: str
    malicious_count: int | None
    total_count: int | None
    categories: list[str]
    summary: dict[str, Any]
    from_cache: bool
    cache_age: str | None
    fetched_at: datetime
    error: str | None


class IndicatorDetailResponse(ApiModel):
    indicator: IndicatorOut
    provider_results: list[ProviderLookupOut]
    internal_sightings: int
    related_messages: list[MessageSummary]
    related_campaigns: list[str]


# ---------------------------------------------------------------------------------------------
# Campaigns and incidents
# ---------------------------------------------------------------------------------------------
class CampaignOut(ApiModel):
    campaign_id: str
    name: str
    first_seen: datetime
    last_seen: datetime
    message_count: int
    recipient_count: int
    reported_by_users: int
    indicators: list[str]
    verdict_distribution: dict[str, int]
    confirmed_malicious: bool
    remediation_state: str
    incident_id: str | None


class IncidentCreateRequest(ApiModel):
    title: str = Field(min_length=3, max_length=255)
    summary: str = Field(default="", max_length=5000)
    severity: Severity = Severity.MEDIUM
    message_ids: list[str] = Field(default_factory=list, max_length=500)
    campaign_id: str | None = Field(default=None, max_length=32)


class IncidentUpdateRequest(ApiModel):
    status: IncidentStatus | None = None
    severity: Severity | None = None
    assigned_to: str | None = Field(default=None, max_length=32)
    summary: str | None = Field(default=None, max_length=5000)


class IncidentOut(ApiModel):
    incident_id: str
    number: int
    title: str
    summary: str
    status: IncidentStatus
    severity: Severity
    confidence: str
    assigned_to: str | None
    opened_by: str | None
    affected_users: list[str]
    message_count: int
    indicator_count: int
    created_at: datetime
    triaged_at: datetime | None
    remediated_at: datetime | None
    closed_at: datetime | None
    timeline: list[dict[str, Any]]


class AnalystNoteRequest(ApiModel):
    body: str = Field(min_length=1, max_length=10_000)


# ---------------------------------------------------------------------------------------------
# Exceptions and policies
# ---------------------------------------------------------------------------------------------
class ExceptionCreateRequest(ApiModel):
    exception_type: ExceptionType
    value: str = Field(min_length=1, max_length=512)
    rule_id: str | None = Field(default=None, max_length=32)
    reason: str = Field(min_length=5, max_length=1000)
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def _future(cls, value: datetime | None) -> datetime | None:
        if value is not None:
            from datetime import UTC
            from datetime import datetime as dt

            now = dt.now(UTC)
            if value.tzinfo is None:
                value = value.replace(tzinfo=UTC)
            if value <= now:
                raise ValueError("expires_at must be in the future")
        return value


class ExceptionOut(ApiModel):
    exception_id: str
    exception_type: ExceptionType
    value: str
    rule_id: str | None
    owner_email: str
    reason: str
    expires_at: datetime | None
    revoked_at: datetime | None
    hit_count: int
    created_at: datetime
    active: bool


class ProtectedIdentityRequest(ApiModel):
    display_name: str = Field(min_length=1, max_length=255)
    email: EmailStr
    categories: list[str] = Field(default_factory=list, max_length=10)
    aliases: list[str] = Field(default_factory=list, max_length=20)
    name_variants: list[str] = Field(default_factory=list, max_length=20)
    approved_delegates: list[str] = Field(default_factory=list, max_length=20)
    approved_external_systems: list[str] = Field(default_factory=list, max_length=20)
    department: str = Field(default="", max_length=255)
    title: str = Field(default="", max_length=255)
    enabled: bool = True


class ProtectedIdentityOut(ProtectedIdentityRequest):
    identity_id: str
    created_at: datetime
    #: critical|high|medium|low — how much damage impersonating this identity would do.
    risk_class: str = "medium"
    vip: bool = False
    #: "directory" when derived from an AD group, "manual" when an analyst created it.
    source: str = "manual"


class PolicyUpdateRequest(ApiModel):
    value: dict[str, Any]
    reason: str = Field(default="", max_length=500)


class PolicyOut(ApiModel):
    key: str
    value: dict[str, Any]
    version: int
    updated_by: str | None
    updated_at: datetime


# ---------------------------------------------------------------------------------------------
# Mail gateways (ТЗ 1.0.2 §24, §25)
# ---------------------------------------------------------------------------------------------
class TrustedHopUpsertRequest(ApiModel):
    """A hop whose headers may be believed once the chain proves the message passed it."""

    hop_type: Literal["gateway", "exchange_edge", "exchange_mailbox", "relay"] = "gateway"
    hostname: str = Field(default="", max_length=255)
    ip_networks: list[str] = Field(default_factory=list, max_length=50)
    expected_headers: list[str] = Field(default_factory=list, max_length=50)
    #: Authentication servers whose Authentication-Results this hop is allowed to write.
    authserv_ids: list[str] = Field(default_factory=list, max_length=20)
    #: Position counted from the delivery end, or null for "anywhere in the chain".
    position_in_chain: int | None = Field(default=None, ge=0, le=50)
    enabled: bool = True


class TrustedHopOut(ApiModel):
    hop_id: str
    hop_type: str
    hostname: str
    ip_networks: list[str]
    expected_headers: list[str]
    authserv_ids: list[str]
    position_in_chain: int | None
    direction: str
    enabled: bool
    gateway_id: str | None


class GatewayUpsertRequest(ApiModel):
    provider_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    provider_type: str = Field(min_length=1, max_length=32)
    display_name: str = Field(default="", max_length=255)
    vendor: str = Field(default="", max_length=64)
    direction: Literal["inbound", "outbound", "both"] = "inbound"
    enabled: bool = True
    #: Header mappings and syslog sources. Credential *values* are refused here (ТЗ 28).
    settings: dict[str, Any] = Field(default_factory=dict)


class GatewayOut(ApiModel):
    gateway_id: str
    provider_id: str
    provider_type: str
    display_name: str
    vendor: str
    direction: str
    enabled: bool
    settings: dict[str, Any]
    capabilities: list[str]
    trusted_hops: list[TrustedHopOut]
    nodes: list[dict[str, Any]]
    last_event_at: datetime | None
    last_error: str | None
    last_error_at: datetime | None


class GatewayEvidenceOut(ApiModel):
    """One gateway observation. ``trusted`` decides whether it influenced the verdict."""

    provider_id: str
    provider_type: str
    verdict: str
    category: str
    engine: str
    threat_name: str
    score: float | None
    policy: str
    source: str
    trusted: bool
    trust_state: str
    trust_reason: str
    observed_at: datetime
    detail: dict[str, Any]


class GatewayConflictOut(ApiModel):
    conflict_id: str
    kind: str
    summary: str
    providers: list[str]
    detail: dict[str, Any]
    detected_at: datetime
    resolved_at: datetime | None = None
    resolution: str = ""


class UpstreamProtectionResponse(ApiModel):
    """The Upstream Protection card of ТЗ 1.0.2 §24."""

    message_id: str
    present: bool
    evidence: list[GatewayEvidenceOut]
    conflicts: list[GatewayConflictOut]
    note: str


# ---------------------------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------------------------
class RemediationProposeRequest(ApiModel):
    action_type: RemediationType
    reason: str = Field(min_length=5, max_length=1000)
    incident_id: str | None = Field(default=None, max_length=32)
    campaign_id: str | None = Field(default=None, max_length=32)
    message_ids: list[str] = Field(default_factory=list, max_length=1000)
    sender: str | None = Field(default=None, max_length=320)
    domain: str | None = Field(default=None, max_length=255)


class ApprovalRequest(ApiModel):
    decision: Literal["approved", "rejected"]
    comment: str = Field(default="", max_length=1000)


class RemediationOut(ApiModel):
    action_id: str
    action_type: RemediationType
    state: RemediationState
    proposed_by: str
    reason: str
    affected_message_count: int
    affected_mailboxes: list[str]
    required_approvals: int
    approvals: list[dict[str, Any]]
    dry_run_report: dict[str, Any]
    rollback_supported: bool
    executed_at: datetime | None
    executed_by: str | None
    result: dict[str, Any]
    created_at: datetime


# ---------------------------------------------------------------------------------------------
# Dashboard, providers, audit
# ---------------------------------------------------------------------------------------------
class DashboardResponse(ApiModel):
    analyses_today: int
    suspicious: int
    high_risk: int
    malicious: int
    unknown: int
    open_incidents: int
    active_campaigns: int
    employee_reports_today: int
    top_impersonated_identities: list[dict[str, Any]]
    top_malicious_domains: list[dict[str, Any]]
    top_reported_senders: list[dict[str, Any]]
    provider_health: list[dict[str, Any]]
    generated_at: datetime


class ProviderHealthOut(ApiModel):
    provider_id: str
    kind: str
    status: str
    mode: str | None
    detail: str | None
    quota: dict[str, Any] | None = None


class AuditEventOut(ApiModel):
    event_id: str
    action: str
    actor_email: str
    actor_role: str
    object_type: str
    object_id: str
    outcome: str
    detail: dict[str, Any]
    ip_address: str
    request_id: str
    created_at: datetime


class PaginatedResponse(ApiModel):
    total: int
    limit: int
    offset: int
    items: list[Any]


class ErrorResponse(ApiModel):
    detail: str
    request_id: str | None = None


# ---------------------------------------------------------------------------------------------
# Detection quality, rule lifecycle and analyst workflow (ТЗ 1.0.3 §54)
# ---------------------------------------------------------------------------------------------
class ClassificationRequest(ApiModel):
    """An analyst's verdict on an incident (ТЗ 1.0.3 §22)."""

    classification: AnalystClassification
    comment: str = Field(default="", max_length=4000)
    confidence: Literal["high", "medium", "low"] = "high"
    #: Which rules produced the wrong answer. Optional, but naming them is what turns a
    #: "false positive" into something a rule owner can actually act on.
    offending_rules: list[str] = Field(default_factory=list, max_length=50)
    offending_signals: list[str] = Field(default_factory=list, max_length=50)


class ClassificationOut(ApiModel):
    classification_id: str
    incident_id: str
    classification: AnalystClassification
    previous_classification: str | None
    analyst_email: str
    confidence: str
    comment: str
    offending_rules: list[str]
    created_at: datetime


class MissedDetectionRequest(ApiModel):
    """Report a message the platform should have caught (ТЗ 1.0.3 §26)."""

    message_id: str | None = None
    incident_id: str | None = None
    source: FalseNegativeSource
    root_cause: RootCause
    expected_detection: str = Field(default="", max_length=255)
    missing_fact: str = Field(default="", max_length=255)
    comment: str = Field(default="", max_length=4000)
    gap_id: str | None = Field(default=None, max_length=32)


class DetectionFeedbackOut(ApiModel):
    feedback_id: str
    kind: str
    message_id: str | None
    incident_id: str | None
    rule_id: str | None
    analyst_email: str
    source: str
    root_cause: str
    expected_detection: str
    missing_fact: str
    gap_id: str | None
    created_at: datetime


class SlaOut(ApiModel):
    state: str
    target: datetime | None
    remaining_seconds: int | None
    #: Elapsed stage timers. Only acknowledgement has a target; the rest are measured but not
    #: bounded, because a thorough investigation is not a breach (ТЗ 1.0.3 §19).
    timers: dict[str, int]


class QueueItemOut(ApiModel):
    """One row of the analyst queue (ТЗ 1.0.3 §17, §18)."""

    incident_id: str
    number: int
    title: str
    #: Priority is not the risk level: it is driven by consequence and spread, so a MALICIOUS
    #: message to one person can legitimately rank below a HIGH_RISK campaign aimed at finance.
    priority: str
    priority_score: int
    priority_factors: list[str]
    sla: SlaOut
    classification: str | None
    confidence: str
    status: str
    severity: str
    age_seconds: int
    affected_users: list[str]
    vip_involved: bool
    campaign_size: int
    gateway_conflict: bool
    employee_report: bool
    assignee: str | None
    analyst_classification: str | None


class AssignRequest(ApiModel):
    assignee_email: EmailStr | None = None
    #: With no assignee the platform picks the least-loaded analyst from this list.
    candidates: list[EmailStr] = Field(default_factory=list, max_length=50)


class TimelineEntryOut(ApiModel):
    """One thing that actually happened to an incident (ТЗ 1.0.3 §21)."""

    at: datetime
    event: str
    detail: str


class RuleOut(ApiModel):
    rule_id: str
    version: int
    title: str
    category: str
    severity: Severity
    status: RuleStatus
    owner: str
    weight: float
    scores: bool
    hard: bool
    scenarios: list[str]
    condition: str | None
    trigger_count: int = 0
    confirmed_tp: int = 0
    confirmed_fp: int = 0
    precision: float | None = None


class RuleStatusChangeRequest(ApiModel):
    status: RuleStatus
    reason: str = Field(min_length=10, max_length=2000)
    reviewer: str = Field(default="", max_length=320)


class SimulationRequest(ApiModel):
    message_id: str
    rule_id: str | None = Field(default=None, max_length=32)


class SimulationSignalOut(ApiModel):
    rule_id: str
    rule_version: int
    title: str
    category: str
    severity: str
    weight: float
    confidence: float
    shadow: bool
    suppressed: bool
    condition: str | None
    evidence: dict[str, Any]


class SimulationOut(ApiModel):
    message_id: str
    classification: RiskLevel
    score: int
    signals: list[SimulationSignalOut]
    matched_facts: dict[str, Any]
    missing_evidence: list[str]
    ruleset_fingerprint: str


class ReplayRequest(ApiModel):
    #: Default false: a replay answers "what would we say now", and answering a question must
    #: not by itself change the stored answer.
    apply: bool = False


class ReplayOut(ApiModel):
    revision_id: str
    analysis_job_id: str
    revision: int
    dry_run: bool
    original_classification: str
    new_classification: str
    original_score: int
    new_score: int
    added_rules: list[str]
    removed_rules: list[str]
    created_at: datetime


class ReevaluationRequest(ApiModel):
    days: int = Field(default=7, ge=1, le=90)
    dry_run: bool = True
    limit: int = Field(default=2000, ge=1, le=20000)


class ReevaluationOut(ApiModel):
    run_id: str
    window_days: int
    dry_run: bool
    messages_examined: int
    verdict_changed: int
    newly_suspicious: int
    newly_cleared: int
    affected_campaigns: list[str]
    affected_users: list[str]
    sample: list[dict[str, Any]]
    started_at: datetime
    finished_at: datetime | None


class DetectionGapOut(ApiModel):
    gap_id: str
    category: str
    description: str
    root_cause: str
    severity: Severity
    status: GapStatus
    owner: str
    target_release: str
    examples: list[str]
    mitigation: str
    planned_fix: str
    reported_misses: int = 0


class GapUpdateRequest(ApiModel):
    status: GapStatus
    note: str = Field(default="", max_length=2000)


class DetectionQualityOut(ApiModel):
    """Detection quality as measured, including what could not be measured (ТЗ 1.0.3 §35)."""

    period_start: datetime
    period_end: datetime
    total_analyzed: int
    classified: int
    confirmed_threats: int
    confirmed_benign: int
    #: Null when there is nothing to compute it from. Never 0.0 — "no data" and "nothing
    #: detected" are different findings and must not look the same in the console.
    precision: float | None
    false_positive_rate: float | None
    reported_misses: int
    unscannable: int
    unknown: int
    open_gaps: int
    shadow_rules: int
    #: Rules currently limited to part of the organisation (ТЗ 1.0.3 §52).
    active_canaries: int = 0
    #: Rollouts past their review date. Nothing expires by itself, so this is the only place an
    #: unfinished rollout becomes visible.
    overdue_canaries: int = 0
    noisy_rules: list[dict[str, Any]]
    silent_rules: list[str]
    unowned_active_rules: list[str]
    coverage_by_scenario: list[dict[str, Any]]


class ThreatScenarioOut(ApiModel):
    scenario_id: str
    title: str
    category: str
    description: str
    severity: Severity
    rules: list[str]
    fixtures: list[str]
    playbook: str
    enabled: bool
    covered: bool
    active_rules: int
    shadow_rules: int


class CampaignMergeRequest(ApiModel):
    """Fold one campaign into another (ТЗ 1.0.3 §32)."""

    source_campaign_id: str = Field(min_length=1, max_length=64)
    #: Required, because a merge is hard to undo and the next reader needs to know why the two
    #: waves were judged to be one.
    reason: str = Field(min_length=5, max_length=2000)


class CampaignSplitRequest(ApiModel):
    """Pull messages out of a campaign into a new one (ТЗ 1.0.3 §32)."""

    message_ids: list[str] = Field(min_length=1, max_length=500)
    name: str = Field(min_length=3, max_length=255)
    reason: str = Field(default="", max_length=2000)


class CanaryStartRequest(ApiModel):
    """Begin a limited rollout of an ACTIVE rule (ТЗ 1.0.3 §52)."""

    scope: CanaryScope
    #: Mailboxes or departments, depending on the scope. Empty for PERCENT.
    scope_values: list[str] = Field(default_factory=list, max_length=500)
    #: 1–99 for PERCENT. Not 100: that is not a canary.
    percent: int = Field(default=0, ge=0, le=100)
    #: When the rollout must be decided. A canary nobody ends is a rule that quietly protects
    #: some people and not others.
    days: int = Field(default=7, ge=1, le=30)
    reason: str = Field(min_length=10, max_length=4000)


class CanaryDecisionRequest(ApiModel):
    state: CanaryState
    note: str = Field(default="", max_length=4000)


class CanaryOut(ApiModel):
    """A rollout and what it has shown so far."""

    rule_id: str
    state: str
    scope: str
    scope_values: list[str]
    percent: int
    review_at: str
    overdue: bool
    inside_triggers: int
    outside_triggers: int
    inside_confirmed: int
    inside_false_positives: int
    outside_confirmed: int
    outside_false_positives: int
    #: Null until an analyst has judged something. An unjudged rollout has no precision, and
    #: showing 100% would be the argument for promoting it.
    inside_precision: float | None
    outside_precision: float | None
    ready_to_promote: bool


# ---------------------------------------------------------------------------------------------
# Feedback, rule quality, candidates, releases, re-evaluation (ТЗ 1.0.3B §38)
# ---------------------------------------------------------------------------------------------
class SignalJudgementIn(ApiModel):
    """One analyst judgement about one signal (ТЗ 1.0.3B §4)."""

    rule_id: str = Field(min_length=1, max_length=32)
    disposition: SignalDisposition
    signal_id: str | None = Field(default=None, max_length=64)
    rule_version: int = Field(default=1, ge=1)
    comment: str = Field(default="", max_length=2000)


class AnalysisFeedbackRequest(ApiModel):
    """Feedback on one analysis. Attached to the analysis, not the message: a verdict belongs
    to a revision, and a message may have several."""

    classification: AnalystClassification
    confidence: Literal["high", "medium", "low"] = "high"
    comment: str = Field(default="", max_length=4000)
    incident_id: str | None = Field(default=None, max_length=64)
    signals: list[SignalJudgementIn] = Field(default_factory=list, max_length=100)
    #: Required for FALSE_POSITIVE. The reason decides who fixes it, which a free-text comment
    #: cannot express in a way anyone can sort or assign.
    fp_reason: FalsePositiveReason | None = None


class MissedDetectionRequestV2(ApiModel):
    """Report a miss with everything needed to act on it (ТЗ 1.0.3B §6)."""

    source: FalseNegativeSource
    root_cause: RootCause
    expected_category: str = Field(min_length=2, max_length=64)
    minimum_classification: Literal["SUSPICIOUS", "HIGH_RISK", "MALICIOUS"]
    severity: Severity
    owner: str = Field(min_length=3, max_length=320)
    target_release: str = Field(min_length=2, max_length=32)
    analysis_id: str | None = Field(default=None, max_length=64)
    message_id: str | None = Field(default=None, max_length=64)
    incident_id: str | None = Field(default=None, max_length=64)
    expected_detection: str = Field(default="", max_length=255)
    missing_fact: str = Field(default="", max_length=255)
    comment: str = Field(default="", max_length=4000)
    gap_id: str | None = Field(default=None, max_length=32)


class RuleQualityOut(ApiModel):
    rule_id: str
    rule_version: int
    trigger_count: int
    analyst_reviewed: int
    true_positive: int
    false_positive: int
    unknown: int
    suppressed: int
    #: Null until enough has been judged. An unreviewed rule has unknown precision, not perfect
    #: precision, and a number here would be read as measured.
    precision: float | None
    affected_messages: int
    affected_incidents: int
    health: RuleHealth
    health_reasons: list[str]


class CandidateCreateRequest(ApiModel):
    name: str = Field(min_length=3, max_length=128)
    source: str = Field(min_length=1, max_length=512)
    description: str = Field(default="", max_length=4000)
    source_kind: Literal["path"] = "path"


class CandidateReviewRequest(ApiModel):
    approve: bool
    comment: str = Field(default="", max_length=4000)


class CandidateOut(ApiModel):
    candidate_id: str
    name: str
    description: str
    source: str
    state: CandidateState
    added_rules: list[str]
    changed_rules: list[str]
    removed_rules: list[str]
    #: True when the change touches a hard signal, malware, credential theft, impersonation or
    #: payment fraud. Such a change may not be approved by its own author.
    critical_change: bool
    critical_reasons: list[str]
    author: str
    reviewer: str
    review_comment: str
    benchmark: dict[str, Any]
    benchmarked_at: datetime | None
    published_at: datetime | None
    release_id: str | None
    created_at: datetime


class CandidateDiffOut(ApiModel):
    """Before/after for a candidate (ТЗ 1.0.3B §11)."""

    messages_examined: int
    messages_changed: int
    verdict_transitions: list[dict[str, Any]]
    newly_detected: list[str]
    newly_missed: list[str]
    new_false_positives: list[str]
    resolved_false_positives: list[str]
    affected_campaigns: list[str]


class ReleasePublishRequest(ApiModel):
    candidate_id: str | None = Field(default=None, max_length=64)
    note: str = Field(default="", max_length=4000)


class ReleaseOut(ApiModel):
    release_id: str
    version: str
    ruleset_fingerprint: str
    parser_version: str
    risk_engine_version: str
    dataset_version: str
    dataset_checksum: str
    commit_sha: str
    candidate_id: str | None
    approved_by: str
    published_by: str
    metrics: dict[str, Any]
    metric_deltas: dict[str, Any]
    known_limitations: list[dict[str, Any]]
    new_rules: list[str]
    changed_rules: list[str]
    removed_rules: list[str]
    changelog: str
    published_at: datetime


class ReanalysisCreateRequest(ApiModel):
    """Start a bulk re-evaluation (ТЗ 1.0.3B §23). Dry run unless explicitly told otherwise."""

    days: int | None = Field(default=7, ge=1, le=365)
    window_from: datetime | None = None
    window_to: datetime | None = None
    dry_run: bool = True
    max_messages: int = Field(default=5000, ge=1, le=20000)
    filters: dict[str, str] = Field(default_factory=dict)
    ruleset_source: str = Field(default="", max_length=512)


class ReanalysisOut(ApiModel):
    job_id: str
    state: ReanalysisState
    dry_run: bool
    window_from: str
    window_to: str
    filters: dict[str, Any]
    max_messages: int
    total_messages: int
    processed: int
    #: Null until the batch size is known: "not started" and "nothing to do" must not look alike.
    progress: float | None
    verdict_changed: int
    newly_suspicious: int
    newly_cleared: int
    sample: list[dict[str, Any]]
    requested_by: str
    cancelled_by: str
    created_at: str
    started_at: str | None
    finished_at: str | None


# ---------------------------------------------------------------------------------------------
# Реальный поток (ТЗ 1.0.4 §23)
# ---------------------------------------------------------------------------------------------
class RealFlowMessageOut(ApiModel):
    """Запись набора валидации.

    Ни темы, ни текста письма здесь нет, и это не упущение. Набор валидации существует для
    измерения качества детектирования; содержимое письма для этого не нужно, а отдавать его в
    список значило бы раздать персональные данные всем, кто смотрит метрики.
    """

    id: str
    source: str
    received_at: str
    message_fingerprint: str
    anonymized: bool
    pii_status: str
    anonymization_report: dict[str, Any]
    #: ``None`` — обычный случай: на реальном потоке ожидаемого ответа не существует.
    expected_classification: str | None
    #: ``None`` означает «не разобрано», а не «верно».
    analyst_classification: str | None
    reviewed_by: str
    reviewed_at: str | None
    production_verdict: str | None
    validation_verdict: str | None
    ruleset_version: str
    parser_version: str
    risk_engine_version: str
    triggered_rules: list[str]
    sampling_reasons: list[str]
    unscannable_reasons: list[str]
    promotion_state: str
    promotion_requested_by: str
    promotion_approved_by: str
    promotion_case_id: str
    promoted_dataset_version: str
    reproducibility_report: dict[str, Any]
    raw_retained_until: str | None


class RealFlowReviewRequest(ApiModel):
    classification: AnalystClassification
    comment: str = Field(default="", max_length=2000)


class PromotionRequestIn(ApiModel):
    #: Номер разбора обязателен: кейс в корпусе без ссылки на то, откуда он взялся, через год
    #: невозможно ни объяснить, ни оспорить.
    case_id: str = Field(min_length=1, max_length=32)


class PromotionDecisionRequest(ApiModel):
    """Согласование, отказ или продвижение — одним решением за раз.

    Продвижение отделено от согласования намеренно: между ними стоит проверка
    воспроизводимости, и решение, принятое до неё, принималось бы без её результата.
    """

    decision: Literal["approve", "reject", "promote"]
    reason: str = Field(default="", max_length=1000)
    dataset_version: str = Field(default="", max_length=32)
    current_dataset_version: str = Field(default="", max_length=32)


class GapValidationRequest(ApiModel):
    """Подтверждение пробела реальным потоком.

    Письма обязательны. Подтверждение без свидетельства — это заявление, а реестр пробелов
    существует как раз чтобы «мы про это знали» нельзя было сказать после события.
    """

    validation_message_ids: list[str] = Field(min_length=1, max_length=100)
    comment: str = Field(default="", max_length=2000)
