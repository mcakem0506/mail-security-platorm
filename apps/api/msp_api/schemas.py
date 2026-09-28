"""API request/response schemas (ТЗ 30: strict validation, no over-exposure)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from msp_contracts import (
    AnalysisStatus,
    ExceptionType,
    IncidentStatus,
    IOCType,
    RemediationState,
    RemediationType,
    RiskLevel,
    Role,
    Severity,
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
