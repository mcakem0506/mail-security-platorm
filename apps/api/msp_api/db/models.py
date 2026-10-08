"""Data model (ТЗ 26).

Storage separation (ТЗ 26.1, 27): metadata, normalised body, raw body, raw EML and attachments
live in different places with different retention. Only metadata and references are kept in
PostgreSQL; raw EML and attachment bytes go to object storage under a stricter ACL, and each
category is deleted independently by the retention worker.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from msp_contracts import (
    AnalysisStatus,
    AnalystClassification,
    CanaryScope,
    CanaryState,
    CandidateState,
    DomainVariantStatus,
    ExceptionType,
    GapStatus,
    IncidentStatus,
    IntakeSource,
    IntakeState,
    IOCType,
    JobState,
    PiiStatus,
    PromotionState,
    ReanalysisState,
    RemediationState,
    RemediationType,
    RiskLevel,
    Role,
    RuleHealth,
    Severity,
    SignalDisposition,
    TIState,
    TIStatus,
    ValidationSource,
)
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, IdMixin, TimestampMixin, UTCDateTime, utcnow


def _enum(enum_cls: type, name: str) -> Enum:
    return Enum(enum_cls, name=name, native_enum=False, values_callable=lambda e: [i.value for i in e])


# ---------------------------------------------------------------------------------------------
# Organisation, identity and access
# ---------------------------------------------------------------------------------------------
class Organization(Base, IdMixin, TimestampMixin):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    corporate_domains: Mapped[list[Any]] = mapped_column(default=list)
    trusted_infrastructure_domains: Mapped[list[Any]] = mapped_column(default=list)
    settings: Mapped[dict[str, Any]] = mapped_column(default=dict)


class User(Base, IdMixin, TimestampMixin):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email", name="uq_users_email"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    role: Mapped[Role] = mapped_column(_enum(Role, "role_enum"), default=Role.EMPLOYEE, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    auth_source: Mapped[str] = mapped_column(String(32), default="local")  # local|ldap|oidc
    password_hash: Mapped[str | None] = mapped_column(String(255), default=None)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)


class MailboxIdentity(Base, IdMixin, TimestampMixin):
    """A mailbox the platform knows about; links messages to a user without exposing content."""

    __tablename__ = "mailbox_identities"
    __table_args__ = (UniqueConstraint("organization_id", "address", name="uq_mailbox_address"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), default=None, index=True)
    address: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    aliases: Mapped[list[Any]] = mapped_column(default=list)
    department: Mapped[str] = mapped_column(String(255), default="")
    title: Mapped[str] = mapped_column(String(255), default="")
    directory_object_id: Mapped[str | None] = mapped_column(String(128), default=None, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    deleted_in_directory: Mapped[bool] = mapped_column(Boolean, default=False)
    manual_override: Mapped[bool] = mapped_column(Boolean, default=False)
    last_synced_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class ProtectedIdentity(Base, IdMixin, TimestampMixin):
    __tablename__ = "protected_identities"

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    mailbox_identity_id: Mapped[str | None] = mapped_column(ForeignKey("mailbox_identities.id"), default=None)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    categories: Mapped[list[Any]] = mapped_column(default=list)
    aliases: Mapped[list[Any]] = mapped_column(default=list)
    name_variants: Mapped[list[Any]] = mapped_column(default=list)
    approved_delegates: Mapped[list[Any]] = mapped_column(default=list)
    approved_external_systems: Mapped[list[Any]] = mapped_column(default=list)
    department: Mapped[str] = mapped_column(String(255), default="")
    title: Mapped[str] = mapped_column(String(255), default="")
    # How much damage impersonating this identity could do: critical|high|medium|low. Kept
    # separate from `categories` because a finance clerk and the CFO share a category but not
    # a blast radius (ТЗ 1.0.1 §5).
    risk_class: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    vip: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    protected: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(16), default="manual")  # manual|directory
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str | None] = mapped_column(String(320), default=None)


# ---------------------------------------------------------------------------------------------
# Messages and content
# ---------------------------------------------------------------------------------------------
class MailMessage(Base, IdMixin, TimestampMixin):
    """Message metadata. Content lives in MailContent / object storage (ТЗ 26.1)."""

    __tablename__ = "mail_messages"
    __table_args__ = (
        Index("ix_mail_messages_org_received", "organization_id", "received_at"),
        Index("ix_mail_messages_sender", "organization_id", "sender_address"),
        Index("ix_mail_messages_fingerprint", "organization_id", "campaign_fingerprint"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    internet_message_id: Mapped[str] = mapped_column(String(998), default="", index=True)
    raw_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(1000), default="")
    sender_address: Mapped[str] = mapped_column(String(320), default="", index=True)
    sender_display_name: Mapped[str] = mapped_column(String(512), default="")
    sender_domain: Mapped[str] = mapped_column(String(255), default="", index=True)
    reply_to_address: Mapped[str] = mapped_column(String(320), default="")
    return_path: Mapped[str] = mapped_column(String(320), default="")
    recipient_count: Mapped[int] = mapped_column(Integer, default=0)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    source: Mapped[IntakeSource] = mapped_column(_enum(IntakeSource, "intake_source_enum"))
    source_mailbox: Mapped[str] = mapped_column(String(320), default="")
    exchange_item_id: Mapped[str] = mapped_column(String(512), default="")
    has_attachments: Mapped[bool] = mapped_column(Boolean, default=False)
    url_count: Mapped[int] = mapped_column(Integer, default=0)
    encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    parse_errors: Mapped[list[Any]] = mapped_column(default=list)
    auth_summary: Mapped[dict[str, Any]] = mapped_column(default=dict)  # spf/dkim/dmarc results
    campaign_fingerprint: Mapped[str] = mapped_column(String(64), default="", index=True)
    campaign_components: Mapped[dict[str, Any]] = mapped_column(default=dict)
    body_simhash: Mapped[str] = mapped_column(String(32), default="")
    reported_by: Mapped[str | None] = mapped_column(String(320), default=None)

    recipients: Mapped[list[MailRecipient]] = relationship(
        back_populates="message", cascade="all, delete-orphan"
    )
    headers: Mapped[list[MailHeader]] = relationship(back_populates="message", cascade="all, delete-orphan")
    attachments: Mapped[list[Attachment]] = relationship(
        back_populates="message", cascade="all, delete-orphan"
    )
    content: Mapped[MailContent | None] = relationship(
        back_populates="message", cascade="all, delete-orphan", uselist=False
    )


class MailContent(Base, IdMixin, TimestampMixin):
    """Body storage with per-category retention (ТЗ 26.1, 27)."""

    __tablename__ = "mail_contents"

    message_id: Mapped[str] = mapped_column(
        ForeignKey("mail_messages.id", ondelete="CASCADE"), unique=True, index=True
    )
    normalized_text: Mapped[str | None] = mapped_column(Text, default=None)
    sanitized_html: Mapped[str | None] = mapped_column(Text, default=None)
    raw_body_key: Mapped[str | None] = mapped_column(String(512), default=None)
    raw_eml_key: Mapped[str | None] = mapped_column(String(512), default=None)
    normalized_purged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    raw_body_purged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    raw_eml_purged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)

    message: Mapped[MailMessage] = relationship(back_populates="content")


class MailRecipient(Base, IdMixin):
    __tablename__ = "mail_recipients"
    __table_args__ = (Index("ix_mail_recipients_address", "address"),)

    message_id: Mapped[str] = mapped_column(ForeignKey("mail_messages.id", ondelete="CASCADE"), index=True)
    address: Mapped[str] = mapped_column(String(320), default="")
    display_name: Mapped[str] = mapped_column(String(512), default="")
    kind: Mapped[str] = mapped_column(String(8), default="to")  # to|cc|bcc
    is_internal: Mapped[bool] = mapped_column(Boolean, default=False)

    message: Mapped[MailMessage] = relationship(back_populates="recipients")


class MailHeader(Base, IdMixin):
    __tablename__ = "mail_headers"

    message_id: Mapped[str] = mapped_column(ForeignKey("mail_messages.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    value: Mapped[str] = mapped_column(Text, default="")
    position: Mapped[int] = mapped_column(Integer, default=0)

    message: Mapped[MailMessage] = relationship(back_populates="headers")


class Attachment(Base, IdMixin, TimestampMixin):
    __tablename__ = "attachments"

    message_id: Mapped[str] = mapped_column(ForeignKey("mail_messages.id", ondelete="CASCADE"), index=True)
    filename: Mapped[str] = mapped_column(String(512), default="")
    normalized_filename: Mapped[str] = mapped_column(String(512), default="")
    declared_mime: Mapped[str] = mapped_column(String(255), default="")
    detected_type: Mapped[str] = mapped_column(String(64), default="")
    extension: Mapped[str] = mapped_column(String(32), default="")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), default="", index=True)
    sha1: Mapped[str | None] = mapped_column(String(40), default=None)
    md5: Mapped[str | None] = mapped_column(String(32), default=None)
    depth: Mapped[int] = mapped_column(Integer, default=0)
    parent_sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    is_archive: Mapped[bool] = mapped_column(Boolean, default=False)
    encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    flags: Mapped[list[Any]] = mapped_column(default=list)
    archive_summary: Mapped[dict[str, Any]] = mapped_column(default=dict)
    storage_key: Mapped[str | None] = mapped_column(String(512), default=None)
    purged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    scan_result: Mapped[dict[str, Any]] = mapped_column(default=dict)

    message: Mapped[MailMessage] = relationship(back_populates="attachments")


# ---------------------------------------------------------------------------------------------
# Indicators and provider lookups
# ---------------------------------------------------------------------------------------------
class Indicator(Base, IdMixin, TimestampMixin):
    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("organization_id", "ioc_type", "value", name="uq_indicator_value"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    ioc_type: Mapped[IOCType] = mapped_column(_enum(IOCType, "ioc_type_enum"), index=True)
    value: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    sighting_count: Mapped[int] = mapped_column(Integer, default=0)
    worst_status: Mapped[TIStatus | None] = mapped_column(
        _enum(TIStatus, "ti_status_enum"), default=None, index=True
    )
    confirmed_malicious: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    notes: Mapped[str] = mapped_column(Text, default="")


class IndicatorObservation(Base, IdMixin):
    __tablename__ = "indicator_observations"
    __table_args__ = (Index("ix_observations_indicator_time", "indicator_id", "observed_at"),)

    indicator_id: Mapped[str] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"), index=True)
    message_id: Mapped[str | None] = mapped_column(
        ForeignKey("mail_messages.id", ondelete="CASCADE"), default=None, index=True
    )
    context: Mapped[str] = mapped_column(String(64), default="")
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class ProviderLookup(Base, IdMixin):
    """Normalised provider answers. Raw provider JSON is never stored here (ТЗ 42.9)."""

    __tablename__ = "provider_lookups"
    __table_args__ = (Index("ix_lookups_provider_indicator", "provider_id", "indicator_value"),)

    analysis_job_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_jobs.id", ondelete="CASCADE"), default=None, index=True
    )
    provider_id: Mapped[str] = mapped_column(String(64), index=True)
    ioc_type: Mapped[IOCType] = mapped_column(_enum(IOCType, "ioc_type_enum"))
    indicator_value: Mapped[str] = mapped_column(String(1024), default="")
    status: Mapped[TIStatus] = mapped_column(_enum(TIStatus, "ti_status_enum"), index=True)
    malicious_count: Mapped[int | None] = mapped_column(Integer, default=None)
    total_count: Mapped[int | None] = mapped_column(Integer, default=None)
    categories: Mapped[list[Any]] = mapped_column(default=list)
    summary: Mapped[dict[str, Any]] = mapped_column(default=dict)
    from_cache: Mapped[bool] = mapped_column(Boolean, default=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer, default=None)
    error: Mapped[str | None] = mapped_column(String(255), default=None)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


# ---------------------------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------------------------
class AnalysisJob(Base, IdMixin, TimestampMixin):
    __tablename__ = "analysis_jobs"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_jobs_idempotency"),
        Index("ix_jobs_org_state", "organization_id", "state"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    message_id: Mapped[str | None] = mapped_column(
        ForeignKey("mail_messages.id", ondelete="SET NULL"), default=None, index=True
    )
    requested_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), default=None, index=True)
    requester_mailbox: Mapped[str] = mapped_column(String(320), default="", index=True)
    source: Mapped[IntakeSource] = mapped_column(_enum(IntakeSource, "intake_source_enum"))
    state: Mapped[JobState] = mapped_column(
        _enum(JobState, "job_state_enum"), default=JobState.QUEUED, index=True
    )
    ti_state: Mapped[TIState] = mapped_column(_enum(TIState, "ti_state_enum"), default=TIState.NOT_REQUIRED)
    status: Mapped[AnalysisStatus] = mapped_column(
        _enum(AnalysisStatus, "analysis_status_enum"), default=AnalysisStatus.QUEUED, index=True
    )
    idempotency_key: Mapped[str | None] = mapped_column(String(128), default=None)
    is_report: Mapped[bool] = mapped_column(Boolean, default=False)
    user_note: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    duration_ms: Mapped[int | None] = mapped_column(Integer, default=None)
    error: Mapped[str | None] = mapped_column(String(500), default=None)
    warnings: Mapped[list[Any]] = mapped_column(default=list)
    # COMPLETE|LIMIT_EXCEEDED|UNSCANNABLE|PARTIAL. A job that could not examine the whole
    # message must never be presented as one that found nothing (ТЗ 1.0.1 §4.2).
    scan_completeness: Mapped[str] = mapped_column(String(16), default="COMPLETE", index=True)

    result: Mapped[AnalysisResult | None] = relationship(
        back_populates="job", cascade="all, delete-orphan", uselist=False
    )


class AnalysisResult(Base, IdMixin, TimestampMixin):
    __tablename__ = "analysis_results"

    job_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_jobs.id", ondelete="CASCADE"), unique=True, index=True
    )
    message_id: Mapped[str | None] = mapped_column(
        ForeignKey("mail_messages.id", ondelete="CASCADE"), default=None, index=True
    )
    classification: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "risk_level_enum"), index=True)
    score: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[str] = mapped_column(String(16), default="low")
    confidence_value: Mapped[float] = mapped_column(Float, default=0.0)
    recommendation: Mapped[str] = mapped_column(Text, default="")
    reasons: Mapped[list[Any]] = mapped_column(default=list)
    hard_signals: Mapped[list[Any]] = mapped_column(default=list)
    suppressed_signals: Mapped[list[Any]] = mapped_column(default=list)
    sources: Mapped[list[Any]] = mapped_column(default=list)
    missing_evidence: Mapped[list[Any]] = mapped_column(default=list)
    facts: Mapped[dict[str, Any]] = mapped_column(default=dict)
    engine_version: Mapped[str] = mapped_column(String(32), default="")
    ruleset_fingerprint: Mapped[str] = mapped_column(Text, default="")
    risk_engine_version: Mapped[str] = mapped_column(String(32), default="")
    scan_completeness: Mapped[str] = mapped_column(String(16), default="COMPLETE")

    job: Mapped[AnalysisJob] = relationship(back_populates="result")
    signals: Mapped[list[DetectionSignal]] = relationship(
        back_populates="result", cascade="all, delete-orphan"
    )


class DetectionSignal(Base, IdMixin):
    __tablename__ = "detection_signals"
    __table_args__ = (Index("ix_signals_rule", "rule_id", "rule_version"),)

    result_id: Mapped[str] = mapped_column(ForeignKey("analysis_results.id", ondelete="CASCADE"), index=True)
    signal_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_id: Mapped[str | None] = mapped_column(String(32), default=None, index=True)
    rule_version: Mapped[int | None] = mapped_column(Integer, default=None)
    category: Mapped[str] = mapped_column(String(64), default="", index=True)
    title: Mapped[str] = mapped_column(String(255), default="")
    explanation: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity_enum"), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    weight: Mapped[float] = mapped_column(Float, default=0.0)
    source: Mapped[str] = mapped_column(String(64), default="")
    evidence: Mapped[dict[str, Any]] = mapped_column(default=dict)
    hard: Mapped[bool] = mapped_column(Boolean, default=False)
    internal: Mapped[bool] = mapped_column(Boolean, default=False)
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    suppressed_by: Mapped[str | None] = mapped_column(String(128), default=None)
    #: A shadow rule fired but contributed nothing to the score (ТЗ 1.0.3 §11).
    #: Persisted because the only way to decide whether a candidate rule is ready to go ACTIVE
    #: is to measure it against real mail. A flag the engine computes but never stores would
    #: make shadow mode unmeasurable, and an unmeasurable shadow mode is pointless.
    shadow: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    #: The rule's lifecycle status at the moment it fired, so a later status change does not
    #: retroactively change how a historical verdict reads.
    rule_status: Mapped[str] = mapped_column(String(16), default="ACTIVE")
    #: Why a signal from a scoring rule did not count, when that was not its lifecycle status:
    #: currently only ``canary`` (ТЗ 1.0.3 §52). Stored separately from ``shadow`` so a rollout
    #: can be measured against the recipients it did not reach.
    withheld_by: Mapped[str | None] = mapped_column(String(16), default=None, index=True)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    result: Mapped[AnalysisResult] = relationship(back_populates="signals")


class RiskVerdictHistory(Base, IdMixin):
    """Verdict changes over time (re-check after new intelligence arrives)."""

    __tablename__ = "risk_verdicts"

    message_id: Mapped[str] = mapped_column(ForeignKey("mail_messages.id", ondelete="CASCADE"), index=True)
    classification: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "risk_level_enum"))
    score: Mapped[int] = mapped_column(Integer, default=0)
    reason: Mapped[str] = mapped_column(String(255), default="")
    changed_by: Mapped[str | None] = mapped_column(String(320), default=None)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


# ---------------------------------------------------------------------------------------------
# Campaigns and incidents
# ---------------------------------------------------------------------------------------------
class Campaign(Base, IdMixin, TimestampMixin):
    __tablename__ = "campaigns"
    __table_args__ = (UniqueConstraint("organization_id", "fingerprint", name="uq_campaign_fingerprint"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    message_count: Mapped[int] = mapped_column(Integer, default=0)
    recipient_count: Mapped[int] = mapped_column(Integer, default=0)
    reported_count: Mapped[int] = mapped_column(Integer, default=0)
    verdict_distribution: Mapped[dict[str, Any]] = mapped_column(default=dict)
    indicators: Mapped[list[Any]] = mapped_column(default=list)
    subjects: Mapped[list[Any]] = mapped_column(default=list)
    senders: Mapped[list[Any]] = mapped_column(default=list)
    confirmed_malicious: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    remediation_state: Mapped[str] = mapped_column(String(32), default="none")
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), default=None, index=True
    )


class CampaignMessage(Base, IdMixin):
    __tablename__ = "campaign_messages"
    __table_args__ = (UniqueConstraint("campaign_id", "message_id", name="uq_campaign_message"),)

    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), index=True)
    message_id: Mapped[str] = mapped_column(ForeignKey("mail_messages.id", ondelete="CASCADE"), index=True)
    similarity: Mapped[float] = mapped_column(Float, default=1.0)
    added_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Case(Base, IdMixin, TimestampMixin):
    """Several campaigns may be grouped into one case (ТЗ 19.2)."""

    __tablename__ = "cases"

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    title: Mapped[str] = mapped_column(String(255), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    owner: Mapped[str | None] = mapped_column(String(320), default=None)


class Incident(Base, IdMixin, TimestampMixin):
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_org_status", "organization_id", "status"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id", ondelete="SET NULL"), default=None)
    number: Mapped[int] = mapped_column(Integer, autoincrement=False, default=0, index=True)
    title: Mapped[str] = mapped_column(String(255), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[IncidentStatus] = mapped_column(
        _enum(IncidentStatus, "incident_status_enum"), default=IncidentStatus.NEW, index=True
    )
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity_enum"), default=Severity.MEDIUM)
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    assigned_to: Mapped[str | None] = mapped_column(ForeignKey("users.id"), default=None, index=True)
    opened_by: Mapped[str | None] = mapped_column(String(320), default=None)
    affected_users: Mapped[list[Any]] = mapped_column(default=list)
    timeline: Mapped[list[Any]] = mapped_column(default=list)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    triaged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    remediated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class IncidentMessage(Base, IdMixin):
    __tablename__ = "incident_messages"
    __table_args__ = (UniqueConstraint("incident_id", "message_id", name="uq_incident_message"),)

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    message_id: Mapped[str] = mapped_column(ForeignKey("mail_messages.id", ondelete="CASCADE"), index=True)
    added_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class IncidentIndicator(Base, IdMixin):
    __tablename__ = "incident_indicators"
    __table_args__ = (UniqueConstraint("incident_id", "indicator_id", name="uq_incident_indicator"),)

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    indicator_id: Mapped[str] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"), index=True)
    added_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AnalystNote(Base, IdMixin, TimestampMixin):
    __tablename__ = "analyst_notes"

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    author_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), default=None)
    author_email: Mapped[str] = mapped_column(String(320), default="")
    body: Mapped[str] = mapped_column(Text, default="")


# ---------------------------------------------------------------------------------------------
# Policy, exceptions, remediation
# ---------------------------------------------------------------------------------------------
class Policy(Base, IdMixin, TimestampMixin):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("organization_id", "key", name="uq_policy_key"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    value: Mapped[dict[str, Any]] = mapped_column(default=dict)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_by: Mapped[str | None] = mapped_column(String(320), default=None)


class PolicyVersion(Base, IdMixin):
    __tablename__ = "policy_versions"

    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    value: Mapped[dict[str, Any]] = mapped_column(default=dict)
    changed_by: Mapped[str | None] = mapped_column(String(320), default=None)
    change_reason: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class DetectionException(Base, IdMixin, TimestampMixin):
    """False-positive control. Every exception has an owner, reason, expiry and audit (ТЗ 15.3)."""

    __tablename__ = "detection_exceptions"
    __table_args__ = (Index("ix_exceptions_org_active", "organization_id", "revoked_at"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    exception_type: Mapped[ExceptionType] = mapped_column(_enum(ExceptionType, "exception_type_enum"))
    value: Mapped[str] = mapped_column(String(512), default="", index=True)
    rule_id: Mapped[str | None] = mapped_column(String(32), default=None, index=True)
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), default=None)
    owner_email: Mapped[str] = mapped_column(String(320), default="")
    reason: Mapped[str] = mapped_column(String(1000), default="")
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    revoked_by: Mapped[str | None] = mapped_column(String(320), default=None)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    # -- governance v2 (ТЗ 1.0.3 §24, §25) ----------------------------------------------------
    #: GLOBAL | DOMAIN | SENDER | RECIPIENT | DEPARTMENT | RULE | INDICATOR
    scope: Mapped[str] = mapped_column(String(16), default="SENDER", index=True)
    created_by: Mapped[str] = mapped_column(String(320), default="")
    #: A high-risk exception needs a second approval before it takes effect (§25). Until then
    #: it exists but does not suppress anything.
    approved_by: Mapped[str | None] = mapped_column(String(320), default=None)
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    #: When someone should look at this again, separate from when it expires.
    review_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None, index=True)
    last_hit_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)

    @property
    def active(self) -> bool:
        """Whether this exception currently suppresses anything.

        An exception awaiting its second approval is deliberately inert: creating it must not
        be enough to silence a malware or VIP-impersonation signal (§25).
        """
        if self.revoked_at is not None:
            return False
        return not (self.requires_approval and self.approved_by is None)


class RemediationAction(Base, IdMixin, TimestampMixin):
    __tablename__ = "remediation_actions"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_remediation_idempotency"),
        CheckConstraint("affected_message_count >= 0", name="affected_non_negative"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), default=None, index=True
    )
    campaign_id: Mapped[str | None] = mapped_column(
        ForeignKey("campaigns.id", ondelete="SET NULL"), default=None
    )
    action_type: Mapped[RemediationType] = mapped_column(_enum(RemediationType, "remediation_type_enum"))
    state: Mapped[RemediationState] = mapped_column(
        _enum(RemediationState, "remediation_state_enum"), default=RemediationState.PROPOSED, index=True
    )
    proposed_by: Mapped[str] = mapped_column(String(320), default="")
    reason: Mapped[str] = mapped_column(String(1000), default="")
    target_selector: Mapped[dict[str, Any]] = mapped_column(default=dict)
    affected_message_count: Mapped[int] = mapped_column(Integer, default=0)
    affected_mailboxes: Mapped[list[Any]] = mapped_column(default=list)
    dry_run_report: Mapped[dict[str, Any]] = mapped_column(default=dict)
    required_approvals: Mapped[int] = mapped_column(Integer, default=1)
    executed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    executed_by: Mapped[str | None] = mapped_column(String(320), default=None)
    rollback_token: Mapped[str | None] = mapped_column(String(128), default=None)
    rollback_supported: Mapped[bool] = mapped_column(Boolean, default=False)
    result: Mapped[dict[str, Any]] = mapped_column(default=dict)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), default=None)

    approvals: Mapped[list[Approval]] = relationship(back_populates="action", cascade="all, delete-orphan")


class Approval(Base, IdMixin):
    __tablename__ = "approvals"
    __table_args__ = (UniqueConstraint("action_id", "approver_id", name="uq_approval_once"),)

    action_id: Mapped[str] = mapped_column(
        ForeignKey("remediation_actions.id", ondelete="CASCADE"), index=True
    )
    approver_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    approver_email: Mapped[str] = mapped_column(String(320), default="")
    decision: Mapped[str] = mapped_column(String(16), default="approved")  # approved|rejected
    comment: Mapped[str] = mapped_column(String(1000), default="")
    decided_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    action: Mapped[RemediationAction] = relationship(back_populates="approvals")


# ---------------------------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------------------------
class Notification(Base, IdMixin, TimestampMixin):
    __tablename__ = "notifications"

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    event: Mapped[str] = mapped_column(String(64), index=True)
    channel: Mapped[str] = mapped_column(String(32), default="dashboard")
    recipient: Mapped[str] = mapped_column(String(320), default="")
    subject: Mapped[str] = mapped_column(String(500), default="")
    body: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict[str, Any]] = mapped_column(default=dict)
    state: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    error: Mapped[str | None] = mapped_column(String(500), default=None)
    read_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class AuditEvent(Base, IdMixin):
    """Append-only audit trail (ТЗ 25). Never contains secrets, tokens or message bodies."""

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_org_time", "organization_id", "created_at"),
        Index("ix_audit_actor", "actor_email", "created_at"),
    )

    organization_id: Mapped[str | None] = mapped_column(String(32), default=None, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(32), default=None)
    actor_email: Mapped[str] = mapped_column(String(320), default="")
    actor_role: Mapped[str] = mapped_column(String(32), default="")
    object_type: Mapped[str] = mapped_column(String(64), default="", index=True)
    object_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    outcome: Mapped[str] = mapped_column(String(16), default="success")
    detail: Mapped[dict[str, Any]] = mapped_column(default=dict)
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")
    request_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class ProviderConfig(Base, IdMixin, TimestampMixin):
    """Provider configuration. Secrets are referenced, never stored here (ТЗ 28)."""

    __tablename__ = "provider_configs"
    __table_args__ = (UniqueConstraint("organization_id", "provider_id", name="uq_provider_config"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    provider_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), default="threat_intel")
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mode: Mapped[str] = mapped_column(String(32), default="disabled")
    settings: Mapped[dict[str, Any]] = mapped_column(default=dict)
    secret_ref: Mapped[str | None] = mapped_column(String(255), default=None)
    updated_by: Mapped[str | None] = mapped_column(String(320), default=None)


class HealthSnapshot(Base, IdMixin):
    __tablename__ = "health_snapshots"

    component: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="unknown")
    detail: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class DirectorySyncRun(Base, IdMixin):
    __tablename__ = "directory_sync_runs"

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    provider_id: Mapped[str] = mapped_column(String(64), default="")
    incremental: Mapped[bool] = mapped_column(Boolean, default=False)
    created: Mapped[int] = mapped_column(Integer, default=0)
    updated: Mapped[int] = mapped_column(Integer, default=0)
    disabled: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[list[Any]] = mapped_column(default=list)
    high_watermark: Mapped[str | None] = mapped_column(String(64), default=None)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class RetentionRun(Base, IdMixin):
    """Record of what retention deleted — the technical fact of deletion is kept (ТЗ 27)."""

    __tablename__ = "retention_runs"

    organization_id: Mapped[str | None] = mapped_column(String(32), default=None, index=True)
    category: Mapped[str] = mapped_column(String(32), index=True)
    deleted_count: Mapped[int] = mapped_column(Integer, default=0)
    cutoff: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    detail: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


# ---------------------------------------------------------------------------------------------
# Durable intake (ТЗ 1.0.1 §4.1)
# ---------------------------------------------------------------------------------------------
class IntakeRecord(Base, IdMixin, TimestampMixin):
    """One message pulled from the security mailbox, tracked until it is safely handed over.

    The record exists so that a worker crash cannot lose a report. It is written *before* the
    message is acknowledged in the mailbox, and the mailbox flag is only changed once the
    analysis job is committed — so the worst outcome of a crash is that the same message is
    fetched again, which the deduplication keys below make harmless.
    """

    __tablename__ = "intake_records"
    __table_args__ = (
        # Three independent identities, because none alone is sufficient: a UID is unique only
        # within one mailbox generation, a Message-ID can be absent or forged, and the content
        # hash cannot distinguish two genuine reports of the same message by different people.
        UniqueConstraint("organization_id", "source_id", "mailbox_uid", name="uq_intake_uid"),
        Index("ix_intake_content", "organization_id", "content_sha256"),
        Index("ix_intake_state", "organization_id", "state"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    source: Mapped[IntakeSource] = mapped_column(_enum(IntakeSource, "intake_source_enum"))
    #: Which mailbox/folder this came from, so the same UID in two mailboxes does not collide.
    source_id: Mapped[str] = mapped_column(String(320), default="")
    mailbox_uid: Mapped[str] = mapped_column(String(128), default="", index=True)
    internet_message_id: Mapped[str] = mapped_column(String(998), default="", index=True)
    content_sha256: Mapped[str] = mapped_column(String(64), default="", index=True)
    reported_by: Mapped[str] = mapped_column(String(320), default="")
    state: Mapped[IntakeState] = mapped_column(
        _enum(IntakeState, "intake_state_enum"), default=IntakeState.FETCHED, index=True
    )
    raw_storage_key: Mapped[str | None] = mapped_column(String(512), default=None)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    #: True when the message exceeded a limit and was deliberately not analysed (§4.2).
    oversized: Mapped[bool] = mapped_column(Boolean, default=False)
    analysis_job_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_jobs.id", ondelete="SET NULL"), default=None, index=True
    )
    #: The record this one duplicates, when the same report arrived twice.
    duplicate_of_id: Mapped[str | None] = mapped_column(String(32), default=None, index=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(String(500), default=None)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    warnings: Mapped[list[Any]] = mapped_column(default=list)


# ---------------------------------------------------------------------------------------------
# Mail gateway topology and evidence (ТЗ 1.0.2 §16, §22, §23, §28)
# ---------------------------------------------------------------------------------------------
class MailGateway(Base, IdMixin, TimestampMixin):
    """A configured upstream gateway. Having none is a valid deployment (ТЗ 1.0.2 §31)."""

    __tablename__ = "mail_gateways"
    __table_args__ = (UniqueConstraint("organization_id", "provider_id", name="uq_mail_gateway"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    provider_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    provider_type: Mapped[str] = mapped_column(String(32), default="generic_header")
    display_name: Mapped[str] = mapped_column(String(255), default="")
    vendor: Mapped[str] = mapped_column(String(64), default="")
    direction: Mapped[str] = mapped_column(String(16), default="inbound")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    #: Header mappings, syslog settings, API settings — never a credential value (ТЗ 28).
    settings: Mapped[dict[str, Any]] = mapped_column(default=dict)
    last_event_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    last_error: Mapped[str | None] = mapped_column(String(500), default=None)
    last_error_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    updated_by: Mapped[str | None] = mapped_column(String(320), default=None)

    nodes: Mapped[list[MailGatewayNode]] = relationship(
        back_populates="gateway", cascade="all, delete-orphan"
    )
    hops: Mapped[list[TrustedHop]] = relationship(back_populates="gateway", cascade="all, delete-orphan")


class MailGatewayNode(Base, IdMixin, TimestampMixin):
    """A physical node of a gateway cluster (KSMG-01, KSMG-02, and so on)."""

    __tablename__ = "mail_gateway_nodes"

    gateway_id: Mapped[str] = mapped_column(ForeignKey("mail_gateways.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="", index=True)
    ip_networks: Mapped[list[Any]] = mapped_column(default=list)
    role: Mapped[str] = mapped_column(String(32), default="gateway")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    gateway: Mapped[MailGateway] = relationship(back_populates="nodes")


class TrustedHop(Base, IdMixin, TimestampMixin):
    """A hop whose headers may be believed, once the chain proves the message passed it.

    This is the ``TrustedMailHop`` entity of ТЗ 1.0.1 §4.3. It exists separately from
    :class:`MailGatewayNode` because not every trusted hop belongs to a gateway: the Exchange
    edge and mailbox servers are trusted hops with no gateway behind them.
    """

    __tablename__ = "trusted_mail_hops"
    __table_args__ = (Index("ix_trusted_hops_org", "organization_id", "enabled"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    gateway_id: Mapped[str | None] = mapped_column(
        ForeignKey("mail_gateways.id", ondelete="CASCADE"), default=None, index=True
    )
    hop_type: Mapped[str] = mapped_column(String(32), default="gateway")
    hostname: Mapped[str] = mapped_column(String(255), default="", index=True)
    ip_networks: Mapped[list[Any]] = mapped_column(default=list)
    expected_headers: Mapped[list[Any]] = mapped_column(default=list)
    authserv_ids: Mapped[list[Any]] = mapped_column(default=list)
    position_in_chain: Mapped[int | None] = mapped_column(Integer, default=None)
    direction: Mapped[str] = mapped_column(String(16), default="inbound")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_by: Mapped[str | None] = mapped_column(String(320), default=None)

    gateway: Mapped[MailGateway | None] = relationship(back_populates="hops")


class MailRoute(Base, IdMixin, TimestampMixin):
    """An expected delivery path, as an ordered list of hop ids (ТЗ 1.0.2 §22)."""

    __tablename__ = "mail_routes"

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    direction: Mapped[str] = mapped_column(String(16), default="inbound")
    #: Ordered from the Internet inwards, for example ksmg-01, exch-edge-01, exch-mbx-01.
    hop_sequence: Mapped[list[Any]] = mapped_column(default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class GatewayCredential(Base, IdMixin, TimestampMixin):
    """A reference to a gateway API credential. The value never reaches this table (ТЗ 28)."""

    __tablename__ = "gateway_credentials"
    __table_args__ = (UniqueConstraint("gateway_id", "purpose", name="uq_gateway_credential"),)

    gateway_id: Mapped[str] = mapped_column(ForeignKey("mail_gateways.id", ondelete="CASCADE"), index=True)
    purpose: Mapped[str] = mapped_column(String(32), default="api")
    auth_scheme: Mapped[str] = mapped_column(String(32), default="bearer")
    username: Mapped[str] = mapped_column(String(255), default="")
    #: Where the secret lives: a file path, a Vault path or a Docker secret name.
    secret_ref: Mapped[str] = mapped_column(String(255), default="")
    rotated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    rotated_by: Mapped[str | None] = mapped_column(String(320), default=None)


class GatewayCapabilityState(Base, IdMixin, TimestampMixin):
    """What a gateway was last *observed* to support (ТЗ 1.0.2 §22).

    Capabilities are probed, never inferred from the product name, so this table records the
    result of probing together with when it was established.
    """

    __tablename__ = "gateway_capability_states"
    __table_args__ = (UniqueConstraint("gateway_id", "capability", name="uq_gateway_capability"),)

    gateway_id: Mapped[str] = mapped_column(ForeignKey("mail_gateways.id", ondelete="CASCADE"), index=True)
    capability: Mapped[str] = mapped_column(String(32), index=True)
    available: Mapped[bool] = mapped_column(Boolean, default=False)
    detail: Mapped[str] = mapped_column(String(500), default="")
    checked_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class GatewayEvidenceRecord(Base, IdMixin):
    """One normalised gateway observation about one message (ТЗ 1.0.2 §16)."""

    __tablename__ = "gateway_evidence"
    __table_args__ = (
        Index("ix_gateway_evidence_message", "message_id", "provider_id"),
        Index("ix_gateway_evidence_time", "organization_id", "observed_at"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    message_id: Mapped[str | None] = mapped_column(
        ForeignKey("mail_messages.id", ondelete="CASCADE"), default=None, index=True
    )
    provider_id: Mapped[str] = mapped_column(String(64), index=True)
    provider_type: Mapped[str] = mapped_column(String(32), default="")
    verdict: Mapped[str] = mapped_column(String(32), default="UNKNOWN", index=True)
    category: Mapped[str] = mapped_column(String(32), default="unknown")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    score: Mapped[float | None] = mapped_column(Float, default=None)
    threat_name: Mapped[str] = mapped_column(String(255), default="")
    engine: Mapped[str] = mapped_column(String(128), default="")
    policy: Mapped[str] = mapped_column(String(255), default="")
    evidence_source: Mapped[str] = mapped_column(String(16), default="header")
    trusted: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    trust_state: Mapped[str] = mapped_column(String(32), default="unverified_chain")
    trust_reason: Mapped[str] = mapped_column(String(500), default="")
    #: A pointer to the original — a header name, syslog id or request id — not the payload.
    raw_reference: Mapped[str] = mapped_column(String(255), default="")
    normalized_detail: Mapped[dict[str, Any]] = mapped_column(default=dict)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class GatewayConflict(Base, IdMixin):
    """A disagreement between sources, kept visible until an analyst resolves it (§28)."""

    __tablename__ = "gateway_conflicts"
    __table_args__ = (Index("ix_gateway_conflicts_open", "organization_id", "resolved_at"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    message_id: Mapped[str | None] = mapped_column(
        ForeignKey("mail_messages.id", ondelete="CASCADE"), default=None, index=True
    )
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), default=None, index=True
    )
    kind: Mapped[str] = mapped_column(String(48), index=True)
    summary: Mapped[str] = mapped_column(String(1000), default="")
    providers: Mapped[list[Any]] = mapped_column(default=list)
    detail: Mapped[dict[str, Any]] = mapped_column(default=dict)
    detected_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    resolved_by: Mapped[str | None] = mapped_column(String(320), default=None)
    resolution: Mapped[str] = mapped_column(String(500), default="")


class MessageTraceRecord(Base, IdMixin):
    """Correlated delivery path across gateway, Exchange and the platform (ТЗ 1.0.2 §23)."""

    __tablename__ = "message_traces"
    __table_args__ = (
        Index("ix_message_traces_correlation", "organization_id", "internet_message_id"),
        Index("ix_message_traces_queue", "organization_id", "queue_id"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    message_id: Mapped[str | None] = mapped_column(
        ForeignKey("mail_messages.id", ondelete="CASCADE"), default=None, index=True
    )
    provider_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    internet_message_id: Mapped[str] = mapped_column(String(998), default="")
    queue_id: Mapped[str] = mapped_column(String(64), default="")
    sender: Mapped[str] = mapped_column(String(320), default="")
    recipient: Mapped[str] = mapped_column(String(320), default="")
    subject_hash: Mapped[str] = mapped_column(String(64), default="", index=True)
    content_sha256: Mapped[str] = mapped_column(String(64), default="", index=True)
    events: Mapped[list[Any]] = mapped_column(default=list)
    final_action: Mapped[str] = mapped_column(String(32), default="")
    complete: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class SyslogDeadLetter(Base, IdMixin):
    """A gateway event that could not be accepted, kept with its reason (ТЗ 1.0.2 §20).

    Dropping an unparseable line silently would hide an integration gap behind an apparently
    quiet gateway.
    """

    __tablename__ = "syslog_dead_letters"

    organization_id: Mapped[str | None] = mapped_column(String(32), default=None, index=True)
    provider_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    source_ip: Mapped[str] = mapped_column(String(64), default="")
    reason: Mapped[str] = mapped_column(String(64), index=True)
    detail: Mapped[str] = mapped_column(String(500), default="")
    raw: Mapped[str] = mapped_column(Text, default="")
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


# ---------------------------------------------------------------------------------------------
# Detection quality (ТЗ 1.0.1 §11)
# ---------------------------------------------------------------------------------------------
class RuleStatistic(Base, IdMixin, TimestampMixin):
    """Per-rule quality counters, so noisy rules can be found rather than guessed at."""

    __tablename__ = "rule_statistics"
    __table_args__ = (UniqueConstraint("organization_id", "rule_id", name="uq_rule_statistic"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    rule_version: Mapped[int] = mapped_column(Integer, default=1)
    trigger_count: Mapped[int] = mapped_column(Integer, default=0)
    confirmed_tp: Mapped[int] = mapped_column(Integer, default=0)
    confirmed_fp: Mapped[int] = mapped_column(Integer, default=0)
    suppressed_count: Mapped[int] = mapped_column(Integer, default=0)
    last_triggered_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None, index=True)

    @property
    def precision_estimate(self) -> float | None:
        """Confirmed precision only.

        Untriaged triggers are deliberately excluded rather than assumed correct: assuming
        would make every new rule look perfect on the day it ships.
        """
        confirmed = self.confirmed_tp + self.confirmed_fp
        return round(self.confirmed_tp / confirmed, 3) if confirmed else None


class PilotMetricSnapshot(Base, IdMixin):
    """A daily roll-up of pilot quality metrics (ТЗ 1.0.1 §11)."""

    __tablename__ = "pilot_metric_snapshots"
    __table_args__ = (UniqueConstraint("organization_id", "period_start", name="uq_pilot_metric_period"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    period_start: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    period_end: Mapped[datetime] = mapped_column(UTCDateTime)
    metrics: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


# ---------------------------------------------------------------------------------------------
# Detection quality and rule lifecycle (ТЗ 1.0.3 §8, §11, §51)
# ---------------------------------------------------------------------------------------------
class RuleRegistryEntry(Base, IdMixin, TimestampMixin):
    """The deployed state of one rule, and who answers for it (ТЗ 1.0.3 §8, §11).

    The rule *definition* lives in the rule pack, which is data under review. This table holds
    what the deployment did with it: status, owner, and the lifecycle history. Keeping them
    apart means a rule can be put into SHADOW for one organisation without editing a file every
    organisation shares.
    """

    __tablename__ = "rule_registry"
    __table_args__ = (UniqueConstraint("organization_id", "rule_id", name="uq_rule_registry"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    rule_version: Mapped[int] = mapped_column(Integer, default=1)
    #: EXPERIMENTAL | SHADOW | ACTIVE | DEGRADED | DISABLED | DEPRECATED
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE", index=True)
    owner: Mapped[str] = mapped_column(String(320), default="")
    category: Mapped[str] = mapped_column(String(64), default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    #: Threat scenarios this rule covers (ТЗ 1.0.3 §28).
    scenarios: Mapped[list[Any]] = mapped_column(default=list)
    last_status_change: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    last_false_positive_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    notes: Mapped[str] = mapped_column(Text, default="")


class RuleChange(Base, IdMixin):
    """One lifecycle transition, with the metrics on either side (ТЗ 1.0.3 §11).

    ``before_metrics`` and ``after_metrics`` are what make a change reviewable later: "we moved
    this to ACTIVE" is not an argument, "precision went from 0.62 to 0.94 on 40 cases" is.
    """

    __tablename__ = "rule_changes"
    __table_args__ = (Index("ix_rule_changes_rule", "rule_id", "created_at"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_version: Mapped[int] = mapped_column(Integer, default=1)
    from_status: Mapped[str] = mapped_column(String(16), default="")
    to_status: Mapped[str] = mapped_column(String(16), default="")
    author: Mapped[str] = mapped_column(String(320), default="")
    reviewer: Mapped[str] = mapped_column(String(320), default="")
    change_reason: Mapped[str] = mapped_column(String(1000), default="")
    before_metrics: Mapped[dict[str, Any]] = mapped_column(default=dict)
    after_metrics: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    activated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class DetectionRelease(Base, IdMixin):
    """A published detection release and what is needed to reproduce it (ТЗ 1.0.3B §24).

    The manifest exists so that "which detection produced this verdict" still has an answer
    months later. It records the parser and risk-engine versions beside the rule pack, because a
    verdict is the product of all of them — the same rules on a different parser are not the
    same detection.

    Known gaps are part of the manifest on purpose: a release shipping with three accepted
    limitations is a different thing from one shipping with none, and that difference belongs in
    the release rather than only in a separate registry.
    """

    __tablename__ = "detection_releases"
    __table_args__ = (UniqueConstraint("organization_id", "version", name="uq_detection_release"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    #: vYYYY.MM.N
    version: Mapped[str] = mapped_column(String(32), index=True)
    ruleset_fingerprint: Mapped[str] = mapped_column(Text, default="")
    parser_version: Mapped[str] = mapped_column(String(32), default="")
    risk_engine_version: Mapped[str] = mapped_column(String(32), default="")
    commit_sha: Mapped[str] = mapped_column(String(64), default="")
    #: The candidate that became this release, when one did.
    candidate_id: Mapped[str | None] = mapped_column(String(32), default=None)
    approved_by: Mapped[str] = mapped_column(String(320), default="")
    #: Deltas against the previous release, generated rather than typed, so the notes cannot
    #: drift from what actually changed.
    metric_deltas: Mapped[dict[str, Any]] = mapped_column(default=dict)
    dataset_version: Mapped[str] = mapped_column(String(32), default="")
    dataset_checksum: Mapped[str] = mapped_column(String(64), default="")
    new_rules: Mapped[list[Any]] = mapped_column(default=list)
    changed_rules: Mapped[list[Any]] = mapped_column(default=list)
    removed_rules: Mapped[list[Any]] = mapped_column(default=list)
    metrics: Mapped[dict[str, Any]] = mapped_column(default=dict)
    gate_result: Mapped[dict[str, Any]] = mapped_column(default=dict)
    known_limitations: Mapped[list[Any]] = mapped_column(default=list)
    changelog: Mapped[str] = mapped_column(Text, default="")
    published_by: Mapped[str] = mapped_column(String(320), default="")
    published_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class DetectionGapRecord(Base, IdMixin, TimestampMixin):
    """A known limitation, with an owner and a target release (ТЗ 1.0.3 §27).

    A miss that falls into a registered gap is an accepted limitation; a miss without one is a
    regression. The registry exists so that "we knew about that" cannot be said after the fact.
    """

    __tablename__ = "detection_gaps"
    __table_args__ = (UniqueConstraint("organization_id", "gap_id", name="uq_detection_gap"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    gap_id: Mapped[str] = mapped_column(String(32), index=True)
    category: Mapped[str] = mapped_column(String(64), default="", index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    root_cause: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[Severity] = mapped_column(
        _enum(Severity, "severity_enum"), default=Severity.MEDIUM, index=True
    )
    status: Mapped[GapStatus] = mapped_column(
        _enum(GapStatus, "gap_status_enum"), default=GapStatus.OPEN, index=True
    )
    owner: Mapped[str] = mapped_column(String(320), default="")
    target_release: Mapped[str] = mapped_column(String(32), default="")
    examples: Mapped[list[Any]] = mapped_column(default=list)
    #: Where the gap was found: analyst report, red-team exercise, post-incident review, the
    #: golden corpus. A gap nobody can trace back to how it surfaced tends to be a guess.
    discovered_from: Mapped[str] = mapped_column(String(32), default="")
    #: Analyses that demonstrate it. These are what make a gap checkable rather than asserted.
    example_analysis_ids: Mapped[list[Any]] = mapped_column(default=list)
    #: What protects in the meantime. A gap without one is an unmitigated hole, and the
    #: registry should make that visible rather than comfortable.
    compensating_controls: Mapped[str] = mapped_column(Text, default="")
    mitigation: Mapped[str] = mapped_column(Text, default="")
    planned_fix: Mapped[str] = mapped_column(Text, default="")
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    #: Подтверждение на реальной почте (ТЗ 1.0.4 §23). Отдельно от ``status``, потому что
    #: статус ``VALIDATION`` означает согласие золотого корпуса, а корпус содержит ровно те
    #: случаи, которые мы придумали. ``None`` здесь — «на живой почте не проверено», и это
    #: честнее, чем молчание.
    real_flow_validated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    real_flow_validated_by: Mapped[str] = mapped_column(String(320), default="")
    #: Свидетельство: сколько писем реального потока и какие именно это подтверждают. Без него
    #: «проверено» было бы словом.
    real_flow_evidence: Mapped[dict[str, Any]] = mapped_column(default=dict)


# ---------------------------------------------------------------------------------------------
# Analyst workflow (ТЗ 1.0.3 §17-§23, §26)
# ---------------------------------------------------------------------------------------------
class IncidentClassification(Base, IdMixin):
    """An analyst's verdict about a message (ТЗ 1.0.3 §22).

    Kept apart from ``Incident.status``: the workflow state of a ticket and the conclusion about
    the mail are different facts, and conflating them would make every quality metric depend on
    whether somebody remembered to close a ticket.
    """

    __tablename__ = "incident_classifications"
    __table_args__ = (Index("ix_classification_incident", "incident_id", "created_at"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    classification: Mapped[AnalystClassification] = mapped_column(
        _enum(AnalystClassification, "analyst_classification_enum"), index=True
    )
    previous_classification: Mapped[str | None] = mapped_column(String(32), default=None)
    analyst_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), default=None)
    analyst_email: Mapped[str] = mapped_column(String(320), default="")
    confidence: Mapped[str] = mapped_column(String(16), default="high")
    comment: Mapped[str] = mapped_column(Text, default="")
    #: Signals the analyst identified as wrong, when the verdict is FALSE_POSITIVE (§23).
    offending_signals: Mapped[list[Any]] = mapped_column(default=list)
    offending_rules: Mapped[list[Any]] = mapped_column(default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class DetectionFeedback(Base, IdMixin):
    """One piece of analyst feedback about detection quality (ТЗ 1.0.3 §23, §26).

    Both directions are recorded through the same table because they answer the same question
    from opposite sides: which rule was wrong, and which rule was missing.
    """

    __tablename__ = "detection_feedback"
    __table_args__ = (Index("ix_feedback_rule", "rule_id", "created_at"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    #: false_positive | false_negative
    kind: Mapped[str] = mapped_column(String(16), index=True)
    message_id: Mapped[str | None] = mapped_column(
        ForeignKey("mail_messages.id", ondelete="SET NULL"), default=None, index=True
    )
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), default=None, index=True
    )
    rule_id: Mapped[str | None] = mapped_column(String(32), default=None, index=True)
    analyst_email: Mapped[str] = mapped_column(String(320), default="")
    analyst_id: Mapped[str | None] = mapped_column(String(32), default=None)
    #: The analysis this feedback is about. A verdict is a property of one analysis revision,
    #: so feedback that only pointed at the message would become ambiguous the first time the
    #: message was replayed (ТЗ 1.0.3B §4).
    analysis_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_jobs.id", ondelete="SET NULL"), default=None, index=True
    )
    classification: Mapped[str] = mapped_column(String(32), default="", index=True)
    confidence: Mapped[str] = mapped_column(String(16), default="high")
    #: Why the detection was wrong (ТЗ 1.0.3B §5). The reason decides who fixes it: an
    #: overbroad rule goes to its owner, a parser context loss goes somewhere else entirely,
    #: and a known vendor may need no rule change at all.
    fp_reason: Mapped[str | None] = mapped_column(String(32), default=None, index=True)
    comment: Mapped[str] = mapped_column(Text, default="")
    #: For a false negative: where the detection should have come from (§26).
    source: Mapped[str] = mapped_column(String(32), default="")
    root_cause: Mapped[str] = mapped_column(String(32), default="")
    expected_detection: Mapped[str] = mapped_column(String(255), default="")
    missing_fact: Mapped[str] = mapped_column(String(255), default="")
    gap_id: Mapped[str | None] = mapped_column(String(32), default=None, index=True)
    #: What should have been detected, for a miss: expected category, the lowest classification
    #: that would have been acceptable, how bad it was, who owns the fix and when (§6). Without
    #: these a reported miss is a complaint rather than a task.
    expected_category: Mapped[str] = mapped_column(String(64), default="")
    minimum_classification: Mapped[str] = mapped_column(String(16), default="")
    severity: Mapped[str] = mapped_column(String(16), default="")
    owner: Mapped[str] = mapped_column(String(320), default="")
    target_release: Mapped[str] = mapped_column(String(32), default="")
    #: The exception proposed in response, when one was. Never created automatically (§23).
    proposed_exception_id: Mapped[str | None] = mapped_column(String(32), default=None)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class IncidentAssignment(Base, IdMixin):
    """Who is working on an incident, and since when (ТЗ 1.0.3 §20)."""

    __tablename__ = "incident_assignments"

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    assignee_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), default=None, index=True)
    assignee_email: Mapped[str] = mapped_column(String(320), default="")
    assigned_by: Mapped[str] = mapped_column(String(320), default="")
    #: manual | round_robin | category | department | severity
    method: Mapped[str] = mapped_column(String(16), default="manual")
    assigned_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    released_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class AnalysisRevision(Base, IdMixin):
    """A re-run of an analysis with a newer engine (ТЗ 1.0.3 §49, §50).

    The original analysis is never overwritten. Replacing it would destroy the only record of
    what the platform actually told people at the time, which is exactly what an investigation
    needs months later.
    """

    __tablename__ = "analysis_revisions"
    __table_args__ = (Index("ix_revision_job", "analysis_job_id", "created_at"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    analysis_job_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_jobs.id", ondelete="CASCADE"), index=True
    )
    message_id: Mapped[str | None] = mapped_column(
        ForeignKey("mail_messages.id", ondelete="CASCADE"), default=None, index=True
    )
    revision: Mapped[int] = mapped_column(Integer, default=1)
    #: dry_run means the revision was computed and recorded but did not replace the verdict.
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True)
    original_classification: Mapped[str] = mapped_column(String(16), default="")
    new_classification: Mapped[str] = mapped_column(String(16), default="")
    original_score: Mapped[int] = mapped_column(Integer, default=0)
    new_score: Mapped[int] = mapped_column(Integer, default=0)
    added_rules: Mapped[list[Any]] = mapped_column(default=list)
    removed_rules: Mapped[list[Any]] = mapped_column(default=list)
    #: Engine versions used for the re-run, so the comparison is reproducible (§48).
    versions: Mapped[dict[str, Any]] = mapped_column(default=dict)
    requested_by: Mapped[str] = mapped_column(String(320), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class ReevaluationRun(Base, IdMixin):
    """A bulk re-evaluation over a time window (ТЗ 1.0.3 §50). Dry-run by default."""

    __tablename__ = "reevaluation_runs"

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    window_days: Mapped[int] = mapped_column(Integer, default=7)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True)
    ruleset_fingerprint: Mapped[str] = mapped_column(Text, default="")
    messages_examined: Mapped[int] = mapped_column(Integer, default=0)
    verdict_changed: Mapped[int] = mapped_column(Integer, default=0)
    newly_suspicious: Mapped[int] = mapped_column(Integer, default=0)
    newly_cleared: Mapped[int] = mapped_column(Integer, default=0)
    affected_campaigns: Mapped[list[Any]] = mapped_column(default=list)
    affected_users: Mapped[list[Any]] = mapped_column(default=list)
    sample: Mapped[list[Any]] = mapped_column(default=list)
    requested_by: Mapped[str] = mapped_column(String(320), default="")
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class ThreatScenario(Base, IdMixin, TimestampMixin):
    """A catalogued attack scenario (ТЗ 1.0.3 §28).

    The catalogue ties a scenario to the rules meant to cover it, the fixtures that exercise it
    and the playbook an analyst follows. That link is what turns "we cover BEC" from a claim
    into something checkable.
    """

    __tablename__ = "threat_scenarios"
    __table_args__ = (UniqueConstraint("organization_id", "scenario_id", name="uq_threat_scenario"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    #: THR-BEC-001 and so on.
    scenario_id: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(255), default="")
    category: Mapped[str] = mapped_column(String(64), default="", index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    rules: Mapped[list[Any]] = mapped_column(default=list)
    fixtures: Mapped[list[Any]] = mapped_column(default=list)
    playbook: Mapped[str] = mapped_column(String(64), default="")
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity_enum"), default=Severity.MEDIUM)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class RuleCanary(Base, IdMixin, TimestampMixin):
    """A rule released to part of the organisation before all of it (ТЗ 1.0.3 §52).

    Scope lives here rather than in the rule file on purpose. The rule is a reviewed artefact in
    Git and describes *what* is dangerous; who it currently applies to is deployment state that
    changes during a rollout and must not require a code review to adjust.

    Outside the scope the rule still evaluates and is still recorded, contributing nothing to
    the verdict. That is what makes the rest of the organisation a control group: the same rule,
    the same mail flow, the only difference being whether its score counted.
    """

    __tablename__ = "rule_canaries"
    __table_args__ = (
        Index("ix_canary_org_rule", "organization_id", "rule_id"),
        Index("ix_canary_state", "organization_id", "state"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_version: Mapped[int] = mapped_column(Integer, default=1)
    scope: Mapped[CanaryScope] = mapped_column(
        _enum(CanaryScope, "canary_scope_enum"), default=CanaryScope.MAILBOX
    )
    #: Mailboxes or departments, depending on ``scope``. Empty for PERCENT.
    scope_values: Mapped[list[Any]] = mapped_column(default=list)
    #: Share of mailboxes for PERCENT scope, 1–100.
    percent: Mapped[int] = mapped_column(Integer, default=0)
    state: Mapped[CanaryState] = mapped_column(
        _enum(CanaryState, "canary_state_enum"), default=CanaryState.ACTIVE, index=True
    )
    #: When the rollout should have been decided. Required: a canary nobody ends is not a
    #: canary, it is a rule that quietly protects some people and not others.
    review_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(320), default="")
    decided_by: Mapped[str] = mapped_column(String(320), default="")
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    decision_note: Mapped[str] = mapped_column(Text, default="")

    @property
    def active(self) -> bool:
        return self.state is CanaryState.ACTIVE

    def overdue(self, now: datetime | None = None) -> bool:
        """Past its review date and still limiting the rule.

        An overdue canary keeps its scope rather than expiring into one state or the other.
        Lifting it automatically would release an unreviewed rule to everybody; dropping it
        automatically would silently switch off detection. Both are decisions, so neither
        happens without a person — the dashboard and the gate surface it instead.
        """
        if not self.active:
            return False
        return (now or utcnow()) > self.review_at


class SignalFeedback(Base, IdMixin):
    """What an analyst thought of one signal (ТЗ 1.0.3B §4).

    Per-signal rather than per-message, because "the platform was wrong" cannot be acted on and
    "BEC-014 fired on an ordinary supplier letter" can. The dispositions in the middle carry the
    most information: a rule that is right about the fact and wrong about how much it matters
    needs its weight changed, not its condition — and nobody can tell those apart from a verdict
    alone.
    """

    __tablename__ = "signal_feedback"
    __table_args__ = (Index("ix_signal_feedback_rule", "rule_id", "disposition"),)

    feedback_id: Mapped[str] = mapped_column(
        ForeignKey("detection_feedback.id", ondelete="CASCADE"), index=True
    )
    #: The signal within the stored analysis. Nullable because an analyst may judge a rule that
    #: did *not* fire, which is how a "too weak" disposition is recorded.
    signal_id: Mapped[str | None] = mapped_column(String(64), default=None, index=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_version: Mapped[int] = mapped_column(Integer, default=1)
    disposition: Mapped[SignalDisposition] = mapped_column(
        _enum(SignalDisposition, "signal_disposition_enum"), index=True
    )
    comment: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class RuleQualitySnapshot(Base, IdMixin):
    """A rule's measured quality over one period (ТЗ 1.0.3B §8).

    Taken as a snapshot rather than computed on demand so that "precision fell" is a statement
    about two periods rather than about the moment someone opened the page. Health is derived
    from these numbers and never switches a rule off: a control that disables itself when the
    data looks odd is a control an unlucky week can turn off.
    """

    __tablename__ = "rule_quality_snapshots"
    __table_args__ = (Index("ix_rule_quality_rule_period", "organization_id", "rule_id", "period_end"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_version: Mapped[int] = mapped_column(Integer, default=1)
    ruleset_version: Mapped[str] = mapped_column(String(64), default="")
    period_start: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    period_end: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    trigger_count: Mapped[int] = mapped_column(Integer, default=0)
    analyst_reviewed: Mapped[int] = mapped_column(Integer, default=0)
    true_positive: Mapped[int] = mapped_column(Integer, default=0)
    false_positive: Mapped[int] = mapped_column(Integer, default=0)
    unknown: Mapped[int] = mapped_column(Integer, default=0)
    suppressed: Mapped[int] = mapped_column(Integer, default=0)
    #: Null when no analyst judged anything in the period. Not 1.0, and not 0.0: an unreviewed
    #: rule has unknown precision, and a number here would be read as measured (ТЗ §8).
    precision: Mapped[float | None] = mapped_column(Float, default=None)
    affected_messages: Mapped[int] = mapped_column(Integer, default=0)
    affected_incidents: Mapped[int] = mapped_column(Integer, default=0)
    health: Mapped[RuleHealth] = mapped_column(
        _enum(RuleHealth, "rule_health_enum"), default=RuleHealth.NO_DATA, index=True
    )
    health_reasons: Mapped[list[Any]] = mapped_column(default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class RuleCandidate(Base, IdMixin, TimestampMixin):
    """A proposed rule pack under review (ТЗ 1.0.3B §10, §12).

    The candidate is a **pointer** to a rule pack — a directory or a Git reference — not a copy
    of its rules in the database. Rules are data that go through code review (§12 of 1.0.3), and
    a pack stored in a table could be published without anyone reading the diff. What lives here
    is the review: who proposed it, who looked at it, what the benchmark said, and whether it may
    be released.

    Publishing therefore records a decision and produces a release manifest; the pack itself
    reaches production by deployment, which is what keeps the reviewed artefact and the running
    artefact the same thing.
    """

    __tablename__ = "rule_candidates"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_rule_candidate_name"),
        Index("ix_rule_candidate_state", "organization_id", "state"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    #: Where the pack lives: a path inside the deployment or a Git reference.
    source: Mapped[str] = mapped_column(String(512), default="")
    source_kind: Mapped[str] = mapped_column(String(16), default="path")
    #: Fingerprint of the pack when it was last validated, so a silently changed pack cannot
    #: inherit an earlier approval.
    ruleset_fingerprint: Mapped[str] = mapped_column(Text, default="")
    base_fingerprint: Mapped[str] = mapped_column(Text, default="")
    state: Mapped[CandidateState] = mapped_column(
        _enum(CandidateState, "candidate_state_enum"), default=CandidateState.DRAFT, index=True
    )
    #: Rule ids this candidate adds, changes or disables, filled in by validation.
    added_rules: Mapped[list[Any]] = mapped_column(default=list)
    changed_rules: Mapped[list[Any]] = mapped_column(default=list)
    removed_rules: Mapped[list[Any]] = mapped_column(default=list)
    #: True when the change touches a rule whose mistakes are expensive — a hard signal, malware,
    #: credential theft, VIP impersonation or payment fraud. Such a change may not be approved by
    #: its own author (§12).
    critical_change: Mapped[bool] = mapped_column(Boolean, default=False)
    critical_reasons: Mapped[list[Any]] = mapped_column(default=list)
    author: Mapped[str] = mapped_column(String(320), default="")
    reviewer: Mapped[str] = mapped_column(String(320), default="")
    review_comment: Mapped[str] = mapped_column(Text, default="")
    reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    #: The last benchmark against the golden corpus: metrics, deltas and the gate verdict.
    benchmark: Mapped[dict[str, Any]] = mapped_column(default=dict)
    benchmarked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    published_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    release_id: Mapped[str | None] = mapped_column(
        ForeignKey("detection_releases.id", ondelete="SET NULL"), default=None
    )

    @property
    def open_for_changes(self) -> bool:
        return self.state in {CandidateState.DRAFT, CandidateState.CHANGES_REQUESTED}


class CampaignMatch(Base, IdMixin):
    """Why one message is in one campaign (ТЗ 1.0.3B §20).

    Per message rather than per campaign: an analyst disagreeing with a membership needs to see
    what tied *that* message in. ``manual`` marks a decision a person made, and correlation does
    not overwrite it — an engine that quietly re-adds a message an analyst removed teaches
    analysts that their decisions do not stick.
    """

    __tablename__ = "campaign_matches"
    __table_args__ = (
        UniqueConstraint("campaign_id", "message_id", name="uq_campaign_match"),
        Index("ix_campaign_match_message", "message_id"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), index=True)
    message_id: Mapped[str] = mapped_column(ForeignKey("mail_messages.id", ondelete="CASCADE"), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    reasons: Mapped[list[Any]] = mapped_column(default=list)
    #: Set when an analyst attached, detached or rejected the relation.
    manual: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    #: An analyst said this message does not belong here. Kept rather than deleted so the
    #: correlation engine can be measured against human judgement.
    rejected: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    decided_by: Mapped[str] = mapped_column(String(320), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class ValidationMessage(Base, IdMixin):
    """Письмо реального потока, взятое в набор валидации (ТЗ 1.0.4 §8).

    Запись существует отдельно от ``mail_messages`` намеренно. Обычное письмо хранится, чтобы по
    нему работал аналитик, и удаляется по сроку хранения почты. Запись валидации хранится, чтобы
    по ней измеряли качество детектирования, и живёт по своему сроку — более долгому для
    обезличенных метрик и более короткому для исходных данных (ТЗ §22). Смешать их значило бы
    либо потерять измерения вместе с почтой, либо держать почту ради измерений.

    Два вердикта хранятся рядом и значат разное:

    * ``production_verdict`` — что платформа решила тогда, на том пакете правил;
    * ``validation_verdict`` — что она решает сейчас, при повторном прогоне.

    Расхождение между ними — не ошибка, а предмет разбора: именно по нему видно, что изменение
    правил дало на настоящей почте.
    """

    __tablename__ = "validation_messages"
    __table_args__ = (
        UniqueConstraint("organization_id", "message_fingerprint", name="uq_validation_message"),
        Index("ix_validation_org_received", "organization_id", "received_at"),
        Index("ix_validation_org_review", "organization_id", "analyst_classification"),
        Index("ix_validation_org_pii", "organization_id", "pii_status"),
        Index("ix_validation_org_promotion", "organization_id", "promotion_state"),
        # Выборка писем с истёкшим сроком хранения исходных данных (ТЗ §22).
        Index("ix_validation_org_raw_retention", "organization_id", "raw_retained_until"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"))
    #: Письмо платформы, если оно ещё не удалено по сроку хранения. Запись валидации переживает
    #: его, поэтому связь необязательная и обнуляется, а не каскадно удаляет запись.
    message_id: Mapped[str | None] = mapped_column(
        ForeignKey("mail_messages.id", ondelete="SET NULL"), default=None, index=True
    )
    source: Mapped[ValidationSource] = mapped_column(_enum(ValidationSource, "validation_source_enum"))
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    #: Отпечаток по структуре, устойчивый к обезличиванию: по нему одно письмо не попадает в
    #: набор дважды из двух источников.
    message_fingerprint: Mapped[str] = mapped_column(String(64))
    anonymized: Mapped[bool] = mapped_column(Boolean, default=False)
    pii_status: Mapped[PiiStatus] = mapped_column(_enum(PiiStatus, "pii_status_enum"), default=PiiStatus.RAW)
    #: Отчёт об обезличивании: сколько замен какого вида сделано. Нужен, чтобы «обезличено» было
    #: проверяемым утверждением.
    anonymization_report: Mapped[dict[str, Any]] = mapped_column(default=dict)
    #: Ключи двух экземпляров письма в объектном хранилище. Разделены потому, что живут разное
    #: время: исходный удаляется по ``raw_retained_until``, обезличенный остаётся для метрик и
    #: для проверки воспроизводимости при продвижении в корпус (ТЗ §10, §22).
    raw_object_key: Mapped[str] = mapped_column(String(512), default="")
    anonymized_object_key: Mapped[str] = mapped_column(String(512), default="")

    #: Чего ожидали от платформы, если это известно заранее (учения, red team). ``None`` —
    #: обычный случай: на реальном потоке ожидаемого ответа нет, и притворяться, что есть,
    #: значило бы считать recall по выдуманной разметке.
    expected_classification: Mapped[RiskLevel | None] = mapped_column(
        _enum(RiskLevel, "risk_level_enum"), default=None
    )
    #: Что сказал аналитик. ``None`` означает «не разобрано», а не «верно».
    analyst_classification: Mapped[AnalystClassification | None] = mapped_column(
        _enum(AnalystClassification, "analyst_classification_enum"), default=None
    )
    reviewed_by: Mapped[str] = mapped_column(String(320), default="")
    reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    review_comment: Mapped[str] = mapped_column(String(2000), default="")

    production_verdict: Mapped[RiskLevel | None] = mapped_column(
        _enum(RiskLevel, "risk_level_enum"), default=None
    )
    validation_verdict: Mapped[RiskLevel | None] = mapped_column(
        _enum(RiskLevel, "risk_level_enum"), default=None
    )
    #: Всё, от чего зависит вердикт, на момент прогона — иначе расхождение не объяснимо.
    ruleset_version: Mapped[str] = mapped_column(String(64), default="")
    parser_version: Mapped[str] = mapped_column(String(64), default="")
    risk_engine_version: Mapped[str] = mapped_column(String(64), default="")

    #: Правила, сработавшие при прогоне валидации: по ним считается шум на реальной почте.
    triggered_rules: Mapped[list[Any]] = mapped_column(default=list)
    #: Почему письмо попало в выборку (ТЗ §14): высокий риск, обращение сотрудника, QR, случайная
    #: доля легитимной почты. Нужно, чтобы метрику нельзя было прочитать как долю от всего потока.
    sampling_reasons: Mapped[list[Any]] = mapped_column(default=list)
    #: Проверка оказалась неполной: шифрование, пароль на архиве, нераспознанный QR-код.
    unscannable_reasons: Mapped[list[Any]] = mapped_column(default=list)

    promotion_state: Mapped[PromotionState] = mapped_column(
        _enum(PromotionState, "promotion_state_enum"),
        default=PromotionState.NOT_REQUESTED,
    )
    promotion_requested_by: Mapped[str] = mapped_column(String(320), default="")
    promotion_approved_by: Mapped[str] = mapped_column(String(320), default="")
    promotion_case_id: Mapped[str] = mapped_column(String(32), default="")
    #: Версия датасета, в которую письмо вошло. Заполняется только когда версия действительно
    #: повышена — автоматического продвижения нет, и пустое значение здесь означает ровно
    #: «в корпусе этого письма ещё нет» (ТЗ §10).
    promoted_dataset_version: Mapped[str] = mapped_column(String(32), default="")
    #: Результат проверки воспроизводимости по обезличенной копии: вердикт и совпал ли он.
    reproducibility_report: Mapped[dict[str, Any]] = mapped_column(default=dict)
    #: Срок, после которого исходные данные удаляются раньше обезличенных метрик (ТЗ §22).
    raw_retained_until: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class ProtectedDomainVariant(Base, IdMixin):
    """Один вариант написания защищаемого домена (ТЗ 1.0.4 §4).

    Варианты вычисляются **офлайн и чисто**: никакого DNS, WHOIS или обхода сети. Реестр не
    отвечает на вопрос «зарегистрирован ли такой домен» — он отвечает на вопрос «если письмо
    придёт с такого домена, что мы о нём уже решили». Первый вопрос требует обращений наружу по
    каждому из сотен вариантов и выдал бы наружу список доменов, которые организация защищает.

    Статус — это память о решении человека. Без реестра аналитик принимал бы одно и то же
    решение про «corps.example» столько раз, сколько приходит писем.
    """

    __tablename__ = "protected_domain_variants"
    __table_args__ = (
        UniqueConstraint("organization_id", "protected_domain", "candidate_domain", name="uq_domain_variant"),
        Index("ix_domain_variant_candidate", "organization_id", "candidate_domain"),
        Index("ix_domain_variant_status", "organization_id", "status"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    #: Защищаемый домен, от которого произведён вариант.
    protected_domain: Mapped[str] = mapped_column(String(253))
    #: Сам вариант.
    candidate_domain: Mapped[str] = mapped_column(String(253))
    #: Какое преобразование его дало: insertion, deletion, substitution, transposition.
    transform_type: Mapped[str] = mapped_column(String(32))
    #: Число правок. Для вариантов этого реестра всегда 1.
    distance: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[DomainVariantStatus] = mapped_column(
        _enum(DomainVariantStatus, "domain_variant_status_enum"),
        default=DomainVariantStatus.GENERATED,
    )
    generated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    #: Когда вариант впервые встретился в почте. ``None`` означает «ни разу», а не «неизвестно».
    first_observed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    last_observed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    observed_count: Mapped[int] = mapped_column(Integer, default=0)
    #: Кто и почему изменил статус. Для KNOWN_LEGITIMATE это обязательно: статус гасит сигнал.
    decided_by: Mapped[str] = mapped_column(String(320), default="")
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    reason: Mapped[str] = mapped_column(String(1000), default="")


class ReanalysisJob(Base, IdMixin):
    """A bulk re-evaluation of historical mail (ТЗ 1.0.3B §23).

    Dry-run by default, pausable and cancellable, and it never notifies anyone or proposes
    remediation. Re-running a month of mail through new rules is the single operation most able
    to flood an organisation with alerts about messages people dealt with weeks ago, so every
    control here exists to keep it an analysis rather than an event.
    """

    __tablename__ = "reanalysis_jobs"
    __table_args__ = (Index("ix_reanalysis_org_state", "organization_id", "state"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    state: Mapped[ReanalysisState] = mapped_column(
        _enum(ReanalysisState, "reanalysis_state_enum"), default=ReanalysisState.QUEUED, index=True
    )
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True)
    window_from: Mapped[datetime] = mapped_column(UTCDateTime)
    window_to: Mapped[datetime] = mapped_column(UTCDateTime)
    filters: Mapped[dict[str, Any]] = mapped_column(default=dict)
    ruleset_source: Mapped[str] = mapped_column(String(512), default="")
    ruleset_fingerprint: Mapped[str] = mapped_column(Text, default="")
    #: Hard ceiling on how many messages one job may touch.
    max_messages: Mapped[int] = mapped_column(Integer, default=5000)
    total_messages: Mapped[int] = mapped_column(Integer, default=0)
    processed: Mapped[int] = mapped_column(Integer, default=0)
    verdict_changed: Mapped[int] = mapped_column(Integer, default=0)
    newly_suspicious: Mapped[int] = mapped_column(Integer, default=0)
    newly_cleared: Mapped[int] = mapped_column(Integer, default=0)
    #: Position in the ordered message list, so a paused job resumes where it stopped rather
    #: than starting over.
    cursor: Mapped[int] = mapped_column(Integer, default=0)
    sample: Mapped[list[Any]] = mapped_column(default=list)
    error: Mapped[str] = mapped_column(Text, default="")
    requested_by: Mapped[str] = mapped_column(String(320), default="")
    cancelled_by: Mapped[str] = mapped_column(String(320), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)

    @property
    def runnable(self) -> bool:
        return self.state in {ReanalysisState.QUEUED, ReanalysisState.RUNNING}

    @property
    def progress(self) -> float | None:
        """Share of the batch processed, or ``None`` when the size is not known yet."""
        if not self.total_messages:
            return None
        return min(1.0, self.processed / self.total_messages)
