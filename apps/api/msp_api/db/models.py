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
    ExceptionType,
    IncidentStatus,
    IntakeSource,
    IOCType,
    JobState,
    RemediationState,
    RemediationType,
    RiskLevel,
    Role,
    Severity,
    TIState,
    TIStatus,
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
