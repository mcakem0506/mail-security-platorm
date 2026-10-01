"""Data contracts exchanged between parser, detection engines, TI hub and risk engine."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .enums import IOCType, RiskLevel, Severity, TIStatus


def utcnow() -> datetime:
    return datetime.now(UTC)


class Address(BaseModel):
    model_config = ConfigDict(frozen=True)

    display_name: str = ""
    address: str = ""
    local_part: str = ""
    domain: str = ""  # lower-case, IDNA-decoded unicode form
    domain_ascii: str = ""  # punycode form


class ExtractedUrl(BaseModel):
    raw: str
    normalized: str
    redacted: str  # safe for logs/notifications: query values removed
    scheme: str
    host: str  # unicode form
    host_ascii: str  # punycode form
    registrable_domain: str
    subdomain: str = ""
    port: int | None = None
    path: str = ""
    has_query: bool = False
    query_keys: list[str] = Field(default_factory=list)
    has_fragment: bool = False
    has_userinfo: bool = False
    is_ip_literal: bool = False
    source: str = "text"  # text|href|form|img|iframe|meta|visible_text|attachment
    visible_text: str | None = None
    parse_error: str | None = None


class AttachmentMeta(BaseModel):
    filename: str
    normalized_filename: str
    declared_mime: str
    detected_type: str
    size: int
    sha256: str
    sha1: str | None = None
    md5: str | None = None
    extension: str = ""
    is_archive: bool = False
    encrypted: bool = False
    depth: int = 0  # 0 = direct attachment, >0 = inside archive/nested message
    parent_sha256: str | None = None
    archive: dict[str, Any] | None = None
    flags: list[str] = Field(default_factory=list)


class Fact(BaseModel):
    """An observation produced by an analysis engine. Rules turn facts into signals."""

    value: Any
    evidence: dict[str, Any] = Field(default_factory=dict)


class Signal(BaseModel):
    """An explainable detection signal. Every verdict is built from signals."""

    id: str
    category: str
    title: str
    explanation: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    weight: float = Field(ge=0.0, le=100.0)
    source: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    rule_id: str | None = None
    rule_version: int | None = None
    hard: bool = False
    internal: bool = False  # hide from employee view (internal detection logic)
    #: Produced by a SHADOW rule: measured and shown to analysts, but it may not change the
    #: verdict and is never shown to an employee (ТЗ 1.0.3 §10). Distinct from ``internal``,
    #: which hides a signal that *did* count.
    shadow: bool = False
    #: Lifecycle state of the rule at evaluation time, so a stored verdict stays readable after
    #: the rule moves on.
    rule_status: str = "ACTIVE"
    #: The rule condition that matched, in its source form. Explainability v2 asks for the
    #: condition itself, not only its outcome (ТЗ 1.0.3 §15).
    rule_condition: str | None = None
    recommendation: str | None = None
    observed_at: datetime = Field(default_factory=utcnow)
    suppressed: bool = False
    suppressed_by: str | None = None
    #: Why a signal from an otherwise scoring rule did not count — currently only ``"canary"``,
    #: meaning the rule is being rolled out and this recipient is outside its scope (ТЗ 1.0.3
    #: §52). Kept separate from ``shadow`` because the two answer different questions: shadow
    #: says the signal did not count, this says what withheld it.
    withheld_by: str | None = None


class Indicator(BaseModel):
    model_config = ConfigDict(frozen=True)

    ioc_type: IOCType
    value: str
    context: str = ""  # from|reply_to|url|attachment|received|...


class TIResult(BaseModel):
    provider_id: str
    ioc_type: IOCType
    indicator: str
    status: TIStatus
    malicious_count: int | None = None
    suspicious_count: int | None = None
    total_count: int | None = None
    categories: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    summary: dict[str, Any] = Field(default_factory=dict)  # normalised, never raw JSON
    fetched_at: datetime = Field(default_factory=utcnow)
    from_cache: bool = False
    latency_ms: int | None = None
    error: str | None = None


class ProviderHealth(BaseModel):
    provider_id: str
    status: str  # ok|degraded|unavailable|not_configured|disabled
    mode: str | None = None
    detail: str | None = None
    checked_at: datetime = Field(default_factory=utcnow)


class QuotaInfo(BaseModel):
    provider_id: str
    per_minute_limit: int | None = None
    per_day_limit: int | None = None
    used_minute: int = 0
    used_day: int = 0
    backoff_until: datetime | None = None


class Reason(BaseModel):
    signal_id: str
    title: str
    explanation: str
    severity: Severity
    source: str
    observed_at: datetime
    internal: bool = False
    recommendation: str | None = None


class EngineVersions(BaseModel):
    """Everything needed to reproduce a verdict later (ТЗ 1.0.3 §48).

    Without these a stored verdict cannot be explained once anything changes: "why did this
    score 72 last month" has no answer if the rules, the parser and the risk engine have all
    moved since.
    """

    model_config = ConfigDict(frozen=True)

    ruleset_version: str = ""
    risk_engine_version: str = ""
    parser_version: str = ""
    ti_policy_version: str = ""


class RiskVerdict(BaseModel):
    classification: RiskLevel
    score: int = Field(ge=0, le=100)
    confidence: str  # low|medium|high
    confidence_value: float
    reasons: list[Reason]
    sources: list[str]
    missing_evidence: list[str]
    hard_signals: list[Reason]
    suppressed: list[Reason] = Field(default_factory=list)
    #: Signals from SHADOW rules. Carried so an analyst can see what a candidate rule *would*
    #: have said, while none of them contributed to ``score`` or ``classification``.
    shadow: list[Reason] = Field(default_factory=list)
    recommendation: str
    engine_version: str
    versions: EngineVersions = Field(default_factory=EngineVersions)
