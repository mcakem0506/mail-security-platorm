"""Enumerations shared by all components (API, worker, add-in contracts)."""

from __future__ import annotations

from enum import StrEnum


class AnalysisStatus(StrEnum):
    """User-facing status of a message check (Outlook add-in states, ТЗ 6.3)."""

    NOT_ANALYZED = "NOT_ANALYZED"
    QUEUED = "QUEUED"
    ANALYZING = "ANALYZING"
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    ERROR = "ERROR"
    REPORTED = "REPORTED"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    CLOSED = "CLOSED"


class JobState(StrEnum):
    QUEUED = "QUEUED"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class TIState(StrEnum):
    """State of asynchronous Threat Intelligence enrichment for a job."""

    NOT_REQUIRED = "NOT_REQUIRED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"


class RiskLevel(StrEnum):
    """Final classification (ТЗ 17). There is deliberately no SAFE value."""

    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.LOW_RISK: 0,
    RiskLevel.UNKNOWN: 1,
    RiskLevel.SUSPICIOUS: 2,
    RiskLevel.HIGH_RISK: 3,
    RiskLevel.MALICIOUS: 4,
}


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_BASE_WEIGHT: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 10,
    Severity.MEDIUM: 25,
    Severity.HIGH: 45,
    Severity.CRITICAL: 70,
}


class TIStatus(StrEnum):
    """Normalised provider verdicts (ТЗ 13.3). NO_NEGATIVE_REPUTATION is NOT safe."""

    KNOWN_BAD = "KNOWN_BAD"
    SUSPICIOUS = "SUSPICIOUS"
    NO_NEGATIVE_REPUTATION = "NO_NEGATIVE_REPUTATION"
    UNKNOWN = "UNKNOWN"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    RATE_LIMITED = "RATE_LIMITED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    ERROR = "ERROR"


TI_FAILURE_STATUSES = frozenset({TIStatus.RATE_LIMITED, TIStatus.PROVIDER_UNAVAILABLE, TIStatus.ERROR})


class IOCType(StrEnum):
    SHA256 = "sha256"
    DOMAIN = "domain"
    URL = "url"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    EMAIL = "email"
    CERT_FINGERPRINT = "cert_fingerprint"


class IncidentStatus(StrEnum):
    NEW = "NEW"
    TRIAGE = "TRIAGE"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED_PHISHING = "CONFIRMED_PHISHING"
    CONFIRMED_MALWARE = "CONFIRMED_MALWARE"
    CONFIRMED_BEC = "CONFIRMED_BEC"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN = "BENIGN"
    REMEDIATION_PENDING = "REMEDIATION_PENDING"
    REMEDIATED = "REMEDIATED"
    CLOSED = "CLOSED"


class Role(StrEnum):
    EMPLOYEE = "employee"
    SECURITY_VIEWER = "security_viewer"
    SECURITY_ANALYST = "security_analyst"
    SECURITY_ADMIN = "security_admin"
    PLATFORM_ADMIN = "platform_admin"


class IntakeSource(StrEnum):
    ADDIN = "addin"
    ADDIN_REPORT = "addin_report"
    SECURITY_MAILBOX = "security_mailbox"
    SHADOW = "shadow"
    UPLOAD = "upload"
    API = "api"


class RemediationType(StrEnum):
    LOCATE = "locate"
    QUARANTINE = "quarantine"
    DELETE = "delete"
    BLOCK_SENDER = "block_sender"
    BLOCK_DOMAIN = "block_domain"
    TRANSPORT_RULE_PROPOSAL = "transport_rule_proposal"
    RELEASE = "release"


class RemediationState(StrEnum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    DRY_RUN_EXECUTED = "DRY_RUN_EXECUTED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ExceptionType(StrEnum):
    TRUSTED_SENDER = "trusted_sender"
    TRUSTED_DOMAIN = "trusted_domain"
    TRUSTED_SENDER_DOMAIN_PAIR = "trusted_sender_domain_pair"
    APPROVED_DELEGATED_SERVICE = "approved_delegated_service"
    APPROVED_MARKETING_PLATFORM = "approved_marketing_platform"
    TEMPORARY = "temporary"
    RULE_SUPPRESSION = "rule_suppression"


class VTMode(StrEnum):
    DISABLED = "disabled"
    MOCK = "mock"
    PREMIUM = "premium"
    PRIVATE_SCANNING = "private_scanning"


class ProtectedCategory(StrEnum):
    EXECUTIVE = "executive"
    FINANCE = "finance"
    HR = "hr"
    ADMINISTRATOR = "administrator"
    SECURITY = "security"
    PROCUREMENT = "procurement"
    VIP = "vip"


class IntakeState(StrEnum):
    """Durable intake state machine for the security mailbox (ТЗ 1.0.1 §4.1).

    A message is only acknowledged in the mailbox after its intake record, its raw content and
    its analysis job are committed. The IMAP ``Seen`` flag is not a receipt: a worker that dies between the
    FETCH and the commit must find the message again on the next poll.
    """

    FETCHED = "FETCHED"  # persisted, raw content not yet stored
    STORED = "STORED"  # raw content committed to object storage
    JOB_CREATED = "JOB_CREATED"  # analysis job exists; safe to acknowledge
    ACKNOWLEDGED = "ACKNOWLEDGED"  # moved to the Processed folder
    DUPLICATE = "DUPLICATE"  # same report already ingested
    RETRY = "RETRY"  # transient failure, will be picked up again
    DEAD_LETTER = "DEAD_LETTER"  # gave up after max retries; moved to Failed


#: States from which a poll may safely re-process the message.
INTAKE_RESUMABLE = frozenset({IntakeState.FETCHED, IntakeState.STORED, IntakeState.RETRY})
#: States that mean the intake is finished, successfully or not.
INTAKE_TERMINAL = frozenset({IntakeState.ACKNOWLEDGED, IntakeState.DUPLICATE, IntakeState.DEAD_LETTER})


class ScanCompleteness(StrEnum):
    """How much of a message the platform was actually able to examine (ТЗ 1.0.1 §4.2).

    ``UNSCANNABLE`` and ``LIMIT_EXCEEDED`` never produce reassuring wording: a message that
    could not be examined is not a message that was found clean.
    """

    COMPLETE = "COMPLETE"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    UNSCANNABLE = "UNSCANNABLE"
    PARTIAL = "PARTIAL"


class RuleStatus(StrEnum):
    """Lifecycle state of a detection rule (ТЗ 1.0.3 §8, §10, §11).

    The states differ in two independent ways: whether the rule is *evaluated* at all, and
    whether its signal is allowed to *change the verdict*. Keeping those separate is what makes
    SHADOW possible — a rule that runs, is measured and is visible to an analyst, while being
    unable to affect what anyone is told.
    """

    #: Being drafted. Not evaluated anywhere, so a half-written rule cannot cost latency.
    EXPERIMENTAL = "EXPERIMENTAL"
    #: Evaluated and measured, but cannot change a verdict and is never shown to an employee.
    SHADOW = "SHADOW"
    #: Normal operation.
    ACTIVE = "ACTIVE"
    #: Active, but quality metrics have flagged it. Still contributes, and says so.
    DEGRADED = "DEGRADED"
    #: Switched off deliberately. Not evaluated.
    DISABLED = "DISABLED"
    #: Retired. Not evaluated, kept so historical verdicts stay explainable.
    DEPRECATED = "DEPRECATED"


#: Statuses whose rules are evaluated at all.
RULE_EVALUATED: frozenset[RuleStatus] = frozenset({RuleStatus.SHADOW, RuleStatus.ACTIVE, RuleStatus.DEGRADED})
#: Statuses whose signals may change the verdict. SHADOW is deliberately absent.
RULE_SCORING: frozenset[RuleStatus] = frozenset({RuleStatus.ACTIVE, RuleStatus.DEGRADED})


class AnalystClassification(StrEnum):
    """What an analyst concluded about a message (ТЗ 1.0.3 §22).

    This is the ground truth every quality metric is computed from, which is why it is a
    separate vocabulary from :class:`IncidentStatus`: an incident's workflow state and an
    analyst's verdict about the mail are different facts, and conflating them would make
    precision depend on whether someone remembered to close a ticket.
    """

    CONFIRMED_PHISHING = "CONFIRMED_PHISHING"
    CONFIRMED_BEC = "CONFIRMED_BEC"
    CONFIRMED_MALWARE = "CONFIRMED_MALWARE"
    SPAM = "SPAM"
    LEGITIMATE = "LEGITIMATE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN_SIMULATION = "BENIGN_SIMULATION"
    UNKNOWN = "UNKNOWN"


#: Classifications that confirm the platform was right about a threat.
CONFIRMED_THREAT: frozenset[AnalystClassification] = frozenset(
    {
        AnalystClassification.CONFIRMED_PHISHING,
        AnalystClassification.CONFIRMED_BEC,
        AnalystClassification.CONFIRMED_MALWARE,
    }
)
#: Classifications that say the platform was wrong to flag the message.
CONFIRMED_BENIGN: frozenset[AnalystClassification] = frozenset(
    {
        AnalystClassification.LEGITIMATE,
        AnalystClassification.FALSE_POSITIVE,
        AnalystClassification.BENIGN_SIMULATION,
    }
)


class Priority(StrEnum):
    """Analyst queue priority (ТЗ 1.0.3 §18).

    Priority is not risk. A MALICIOUS message to one person who already deleted it is less
    urgent than a HIGH_RISK campaign aimed at the finance department, and a queue sorted by
    risk score alone sends analysts to the wrong one first.
    """

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


PRIORITY_ORDER: dict[Priority, int] = {
    Priority.P1: 0,
    Priority.P2: 1,
    Priority.P3: 2,
    Priority.P4: 3,
}


class SlaState(StrEnum):
    """Where an incident stands against its acknowledgement target (ТЗ 1.0.3 §19)."""

    ON_TIME = "ON_TIME"
    DUE_SOON = "DUE_SOON"
    BREACHED = "BREACHED"
    MET = "MET"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class GapStatus(StrEnum):
    """Lifecycle of a known detection gap (ТЗ 1.0.3 §27)."""

    OPEN = "OPEN"
    ACCEPTED = "ACCEPTED"
    IN_PROGRESS = "IN_PROGRESS"
    FIXED = "FIXED"
    WONT_FIX = "WONT_FIX"


class FalseNegativeSource(StrEnum):
    """Who found the miss (ТЗ 1.0.3 §26).

    Recorded because the platform cannot discover its own false negatives: every one of these
    means a human or another system noticed something the platform did not.
    """

    ANALYST = "ANALYST"
    EMPLOYEE_REPORT = "EMPLOYEE_REPORT"
    GATEWAY = "GATEWAY"
    POST_INCIDENT = "POST_INCIDENT"
    EXTERNAL_TI = "EXTERNAL_TI"


class RootCause(StrEnum):
    """Why a message was missed (ТЗ 1.0.3 §26).

    Naming the layer matters: a miss caused by a parser limit is fixed somewhere completely
    different from one caused by a rule that never fired.
    """

    MISSING_FACT = "MISSING_FACT"
    MISSING_RULE = "MISSING_RULE"
    PARSER_FAILURE = "PARSER_FAILURE"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    RULE_FAILURE = "RULE_FAILURE"
    RISK_AGGREGATION_FAILURE = "RISK_AGGREGATION_FAILURE"
    UNKNOWN = "UNKNOWN"
