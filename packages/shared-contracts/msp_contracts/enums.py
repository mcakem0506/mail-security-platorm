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
    #: Unwanted mail, confirmed as such. Separate from the attack verdicts on purpose: flagging
    #: spam is not a false positive, and treating it as an attack is an error.
    CONFIRMED_SPAM = "CONFIRMED_SPAM"
    #: Someone was impersonated, but the message asked for nothing yet — reconnaissance, or the
    #: opening move. Confirmed as a threat without being phishing, BEC or malware.
    CONFIRMED_IMPERSONATION = "CONFIRMED_IMPERSONATION"
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
        AnalystClassification.CONFIRMED_IMPERSONATION,
    }
)
#: Spam sits in neither set. It is unwanted but not an attack, so counting it as a confirmed
#: threat would inflate precision and counting it as benign would turn every spam flag into a
#: false positive.
CONFIRMED_UNWANTED: frozenset[AnalystClassification] = frozenset({AnalystClassification.CONFIRMED_SPAM})
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
    #: Fixed in a candidate pack and waiting for the golden corpus to agree. A gap is not closed
    #: by a code change, it is closed by a case that used to fail and now passes.
    VALIDATION = "VALIDATION"
    RESOLVED = "RESOLVED"
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
    #: Found by a planned exercise rather than by an attack. Counted separately because a miss
    #: a red team had to construct says something different about exposure than one a real
    #: campaign walked through.
    RED_TEAM = "RED_TEAM"


class RootCause(StrEnum):
    """Why a message was missed (ТЗ 1.0.3 §26).

    Naming the layer matters: a miss caused by a parser limit is fixed somewhere completely
    different from one caused by a rule that never fired.
    """

    MISSING_RULE = "MISSING_RULE"
    MISSING_FACT = "MISSING_FACT"
    PARSER_FAILURE = "PARSER_FAILURE"
    #: Extracted, but the normalised form lost what mattered — a decoded header, a folded
    #: subject, a punycode host rendered back to Unicode.
    NORMALIZATION_FAILURE = "NORMALIZATION_FAILURE"
    #: External intelligence had nothing on an indicator that later proved malicious.
    TI_MISSING = "TI_MISSING"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    #: The rule exists and the facts were there; its condition did not match.
    RULE_LOGIC = "RULE_LOGIC"
    #: Signals fired, but the score never reached the threshold.
    RISK_AGGREGATION = "RISK_AGGREGATION"
    #: An exception suppressed the signal that would have caught it. The most dangerous of
    #: these, because the platform was not blind — it had been told to look away.
    EXCEPTION_SUPPRESSION = "EXCEPTION_SUPPRESSION"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class CanaryScope(StrEnum):
    """How a canary rollout picks the mailboxes a rule applies to (ТЗ 1.0.3 §52)."""

    #: An explicit list of mailboxes. The most predictable, and the right choice for a rule
    #: aimed at a specific group — the finance department, say.
    MAILBOX = "MAILBOX"
    #: Everyone in the named departments, as the directory reports them.
    DEPARTMENT = "DEPARTMENT"
    #: A deterministic share of mailboxes, chosen by hashing the address. Stable by
    #: construction: the same person is always on the same side of the split, because a rule
    #: that treats one person differently from one message to the next cannot be explained to
    #: them and cannot be measured.
    PERCENT = "PERCENT"


class CanaryState(StrEnum):
    """Where a canary rollout stands."""

    ACTIVE = "ACTIVE"
    #: Scope lifted, rule now applies to everyone.
    PROMOTED = "PROMOTED"
    #: Rolled back; the rule is expected to go to DEGRADED or SHADOW in the rule pack.
    ABORTED = "ABORTED"


class SignalDisposition(StrEnum):
    """What an analyst thought of one signal inside a verdict (ТЗ 1.0.3B §4).

    Per-signal rather than per-message, because "the platform was wrong" is not actionable and
    "rule BEC-014 fired on an ordinary supplier letter" is. The middle values matter most: a
    rule that is right about the fact and wrong about how much it matters needs its weight
    changed, not its condition.
    """

    CORRECT = "CORRECT"
    INCORRECT = "INCORRECT"
    #: Right about the fact, too loud about it.
    TOO_SEVERE = "TOO_SEVERE"
    #: Right about the fact, too quiet to matter.
    TOO_WEAK = "TOO_WEAK"
    #: True, but not evidence of anything here.
    IRRELEVANT = "IRRELEVANT"
    #: Says the same thing another signal already said.
    DUPLICATE = "DUPLICATE"


class FalsePositiveReason(StrEnum):
    """Why a detection was wrong (ТЗ 1.0.3B §5).

    The reason decides who fixes it and how. "Overbroad rule" goes to the rule owner, "parser
    context loss" goes to the parser, and "known vendor" may need no rule change at all — only
    an exception with an owner and a review date. A free-text comment alone cannot be counted,
    sorted or assigned.
    """

    LEGITIMATE_BUSINESS_PATTERN = "LEGITIMATE_BUSINESS_PATTERN"
    TRUSTED_EXTERNAL_SERVICE = "TRUSTED_EXTERNAL_SERVICE"
    SHARED_ROLE_NAME = "SHARED_ROLE_NAME"
    EXPECTED_FORWARDING = "EXPECTED_FORWARDING"
    EXPECTED_DOMAIN_ALIAS = "EXPECTED_DOMAIN_ALIAS"
    KNOWN_VENDOR = "KNOWN_VENDOR"
    AUTHENTICATION_EDGE_CASE = "AUTHENTICATION_EDGE_CASE"
    PARSER_CONTEXT_LOSS = "PARSER_CONTEXT_LOSS"
    OVERBROAD_RULE = "OVERBROAD_RULE"
    OTHER = "OTHER"


class RuleHealth(StrEnum):
    """How a rule is doing in production (ТЗ 1.0.3B §8).

    Health never switches a rule off by itself. A rule is disabled by a reviewed change, because
    an automatic rule that silences detection when the data looks odd is a way for an attacker,
    or an unlucky week, to turn off a control.
    """

    HEALTHY = "HEALTHY"
    #: Fires, but nobody has judged any of it — precision is unknown, not good.
    NO_DATA = "NO_DATA"
    NOISY = "NOISY"
    #: Precision fell against the previous period.
    REGRESSED = "REGRESSED"
    #: Barely fires; the scenario it covers may be unmeasured rather than absent.
    LOW_COVERAGE = "LOW_COVERAGE"
    DEGRADED = "DEGRADED"


class CandidateState(StrEnum):
    """Review state of a candidate rule pack (ТЗ 1.0.3B §12)."""

    DRAFT = "DRAFT"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"
    APPROVED = "APPROVED"
    PUBLISHED = "PUBLISHED"
    REJECTED = "REJECTED"


class ValidationSource(StrEnum):
    """Откуда письмо попало в набор валидации (ТЗ 1.0.4 §11).

    Источник хранится не для статистики: от него зависит, что о письме известно. Из ящика
    безопасности приходит то, что переслал человек, — со своим заголовком пересылки и без части
    исходных. Копия из журнала даёт письмо в том виде, в котором его видел сервер. Это разные
    данные, и смешивать их в одной метрике, не называя источник, значит считать несравнимое.
    """

    SECURITY_MAILBOX = "SECURITY_MAILBOX"
    EWS_READONLY = "EWS_READONLY"
    JOURNAL_COPY = "JOURNAL_COPY"
    GATEWAY_EVIDENCE = "GATEWAY_EVIDENCE"
    ANALYST_UPLOAD = "ANALYST_UPLOAD"


class PiiStatus(StrEnum):
    """Что сделано с персональными данными письма (ТЗ 1.0.4 §8, §22).

    ``RAW`` — письмо как пришло. Такое письмо нельзя ни экспортировать, ни продвигать в золотой
    корпус, и срок его хранения короче всех остальных.

    ``ANONYMIZED`` — замены сделаны автоматически. ``REVIEWED`` — человек подтвердил, что в
    результате ничего не осталось. Разделены намеренно: автоматическая замена находит то, что
    описано шаблоном, а фамилию в середине фразы — нет, и признавать её работу за проверку
    значило бы выдавать её возможности за гарантию.
    """

    RAW = "RAW"
    ANONYMIZED = "ANONYMIZED"
    REVIEWED = "REVIEWED"
    #: Проверка нашла то, чего быть не должно. Состояние тупиковое: такое письмо не экспортируется.
    REJECTED = "REJECTED"


class PromotionState(StrEnum):
    """Путь письма в золотой корпус (ТЗ 1.0.4 §10). Автоматического продвижения нет."""

    NOT_REQUESTED = "NOT_REQUESTED"
    REQUESTED = "REQUESTED"
    APPROVED = "APPROVED"
    PROMOTED = "PROMOTED"
    REJECTED = "REJECTED"


class QrHealth(StrEnum):
    """Состояние необязательного компонента чтения QR-кодов (ТЗ 1.0.4 §6).

    ``DISABLED`` и ``FAILED`` различаются намеренно. Первое означает «компонент не установлен, и
    так задумано», второе — «установлен и не работает». Для администратора это разные задачи, а
    для письма — одинаковое следствие: код остаётся непрочитанным и помечается как
    непрочитанный, а не как отсутствующий.
    """

    AVAILABLE = "AVAILABLE"
    DEGRADED = "DEGRADED"
    DISABLED = "DISABLED"
    FAILED = "FAILED"


class DomainVariantStatus(StrEnum):
    """Состояние варианта защищаемого домена (ТЗ 1.0.4 §4).

    ``GENERATED`` — вариант вычислен офлайн и ни разу не встречался. Таких большинство: для
    четырёхбуквенной метки их больше трёхсот, и это нормально — реестр существует, чтобы
    встреченный вариант можно было опознать мгновенно, а не чтобы перечислять угрозы.

    ``KNOWN_LEGITIMATE`` обращается с вариантом как с исключением, потому что им и является:
    он гасит сигнал. Поэтому у него есть владелец, причина и запись в аудите.
    """

    GENERATED = "GENERATED"
    OBSERVED = "OBSERVED"
    APPROVED_SUSPICIOUS = "APPROVED_SUSPICIOUS"
    KNOWN_LEGITIMATE = "KNOWN_LEGITIMATE"
    IGNORED = "IGNORED"


class CampaignMatchReason(StrEnum):
    """Why a message was put in a campaign (ТЗ 1.0.3B §20).

    Stored per match rather than per campaign: an analyst disagreeing with one message's
    membership needs to see what tied *that* message in, not the campaign's general shape.
    """

    SAME_URL = "SAME_URL"
    SAME_HASH = "SAME_HASH"
    SAME_SENDER = "SAME_SENDER"
    SAME_DOMAIN = "SAME_DOMAIN"
    SUBJECT_SIMILARITY = "SUBJECT_SIMILARITY"
    BODY_SIMILARITY = "BODY_SIMILARITY"
    TEMPORAL_CLUSTER = "TEMPORAL_CLUSTER"
    SAME_INFRASTRUCTURE = "SAME_INFRASTRUCTURE"
    SAME_GATEWAY_SIGNATURE = "SAME_GATEWAY_SIGNATURE"


class ReanalysisState(StrEnum):
    """Lifecycle of a bulk re-evaluation job (ТЗ 1.0.3B §23)."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
