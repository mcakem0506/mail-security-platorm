"""Модель принуждения MSP 1.3 (ТЗ §4–§9, §23).

Никакого общего флага ``ENFORCEMENT=true`` нет и быть не может: у каждого контроля свой жизненный цикл и
своя готовность (§4). Состояния ``PRODUCTION_GLOBAL`` в этом этапе не существует (§5).
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def utcnow() -> datetime:
    return datetime.now(UTC)


class ControlType(StrEnum):
    SPAM_REJECT = "SPAM_REJECT"
    DMARC_REJECT = "DMARC_REJECT"
    RBL_REJECT = "RBL_REJECT"
    MALWARE_REJECT = "MALWARE_REJECT"
    PHISHING_REJECT = "PHISHING_REJECT"
    TEMPFAIL_ABUSE = "TEMPFAIL_ABUSE"
    QUARANTINE = "QUARANTINE"
    OUTBOUND_BLOCK = "OUTBOUND_BLOCK"


#: Контроли, которые могут отвечать в исходной SMTP-сессии (до ``250``).
PREQUEUE_CONTROLS = frozenset(
    {
        ControlType.SPAM_REJECT,
        ControlType.DMARC_REJECT,
        ControlType.RBL_REJECT,
        ControlType.MALWARE_REJECT,
        ControlType.PHISHING_REJECT,
        ControlType.TEMPFAIL_ABUSE,
    }
)

#: Контроли, действующие после ``250``: только удержание, карантин и разбор (§10, §11).
AFTERQUEUE_CONTROLS = frozenset({ControlType.QUARANTINE, ControlType.OUTBOUND_BLOCK})

#: Контроли, обход которых требует четырёх глаз (§40).
SENSITIVE_CONTROLS = frozenset(
    {
        ControlType.MALWARE_REJECT,
        ControlType.DMARC_REJECT,
        ControlType.RBL_REJECT,
        ControlType.PHISHING_REJECT,
    }
)


class ControlState(StrEnum):
    DISABLED = "DISABLED"
    SHADOW = "SHADOW"
    CANARY = "CANARY"
    PILOT = "PILOT"
    PAUSED = "PAUSED"
    ROLLED_BACK = "ROLLED_BACK"


#: Состояния, в которых контроль действует на почту.
ACTIVE_STATES = frozenset({ControlState.CANARY, ControlState.PILOT})

#: Допустимые переходы. В ``CANARY``/``PILOT`` попадают только из ``SHADOW`` (или из ``PAUSED`` обратно) и
#: только через проверку готовности и четыре глаза; ``ROLLED_BACK`` и ``PAUSED`` не включают контроль сами.
TRANSITIONS: dict[ControlState, frozenset[ControlState]] = {
    ControlState.DISABLED: frozenset({ControlState.SHADOW}),
    ControlState.SHADOW: frozenset({ControlState.CANARY, ControlState.DISABLED, ControlState.PAUSED}),
    ControlState.CANARY: frozenset(
        {ControlState.PILOT, ControlState.PAUSED, ControlState.ROLLED_BACK, ControlState.SHADOW}
    ),
    ControlState.PILOT: frozenset({ControlState.PAUSED, ControlState.ROLLED_BACK, ControlState.SHADOW}),
    ControlState.PAUSED: frozenset(
        {ControlState.SHADOW, ControlState.CANARY, ControlState.PILOT, ControlState.ROLLED_BACK}
    ),
    ControlState.ROLLED_BACK: frozenset({ControlState.SHADOW, ControlState.DISABLED}),
}


class Readiness(StrEnum):
    READY = "READY"
    READY_WITH_WARNINGS = "READY_WITH_WARNINGS"
    NOT_READY = "NOT_READY"
    BLOCKED_BY_GAP = "BLOCKED_BY_GAP"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    TEMPFAIL = "TEMPFAIL"
    REJECT = "REJECT"
    HOLD = "HOLD"
    QUARANTINE = "QUARANTINE"
    BYPASS = "BYPASS"
    NO_DECISION = "NO_DECISION"


class FailMode(StrEnum):
    """Постоянный отказ из-за внутренней ошибки запрещён (§15): режима ``FAIL_REJECT`` нет."""

    FAIL_OPEN = "FAIL_OPEN"
    FAIL_TEMPFAIL = "FAIL_TEMPFAIL"


class AppliedAction(StrEnum):
    """Что реально сделано с письмом. Хранится рядом с предложенным (§23)."""

    OBSERVE_ONLY = "OBSERVE_ONLY"
    DELIVERED = "DELIVERED"
    SMTP_TEMPFAIL = "SMTP_TEMPFAIL"
    SMTP_REJECT = "SMTP_REJECT"
    HELD = "HELD"
    QUARANTINED = "QUARANTINED"
    BYPASS_BY_EXCEPTION = "BYPASS_BY_EXCEPTION"
    BYPASS_KILL_SWITCH = "BYPASS_KILL_SWITCH"
    BYPASS_LOCAL = "BYPASS_LOCAL"
    SAFE_MODE = "SAFE_MODE"


class ExceptionScope(StrEnum):
    SENDER = "SENDER"
    SENDER_DOMAIN = "SENDER_DOMAIN"
    RECIPIENT = "RECIPIENT"
    RECIPIENT_GROUP = "RECIPIENT_GROUP"
    SOURCE_IP = "SOURCE_IP"
    MESSAGE_ID = "MESSAGE_ID"
    CAMPAIGN = "CAMPAIGN"
    CONTROL = "CONTROL"


#: Контроль → допустимый режим сбоя по умолчанию (§15).
DEFAULT_FAIL_MODE: dict[ControlType, FailMode] = {
    ControlType.SPAM_REJECT: FailMode.FAIL_OPEN,
    ControlType.DMARC_REJECT: FailMode.FAIL_OPEN,
    ControlType.RBL_REJECT: FailMode.FAIL_OPEN,
    ControlType.MALWARE_REJECT: FailMode.FAIL_OPEN,
    ControlType.PHISHING_REJECT: FailMode.FAIL_OPEN,
    ControlType.TEMPFAIL_ABUSE: FailMode.FAIL_TEMPFAIL,
    ControlType.QUARANTINE: FailMode.FAIL_OPEN,
    ControlType.OUTBOUND_BLOCK: FailMode.FAIL_OPEN,
}


class EnforcementDecision(Strict):
    """Решение с доказательствами и версией политики. Пятисотый ответ без них невозможен (§93, п. 9)."""

    transport_message_id: str = ""
    control_id: str
    control_type: ControlType
    decision: Decision
    smtp_action: str = ""
    suggested_action: str = ""
    applied_action: AppliedAction = AppliedAction.OBSERVE_ONLY
    reason_codes: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    policy_version: str = ""
    policy_checksum: str = ""
    engine_versions: dict[str, str] = Field(default_factory=dict)
    decided_at: datetime = Field(default_factory=utcnow)
    latency_ms: float = 0.0
    fail_mode_applied: FailMode | None = None
    recipient_count: int = 1
    #: Ссылка на предыдущую попытку той же сессии (повтор, §69).
    previous_attempt: str = ""

    def is_destructive(self) -> bool:
        return self.decision in (Decision.REJECT, Decision.QUARANTINE, Decision.HOLD, Decision.TEMPFAIL)


class RejectSafetyReport(Strict):
    """§45. Знаменателя нет — значение ``None``, а не 0."""

    reviewed_rejects: int = 0
    confirmed_correct: int = 0
    confirmed_fp: int = 0
    critical_fp: int = 0
    fp_rate: float | None = None
    fp_upper_bound: float | None = None
    sample_window: str = ""
    ready_for_canary: bool = False
    ready_for_pilot: bool = False
    reasons: tuple[str, ...] = ()
