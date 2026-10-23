"""Движок решений принуждения (ТЗ §9–§15, §19–§23, §25–§31, §41, §53, §57, §68, §69).

Движок **не анализирует** письмо (§13): он получает нормализованные свидетельства, применяет версионированную
политику узла и возвращает решение с причинами. Решение принимается по проверенной локальной копии политики и
не требует плоскости управления, базы данных или внешних сервисов (§48).

Порядок проверок для каждого контроля:

1. локальный обход и общий выключатель (работают без плоскости управления);
2. безопасный режим при просроченной политике;
3. состояние контроля (в ``SHADOW`` решение только предлагается);
4. область канарейки — для всех получателей сразу (§68);
5. исключение (§41): применённое действие меняется, предложенное и свидетельства остаются;
6. условия контроля; блокировка по пробелам срабатывает здесь же и независимо от панели (§8, §73);
7. тайм-аут и режим сбоя (§14, §15).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime

from pydantic import Field

from .canary import all_recipients_in_scope
from .exceptions import matching
from .model import (
    ACTIVE_STATES,
    AFTERQUEUE_CONTROLS,
    PREQUEUE_CONTROLS,
    AppliedAction,
    ControlState,
    ControlType,
    Decision,
    EnforcementDecision,
    FailMode,
    Strict,
    utcnow,
)
from .policy import ControlPolicy, EnforcementPolicy, PolicyStatus
from .readiness import blocking_gaps, restricted_reasons

#: Порядок опроса контролей; при равной тяжести побеждает более ранний.
CONTROL_ORDER = (
    ControlType.MALWARE_REJECT,
    ControlType.PHISHING_REJECT,
    ControlType.DMARC_REJECT,
    ControlType.RBL_REJECT,
    ControlType.SPAM_REJECT,
    ControlType.TEMPFAIL_ABUSE,
    ControlType.QUARANTINE,
    ControlType.OUTBOUND_BLOCK,
)

_SEVERITY = {
    Decision.REJECT: 5,
    Decision.TEMPFAIL: 4,
    Decision.QUARANTINE: 3,
    Decision.HOLD: 2,
    Decision.ALLOW: 1,
    Decision.BYPASS: 1,
    Decision.NO_DECISION: 0,
}


class MalwareEvidence(Strict):
    verdict: str = "UNKNOWN"  # MALICIOUS | CLEAN | UNKNOWN
    confidence: float = 0.0
    encrypted_unscannable: bool = False
    unsupported: bool = False
    timed_out: bool = False


class EnforcementInput(Strict):
    """Нормализованные свидетельства. Заголовки из письма сюда не попадают как доверенные (§57)."""

    transport_message_id: str = ""
    message_id: str = ""
    sender: str = ""
    recipients: tuple[str, ...] = ()
    source_ip: str = ""
    direction: str = "INBOUND"
    #: Свидетельства сканера и аутентификации получены от самого шлюза (доверенный путь), а не из заголовков.
    trusted_evidence: bool = False
    spam_score: float = 0.0
    spam_class: str = "UNKNOWN"
    suggested_action: str = ""
    reason_codes: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    rbl_listed: tuple[str, ...] = ()  # коды совпавших лицензированных провайдеров
    rbl_provider_errors: bool = False
    dmarc_result: str = "NONE"  # PASS | FAIL | TEMPERROR | NONE
    dmarc_policy: str = "NONE"  # NONE | QUARANTINE | REJECT
    forwarding_or_list: bool = False
    arc_pass: bool = False
    malware: MalwareEvidence = Field(default_factory=MalwareEvidence)
    risk_verdict: str = "UNKNOWN"  # итог полного анализа MSP после очереди
    abuse_flag: bool = False
    compromised_account: bool = False
    campaign: str = ""
    #: Сколько миллисекунд ушло на получение свидетельств (для тайм-аута).
    elapsed_ms: float = 0.0
    previous_attempt: str = ""


class Switches(Strict):
    """Состояние, которое должно работать без плоскости управления (§19, §20)."""

    kill_switch: bool = False
    local_bypass: bool = False


class Runtime(Strict):
    policy: EnforcementPolicy | None = None
    status: PolicyStatus = PolicyStatus.SAFE_MODE
    switches: Switches = Field(default_factory=Switches)
    exception_uses: Mapping[str, int] = Field(default_factory=dict)
    engine_versions: Mapping[str, str] = Field(default_factory=dict)
    now: datetime = Field(default_factory=utcnow)


class Outcome(Strict):
    final: EnforcementDecision | None
    decisions: tuple[EnforcementDecision, ...] = ()
    smtp_reply: str = ""
    consumed_exceptions: tuple[str, ...] = ()


def _base(inp: EnforcementInput, rt: Runtime, cp: ControlPolicy) -> dict[str, object]:
    return {
        "transport_message_id": inp.transport_message_id,
        "control_id": cp.control_type.value,
        "control_type": cp.control_type,
        "policy_version": rt.policy.version if rt.policy else "",
        "policy_checksum": rt.policy.checksum() if rt.policy else "",
        "engine_versions": dict(rt.engine_versions),
        "latency_ms": inp.elapsed_ms,
        "recipient_count": len(inp.recipients),
        "evidence_ids": inp.evidence_ids,
        "previous_attempt": inp.previous_attempt,
    }


def _candidate(
    cp: ControlPolicy, inp: EnforcementInput, gaps: Mapping[str, str]
) -> tuple[Decision, tuple[str, ...]]:
    """Что контроль предложил бы по условиям, не глядя на состояние. ``NO_DECISION`` — условий нет."""
    kind = cp.control_type
    th = cp.thresholds
    reasons = tuple(inp.reason_codes)

    if kind is ControlType.SPAM_REJECT:
        if inp.spam_score < th.get("reject_score", 15.0) or inp.spam_class != "HIGH_CONFIDENCE_SPAM":
            return Decision.NO_DECISION, ()
        # GAP-005: SPF не может быть единственным основанием отказа (§7).
        solid = [r for r in reasons if r not in restricted_reasons(gaps)]
        if not solid:
            return Decision.NO_DECISION, ("SPF_ONLY_FORBIDDEN_BY_GAP-005",)
        return Decision.REJECT, tuple(solid)

    if kind is ControlType.DMARC_REJECT:
        if blocking_gaps(kind, gaps):
            return Decision.NO_DECISION, ("BLOCKED_BY_GAP",)
        if inp.dmarc_result == "TEMPERROR":
            return Decision.NO_DECISION, ("DMARC_TEMPERROR_IS_NOT_FAIL",)
        if inp.dmarc_result != "FAIL" or inp.dmarc_policy != "REJECT":
            return Decision.NO_DECISION, ()
        if inp.forwarding_or_list or inp.arc_pass:
            return Decision.NO_DECISION, ("FORWARDING_OR_ARC_CONTEXT",)
        return Decision.REJECT, ("DMARC_POLICY_REJECT_FAIL",)

    if kind is ControlType.RBL_REJECT:
        if inp.rbl_provider_errors and not inp.rbl_listed:
            return Decision.NO_DECISION, ("PROVIDER_ERROR_IS_NOT_A_LISTING",)
        if not inp.rbl_listed:
            return Decision.NO_DECISION, ()
        return Decision.REJECT, tuple(f"RBL_LISTED:{code}" for code in inp.rbl_listed)

    if kind is ControlType.MALWARE_REJECT:
        m = inp.malware
        if m.encrypted_unscannable or m.unsupported:
            return Decision.NO_DECISION, ("ENCRYPTED_OR_UNSUPPORTED_IS_NOT_MALWARE",)
        if m.verdict == "MALICIOUS" and m.confidence >= th.get("min_confidence", 0.95):
            return Decision.REJECT, ("MALWARE_HIGH_CONFIDENCE",)
        return Decision.NO_DECISION, ()

    if kind is ControlType.PHISHING_REJECT:
        if inp.risk_verdict == "MALICIOUS" and inp.spam_score >= th.get("reject_score", 15.0):
            return Decision.REJECT, ("PHISHING_SYNC_PATH",)
        return Decision.NO_DECISION, ()

    if kind is ControlType.TEMPFAIL_ABUSE:
        return (Decision.TEMPFAIL, ("CONNECTION_ABUSE",)) if inp.abuse_flag else (Decision.NO_DECISION, ())

    if kind is ControlType.QUARANTINE:
        m = inp.malware
        if inp.risk_verdict in ("HIGH_RISK", "MALICIOUS"):
            return Decision.QUARANTINE, (f"RISK_{inp.risk_verdict}",)
        if m.encrypted_unscannable:
            return Decision.QUARANTINE, ("ENCRYPTED_UNSCANNABLE",)
        return Decision.NO_DECISION, ()

    if kind is ControlType.OUTBOUND_BLOCK:
        if inp.direction != "OUTBOUND":
            return Decision.NO_DECISION, ()
        if inp.malware.verdict == "MALICIOUS":
            return Decision.HOLD, ("OUTBOUND_MALWARE",)
        if inp.compromised_account:
            return Decision.TEMPFAIL, ("COMPROMISED_ACCOUNT",)
    return Decision.NO_DECISION, ()


def _allowed_here(kind: ControlType, decision: Decision) -> bool:
    """§10–§11: после ``250`` 5xx невозможен, до очереди — только ответ SMTP."""
    if decision in (Decision.REJECT, Decision.TEMPFAIL):
        return kind in PREQUEUE_CONTROLS or (
            kind is ControlType.OUTBOUND_BLOCK and decision is Decision.TEMPFAIL
        )
    if decision in (Decision.QUARANTINE, Decision.HOLD):
        return kind in AFTERQUEUE_CONTROLS
    return True


_APPLIED = {
    Decision.REJECT: AppliedAction.SMTP_REJECT,
    Decision.TEMPFAIL: AppliedAction.SMTP_TEMPFAIL,
    Decision.QUARANTINE: AppliedAction.QUARANTINED,
    Decision.HOLD: AppliedAction.HELD,
}


def evaluate_control(
    inp: EnforcementInput, rt: Runtime, cp: ControlPolicy
) -> tuple[EnforcementDecision, str | None]:
    """Решение одного контроля и, если сработало исключение, его идентификатор (для учёта использований)."""
    policy = rt.policy
    assert policy is not None
    base = _base(inp, rt, cp)
    fail = cp.effective_fail_mode()

    def make(
        decision: Decision,
        applied: AppliedAction,
        reasons: Iterable[str],
        suggested: str = "",
        fail_mode: FailMode | None = None,
        smtp: str = "",
    ) -> EnforcementDecision:
        return EnforcementDecision(
            **base,  # type: ignore[arg-type]
            decision=decision,
            applied_action=applied,
            reason_codes=tuple(reasons),
            suggested_action=suggested,
            fail_mode_applied=fail_mode,
            smtp_action=smtp,
        )

    suggested_decision, reasons = _candidate(cp, inp, policy.gaps)
    suggested = suggested_decision.value if suggested_decision is not Decision.NO_DECISION else ""

    # 1–2. обход и безопасный режим
    if rt.switches.local_bypass:
        return make(Decision.BYPASS, AppliedAction.BYPASS_LOCAL, ("LOCAL_BYPASS", *reasons), suggested), None
    if rt.switches.kill_switch:
        return make(
            Decision.BYPASS, AppliedAction.BYPASS_KILL_SWITCH, ("KILL_SWITCH", *reasons), suggested
        ), None
    if rt.status in (PolicyStatus.SAFE_MODE, PolicyStatus.INVALID):
        return make(
            Decision.BYPASS, AppliedAction.SAFE_MODE, ("SAFE_MODE_STALE_POLICY", *reasons), suggested
        ), None

    # 3. состояние контроля
    if cp.state not in ACTIVE_STATES:
        return make(
            Decision.ALLOW, AppliedAction.OBSERVE_ONLY, (f"STATE_{cp.state.value}", *reasons), suggested
        ), None

    # 6a. пробелы блокируют контроль технически, даже если панель выставила состояние
    if blocking_gaps(cp.control_type, policy.gaps):
        return make(
            Decision.NO_DECISION, AppliedAction.OBSERVE_ONLY, ("BLOCKED_BY_GAP", *reasons), suggested
        ), None

    # доверие к свидетельствам (§57): без доверенного пути принуждения нет
    if not inp.trusted_evidence:
        return make(
            Decision.NO_DECISION, AppliedAction.OBSERVE_ONLY, ("UNTRUSTED_EVIDENCE", *reasons), suggested
        ), None

    # 7. тайм-аут и режим сбоя
    if inp.elapsed_ms > cp.hard_timeout_ms:
        if fail is FailMode.FAIL_TEMPFAIL and cp.control_type in PREQUEUE_CONTROLS:
            return make(
                Decision.TEMPFAIL,
                AppliedAction.SMTP_TEMPFAIL,
                ("DECISION_TIMEOUT",),
                suggested,
                fail,
                cp.tempfail_reply,
            ), None
        return make(
            Decision.NO_DECISION,
            AppliedAction.OBSERVE_ONLY,
            ("DECISION_TIMEOUT", *reasons),
            suggested,
            FailMode.FAIL_OPEN,
        ), None
    if cp.control_type is ControlType.MALWARE_REJECT and inp.malware.timed_out:
        return make(
            Decision.NO_DECISION,
            AppliedAction.OBSERVE_ONLY,
            ("SCANNER_TIMEOUT_FAIL_OPEN",),
            suggested,
            FailMode.FAIL_OPEN,
        ), None

    if suggested_decision is Decision.NO_DECISION:
        return make(Decision.ALLOW, AppliedAction.OBSERVE_ONLY, reasons, ""), None

    # Каждый отказ несёт свидетельства и версию политики (ТЗ §93, п. 9): без них решение не исполняется.
    if suggested_decision is Decision.REJECT and not (inp.evidence_ids and reasons and policy.version):
        return make(
            Decision.NO_DECISION,
            AppliedAction.OBSERVE_ONLY,
            ("MISSING_EVIDENCE_FOR_REJECT", *reasons),
            suggested,
        ), None

    if not _allowed_here(cp.control_type, suggested_decision):
        return make(
            Decision.NO_DECISION,
            AppliedAction.OBSERVE_ONLY,
            ("ACTION_NOT_ALLOWED_AT_THIS_STAGE", *reasons),
            suggested,
        ), None

    # 4. область (все получатели сразу)
    if not all_recipients_in_scope(
        cp.canary_scope,
        cp.control_type,
        recipients=inp.recipients,
        sender=inp.sender,
        source_ip=inp.source_ip,
        groups=policy.groups,
    ):
        return make(
            Decision.ALLOW, AppliedAction.OBSERVE_ONLY, ("OUT_OF_CANARY_SCOPE", *reasons), suggested
        ), None

    # 5. исключение
    exc = matching(
        policy.exceptions,
        cp.control_type,
        now=rt.now,
        sender=inp.sender,
        recipients=inp.recipients,
        source_ip=inp.source_ip,
        message_id=inp.message_id,
        campaign=inp.campaign,
        groups=policy.groups,
        uses=rt.exception_uses,
    )
    if exc is not None:
        return make(
            Decision.BYPASS, AppliedAction.BYPASS_BY_EXCEPTION, ("EXCEPTION", exc.id, *reasons), suggested
        ), exc.id

    smtp = ""
    if suggested_decision is Decision.REJECT:
        smtp = cp.reject_reply
    elif suggested_decision is Decision.TEMPFAIL:
        smtp = cp.tempfail_reply
    return make(suggested_decision, _APPLIED[suggested_decision], reasons, suggested, None, smtp), None


def decide(inp: EnforcementInput, rt: Runtime) -> Outcome:
    """Решения по всем контролям политики и итоговое — самое строгое из действующих."""
    if rt.policy is None:
        return Outcome(final=None)
    decisions: list[EnforcementDecision] = []
    consumed: list[str] = []
    order = {kind: i for i, kind in enumerate(CONTROL_ORDER)}
    for cp in sorted(rt.policy.controls, key=lambda c: order.get(c.control_type, 99)):
        d, used = evaluate_control(inp, rt, cp)
        decisions.append(d)
        if used:
            consumed.append(used)
    applied = [
        d
        for d in decisions
        if d.applied_action
        in (
            AppliedAction.SMTP_REJECT,
            AppliedAction.SMTP_TEMPFAIL,
            AppliedAction.QUARANTINED,
            AppliedAction.HELD,
        )
    ]
    final = max(applied, key=lambda d: _SEVERITY[d.decision], default=None)
    return Outcome(
        final=final,
        decisions=tuple(decisions),
        smtp_reply=final.smtp_action if final else "",
        consumed_exceptions=tuple(consumed),
    )


__all__ = [
    "ControlState",
    "EnforcementInput",
    "MalwareEvidence",
    "Outcome",
    "Runtime",
    "Switches",
    "decide",
    "evaluate_control",
]
