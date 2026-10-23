"""Готовность контролей и блокировка известными пробелами (ТЗ §4–§8, §24–§30, §45–§46, §84).

Готовность считается отдельно для каждого контроля. Известный пробел блокирует активацию технически:
``BLOCKED_BY_GAP`` нельзя обойти ни настройкой, ни обходом проверки (§8, §73).
"""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import Field

from .model import ControlType, Readiness, RejectSafetyReport, Strict

#: Контроль → пробелы, которые должны быть ``RESOLVED``, иначе контроль заблокирован.
BLOCKING_GAPS: dict[ControlType, tuple[str, ...]] = {
    ControlType.DMARC_REJECT: ("GAP-006",),
}

#: Пробелы, ограничивающие *основания* решений, а не контроль целиком.
#: GAP-005: SPF остаётся свидетельством и не может быть единственным основанием отказа (§7).
REASON_RESTRICTING_GAPS: dict[str, frozenset[str]] = {
    "GAP-005": frozenset({"AUTH_SPF_FAIL", "AUTH_SPF_SOFTFAIL", "AUTH_SPF_PERMERROR", "AUTH_SPF_NONE"}),
}

RESOLVED = "RESOLVED"

#: Параметры охраны по умолчанию (§46); переопределяются настройками организации.
DEFAULT_MIN_REVIEWED = 100
DEFAULT_MAX_FP_UPPER = 0.01


class ReadinessInput(Strict):
    gaps: Mapping[str, str] = Field(default_factory=dict)  # gap_id -> статус реестра
    reject_safety: RejectSafetyReport = Field(default_factory=RejectSafetyReport)
    min_reviewed: int = DEFAULT_MIN_REVIEWED
    max_fp_upper: float = DEFAULT_MAX_FP_UPPER
    #: Выборка получена на реальном потоке (иначе лабораторная) — для пилота нужна только реальная (§83).
    real_evidence: bool = False
    lab_mode: bool = False
    thresholds_versioned: bool = True
    control_tests_green: bool = False
    rspamd_failopen_tested: bool = False
    #: Аудит действий сканера (§50): ``False`` — найден неизвестный источник reject/soft reject.
    effective_actions_clean: bool = False
    systemic_fp_unresolved: bool = False
    # RBL
    license_approved: bool = False
    provider_healthy: bool = False
    no_secret_leakage_tested: bool = False
    # MALWARE
    timeout_semantics_tested: bool = False
    malware_high_confidence_only: bool = False
    # PHISHING
    sync_path_approved: bool = False
    # QUARANTINE
    quarantine_backend_healthy: bool = False
    release_tested: bool = False
    # OUTBOUND
    outbound_acceptance: bool = False


class ReadinessReport(Strict):
    control_type: ControlType
    status: Readiness
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    can_canary: bool = False
    can_pilot: bool = False


def blocking_gaps(control: ControlType, gaps: Mapping[str, str]) -> tuple[str, ...]:
    """Пробелы, не закрытые для этого контроля. Нет записи о пробеле — он считается открытым."""
    return tuple(gap for gap in BLOCKING_GAPS.get(control, ()) if gaps.get(gap) != RESOLVED)


def restricted_reasons(gaps: Mapping[str, str]) -> frozenset[str]:
    """Коды оснований, которые не могут быть единственной причиной отказа, пока пробел открыт."""
    out: set[str] = set()
    for gap, codes in REASON_RESTRICTING_GAPS.items():
        if gaps.get(gap) != RESOLVED:
            out |= codes
    return frozenset(out)


def _sample_reasons(inp: ReadinessInput) -> list[str]:
    rs = inp.reject_safety
    reasons: list[str] = []
    if rs.reviewed_rejects < inp.min_reviewed:
        reasons.append(f"INSUFFICIENT_SAMPLE: просмотрено {rs.reviewed_rejects}, нужно {inp.min_reviewed}")
    if rs.critical_fp > 0:
        reasons.append(f"CRITICAL_FP: {rs.critical_fp}")
    if rs.fp_rate is None:
        reasons.append("FP_NOT_MEASURED")
    elif rs.fp_rate > inp.max_fp_upper:
        reasons.append(f"FP_ABOVE_THRESHOLD: доля ложных {rs.fp_rate:.2%} > {inp.max_fp_upper:.2%}")
    if inp.systemic_fp_unresolved:
        reasons.append("SYSTEMIC_FP_UNRESOLVED")
    return reasons


def assess(control: ControlType, inp: ReadinessInput) -> ReadinessReport:
    blocked = blocking_gaps(control, inp.gaps)
    if blocked:
        return ReadinessReport(
            control_type=control,
            status=Readiness.BLOCKED_BY_GAP,
            reasons=tuple(f"GAP_OPEN:{gap}" for gap in blocked),
        )

    reasons: list[str] = []
    warnings: list[str] = []

    # Общее для всех: аудит скрытых действий сканера (§50) и версионируемые пороги.
    if not inp.effective_actions_clean:
        reasons.append("EFFECTIVE_ACTIONS_NOT_AUDITED_OR_UNKNOWN_SOURCE")
    if not inp.thresholds_versioned:
        reasons.append("THRESHOLDS_NOT_VERSIONED")
    if not inp.control_tests_green:
        reasons.append("CONTROL_TESTS_NOT_GREEN")

    if control in (ControlType.SPAM_REJECT, ControlType.RBL_REJECT, ControlType.MALWARE_REJECT):
        reasons.extend(_sample_reasons(inp))
    if control is ControlType.SPAM_REJECT and not inp.rspamd_failopen_tested:
        reasons.append("RSPAMD_FAILOPEN_NOT_TESTED")
    if control is ControlType.RBL_REJECT:
        if not inp.license_approved:
            reasons.append("LICENSE_NOT_APPROVED")
        if not inp.provider_healthy:
            reasons.append("PROVIDER_NOT_HEALTHY")
        if not inp.no_secret_leakage_tested:
            reasons.append("SECRET_LEAKAGE_NOT_TESTED")
    if control is ControlType.MALWARE_REJECT:
        if not inp.malware_high_confidence_only:
            reasons.append("NOT_HIGH_CONFIDENCE_ONLY")
        if not inp.timeout_semantics_tested:
            reasons.append("TIMEOUT_SEMANTICS_NOT_TESTED")
    if control is ControlType.PHISHING_REJECT and not inp.sync_path_approved:
        reasons.append("SYNC_PATH_NOT_APPROVED")
    if control is ControlType.TEMPFAIL_ABUSE and not inp.rspamd_failopen_tested:
        reasons.append("ABUSE_PATH_NOT_VALIDATED")
    if control is ControlType.QUARANTINE:
        if not inp.quarantine_backend_healthy:
            reasons.append("QUARANTINE_BACKEND_NOT_HEALTHY")
        if not inp.release_tested:
            reasons.append("RELEASE_NOT_TESTED")
    if control is ControlType.OUTBOUND_BLOCK and not inp.outbound_acceptance:
        reasons.append("OUTBOUND_ACCEPTANCE_MISSING")

    if reasons:
        return ReadinessReport(control_type=control, status=Readiness.NOT_READY, reasons=tuple(reasons))

    # Условия выполнены. Лабораторная выборка допускает только канарейку в лабораторном режиме (§83).
    if inp.reject_safety.fp_upper_bound is not None and inp.reject_safety.fp_upper_bound > inp.max_fp_upper:
        warnings.append(
            f"FP_UPPER_BOUND_ABOVE_THRESHOLD: верхняя граница {inp.reject_safety.fp_upper_bound:.2%} "
            f"выше допустимых {inp.max_fp_upper:.2%} (выборка мала для уверенности)"
        )
    needs_sample = control in (ControlType.SPAM_REJECT, ControlType.RBL_REJECT, ControlType.MALWARE_REJECT)
    if needs_sample and not inp.real_evidence:
        warnings.append("LAB_EVIDENCE_ONLY: выборка лабораторная, для пилота нужна выборка реального потока")
        return ReadinessReport(
            control_type=control,
            status=Readiness.READY_WITH_WARNINGS,
            warnings=tuple(warnings),
            can_canary=inp.lab_mode,
            can_pilot=False,
        )
    if inp.gaps.get("GAP-005") != RESOLVED:
        warnings.append("GAP-005_OPEN: SPF не может быть единственным основанием отказа")
    return ReadinessReport(
        control_type=control,
        status=Readiness.READY_WITH_WARNINGS if warnings else Readiness.READY,
        warnings=tuple(warnings),
        can_canary=True,
        can_pilot=True,
    )


def build_reject_safety(
    *,
    reviewed: int,
    confirmed_correct: int,
    confirmed_fp: int,
    critical_fp: int = 0,
    sample_window: str = "",
    min_reviewed: int = DEFAULT_MIN_REVIEWED,
    max_fp_upper: float = DEFAULT_MAX_FP_UPPER,
    systemic_unresolved: bool = False,
) -> RejectSafetyReport:
    """§45. Нет знаменателя — доли ``None``, а не 0. Готовность к канарейке и пилоту считается здесь же."""
    from msp_antispam.validation import wilson_upper  # повторное использование расчёта этапа 1.2

    judged = confirmed_correct + confirmed_fp
    rate = round(confirmed_fp / judged, 4) if judged else None
    upper = round(wilson_upper(confirmed_fp, judged), 4) if judged else None
    reasons: list[str] = []
    if reviewed < min_reviewed:
        reasons.append("INSUFFICIENT_SAMPLE")
    if judged == 0:
        reasons.append("NO_DENOMINATOR")
    if critical_fp:
        reasons.append("CRITICAL_FP")
    if rate is not None and rate > max_fp_upper:
        reasons.append("FP_ABOVE_THRESHOLD")
    if systemic_unresolved:
        reasons.append("SYSTEMIC_FP_UNRESOLVED")
    ok = not reasons
    return RejectSafetyReport(
        reviewed_rejects=reviewed,
        confirmed_correct=confirmed_correct,
        confirmed_fp=confirmed_fp,
        critical_fp=critical_fp,
        fp_rate=rate,
        fp_upper_bound=upper,
        sample_window=sample_window,
        ready_for_canary=ok,
        ready_for_pilot=ok,
        reasons=tuple(reasons),
    )
