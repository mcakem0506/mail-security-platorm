"""Explainable risk engine (ТЗ 17).

Design rules encoded here:
* there is no SAFE outcome — the lowest classification is LOW_RISK;
* a score exists internally but the UI is always given classification + reasons + sources;
* hard signals (known-bad hash/URL, local AV detection, confirmed active campaign) raise the
  classification directly and keep their source and timestamp;
* UNKNOWN wins over LOW_RISK when evidence is missing (encrypted content, provider outage,
  unsupported format, partial analysis) — absence of detection is never treated as safety.
"""

from __future__ import annotations

from dataclasses import dataclass

from msp_contracts import (
    RISK_ORDER,
    Reason,
    RiskLevel,
    RiskVerdict,
    Severity,
    Signal,
)

RISK_ENGINE_VERSION = "risk-1.0.0"

_CATEGORY_CAP = 2  # at most N signals of one category contribute full weight
_DIMINISHING = 0.45  # weight factor for each further signal in the same category

_RECOMMENDATIONS: dict[RiskLevel, str] = {
    RiskLevel.MALICIOUS: (
        "Не открывайте вложения и не переходите по ссылкам. Письмо передано службе информационной "
        "безопасности."
    ),
    RiskLevel.HIGH_RISK: (
        "Не выполняйте инструкции из письма и не вводите учётные данные. Сообщите о письме в службу "
        "информационной безопасности."
    ),
    RiskLevel.SUSPICIOUS: (
        "Отнеситесь к письму с осторожностью: проверьте отправителя по известному контакту и не "
        "передавайте конфиденциальные данные."
    ),
    RiskLevel.UNKNOWN: (
        "Проверка выполнена не полностью, поэтому подтвердить безопасность письма нельзя. При любых "
        "сомнениях обратитесь в службу информационной безопасности."
    ),
    RiskLevel.LOW_RISK: (
        "Признаков атаки не обнаружено. Это не гарантирует безопасность письма — сохраняйте обычную "
        "осторожность с вложениями и ссылками."
    ),
}


@dataclass
class RiskThresholds:
    suspicious: int = 25
    high_risk: int = 50
    malicious: int = 80

    def classify(self, score: int) -> RiskLevel:
        if score >= self.malicious:
            return RiskLevel.MALICIOUS
        if score >= self.high_risk:
            return RiskLevel.HIGH_RISK
        if score >= self.suspicious:
            return RiskLevel.SUSPICIOUS
        return RiskLevel.LOW_RISK


def _to_reason(s: Signal) -> Reason:
    return Reason(
        signal_id=s.id,
        title=s.title,
        explanation=s.explanation,
        severity=s.severity,
        source=s.source,
        observed_at=s.observed_at,
        internal=s.internal,
        recommendation=s.recommendation,
    )


def _score(signals: list[Signal]) -> tuple[int, float]:
    """Saturating aggregation: many weak signals cannot alone reach MALICIOUS."""
    per_category: dict[str, list[Signal]] = {}
    for s in signals:
        per_category.setdefault(s.category, []).append(s)
    total = 0.0
    weighted_conf = 0.0
    for group in per_category.values():
        group.sort(key=lambda s: (-s.weight * s.confidence, s.id))
        for index, s in enumerate(group):
            factor = 1.0 if index < _CATEGORY_CAP else _DIMINISHING ** (index - _CATEGORY_CAP + 1)
            contribution = s.weight * s.confidence * factor
            total += contribution
            weighted_conf += contribution * s.confidence
    # Saturating curve: sum -> 0..100 without letting noise accumulate to certainty.
    score = 100.0 * (1.0 - pow(2.718281828, -total / 55.0))
    confidence = (weighted_conf / total) if total > 0 else 0.0
    return round(min(score, 99.0)), confidence


def _confidence_label(value: float, signals: list[Signal], hard: bool) -> str:
    if hard:
        return "high"
    if not signals:
        return "low"
    if value >= 0.8:
        return "high"
    if value >= 0.6:
        return "medium"
    return "low"


def evaluate(
    signals: list[Signal],
    *,
    missing_evidence: list[str] | None = None,
    thresholds: RiskThresholds | None = None,
    analysis_complete: bool = True,
    content_encrypted: bool = False,
    unparseable: bool = False,
    max_reasons: int = 8,
) -> RiskVerdict:
    thresholds = thresholds or RiskThresholds()
    missing = list(dict.fromkeys(missing_evidence or []))
    active = [s for s in signals if not s.suppressed]
    suppressed = [s for s in signals if s.suppressed]
    hard_signals = [s for s in active if s.hard]

    score, confidence_value = _score(active)
    classification = thresholds.classify(score)

    # Hard signals set a floor on the classification and keep their provenance.
    if hard_signals:
        floor = (
            RiskLevel.MALICIOUS
            if any(s.severity == Severity.CRITICAL for s in hard_signals)
            else RiskLevel.HIGH_RISK
        )
        if RISK_ORDER[floor] > RISK_ORDER[classification]:
            classification = floor
        score = max(score, thresholds.malicious if floor is RiskLevel.MALICIOUS else thresholds.high_risk)

    # UNKNOWN: insufficient evidence must never be reported as a clean result.
    evidence_incomplete = content_encrypted or unparseable or not analysis_complete or bool(missing)
    if classification is RiskLevel.LOW_RISK and evidence_incomplete:
        classification = RiskLevel.UNKNOWN

    ordered = sorted(
        active,
        key=lambda s: (-(s.weight * s.confidence), s.id),
    )
    reasons = [_to_reason(s) for s in ordered[:max_reasons]]
    sources = sorted({s.source for s in active}) or ["local_analysis"]
    return RiskVerdict(
        classification=classification,
        score=score,
        confidence=_confidence_label(confidence_value, active, bool(hard_signals)),
        confidence_value=round(confidence_value, 3),
        reasons=reasons,
        sources=sources,
        missing_evidence=missing,
        hard_signals=[_to_reason(s) for s in hard_signals],
        suppressed=[_to_reason(s) for s in suppressed],
        recommendation=_RECOMMENDATIONS[classification],
        engine_version=RISK_ENGINE_VERSION,
    )


def employee_reasons(verdict: RiskVerdict, limit: int = 5) -> list[Reason]:
    """Reasons shown to an employee: internal detection logic is never exposed (ТЗ 6.4)."""
    return [r for r in verdict.reasons if not r.internal][:limit]
