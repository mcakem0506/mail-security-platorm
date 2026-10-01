"""Analyst feedback on a detection, and the rule quality it feeds (ТЗ 1.0.3B §4–§8).

Feedback is attached to an **analysis**, not to a message. A verdict belongs to one analysis
revision; feedback that pointed only at the message would become ambiguous the first time that
message was replayed with different rules, and the whole point of this domain is to be able to
say later which detection an analyst was judging.

Two principles run through the module:

* **Per-signal, not per-message.** "The platform was wrong" cannot be acted on; "BEC-014 fired
  on an ordinary supplier letter" can. The dispositions in the middle — too severe, too weak —
  carry the most information, because a rule that is right about the fact and wrong about how
  much it matters needs its weight changed rather than its condition.
* **Feedback never changes a rule.** It produces a record, statistics and, when asked, a tuning
  task. A rule that retunes itself from analyst clicks is a rule an attacker can retune by
  provoking the right clicks (ТЗ 1.0.3B §2.6).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from msp_contracts import (
    CONFIRMED_BENIGN,
    CONFIRMED_THREAT,
    AnalystClassification,
    FalseNegativeSource,
    FalsePositiveReason,
    RootCause,
    RuleHealth,
    SignalDisposition,
    utcnow,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db.models import (
    AnalysisJob,
    AnalysisResult,
    DetectionFeedback,
    DetectionSignal,
    IncidentMessage,
    RuleQualitySnapshot,
    RuleRegistryEntry,
    RuleStatistic,
    SignalFeedback,
)

logger = logging.getLogger(__name__)


class FeedbackError(ValueError):
    """Feedback that cannot be recorded, with the reason in the message."""


@dataclass
class SignalJudgement:
    """One analyst judgement about one signal."""

    rule_id: str
    disposition: SignalDisposition
    signal_id: str | None = None
    rule_version: int = 1
    comment: str = ""


#: Dispositions that mean the rule was wrong about this message. ``TOO_SEVERE`` is deliberately
#: not among them: the rule saw something real and overstated it, which is a weight problem, and
#: counting it as a false positive would push an owner to delete a useful rule.
WRONG_DISPOSITIONS: frozenset[SignalDisposition] = frozenset(
    {SignalDisposition.INCORRECT, SignalDisposition.IRRELEVANT}
)


def record_feedback(
    session: Session,
    *,
    organization_id: str,
    analysis_id: str,
    classification: AnalystClassification,
    analyst_email: str,
    analyst_id: str | None = None,
    confidence: str = "high",
    comment: str = "",
    incident_id: str | None = None,
    signals: list[SignalJudgement] | None = None,
    fp_reason: FalsePositiveReason | None = None,
) -> DetectionFeedback:
    """Record what an analyst concluded about one analysis (ТЗ 1.0.3B §4, §5)."""
    job = session.get(AnalysisJob, analysis_id)
    if job is None or job.organization_id != organization_id:
        raise FeedbackError("анализ не найден")

    judgements = list(signals or [])
    if classification is AnalystClassification.FALSE_POSITIVE:
        # A false positive without a reason is a complaint. The reason decides who fixes it: an
        # overbroad rule goes to its owner, a parser context loss somewhere else entirely, and a
        # known vendor may need no rule change at all (§5).
        if fp_reason is None:
            raise FeedbackError("при ложном срабатывании требуется указать причину")
        if not judgements:
            raise FeedbackError(
                "при ложном срабатывании требуется указать хотя бы один сигнал, который сработал неверно"
            )
    if classification in CONFIRMED_BENIGN and not comment.strip():
        raise FeedbackError("при закрытии как безопасного требуется комментарий с обоснованием")

    feedback = DetectionFeedback(
        organization_id=organization_id,
        kind="false_positive" if classification is AnalystClassification.FALSE_POSITIVE else "classification",
        analysis_id=analysis_id,
        message_id=job.message_id,
        incident_id=incident_id,
        analyst_email=analyst_email,
        analyst_id=analyst_id,
        classification=classification.value,
        confidence=confidence,
        fp_reason=fp_reason.value if fp_reason else None,
        comment=comment[:4000],
    )
    session.add(feedback)
    session.flush()

    for judgement in judgements:
        session.add(
            SignalFeedback(
                feedback_id=feedback.id,
                signal_id=judgement.signal_id,
                rule_id=judgement.rule_id,
                rule_version=judgement.rule_version,
                disposition=judgement.disposition,
                comment=judgement.comment[:2000],
            )
        )

    _apply_to_statistics(session, organization_id, classification, judgements, job)
    logger.info(
        "feedback.recorded",
        extra={
            "analysis_id": analysis_id,
            "classification": classification.value,
            "signals": len(judgements),
        },
    )
    return feedback


def _apply_to_statistics(
    session: Session,
    organization_id: str,
    classification: AnalystClassification,
    judgements: list[SignalJudgement],
    job: AnalysisJob,
) -> None:
    """Attribute the verdict to the rules it concerns.

    When the analyst named signals, only those rules are counted — that is better data, and it
    is why the console asks. Without them the verdict applies to every rule that scored, which
    is a blunt but honest fallback.
    """
    rule_ids: list[str]
    wrong: set[str] = set()
    if judgements:
        rule_ids = [j.rule_id for j in judgements]
        wrong = {j.rule_id for j in judgements if j.disposition in WRONG_DISPOSITIONS}
    else:
        result = session.execute(
            select(AnalysisResult).where(AnalysisResult.job_id == job.id)
        ).scalar_one_or_none()
        if result is None:
            return
        rule_ids = [
            row
            for row in session.execute(
                select(DetectionSignal.rule_id)
                .where(
                    DetectionSignal.result_id == result.id,
                    DetectionSignal.rule_id.is_not(None),
                    DetectionSignal.suppressed.is_(False),
                    DetectionSignal.shadow.is_(False),
                )
                .distinct()
            )
            .scalars()
            .all()
            if row
        ]
        if classification in CONFIRMED_BENIGN:
            wrong = set(rule_ids)

    now = utcnow()
    for rule_id in dict.fromkeys(rule_ids):
        stat = session.execute(
            select(RuleStatistic).where(
                RuleStatistic.organization_id == organization_id,
                RuleStatistic.rule_id == rule_id,
            )
        ).scalar_one_or_none()
        if stat is None:
            stat = RuleStatistic(organization_id=organization_id, rule_id=rule_id)
            session.add(stat)
            session.flush()
        if rule_id in wrong or classification in CONFIRMED_BENIGN:
            stat.confirmed_fp += 1
            entry = session.execute(
                select(RuleRegistryEntry).where(
                    RuleRegistryEntry.organization_id == organization_id,
                    RuleRegistryEntry.rule_id == rule_id,
                )
            ).scalar_one_or_none()
            if entry is not None:
                entry.last_false_positive_at = now
        elif classification in CONFIRMED_THREAT:
            stat.confirmed_tp += 1


def record_missed_detection(
    session: Session,
    *,
    organization_id: str,
    source: FalseNegativeSource,
    root_cause: RootCause,
    analyst_email: str,
    expected_category: str,
    minimum_classification: str,
    severity: str,
    owner: str,
    target_release: str,
    analysis_id: str | None = None,
    message_id: str | None = None,
    incident_id: str | None = None,
    expected_detection: str = "",
    missing_fact: str = "",
    comment: str = "",
    gap_id: str | None = None,
) -> DetectionFeedback:
    """Record a miss, with everything needed to act on it (ТЗ 1.0.3B §6).

    The five required fields are what separate a task from a complaint. The platform cannot
    discover its own false negatives, so this record is the only trace that one happened — and a
    trace nobody can assign, prioritise or close is not worth keeping.
    """
    missing = [
        name
        for name, value in (
            ("ожидаемая категория", expected_category),
            ("минимальная классификация", minimum_classification),
            ("серьёзность", severity),
            ("владелец", owner),
            ("целевой релиз", target_release),
        )
        if not str(value).strip()
    ]
    if missing:
        raise FeedbackError("для пропуска обязательны: " + ", ".join(missing))

    feedback = DetectionFeedback(
        organization_id=organization_id,
        kind="false_negative",
        analysis_id=analysis_id,
        message_id=message_id,
        incident_id=incident_id,
        analyst_email=analyst_email,
        source=source.value,
        root_cause=root_cause.value,
        expected_detection=expected_detection[:255],
        missing_fact=missing_fact[:255],
        expected_category=expected_category[:64],
        minimum_classification=minimum_classification[:16],
        severity=severity[:16],
        owner=owner[:320],
        target_release=target_release[:32],
        comment=comment[:4000],
        gap_id=gap_id,
    )
    session.add(feedback)
    return feedback


# ---------------------------------------------------------------------------------------------
# Rule quality (ТЗ 1.0.3B §8)
# ---------------------------------------------------------------------------------------------
#: Below this many judged triggers, precision is not a measurement — it is an anecdote.
MIN_REVIEWED_FOR_PRECISION = 5
#: Share of judged triggers that may be wrong before a rule counts as noisy.
NOISY_THRESHOLD = 0.3
#: Precision drop against the previous period that counts as a regression.
REGRESSION_DROP = 0.15


@dataclass
class RuleQuality:
    """One rule's measured quality over a period."""

    rule_id: str
    rule_version: int = 1
    trigger_count: int = 0
    analyst_reviewed: int = 0
    true_positive: int = 0
    false_positive: int = 0
    unknown: int = 0
    suppressed: int = 0
    affected_messages: int = 0
    affected_incidents: int = 0
    health: RuleHealth = RuleHealth.NO_DATA
    health_reasons: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float | None:
        """``None`` when nothing has been judged.

        Not 1.0 and not 0.0: an unreviewed rule has unknown precision, and any number here would
        be read as measured. This is the same rule the dashboards follow, applied at the source.
        """
        judged = self.true_positive + self.false_positive
        return (self.true_positive / judged) if judged else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "trigger_count": self.trigger_count,
            "analyst_reviewed": self.analyst_reviewed,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "unknown": self.unknown,
            "suppressed": self.suppressed,
            "precision": self.precision,
            "affected_messages": self.affected_messages,
            "affected_incidents": self.affected_incidents,
            "health": self.health.value,
            "health_reasons": self.health_reasons,
        }


def assess_health(
    quality: RuleQuality, *, previous_precision: float | None = None, is_active: bool = True
) -> tuple[RuleHealth, list[str]]:
    """Derive health from the numbers.

    Health never switches a rule off. A rule is disabled by a reviewed change, because a control
    that disables itself when its data looks odd is a control an unlucky week — or an attacker
    who provokes the right feedback — can turn off.
    """
    reasons: list[str] = []
    if quality.trigger_count == 0:
        return RuleHealth.LOW_COVERAGE if is_active else RuleHealth.NO_DATA, [
            "за период правило не срабатывало"
        ]

    judged = quality.true_positive + quality.false_positive
    if judged < MIN_REVIEWED_FOR_PRECISION:
        return RuleHealth.NO_DATA, [f"решений аналитика: {judged}, этого мало для оценки точности"]

    precision = quality.precision or 0.0
    if precision < 1 - NOISY_THRESHOLD:
        reasons.append(f"точность {precision:.2f} ниже порога {1 - NOISY_THRESHOLD:.2f}")
        return RuleHealth.NOISY, reasons

    if previous_precision is not None and precision < previous_precision - REGRESSION_DROP:
        reasons.append(
            f"точность упала с {previous_precision:.2f} до {precision:.2f} относительно предыдущего периода"
        )
        return RuleHealth.REGRESSED, reasons

    if quality.suppressed and quality.suppressed >= quality.trigger_count * 0.5:
        reasons.append("больше половины срабатываний подавлено исключениями")
        return RuleHealth.DEGRADED, reasons

    return RuleHealth.HEALTHY, reasons


def measure_rules(session: Session, organization_id: str, *, days: int = 30) -> dict[str, RuleQuality]:
    """Measure every rule that fired in the period."""
    end = utcnow()
    start = end - timedelta(days=days)

    rows = session.execute(
        select(
            DetectionSignal.rule_id,
            DetectionSignal.rule_version,
            DetectionSignal.suppressed,
            DetectionSignal.shadow,
            AnalysisResult.message_id,
        )
        .join(AnalysisResult, AnalysisResult.id == DetectionSignal.result_id)
        .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
        .where(
            AnalysisJob.organization_id == organization_id,
            DetectionSignal.observed_at >= start,
            DetectionSignal.rule_id.is_not(None),
        )
    ).all()

    quality: dict[str, RuleQuality] = {}
    messages: dict[str, set[str]] = {}
    for rule_id, rule_version, suppressed, shadow, message_id in rows:
        if not rule_id:
            continue
        entry = quality.setdefault(rule_id, RuleQuality(rule_id=rule_id))
        entry.rule_version = rule_version or entry.rule_version
        entry.trigger_count += 1
        if suppressed:
            entry.suppressed += 1
        if message_id:
            messages.setdefault(rule_id, set()).add(message_id)
        _ = shadow

    # Analyst judgements, taken from the per-signal feedback where it exists.
    judgements = session.execute(
        select(SignalFeedback.rule_id, SignalFeedback.disposition, DetectionFeedback.classification)
        .join(DetectionFeedback, DetectionFeedback.id == SignalFeedback.feedback_id)
        .where(
            DetectionFeedback.organization_id == organization_id,
            DetectionFeedback.created_at >= start,
        )
    ).all()
    for rule_id, disposition, classification in judgements:
        entry = quality.setdefault(rule_id, RuleQuality(rule_id=rule_id))
        entry.analyst_reviewed += 1
        if disposition in WRONG_DISPOSITIONS:
            entry.false_positive += 1
        elif disposition is SignalDisposition.CORRECT and classification in {
            c.value for c in CONFIRMED_THREAT
        }:
            entry.true_positive += 1
        elif classification == AnalystClassification.UNKNOWN.value:
            entry.unknown += 1

    for rule_id, seen in messages.items():
        quality[rule_id].affected_messages = len(seen)
        quality[rule_id].affected_incidents = int(
            session.execute(
                select(func.count(func.distinct(IncidentMessage.incident_id))).where(
                    IncidentMessage.message_id.in_(seen)
                )
            ).scalar_one()
            or 0
        )

    return quality


def snapshot_rules(
    session: Session, organization_id: str, *, days: int = 30, ruleset_version: str = ""
) -> list[RuleQualitySnapshot]:
    """Store a measurement of every rule for the period (ТЗ 1.0.3B §8).

    Snapshots rather than on-demand computation, so "precision fell" is a statement about two
    periods instead of about the moment someone opened the page.
    """
    end = utcnow()
    start = end - timedelta(days=days)
    measured = measure_rules(session, organization_id, days=days)

    previous = {
        row.rule_id: row.precision
        for row in session.execute(
            select(RuleQualitySnapshot).where(
                RuleQualitySnapshot.organization_id == organization_id,
                RuleQualitySnapshot.period_end <= start,
            )
        )
        .scalars()
        .all()
    }

    active_rules = {
        row.rule_id
        for row in session.execute(
            select(RuleRegistryEntry).where(
                RuleRegistryEntry.organization_id == organization_id,
                RuleRegistryEntry.status == "ACTIVE",
            )
        )
        .scalars()
        .all()
    }

    created: list[RuleQualitySnapshot] = []
    for rule_id, quality in sorted(measured.items()):
        health, reasons = assess_health(
            quality,
            previous_precision=previous.get(rule_id),
            is_active=rule_id in active_rules or not active_rules,
        )
        quality.health = health
        quality.health_reasons = reasons
        snapshot = RuleQualitySnapshot(
            organization_id=organization_id,
            rule_id=rule_id,
            rule_version=quality.rule_version,
            ruleset_version=ruleset_version[:64],
            period_start=start,
            period_end=end,
            trigger_count=quality.trigger_count,
            analyst_reviewed=quality.analyst_reviewed,
            true_positive=quality.true_positive,
            false_positive=quality.false_positive,
            unknown=quality.unknown,
            suppressed=quality.suppressed,
            precision=quality.precision,
            affected_messages=quality.affected_messages,
            affected_incidents=quality.affected_incidents,
            health=health,
            health_reasons=reasons,
        )
        session.add(snapshot)
        created.append(snapshot)
    return created


def latest_snapshots(
    session: Session, organization_id: str, *, limit: int = 500
) -> list[RuleQualitySnapshot]:
    rows = (
        session.execute(
            select(RuleQualitySnapshot)
            .where(RuleQualitySnapshot.organization_id == organization_id)
            .order_by(RuleQualitySnapshot.period_end.desc(), RuleQualitySnapshot.rule_id)
            .limit(limit * 2)
        )
        .scalars()
        .all()
    )
    seen: dict[str, RuleQualitySnapshot] = {}
    for row in rows:
        seen.setdefault(row.rule_id, row)
    return list(seen.values())[:limit]
