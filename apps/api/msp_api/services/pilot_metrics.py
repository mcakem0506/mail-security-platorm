"""Detection quality metrics for the shadow pilot (ТЗ 1.0.1 §10, §11, §12).

The pilot exists to answer one question with evidence rather than opinion: does this platform
detect the attacks that reach this organisation, and how much noise does it make doing it?

Two measurement rules are deliberate and shape everything below.

**Precision is computed from confirmed triage only.** A rule that fired a thousand times and was
never reviewed has no precision, not a perfect one. ``precision_estimate`` is ``None`` until an
analyst has actually confirmed or rejected something, so a new rule cannot look good by being
unexamined.

**A false negative is only counted when someone found it.** The platform cannot know what it
missed; it can only record the misses that were discovered afterwards, by an employee report, by
an incident, or by a later verdict change. The metric is therefore named for what it is — a
lower bound — rather than presented as a recall figure the data cannot support.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from msp_contracts import IncidentStatus, JobState, RiskLevel, ScanCompleteness, TIState
from sqlalchemy import Float, and_, cast, func, select
from sqlalchemy.orm import Session

from ..db.base import utcnow
from ..db.models import (
    AnalysisJob,
    AnalysisResult,
    DetectionSignal,
    GatewayConflict,
    Incident,
    IncidentMessage,
    IntakeRecord,
    MailMessage,
    PilotMetricSnapshot,
    RuleStatistic,
)

logger = logging.getLogger(__name__)

#: Incident outcomes that confirm the detection was right.
_TRUE_POSITIVE_STATUSES = {
    IncidentStatus.CONFIRMED_PHISHING,
    IncidentStatus.CONFIRMED_MALWARE,
    IncidentStatus.CONFIRMED_BEC,
}
_FALSE_POSITIVE_STATUSES = {IncidentStatus.FALSE_POSITIVE, IncidentStatus.BENIGN}


@dataclass
class Period:
    start: datetime
    end: datetime

    @classmethod
    def last_days(cls, days: int) -> Period:
        now = utcnow()
        return cls(start=now - timedelta(days=days), end=now)


# ---------------------------------------------------------------------------------------------
# Per-rule statistics
# ---------------------------------------------------------------------------------------------
def record_rule_triggers(session: Session, *, organization_id: str, signals: list) -> int:
    """Count each rule activation as the analysis is persisted.

    Suppressed signals are counted separately rather than ignored: a rule that fires constantly
    and is always suppressed by an exception is still a rule worth revisiting.
    """
    now = utcnow()
    touched = 0
    for signal in signals:
        rule_id = getattr(signal, "rule_id", None)
        if not rule_id:
            continue
        stat = session.execute(
            select(RuleStatistic).where(
                RuleStatistic.organization_id == organization_id, RuleStatistic.rule_id == rule_id
            )
        ).scalar_one_or_none()
        if stat is None:
            stat = RuleStatistic(
                organization_id=organization_id,
                rule_id=rule_id,
                rule_version=getattr(signal, "rule_version", 1) or 1,
            )
            session.add(stat)
            session.flush()
        stat.rule_version = getattr(signal, "rule_version", stat.rule_version) or stat.rule_version
        stat.trigger_count += 1
        stat.last_triggered_at = now
        if getattr(signal, "suppressed", False):
            stat.suppressed_count += 1
        touched += 1
    return touched


def record_triage(session: Session, *, organization_id: str, incident: Incident) -> int:
    """Attribute an analyst's verdict back to the rules that produced it.

    Called when an incident reaches a confirmed outcome, so precision reflects human judgement
    rather than the platform grading its own work.
    """
    if incident.status in _TRUE_POSITIVE_STATUSES:
        field = "confirmed_tp"
    elif incident.status in _FALSE_POSITIVE_STATUSES:
        field = "confirmed_fp"
    else:
        return 0

    rule_ids = (
        session.execute(
            select(DetectionSignal.rule_id)
            .join(AnalysisResult, AnalysisResult.id == DetectionSignal.result_id)
            .join(IncidentMessage, IncidentMessage.message_id == AnalysisResult.message_id)
            .where(
                IncidentMessage.incident_id == incident.id,
                DetectionSignal.rule_id.is_not(None),
                DetectionSignal.suppressed.is_(False),
            )
            .distinct()
        )
        .scalars()
        .all()
    )
    updated = 0
    for rule_id in rule_ids:
        stat = session.execute(
            select(RuleStatistic).where(
                RuleStatistic.organization_id == organization_id, RuleStatistic.rule_id == rule_id
            )
        ).scalar_one_or_none()
        if stat is None:
            stat = RuleStatistic(organization_id=organization_id, rule_id=rule_id)
            session.add(stat)
            session.flush()
        setattr(stat, field, getattr(stat, field) + 1)
        updated += 1
    return updated


def rule_quality(session: Session, organization_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
    """Per-rule quality, as required by ТЗ 1.0.1 §11."""
    stats = (
        session.execute(
            select(RuleStatistic)
            .where(RuleStatistic.organization_id == organization_id)
            .order_by(RuleStatistic.trigger_count.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return [
        {
            "rule_id": stat.rule_id,
            "rule_version": stat.rule_version,
            "trigger_count": stat.trigger_count,
            "confirmed_tp": stat.confirmed_tp,
            "confirmed_fp": stat.confirmed_fp,
            "precision_estimate": stat.precision_estimate,
            "suppressed_count": stat.suppressed_count,
            "last_triggered_at": stat.last_triggered_at.isoformat() if stat.last_triggered_at else None,
        }
        for stat in stats
    ]


def noisy_rules(session: Session, organization_id: str, *, limit: int = 10) -> list[dict[str, Any]]:
    """Rules that fire often and are confirmed wrong, or suppressed, more often than not."""
    candidates = [
        row
        for row in rule_quality(session, organization_id, limit=200)
        if row["trigger_count"] >= 5
        and (
            (row["precision_estimate"] is not None and row["precision_estimate"] < 0.5)
            or row["suppressed_count"] > row["trigger_count"] / 2
        )
    ]
    candidates.sort(key=lambda row: (row["precision_estimate"] or 0.0, -row["trigger_count"]))
    return candidates[:limit]


def effective_rules(session: Session, organization_id: str, *, limit: int = 10) -> list[dict[str, Any]]:
    """Rules an analyst has repeatedly confirmed as right."""
    candidates = [
        row
        for row in rule_quality(session, organization_id, limit=200)
        if row["confirmed_tp"] >= 2 and (row["precision_estimate"] or 0.0) >= 0.7
    ]
    candidates.sort(key=lambda row: (-(row["precision_estimate"] or 0.0), -row["confirmed_tp"]))
    return candidates[:limit]


# ---------------------------------------------------------------------------------------------
# Pilot-wide metrics
# ---------------------------------------------------------------------------------------------
def _percentile(values: list[float], fraction: float) -> float | None:
    """Nearest-rank percentile. Computed in Python because the pilot is small."""
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round(fraction * len(ordered)) - 1))
    return round(ordered[index], 1)


def collect(session: Session, organization_id: str, period: Period) -> dict[str, Any]:
    """Every metric ТЗ 1.0.1 §11 requires, for one period."""
    in_period = and_(AnalysisJob.created_at >= period.start, AnalysisJob.created_at < period.end)

    verdict_rows = session.execute(
        select(AnalysisResult.classification, func.count(AnalysisResult.id))
        .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
        .where(AnalysisJob.organization_id == organization_id, in_period)
        .group_by(AnalysisResult.classification)
    ).all()
    by_verdict = {
        (level.value if hasattr(level, "value") else str(level)): int(count) for level, count in verdict_rows
    }

    total = session.execute(
        select(func.count(AnalysisJob.id)).where(AnalysisJob.organization_id == organization_id, in_period)
    ).scalar_one()
    employee_reports = session.execute(
        select(func.count(AnalysisJob.id)).where(
            AnalysisJob.organization_id == organization_id, in_period, AnalysisJob.is_report.is_(True)
        )
    ).scalar_one()
    unscannable = session.execute(
        select(func.count(AnalysisJob.id)).where(
            AnalysisJob.organization_id == organization_id,
            in_period,
            AnalysisJob.scan_completeness != ScanCompleteness.COMPLETE.value,
        )
    ).scalar_one()
    ti_unavailable = session.execute(
        select(func.count(AnalysisJob.id)).where(
            AnalysisJob.organization_id == organization_id,
            in_period,
            AnalysisJob.ti_state.in_([TIState.UNAVAILABLE, TIState.PARTIAL]),
        )
    ).scalar_one()
    failed = session.execute(
        select(func.count(AnalysisJob.id)).where(
            AnalysisJob.organization_id == organization_id, in_period, AnalysisJob.state == JobState.FAILED
        )
    ).scalar_one()

    duration_values: list[Any] = list(
        session.execute(
            select(cast(AnalysisJob.duration_ms, Float)).where(
                AnalysisJob.organization_id == organization_id,
                in_period,
                AnalysisJob.duration_ms.is_not(None),
            )
        )
        .scalars()
        .all()
    )
    durations = [float(value) for value in duration_values if value is not None]

    incident_rows = session.execute(
        select(Incident.status, func.count(Incident.id))
        .where(
            Incident.organization_id == organization_id,
            Incident.created_at >= period.start,
            Incident.created_at < period.end,
        )
        .group_by(Incident.status)
    ).all()
    by_incident_status = {
        (status.value if hasattr(status, "value") else str(status)): int(count)
        for status, count in incident_rows
    }
    true_positive = sum(by_incident_status.get(s.value, 0) for s in _TRUE_POSITIVE_STATUSES)
    false_positive = sum(by_incident_status.get(s.value, 0) for s in _FALSE_POSITIVE_STATUSES)

    return {
        "period": {"start": period.start.isoformat(), "end": period.end.isoformat()},
        "total_analyzed": int(total),
        "employee_reports": int(employee_reports),
        "by_verdict": by_verdict,
        "unknown": by_verdict.get(RiskLevel.UNKNOWN.value, 0),
        "unscannable": int(unscannable),
        "ti_unavailable": int(ti_unavailable),
        "failed_jobs": int(failed),
        "true_positive": true_positive,
        "false_positive": false_positive,
        # Named for what the data supports: the platform cannot know what it never saw.
        "false_negative_discovered": _false_negatives(session, organization_id, period),
        "latency_ms": {
            "median": _percentile(durations, 0.5),
            "p95": _percentile(durations, 0.95),
            "p99": _percentile(durations, 0.99),
            "samples": len(durations),
        },
        "top_noisy_rules": noisy_rules(session, organization_id),
        "top_effective_rules": effective_rules(session, organization_id),
        "top_impersonated_identities": _top_impersonated(session, organization_id, period),
        "top_suspicious_domains": _top_domains(session, organization_id, period),
        "campaigns_detected": _campaigns(session, organization_id, period),
        "gateway_conflicts": _conflicts(session, organization_id, period),
        "intake": _intake(session, organization_id, period),
    }


def _false_negatives(session: Session, organization_id: str, period: Period) -> int:
    """Messages first judged harmless and later found to be part of a confirmed incident.

    This is a lower bound on what was missed, not a recall measurement: it counts only the
    misses somebody actually discovered.
    """
    return int(
        session.execute(
            select(func.count(func.distinct(AnalysisResult.message_id)))
            .join(IncidentMessage, IncidentMessage.message_id == AnalysisResult.message_id)
            .join(Incident, Incident.id == IncidentMessage.incident_id)
            .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
            .where(
                AnalysisJob.organization_id == organization_id,
                AnalysisJob.created_at >= period.start,
                AnalysisJob.created_at < period.end,
                AnalysisResult.classification.in_([RiskLevel.LOW_RISK, RiskLevel.UNKNOWN]),
                Incident.status.in_(list(_TRUE_POSITIVE_STATUSES)),
            )
        ).scalar_one()
        or 0
    )


def _top_impersonated(session: Session, organization_id: str, period: Period) -> list[dict[str, Any]]:
    evidence_rows: Any = session.execute(
        select(DetectionSignal.evidence)
        .join(AnalysisResult, AnalysisResult.id == DetectionSignal.result_id)
        .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
        .where(
            AnalysisJob.organization_id == organization_id,
            AnalysisJob.created_at >= period.start,
            AnalysisJob.created_at < period.end,
            DetectionSignal.category.in_(["executive_impersonation", "vendor_impersonation"]),
            DetectionSignal.suppressed.is_(False),
        )
        .limit(5000)
    ).scalars()

    counts: dict[str, int] = {}
    for evidence in evidence_rows:
        for payload in (evidence or {}).values():
            if not isinstance(payload, dict):
                continue
            identity = payload.get("identity_email") or payload.get("identity")
            if identity:
                counts[str(identity)] = counts.get(str(identity), 0) + 1
    ordered = sorted(counts.items(), key=lambda item: -item[1])[:10]
    return [{"identity": identity, "count": count} for identity, count in ordered]


def _top_domains(session: Session, organization_id: str, period: Period) -> list[dict[str, Any]]:
    rows = session.execute(
        select(MailMessage.sender_domain, func.count(MailMessage.id))
        .join(AnalysisResult, AnalysisResult.message_id == MailMessage.id)
        .where(
            MailMessage.organization_id == organization_id,
            MailMessage.received_at >= period.start,
            MailMessage.received_at < period.end,
            MailMessage.sender_domain != "",
            AnalysisResult.classification.in_(
                [RiskLevel.SUSPICIOUS, RiskLevel.HIGH_RISK, RiskLevel.MALICIOUS]
            ),
        )
        .group_by(MailMessage.sender_domain)
        .order_by(func.count(MailMessage.id).desc())
        .limit(10)
    ).all()
    return [{"domain": domain, "count": int(count)} for domain, count in rows]


def _campaigns(session: Session, organization_id: str, period: Period) -> int:
    from ..db.models import Campaign

    return int(
        session.execute(
            select(func.count(Campaign.id)).where(
                Campaign.organization_id == organization_id,
                Campaign.first_seen >= period.start,
                Campaign.first_seen < period.end,
            )
        ).scalar_one()
        or 0
    )


def _conflicts(session: Session, organization_id: str, period: Period) -> dict[str, int]:
    rows = session.execute(
        select(GatewayConflict.kind, func.count(GatewayConflict.id))
        .where(
            GatewayConflict.organization_id == organization_id,
            GatewayConflict.detected_at >= period.start,
            GatewayConflict.detected_at < period.end,
        )
        .group_by(GatewayConflict.kind)
    ).all()
    return {str(kind): int(count) for kind, count in rows}


def _intake(session: Session, organization_id: str, period: Period) -> dict[str, int]:
    rows = session.execute(
        select(IntakeRecord.state, func.count(IntakeRecord.id))
        .where(
            IntakeRecord.organization_id == organization_id,
            IntakeRecord.fetched_at >= period.start,
            IntakeRecord.fetched_at < period.end,
        )
        .group_by(IntakeRecord.state)
    ).all()
    return {str(state.value if hasattr(state, "value") else state): int(count) for state, count in rows}


def snapshot(session: Session, organization_id: str, period: Period) -> PilotMetricSnapshot:
    """Store one period's metrics, so the pilot report is built from recorded data."""
    metrics = collect(session, organization_id, period)
    existing = session.execute(
        select(PilotMetricSnapshot).where(
            PilotMetricSnapshot.organization_id == organization_id,
            PilotMetricSnapshot.period_start == period.start,
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.metrics = metrics
        existing.period_end = period.end
        return existing
    row = PilotMetricSnapshot(
        organization_id=organization_id,
        period_start=period.start,
        period_end=period.end,
        metrics=metrics,
    )
    session.add(row)
    return row
