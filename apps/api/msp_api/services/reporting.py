"""Reporting and export (ТЗ 37).

Reports are built from stored analysis results, so a report can always be reconstructed and
explained. Exports are CSV and JSON; a CSV is written defensively because spreadsheet software
interprets some leading characters as formulas.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from msp_contracts import IncidentStatus, RiskLevel
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from ..db.base import utcnow
from ..db.models import (
    AnalysisJob,
    AnalysisResult,
    AuditEvent,
    Campaign,
    DetectionException,
    DetectionSignal,
    Incident,
    IncidentClassification,
    IncidentMessage,
    Indicator,
    MailMessage,
    ProviderLookup,
)

# A leading =, +, -, @, tab or CR makes Excel and LibreOffice treat a cell as a formula.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

_IMPERSONATION_CATEGORIES = (
    "executive_impersonation",
    "display_name_impersonation",
    "corporate_identity_impersonation",
    "vendor_impersonation",
)


def csv_safe(value: Any) -> str:
    """Neutralise CSV formula injection while keeping the value readable."""
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def to_csv(rows: list[dict[str, Any]], columns: list[str] | None = None) -> str:
    if not rows:
        return ""
    fieldnames = columns or list(rows[0].keys())
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: csv_safe(row.get(key)) for key in fieldnames})
    return buffer.getvalue()


@dataclass
class ReportPeriod:
    start: datetime
    end: datetime

    @classmethod
    def last_days(cls, days: int = 7) -> ReportPeriod:
        end = utcnow()
        return cls(start=end - timedelta(days=days), end=end)

    def as_dict(self) -> dict[str, str]:
        return {
            "from": self.start.isoformat(),
            "to": self.end.isoformat(),
            "days": str((self.end - self.start).days),
        }


@dataclass
class Report:
    name: str
    period: ReportPeriod
    summary: dict[str, Any] = field(default_factory=dict)
    rows: list[dict[str, Any]] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)

    def as_json(self) -> dict[str, Any]:
        return {
            "report": self.name,
            "period": self.period.as_dict(),
            "generated_at": utcnow().isoformat(),
            "summary": self.summary,
            "rows": self.rows,
        }

    def as_csv(self) -> str:
        return to_csv(self.rows, self.columns or None)


def _verdict_counts(session: Session, organization_id: str, period: ReportPeriod) -> dict[str, int]:
    rows = session.execute(
        select(AnalysisResult.classification, func.count())
        .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
        .where(
            AnalysisJob.organization_id == organization_id,
            AnalysisResult.created_at >= period.start,
            AnalysisResult.created_at < period.end,
        )
        .group_by(AnalysisResult.classification)
    ).all()
    counts = {level.value: 0 for level in RiskLevel}
    for classification, count in rows:
        key = classification.value if hasattr(classification, "value") else str(classification)
        counts[key] = int(count)
    return counts


def phishing_summary(session: Session, organization_id: str, days: int = 7) -> Report:
    """Weekly phishing summary (ТЗ 37)."""
    period = ReportPeriod.last_days(days)
    counts = _verdict_counts(session, organization_id, period)

    analyses = int(
        session.execute(
            select(func.count())
            .select_from(AnalysisJob)
            .where(
                AnalysisJob.organization_id == organization_id,
                AnalysisJob.created_at >= period.start,
            )
        ).scalar_one()
    )
    reports = int(
        session.execute(
            select(func.count())
            .select_from(AnalysisJob)
            .where(
                AnalysisJob.organization_id == organization_id,
                AnalysisJob.is_report.is_(True),
                AnalysisJob.created_at >= period.start,
            )
        ).scalar_one()
    )
    incidents = int(
        session.execute(
            select(func.count())
            .select_from(Incident)
            .where(Incident.organization_id == organization_id, Incident.created_at >= period.start)
        ).scalar_one()
    )
    campaigns = int(
        session.execute(
            select(func.count())
            .select_from(Campaign)
            .where(Campaign.organization_id == organization_id, Campaign.last_seen >= period.start)
        ).scalar_one()
    )

    top_rules = session.execute(
        select(
            DetectionSignal.rule_id,
            DetectionSignal.title,
            DetectionSignal.category,
            func.count().label("hits"),
        )
        .join(AnalysisResult, AnalysisResult.id == DetectionSignal.result_id)
        .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
        .where(
            AnalysisJob.organization_id == organization_id,
            DetectionSignal.suppressed.is_(False),
            DetectionSignal.observed_at >= period.start,
        )
        .group_by(DetectionSignal.rule_id, DetectionSignal.title, DetectionSignal.category)
        .order_by(desc("hits"))
        .limit(20)
    ).all()

    return Report(
        name="phishing_summary",
        period=period,
        summary={
            "analyses": analyses,
            "employee_reports": reports,
            "incidents_created": incidents,
            "active_campaigns": campaigns,
            "verdicts": counts,
            # Stated explicitly so a reader cannot mistake "no detection" for "no threats".
            "note": (
                "Отсутствие обнаружения не означает отсутствие угроз. Отчёт отражает только то, "
                "что платформа смогла проверить за период."
            ),
        },
        rows=[
            {
                "rule_id": rule_id,
                "title": title,
                "category": category,
                "hits": int(hits),
            }
            for rule_id, title, category, hits in top_rules
        ],
        columns=["rule_id", "title", "category", "hits"],
    )


def impersonated_identities(session: Session, organization_id: str, days: int = 30) -> Report:
    """Most impersonated identities (ТЗ 37)."""
    period = ReportPeriod.last_days(days)
    rows = session.execute(
        select(
            DetectionSignal.title,
            DetectionSignal.category,
            func.count().label("hits"),
        )
        .join(AnalysisResult, AnalysisResult.id == DetectionSignal.result_id)
        .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
        .where(
            AnalysisJob.organization_id == organization_id,
            DetectionSignal.category.in_(_IMPERSONATION_CATEGORIES),
            DetectionSignal.suppressed.is_(False),
            DetectionSignal.observed_at >= period.start,
        )
        .group_by(DetectionSignal.title, DetectionSignal.category)
        .order_by(desc("hits"))
        .limit(50)
    ).all()
    return Report(
        name="impersonated_identities",
        period=period,
        summary={"total_signals": sum(int(r[2]) for r in rows)},
        rows=[{"signal": title, "category": category, "hits": int(hits)} for title, category, hits in rows],
        columns=["signal", "category", "hits"],
    )


def incidents_report(session: Session, organization_id: str, days: int = 30) -> Report:
    """Incidents with mean time to triage and to remediate (ТЗ 37)."""
    period = ReportPeriod.last_days(days)
    incidents = (
        session.execute(
            select(Incident)
            .where(Incident.organization_id == organization_id, Incident.created_at >= period.start)
            .order_by(desc(Incident.created_at))
            .limit(1000)
        )
        .scalars()
        .all()
    )

    triage_deltas: list[float] = []
    remediate_deltas: list[float] = []
    rows: list[dict[str, Any]] = []
    for incident in incidents:
        triage_minutes = None
        if incident.triaged_at is not None:
            triage_minutes = (incident.triaged_at - incident.created_at).total_seconds() / 60
            triage_deltas.append(triage_minutes)
        remediate_minutes = None
        if incident.remediated_at is not None:
            remediate_minutes = (incident.remediated_at - incident.created_at).total_seconds() / 60
            remediate_deltas.append(remediate_minutes)
        rows.append(
            {
                "number": incident.number,
                "title": incident.title,
                "status": incident.status.value,
                "severity": incident.severity.value,
                "created_at": incident.created_at.isoformat(),
                "minutes_to_triage": round(triage_minutes, 1) if triage_minutes is not None else "",
                "minutes_to_remediate": round(remediate_minutes, 1) if remediate_minutes is not None else "",
                "affected_users": len(incident.affected_users or []),
            }
        )

    confirmed = sum(
        1
        for i in incidents
        if i.status
        in {
            IncidentStatus.CONFIRMED_PHISHING,
            IncidentStatus.CONFIRMED_MALWARE,
            IncidentStatus.CONFIRMED_BEC,
        }
    )
    false_positives = sum(1 for i in incidents if i.status is IncidentStatus.FALSE_POSITIVE)
    return Report(
        name="incidents",
        period=period,
        summary={
            "total": len(incidents),
            "confirmed": confirmed,
            "false_positives": false_positives,
            "mean_minutes_to_triage": round(sum(triage_deltas) / len(triage_deltas), 1)
            if triage_deltas
            else None,
            "mean_minutes_to_remediate": (
                round(sum(remediate_deltas) / len(remediate_deltas), 1) if remediate_deltas else None
            ),
        },
        rows=rows,
        columns=[
            "number",
            "title",
            "status",
            "severity",
            "created_at",
            "minutes_to_triage",
            "minutes_to_remediate",
            "affected_users",
        ],
    )


def campaigns_report(session: Session, organization_id: str, days: int = 30) -> Report:
    period = ReportPeriod.last_days(days)
    campaigns = (
        session.execute(
            select(Campaign)
            .where(Campaign.organization_id == organization_id, Campaign.last_seen >= period.start)
            .order_by(desc(Campaign.message_count))
            .limit(500)
        )
        .scalars()
        .all()
    )
    return Report(
        name="campaigns",
        period=period,
        summary={
            "total": len(campaigns),
            "confirmed_malicious": sum(1 for c in campaigns if c.confirmed_malicious),
            "largest": max((c.message_count for c in campaigns), default=0),
        },
        rows=[
            {
                "name": c.name,
                "first_seen": c.first_seen.isoformat(),
                "last_seen": c.last_seen.isoformat(),
                "messages": c.message_count,
                "recipients": c.recipient_count,
                "reported_by_users": c.reported_count,
                "confirmed_malicious": c.confirmed_malicious,
                "indicators": "; ".join((c.indicators or [])[:10]),
            }
            for c in campaigns
        ],
        columns=[
            "name",
            "first_seen",
            "last_seen",
            "messages",
            "recipients",
            "reported_by_users",
            "confirmed_malicious",
            "indicators",
        ],
    )


def employee_reporting(session: Session, organization_id: str, days: int = 30) -> Report:
    """Who reports phishing, and whether their reports turn out to be real (ТЗ 37)."""
    period = ReportPeriod.last_days(days)
    rows = session.execute(
        select(
            MailMessage.reported_by,
            func.count(MailMessage.id).label("reports"),
        )
        .where(
            MailMessage.organization_id == organization_id,
            MailMessage.reported_by.is_not(None),
            MailMessage.received_at >= period.start,
        )
        .group_by(MailMessage.reported_by)
        .order_by(desc("reports"))
        .limit(200)
    ).all()

    out: list[dict[str, Any]] = []
    for reporter, reports in rows:
        confirmed = int(
            session.execute(
                select(func.count())
                .select_from(AnalysisResult)
                .join(MailMessage, MailMessage.id == AnalysisResult.message_id)
                .where(
                    MailMessage.organization_id == organization_id,
                    MailMessage.reported_by == reporter,
                    MailMessage.received_at >= period.start,
                    AnalysisResult.classification.in_([RiskLevel.HIGH_RISK, RiskLevel.MALICIOUS]),
                )
            ).scalar_one()
        )
        out.append(
            {
                "reporter": reporter,
                "reports": int(reports),
                "confirmed_high_or_malicious": confirmed,
                "precision": round(confirmed / int(reports), 2) if reports else 0.0,
            }
        )
    return Report(
        name="employee_reporting",
        period=period,
        summary={
            "reporters": len(out),
            "total_reports": sum(r["reports"] for r in out),
        },
        rows=out,
        columns=["reporter", "reports", "confirmed_high_or_malicious", "precision"],
    )


def false_positives_report(session: Session, organization_id: str, days: int = 30) -> Report:
    """Active exceptions and how often they suppress detection (ТЗ 37, 15.3)."""
    period = ReportPeriod.last_days(days)
    exceptions = (
        session.execute(
            select(DetectionException).where(DetectionException.organization_id == organization_id)
        )
        .scalars()
        .all()
    )
    now = utcnow()
    rows = [
        {
            "type": e.exception_type.value,
            "value": e.value,
            "rule_id": e.rule_id or "",
            "owner": e.owner_email,
            "reason": e.reason,
            "expires_at": e.expires_at.isoformat() if e.expires_at else "бессрочно",
            "hits": e.hit_count,
            "active": e.revoked_at is None and (e.expires_at is None or e.expires_at > now),
        }
        for e in exceptions
    ]
    suppressed = int(
        session.execute(
            select(func.count())
            .select_from(DetectionSignal)
            .join(AnalysisResult, AnalysisResult.id == DetectionSignal.result_id)
            .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
            .where(
                AnalysisJob.organization_id == organization_id,
                DetectionSignal.suppressed.is_(True),
                DetectionSignal.observed_at >= period.start,
            )
        ).scalar_one()
    )
    return Report(
        name="false_positives",
        period=period,
        summary={
            "exceptions_total": len(rows),
            "exceptions_active": sum(1 for r in rows if r["active"]),
            "exceptions_without_expiry": sum(1 for r in rows if r["expires_at"] == "бессрочно"),
            "signals_suppressed_in_period": suppressed,
        },
        rows=rows,
        columns=["type", "value", "rule_id", "owner", "reason", "expires_at", "hits", "active"],
    )


def provider_availability(session: Session, organization_id: str, days: int = 7) -> Report:
    """Provider availability measured from actual lookups (ТЗ 37)."""
    period = ReportPeriod.last_days(days)
    rows = session.execute(
        select(
            ProviderLookup.provider_id,
            ProviderLookup.status,
            func.count().label("count"),
            func.avg(ProviderLookup.latency_ms).label("avg_latency"),
        )
        .where(ProviderLookup.fetched_at >= period.start)
        .group_by(ProviderLookup.provider_id, ProviderLookup.status)
        .order_by(ProviderLookup.provider_id)
    ).all()

    per_provider: dict[str, dict[str, Any]] = {}
    for provider_id, status, count, avg_latency in rows:
        status_value = status.value if hasattr(status, "value") else str(status)
        entry = per_provider.setdefault(
            provider_id, {"provider": provider_id, "total": 0, "failures": 0, "avg_latency_ms": 0.0}
        )
        entry["total"] += int(count)
        if status_value in {"RATE_LIMITED", "PROVIDER_UNAVAILABLE", "ERROR"}:
            entry["failures"] += int(count)
        entry[f"status_{status_value}"] = int(count)
        if avg_latency:
            entry["avg_latency_ms"] = round(float(avg_latency), 1)

    out = []
    for entry in per_provider.values():
        total = entry["total"] or 1
        entry["availability"] = round(1 - entry["failures"] / total, 4)
        out.append(entry)
    return Report(
        name="provider_availability",
        period=period,
        summary={"providers": len(out)},
        rows=out,
        columns=["provider", "total", "failures", "availability", "avg_latency_ms"],
    )


def provider_quality(session: Session, organization_id: str, days: int = 30) -> Report:
    """What each external source is actually worth (ТЗ 1.0.3 §36).

    Availability answers "did it answer"; this answers "was the answer any use". The two come
    apart constantly: a provider can be up all month and return "no data" for every indicator
    an organisation cares about, and paying for it is then a decision somebody should be able
    to make from a number.

    Four things are measured per provider:

    * **coverage** — the share of lookups that came back with a usable answer rather than
      "unknown". A provider with 100% availability and 5% coverage is not protecting anyone.
    * **cache hit rate** — how much of the traffic never left the network at all. High is good
      for cost and for privacy (ТЗ §49: every outbound lookup is data leaving the organisation).
    * **decisiveness** — how often this provider was the source of a signal that scored. A
      provider that never contributes to a verdict is a subscription, not a control.
    * **contradicted** — how often a message it flagged was later classified benign by an
      analyst. This is the one number that can justify lowering a provider's weight.

    Every ratio is ``None`` when its denominator is zero. A provider with no lookups has no
    coverage; it does not have 0% coverage, and the two must not look the same.
    """
    period = ReportPeriod.last_days(days)

    lookups = (
        session.execute(
            select(ProviderLookup)
            .join(AnalysisJob, AnalysisJob.id == ProviderLookup.analysis_job_id)
            .where(
                AnalysisJob.organization_id == organization_id,
                ProviderLookup.fetched_at >= period.start,
            )
        )
        .scalars()
        .all()
    )

    #: Signals whose source names a provider, used for decisiveness.
    signal_rows = session.execute(
        select(DetectionSignal.source, AnalysisResult.id, DetectionSignal.suppressed)
        .join(AnalysisResult, AnalysisResult.id == DetectionSignal.result_id)
        .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
        .where(
            AnalysisJob.organization_id == organization_id,
            AnalysisResult.created_at >= period.start,
        )
    ).all()

    benign_results: set[str] = set()
    for result_id, classification in session.execute(
        select(AnalysisResult.id, IncidentClassification.classification)
        .join(IncidentMessage, IncidentMessage.message_id == AnalysisResult.message_id)
        .join(
            IncidentClassification,
            IncidentClassification.incident_id == IncidentMessage.incident_id,
        )
        .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
        .where(
            AnalysisJob.organization_id == organization_id,
            AnalysisResult.created_at >= period.start,
        )
    ).all():
        value = classification.value if hasattr(classification, "value") else str(classification)
        if value in {"LEGITIMATE", "FALSE_POSITIVE", "BENIGN_SIMULATION"}:
            benign_results.add(result_id)

    per_provider: dict[str, dict[str, Any]] = {}
    for lookup in lookups:
        entry = per_provider.setdefault(
            lookup.provider_id,
            {
                "provider": lookup.provider_id,
                "lookups": 0,
                "from_cache": 0,
                "failures": 0,
                "with_answer": 0,
                "latency_sum": 0,
                "latency_samples": 0,
                "decisive": 0,
                "contradicted": 0,
            },
        )
        entry["lookups"] += 1
        status = lookup.status.value if hasattr(lookup.status, "value") else str(lookup.status)
        if lookup.from_cache:
            entry["from_cache"] += 1
        if status in {"RATE_LIMITED", "PROVIDER_UNAVAILABLE", "ERROR"}:
            entry["failures"] += 1
        elif status not in {"UNKNOWN", "NOT_FOUND", "SKIPPED_BY_POLICY"}:
            entry["with_answer"] += 1
        if lookup.latency_ms:
            entry["latency_sum"] += int(lookup.latency_ms)
            entry["latency_samples"] += 1

    for source, result_id, suppressed in signal_rows:
        provider = str(source or "")
        if provider not in per_provider:
            continue
        if suppressed:
            continue
        per_provider[provider]["decisive"] += 1
        if result_id in benign_results:
            per_provider[provider]["contradicted"] += 1

    rows: list[dict[str, Any]] = []
    for entry in per_provider.values():
        total = entry["lookups"]
        decisive = entry["decisive"]
        rows.append(
            {
                "provider": entry["provider"],
                "lookups": total,
                "availability": _share(total - entry["failures"], total),
                "coverage": _share(entry["with_answer"], total),
                "cache_hit_rate": _share(entry["from_cache"], total),
                "avg_latency_ms": (
                    round(entry["latency_sum"] / entry["latency_samples"], 1)
                    if entry["latency_samples"]
                    else None
                ),
                "decisive_signals": decisive,
                "contradicted_by_analyst": entry["contradicted"],
                "contradiction_rate": _share(entry["contradicted"], decisive),
            }
        )
    rows.sort(key=lambda row: (-(row["coverage"] or 0.0), row["provider"]))

    return Report(
        name="provider_quality",
        period=period,
        summary={
            "providers": len(rows),
            "lookups": sum(row["lookups"] for row in rows),
            "note": (
                "Пустое значение означает, что метрику не на чем посчитать. Это не ноль: "
                "источник без запросов не имеет нулевого покрытия."
            ),
        },
        rows=rows,
        columns=[
            "provider",
            "lookups",
            "availability",
            "coverage",
            "cache_hit_rate",
            "avg_latency_ms",
            "decisive_signals",
            "contradicted_by_analyst",
            "contradiction_rate",
        ],
    )


def _share(part: int, whole: int) -> float | None:
    """A ratio, or ``None`` when there is nothing to divide by."""
    if not whole:
        return None
    return round(part / whole, 4)


def indicators_export(session: Session, organization_id: str, confirmed_only: bool = True) -> Report:
    """Export indicators for sharing with other systems (ТЗ 37)."""
    query = select(Indicator).where(Indicator.organization_id == organization_id)
    if confirmed_only:
        query = query.where(Indicator.confirmed_malicious.is_(True))
    indicators = session.execute(query.order_by(desc(Indicator.last_seen)).limit(10_000)).scalars().all()
    return Report(
        name="indicators",
        period=ReportPeriod.last_days(365),
        summary={"total": len(indicators), "confirmed_only": confirmed_only},
        rows=[
            {
                "type": i.ioc_type.value,
                "value": i.value,
                "first_seen": i.first_seen.isoformat(),
                "last_seen": i.last_seen.isoformat(),
                "sightings": i.sighting_count,
                "confirmed_malicious": i.confirmed_malicious,
            }
            for i in indicators
        ],
        columns=["type", "value", "first_seen", "last_seen", "sightings", "confirmed_malicious"],
    )


def audit_export(session: Session, organization_id: str, days: int = 30) -> Report:
    """Audit export. The stored events are already free of secrets and message bodies (ТЗ 25)."""
    period = ReportPeriod.last_days(days)
    events = (
        session.execute(
            select(AuditEvent)
            .where(AuditEvent.organization_id == organization_id, AuditEvent.created_at >= period.start)
            .order_by(desc(AuditEvent.created_at))
            .limit(50_000)
        )
        .scalars()
        .all()
    )
    return Report(
        name="audit",
        period=period,
        summary={"total": len(events)},
        rows=[
            {
                "created_at": e.created_at.isoformat(),
                "action": e.action,
                "actor": e.actor_email,
                "role": e.actor_role,
                "object_type": e.object_type,
                "object_id": e.object_id,
                "outcome": e.outcome,
                "ip": e.ip_address,
                "request_id": e.request_id,
            }
            for e in events
        ],
        columns=[
            "created_at",
            "action",
            "actor",
            "role",
            "object_type",
            "object_id",
            "outcome",
            "ip",
            "request_id",
        ],
    )


REPORTS = {
    "phishing_summary": phishing_summary,
    "impersonated_identities": impersonated_identities,
    "incidents": incidents_report,
    "campaigns": campaigns_report,
    "employee_reporting": employee_reporting,
    "false_positives": false_positives_report,
    "provider_availability": provider_availability,
    "provider_quality": provider_quality,
    "indicators": indicators_export,
    "audit": audit_export,
}
