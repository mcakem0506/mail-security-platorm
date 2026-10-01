"""Related search, evidence graph, campaign curation and reporting quality.

ТЗ 1.0.3 §16, §30, §31, §32, §33.

What these have in common is that they answer questions an analyst asks *about the surroundings
of a message*, not about the message itself. Three principles run through all of them:

* **Nothing is merged automatically.** Correlation proposes; an analyst decides. A wrong
  automatic merge hides one campaign inside another, and the hidden one is the one that gets
  missed.
* **Every link states why it exists.** A graph edge or a "related message" with no stated
  reason is an assertion the analyst has to take on faith, and they are right not to.
* **A number nobody can act on is not a metric.** The reporting-quality figures exist to decide
  who needs training and whose reports should be looked at first — not to rank employees.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from msp_contracts import IOCType, RiskLevel, utcnow
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db.models import (
    AnalysisJob,
    AnalysisResult,
    Attachment,
    Campaign,
    CampaignMessage,
    DetectionSignal,
    Incident,
    IncidentClassification,
    IncidentMessage,
    Indicator,
    IndicatorObservation,
    MailMessage,
    MailRecipient,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------------------------
# One-click related search (ТЗ 1.0.3 §30)
# ---------------------------------------------------------------------------------------------
@dataclass
class RelatedMessage:
    message_id: str
    subject: str
    sender_address: str
    received_at: str
    classification: str | None
    #: Why this message is in the list. Never empty — an unexplained link is not evidence.
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "subject": self.subject,
            "sender_address": self.sender_address,
            "received_at": self.received_at,
            "classification": self.classification,
            "reasons": self.reasons,
        }


#: Relations searched, in the order an analyst usually wants them.
RELATION_LABELS: dict[str, str] = {
    "same_sender": "тот же отправитель",
    "same_sender_domain": "тот же домен отправителя",
    "same_campaign": "та же кампания",
    "same_attachment": "то же вложение",
    "same_url_domain": "тот же домен в ссылках",
    "same_reply_to": "тот же адрес для ответа",
    "same_subject": "та же тема",
}


def find_related(
    session: Session,
    *,
    organization_id: str,
    message_id: str,
    days: int = 90,
    limit: int = 100,
) -> list[RelatedMessage]:
    """Everything connected to one message, with the connection named (ТЗ 1.0.3 §30).

    One query per relation rather than one clever join: the analyst needs to know *which*
    relation matched, and a combined query would have to reconstruct that afterwards.
    """
    message = session.get(MailMessage, message_id)
    if message is None or message.organization_id != organization_id:
        return []
    since = utcnow() - timedelta(days=days)
    found: dict[str, RelatedMessage] = {}

    def add(row: MailMessage, reason: str) -> None:
        if row.id == message_id:
            return
        entry = found.get(row.id)
        if entry is None:
            entry = RelatedMessage(
                message_id=row.id,
                subject=row.subject[:200],
                sender_address=row.sender_address,
                received_at=row.received_at.isoformat(),
                classification=_classification_of(session, row.id),
            )
            found[row.id] = entry
        label = RELATION_LABELS.get(reason, reason)
        if label not in entry.reasons:
            entry.reasons.append(label)

    base = select(MailMessage).where(
        MailMessage.organization_id == organization_id,
        MailMessage.received_at >= since,
    )

    if message.sender_address:
        for row in session.execute(
            base.where(MailMessage.sender_address == message.sender_address).limit(limit)
        ).scalars():
            add(row, "same_sender")
    if message.sender_domain:
        for row in session.execute(
            base.where(MailMessage.sender_domain == message.sender_domain).limit(limit)
        ).scalars():
            add(row, "same_sender_domain")
    if message.campaign_fingerprint:
        for row in session.execute(
            base.where(MailMessage.campaign_fingerprint == message.campaign_fingerprint).limit(limit)
        ).scalars():
            add(row, "same_campaign")
    if message.reply_to_address:
        for row in session.execute(
            base.where(MailMessage.reply_to_address == message.reply_to_address).limit(limit)
        ).scalars():
            add(row, "same_reply_to")
    if message.subject:
        for row in session.execute(base.where(MailMessage.subject == message.subject).limit(limit)).scalars():
            add(row, "same_subject")

    hashes = [
        row
        for row in session.execute(select(Attachment.sha256).where(Attachment.message_id == message_id))
        .scalars()
        .all()
        if row
    ]
    if hashes:
        for row in session.execute(
            base.join(Attachment, Attachment.message_id == MailMessage.id)
            .where(Attachment.sha256.in_(hashes))
            .limit(limit)
        ).scalars():
            add(row, "same_attachment")

    domains = [
        value
        for value in session.execute(
            select(Indicator.value)
            .join(IndicatorObservation, IndicatorObservation.indicator_id == Indicator.id)
            .where(
                IndicatorObservation.message_id == message_id,
                Indicator.ioc_type == IOCType.DOMAIN,
            )
            .limit(20)
        )
        .scalars()
        .all()
        if value
    ]
    if domains:
        for row in session.execute(
            base.join(IndicatorObservation, IndicatorObservation.message_id == MailMessage.id)
            .join(Indicator, Indicator.id == IndicatorObservation.indicator_id)
            .where(Indicator.ioc_type == IOCType.DOMAIN, Indicator.value.in_(domains))
            .limit(limit)
        ).scalars():
            add(row, "same_url_domain")

    # Strongest links first: a message connected three ways is more interesting than one
    # sharing only a subject line.
    return sorted(found.values(), key=lambda item: (-len(item.reasons), item.received_at), reverse=False)[
        :limit
    ]


def _classification_of(session: Session, message_id: str) -> str | None:
    row = session.execute(
        select(AnalysisResult.classification)
        .where(AnalysisResult.message_id == message_id)
        .order_by(AnalysisResult.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    return row.value if isinstance(row, RiskLevel) else (str(row) if row else None)


# ---------------------------------------------------------------------------------------------
# Evidence graph (ТЗ 1.0.3 §16)
# ---------------------------------------------------------------------------------------------
@dataclass
class GraphNode:
    id: str
    kind: str
    label: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    kind: str
    label: str


@dataclass
class EvidenceGraph:
    """How a verdict was reached, as something an analyst can look at (ТЗ 1.0.3 §16).

    The graph shows the chain the engine actually followed: message → observed facts → rules
    that matched those facts → the verdict. It is built from the stored analysis rather than
    re-derived, so what it shows is what happened, not what would happen today.
    """

    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)

    def add_node(self, node: GraphNode) -> str:
        if all(existing.id != node.id for existing in self.nodes):
            self.nodes.append(node)
        return node.id

    def add_edge(self, source: str, target: str, kind: str, label: str) -> None:
        self.edges.append(GraphEdge(source=source, target=target, kind=kind, label=label))

    def as_dict(self) -> dict[str, Any]:
        return {
            "nodes": [{"id": n.id, "kind": n.kind, "label": n.label, "detail": n.detail} for n in self.nodes],
            "edges": [
                {"source": e.source, "target": e.target, "kind": e.kind, "label": e.label} for e in self.edges
            ],
        }


def build_evidence_graph(session: Session, *, job_id: str) -> EvidenceGraph | None:
    job = session.get(AnalysisJob, job_id)
    if job is None:
        return None
    result = session.execute(
        select(AnalysisResult).where(AnalysisResult.job_id == job_id)
    ).scalar_one_or_none()
    if result is None:
        return None

    graph = EvidenceGraph()
    message = session.get(MailMessage, job.message_id) if job.message_id else None
    message_node = graph.add_node(
        GraphNode(
            id=f"message:{job.message_id or job.id}",
            kind="message",
            label=(message.subject[:80] if message else "письмо"),
            detail={
                "sender": message.sender_address if message else "",
                "received_at": message.received_at.isoformat() if message else "",
            },
        )
    )
    verdict_node = graph.add_node(
        GraphNode(
            id=f"verdict:{result.id}",
            kind="verdict",
            label=result.classification.value,
            detail={
                "score": result.score,
                "confidence": result.confidence,
                "scan_completeness": result.scan_completeness,
            },
        )
    )

    signals = (
        session.execute(select(DetectionSignal).where(DetectionSignal.result_id == result.id)).scalars().all()
    )
    for signal in signals:
        rule_node = graph.add_node(
            GraphNode(
                id=f"rule:{signal.rule_id or signal.signal_id}",
                kind="rule",
                label=signal.title[:80],
                detail={
                    "rule_id": signal.rule_id,
                    "severity": signal.severity.value,
                    "weight": signal.weight,
                    "shadow": signal.shadow,
                    "suppressed": signal.suppressed,
                    "suppressed_by": signal.suppressed_by,
                },
            )
        )
        # Facts are the reason a rule matched, and they are what an analyst argues with.
        for key, value in list(signal.evidence.items())[:6]:
            fact_node = graph.add_node(
                GraphNode(
                    id=f"fact:{signal.rule_id or signal.signal_id}:{key}",
                    kind="fact",
                    label=f"{key}: {str(value)[:60]}",
                    detail={"key": key, "value": str(value)[:200]},
                )
            )
            graph.add_edge(message_node, fact_node, "observed", "наблюдалось в письме")
            graph.add_edge(fact_node, rule_node, "matched", "сработало условие")
        if not signal.evidence:
            graph.add_edge(message_node, rule_node, "matched", "сработало правило")

        if signal.suppressed:
            graph.add_edge(
                rule_node,
                verdict_node,
                "suppressed",
                f"подавлено: {signal.suppressed_by or 'исключение'}",
            )
        elif signal.shadow:
            # A shadow rule is drawn, and drawn as contributing nothing. Hiding it would make
            # the graph disagree with the shadow report.
            graph.add_edge(rule_node, verdict_node, "shadow", "теневое: баллов не даёт")
        else:
            graph.add_edge(rule_node, verdict_node, "contributed", f"+{signal.weight:g}")

    for missing in list(result.missing_evidence or [])[:10]:
        gap_node = graph.add_node(
            GraphNode(
                id=f"gap:{abs(hash(str(missing))) % 10**12}",
                kind="missing",
                label=str(missing)[:100],
            )
        )
        # Drawn pointing at the verdict on purpose: what the platform could not see is part of
        # how the verdict was reached, not a footnote to it.
        graph.add_edge(gap_node, verdict_node, "limited", "не проверено")

    return graph


# ---------------------------------------------------------------------------------------------
# Campaign curation (ТЗ 1.0.3 §31, §32)
# ---------------------------------------------------------------------------------------------
@dataclass
class MergeSuggestion:
    campaign_id: str
    other_campaign_id: str
    score: float
    reasons: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "other_campaign_id": self.other_campaign_id,
            "score": round(self.score, 3),
            "reasons": self.reasons,
        }


def suggest_merges(session: Session, organization_id: str, *, limit: int = 20) -> list[MergeSuggestion]:
    """Campaigns that look like the same wave (ТЗ 1.0.3 §31).

    Suggestions only. Merging automatically would let one noisy similarity swallow a separate
    campaign, and a campaign that has disappeared into another is one nobody will investigate.
    """
    campaigns = (
        session.execute(
            select(Campaign)
            .where(Campaign.organization_id == organization_id)
            .order_by(Campaign.last_seen.desc())
            .limit(200)
        )
        .scalars()
        .all()
    )
    out: list[MergeSuggestion] = []
    for index, left in enumerate(campaigns):
        for right in campaigns[index + 1 :]:
            score, reasons = _campaign_similarity(left, right)
            if score >= 0.5:
                out.append(
                    MergeSuggestion(
                        campaign_id=left.id,
                        other_campaign_id=right.id,
                        score=score,
                        reasons=reasons,
                    )
                )
    out.sort(key=lambda item: -item.score)
    return out[:limit]


def _campaign_similarity(left: Campaign, right: Campaign) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = 0.0

    left_senders = {str(s).lower() for s in (left.senders or [])}
    right_senders = {str(s).lower() for s in (right.senders or [])}
    if left_senders & right_senders:
        score += 0.4
        reasons.append("совпадают отправители")

    left_indicators = {str(i).lower() for i in (left.indicators or [])}
    right_indicators = {str(i).lower() for i in (right.indicators or [])}
    shared = left_indicators & right_indicators
    if shared:
        score += min(0.4, 0.15 * len(shared))
        reasons.append(f"общих индикаторов: {len(shared)}")

    left_subjects = {str(s).lower() for s in (left.subjects or [])}
    right_subjects = {str(s).lower() for s in (right.subjects or [])}
    if left_subjects & right_subjects:
        score += 0.2
        reasons.append("совпадают темы")

    # Waves far apart in time are usually different campaigns even when they look alike.
    gap = abs((left.last_seen - right.last_seen).total_seconds())
    if gap <= 86_400 and reasons:
        score += 0.1
        reasons.append("в пределах суток")
    elif gap > 30 * 86_400:
        score -= 0.2
        reasons.append("разнесены более чем на месяц")

    return max(0.0, min(1.0, score)), reasons


def merge_campaigns(
    session: Session, *, organization_id: str, target_id: str, source_id: str, actor: str
) -> Campaign | None:
    """Fold one campaign into another, keeping the evidence (ТЗ 1.0.3 §32)."""
    target = session.get(Campaign, target_id)
    source = session.get(Campaign, source_id)
    if target is None or source is None:
        return None
    if target.organization_id != organization_id or source.organization_id != organization_id:
        return None
    if target.id == source.id:
        return None

    moved = (
        session.execute(select(CampaignMessage).where(CampaignMessage.campaign_id == source.id))
        .scalars()
        .all()
    )
    existing = set(
        session.execute(select(CampaignMessage.message_id).where(CampaignMessage.campaign_id == target.id))
        .scalars()
        .all()
    )
    for link in moved:
        if link.message_id in existing:
            session.delete(link)
        else:
            link.campaign_id = target.id

    target.message_count += source.message_count
    target.recipient_count += source.recipient_count
    target.reported_count += source.reported_count
    target.first_seen = min(target.first_seen, source.first_seen)
    target.last_seen = max(target.last_seen, source.last_seen)
    target.indicators = sorted({*(target.indicators or []), *(source.indicators or [])})[:200]
    target.subjects = sorted({*(target.subjects or []), *(source.subjects or [])})[:50]
    target.senders = sorted({*(target.senders or []), *(source.senders or [])})[:50]
    target.confirmed_malicious = target.confirmed_malicious or source.confirmed_malicious
    distribution = dict(target.verdict_distribution or {})
    for key, value in (source.verdict_distribution or {}).items():
        distribution[key] = distribution.get(key, 0) + int(value)
    target.verdict_distribution = distribution

    logger.info(
        "campaign.merged",
        extra={"target": target.id, "source": source.id, "actor": actor},
    )
    session.delete(source)
    return target


def split_campaign(
    session: Session,
    *,
    organization_id: str,
    campaign_id: str,
    message_ids: list[str],
    name: str,
    actor: str,
) -> Campaign | None:
    """Pull messages out of a campaign into a new one (ТЗ 1.0.3 §32).

    The counterpart to merging, and the more important of the two: correlation that lumps two
    waves together hides the smaller one, and this is how an analyst gets it back.
    """
    campaign = session.get(Campaign, campaign_id)
    if campaign is None or campaign.organization_id != organization_id:
        return None
    wanted = set(message_ids)
    if not wanted:
        return None

    links = (
        session.execute(
            select(CampaignMessage).where(
                CampaignMessage.campaign_id == campaign.id,
                CampaignMessage.message_id.in_(wanted),
            )
        )
        .scalars()
        .all()
    )
    if not links or len(links) >= campaign.message_count:
        # Splitting everything out is a rename, not a split, and would leave an empty husk.
        return None

    messages = session.execute(select(MailMessage).where(MailMessage.id.in_(wanted))).scalars().all()
    now = utcnow()
    created = Campaign(
        organization_id=organization_id,
        fingerprint=f"split:{campaign.id}:{int(now.timestamp())}",
        name=name[:255],
        first_seen=min((m.received_at for m in messages), default=now),
        last_seen=max((m.received_at for m in messages), default=now),
        message_count=len(links),
        recipient_count=sum(m.recipient_count for m in messages),
        reported_count=sum(1 for m in messages if m.reported_by),
        verdict_distribution={},
        indicators=[],
        subjects=sorted({m.subject[:200] for m in messages})[:50],
        senders=sorted({m.sender_address for m in messages})[:50],
    )
    session.add(created)
    session.flush()
    for link in links:
        link.campaign_id = created.id

    campaign.message_count = max(0, campaign.message_count - len(links))
    campaign.recipient_count = max(0, campaign.recipient_count - created.recipient_count)
    campaign.reported_count = max(0, campaign.reported_count - created.reported_count)
    logger.info(
        "campaign.split",
        extra={"from": campaign.id, "to": created.id, "messages": len(links), "actor": actor},
    )
    return created


# ---------------------------------------------------------------------------------------------
# Employee reporting quality (ТЗ 1.0.3 §33)
# ---------------------------------------------------------------------------------------------
def reporting_quality(
    session: Session, organization_id: str, *, days: int = 90, limit: int = 50
) -> dict[str, Any]:
    """How useful employee reports are (ТЗ 1.0.3 §33).

    Read carefully: a low confirmation rate is **not** a reason to discourage reporting. An
    employee who reports ten harmless messages and one real attack has paid for themselves. The
    numbers exist to decide where training helps and whose reports to open first — never to
    rank people, which is why no leaderboard is produced and reporters are counted, not named,
    in the aggregate.
    """
    since = utcnow() - timedelta(days=days)
    reported = (
        session.execute(
            select(MailMessage).where(
                MailMessage.organization_id == organization_id,
                MailMessage.reported_by.is_not(None),
                MailMessage.received_at >= since,
            )
        )
        .scalars()
        .all()
    )
    if not reported:
        return {
            "period_days": days,
            "total_reports": 0,
            "reporters": 0,
            "confirmed_threats": 0,
            "confirmation_rate": None,
            "reports_that_found_something_new": 0,
            "top_reporters": [],
            "note": "За период сообщений от сотрудников не было.",
        }

    # The analyst's verdict on the incident the message belongs to is the ground truth.
    classification_by_message = _classification_by_message(session, [m.id for m in reported])
    confirmed_values = {"CONFIRMED_PHISHING", "CONFIRMED_BEC", "CONFIRMED_MALWARE"}

    per_reporter: dict[str, dict[str, Any]] = {}
    confirmed = 0
    found_new = 0
    for message in reported:
        reporter = (message.reported_by or "").lower()
        stats = per_reporter.setdefault(
            reporter, {"reporter": reporter, "reports": 0, "confirmed": 0, "found_new": 0}
        )
        stats["reports"] += 1
        verdict = classification_by_message.get(message.id)
        if verdict in confirmed_values:
            confirmed += 1
            stats["confirmed"] += 1
            platform_verdict = _classification_of(session, message.id)
            if platform_verdict in {None, "LOW_RISK", "UNKNOWN"}:
                # The employee caught something the platform did not. This is the number that
                # justifies the reporting button existing at all.
                found_new += 1
                stats["found_new"] += 1

    rows = sorted(per_reporter.values(), key=lambda item: (-item["confirmed"], -item["reports"]))
    for row in rows:
        row["confirmation_rate"] = row["confirmed"] / row["reports"] if row["reports"] else None

    return {
        "period_days": days,
        "total_reports": len(reported),
        "reporters": len(per_reporter),
        "confirmed_threats": confirmed,
        # Null when nothing has been classified: an unclassified backlog must not read as a
        # 0% confirmation rate.
        "confirmation_rate": (confirmed / len(reported)) if classification_by_message else None,
        "classified_reports": len(classification_by_message),
        "reports_that_found_something_new": found_new,
        "top_reporters": rows[:limit],
        "note": (
            "Низкая доля подтверждений не повод отговаривать сотрудников сообщать: один "
            "реальный случай из десяти окупает остальные девять."
        ),
    }


def _classification_by_message(session: Session, message_ids: list[str]) -> dict[str, str]:
    """Map message → the analyst's latest verdict on the incident that contains it."""
    if not message_ids:
        return {}
    rows = session.execute(
        select(
            IncidentMessage.message_id,
            IncidentClassification.classification,
            IncidentClassification.created_at,
        )
        .join(Incident, Incident.id == IncidentMessage.incident_id)
        .join(IncidentClassification, IncidentClassification.incident_id == Incident.id)
        .where(IncidentMessage.message_id.in_(message_ids))
        .order_by(IncidentClassification.created_at)
    ).all()
    out: dict[str, str] = {}
    for message_id, classification, _created in rows:
        out[message_id] = classification.value if hasattr(classification, "value") else str(classification)
    return out


def recipient_exposure(session: Session, *, message_id: str) -> dict[str, Any]:
    """Who received a message and what is known about them, for the incident card."""
    recipients = (
        session.execute(select(MailRecipient).where(MailRecipient.message_id == message_id)).scalars().all()
    )
    return {
        "total": len(recipients),
        "addresses": [row.address for row in recipients[:200]],
    }


def campaign_message_count(session: Session, campaign_id: str) -> int:
    return int(
        session.execute(
            select(func.count(CampaignMessage.id)).where(CampaignMessage.campaign_id == campaign_id)
        ).scalar_one()
        or 0
    )
