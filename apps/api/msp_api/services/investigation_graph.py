"""Evidence graph, related search and campaign membership (ТЗ 1.0.3B §18–§21).

The three answer different questions about the surroundings of a message, and share one rule:
**every link states why it exists**. A graph edge, a related message or a campaign membership
without a stated reason is an assertion the analyst has to take on faith, and they are right not
to.

Everything here is bounded. An evidence graph that grows with a campaign of ten thousand
messages is not an investigation aid, it is an outage, so nodes and edges are capped and the
caller is told when a cap was reached rather than handed a silently truncated picture.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from msp_contracts import CampaignMatchReason, IOCType, RiskLevel, utcnow
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..db.models import (
    AnalysisJob,
    AnalysisResult,
    Attachment,
    Campaign,
    CampaignMatch,
    CampaignMessage,
    DetectionSignal,
    GatewayEvidenceRecord,
    Incident,
    IncidentMessage,
    Indicator,
    IndicatorObservation,
    MailMessage,
    MailRecipient,
    ProtectedIdentity,
)

logger = logging.getLogger(__name__)

#: Caps for one graph. Large enough to show a campaign's shape, small enough that the query and
#: the browser both survive it.
MAX_NODES = 300
MAX_EDGES = 600


# ---------------------------------------------------------------------------------------------
# Evidence graph (ТЗ 1.0.3B §18)
# ---------------------------------------------------------------------------------------------
NODE_KINDS = (
    "Message",
    "Sender",
    "Domain",
    "IP",
    "URL",
    "Attachment",
    "Hash",
    "ProtectedIdentity",
    "GatewayEvidence",
    "TIObservation",
    "Campaign",
    "Incident",
    "User",
)

EDGE_KINDS = (
    "SENT_BY",
    "CONTAINS",
    "RESOLVES_TO",
    "TARGETS_IDENTITY",
    "SEEN_IN",
    "RELATED_TO",
    "REPORTED_BY",
    "PART_OF_CAMPAIGN",
)


@dataclass
class Node:
    id: str
    kind: str
    label: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    source: str
    target: str
    kind: str
    label: str


@dataclass
class Graph:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    truncated: list[str] = field(default_factory=list)

    def add_node(self, node: Node) -> str | None:
        if any(existing.id == node.id for existing in self.nodes):
            return node.id
        if len(self.nodes) >= MAX_NODES:
            if "MAX_NODES" not in self.truncated:
                self.truncated.append("MAX_NODES")
            return None
        self.nodes.append(node)
        return node.id

    def add_edge(self, source: str | None, target: str | None, kind: str, label: str) -> None:
        if source is None or target is None:
            return
        if len(self.edges) >= MAX_EDGES:
            if "MAX_EDGES" not in self.truncated:
                self.truncated.append("MAX_EDGES")
            return
        self.edges.append(Edge(source=source, target=target, kind=kind, label=label))

    def as_dict(self) -> dict[str, Any]:
        return {
            "nodes": [{"id": n.id, "kind": n.kind, "label": n.label, "detail": n.detail} for n in self.nodes],
            "edges": [
                {"source": e.source, "target": e.target, "kind": e.kind, "label": e.label} for e in self.edges
            ],
            # Non-empty when a cap was reached. A truncated graph presented as complete would
            # let an analyst conclude "nothing else is connected" from a picture that simply
            # stopped drawing.
            "truncated": self.truncated,
            "complete": not self.truncated,
        }


def build_graph(session: Session, *, organization_id: str, message_id: str) -> Graph | None:
    """The neighbourhood of one message, as entities and named relations (ТЗ 1.0.3B §18)."""
    message = session.get(MailMessage, message_id)
    if message is None or message.organization_id != organization_id:
        return None

    graph = Graph()
    message_node = graph.add_node(
        Node(
            id=f"message:{message.id}",
            kind="Message",
            label=message.subject[:80] or "(без темы)",
            detail={
                "received_at": message.received_at.isoformat(),
                "classification": _classification_of(session, message.id),
                "recipient_count": message.recipient_count,
            },
        )
    )

    sender_node = graph.add_node(
        Node(
            id=f"sender:{message.sender_address}",
            kind="Sender",
            label=message.sender_address or "(нет адреса)",
            detail={"display_name": message.sender_display_name},
        )
    )
    graph.add_edge(message_node, sender_node, "SENT_BY", "отправлено")

    if message.sender_domain:
        domain_node = graph.add_node(
            Node(id=f"domain:{message.sender_domain}", kind="Domain", label=message.sender_domain)
        )
        graph.add_edge(sender_node, domain_node, "RESOLVES_TO", "домен отправителя")

    if message.reply_to_address and message.reply_to_address != message.sender_address:
        reply_node = graph.add_node(
            Node(
                id=f"sender:{message.reply_to_address}",
                kind="Sender",
                label=message.reply_to_address,
                detail={"role": "reply_to"},
            )
        )
        # Drawn separately because a Reply-To that differs from From is the whole trick in a
        # large share of payment fraud.
        graph.add_edge(message_node, reply_node, "RELATED_TO", "адрес для ответа отличается")

    for attachment in (
        session.execute(select(Attachment).where(Attachment.message_id == message.id)).scalars().all()[:50]
    ):
        attachment_node = graph.add_node(
            Node(
                id=f"attachment:{attachment.sha256}",
                kind="Attachment",
                label=attachment.normalized_filename[:60],
                detail={"type": attachment.detected_type, "size": attachment.size_bytes},
            )
        )
        graph.add_edge(message_node, attachment_node, "CONTAINS", "вложение")
        hash_node = graph.add_node(
            Node(
                id=f"hash:{attachment.sha256}",
                kind="Hash",
                label=attachment.sha256[:16] + "…",
                detail={"algorithm": "sha256", "value": attachment.sha256},
            )
        )
        graph.add_edge(attachment_node, hash_node, "CONTAINS", "sha256")

    observations = session.execute(
        select(Indicator, IndicatorObservation)
        .join(IndicatorObservation, IndicatorObservation.indicator_id == Indicator.id)
        .where(IndicatorObservation.message_id == message.id)
        .limit(100)
    ).all()
    for indicator, observation in observations:
        kind = {
            IOCType.URL: "URL",
            IOCType.DOMAIN: "Domain",
            IOCType.IPV4: "IP",
            IOCType.SHA256: "Hash",
        }.get(indicator.ioc_type, "TIObservation")
        node = graph.add_node(
            Node(
                id=f"{kind.lower()}:{indicator.value}",
                kind=kind,
                label=indicator.value[:70],
                detail={
                    "ioc_type": indicator.ioc_type.value,
                    "context": observation.context,
                    "verdict": getattr(indicator, "verdict", None),
                },
            )
        )
        graph.add_edge(message_node, node, "CONTAINS", observation.context or "индикатор")

    for recipient in (
        session.execute(select(MailRecipient).where(MailRecipient.message_id == message.id))
        .scalars()
        .all()[:50]
    ):
        protected = session.execute(
            select(ProtectedIdentity).where(
                ProtectedIdentity.organization_id == organization_id,
                func.lower(ProtectedIdentity.email) == recipient.address.lower(),
            )
        ).scalar_one_or_none()
        if protected is None:
            continue
        identity_node = graph.add_node(
            Node(
                id=f"identity:{protected.id}",
                kind="ProtectedIdentity",
                label=protected.display_name or protected.email,
                detail={"email": protected.email, "vip": protected.vip},
            )
        )
        graph.add_edge(message_node, identity_node, "TARGETS_IDENTITY", "защищаемый получатель")

    for evidence in (
        session.execute(select(GatewayEvidenceRecord).where(GatewayEvidenceRecord.message_id == message.id))
        .scalars()
        .all()[:20]
    ):
        evidence_node = graph.add_node(
            Node(
                id=f"gateway:{evidence.id}",
                kind="GatewayEvidence",
                label=f"{evidence.provider_id}: {evidence.verdict}",
                detail={
                    "trusted": evidence.trusted,
                    "trust_state": getattr(evidence, "trust_state", ""),
                    "category": evidence.category,
                },
            )
        )
        graph.add_edge(message_node, evidence_node, "SEEN_IN", "вердикт шлюза")

    for match in (
        session.execute(select(CampaignMatch).where(CampaignMatch.message_id == message.id))
        .scalars()
        .all()[:10]
    ):
        campaign = session.get(Campaign, match.campaign_id)
        if campaign is None:
            continue
        campaign_node = graph.add_node(
            Node(
                id=f"campaign:{campaign.id}",
                kind="Campaign",
                label=campaign.name[:60],
                detail={"messages": campaign.message_count, "confidence": match.confidence},
            )
        )
        graph.add_edge(
            message_node,
            campaign_node,
            "PART_OF_CAMPAIGN",
            ", ".join(str(r) for r in (match.reasons or [])) or "корреляция",
        )

    for link in (
        session.execute(select(IncidentMessage).where(IncidentMessage.message_id == message.id))
        .scalars()
        .all()[:10]
    ):
        incident = session.get(Incident, link.incident_id)
        if incident is None:
            continue
        incident_node = graph.add_node(
            Node(
                id=f"incident:{incident.id}",
                kind="Incident",
                label=f"#{incident.number} {incident.title[:50]}",
                detail={"status": incident.status.value, "severity": incident.severity.value},
            )
        )
        graph.add_edge(message_node, incident_node, "SEEN_IN", "инцидент")

    if message.reported_by:
        user_node = graph.add_node(
            Node(id=f"user:{message.reported_by}", kind="User", label=message.reported_by)
        )
        graph.add_edge(message_node, user_node, "REPORTED_BY", "сообщил сотрудник")

    return graph


def _classification_of(session: Session, message_id: str) -> str | None:
    row = session.execute(
        select(AnalysisResult.classification)
        .where(AnalysisResult.message_id == message_id)
        .order_by(AnalysisResult.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    return row.value if isinstance(row, RiskLevel) else (str(row) if row else None)


# ---------------------------------------------------------------------------------------------
# Related search v2 (ТЗ 1.0.3B §19)
# ---------------------------------------------------------------------------------------------
#: Relations, with how much each is worth. Subject is kept but weakest: «Счёт на оплату» is half
#: the corporate mail, and a message tied only by its subject must never outrank one tied by a
#: shared attachment.
RELATION_WEIGHTS: dict[str, tuple[int, str]] = {
    "message_id": (100, "тот же RFC Message-ID"),
    "attachment_hash": (90, "то же вложение"),
    "campaign": (85, "та же кампания"),
    "sender": (80, "тот же отправитель"),
    "reply_to": (75, "тот же адрес для ответа"),
    "url_host": (70, "тот же узел в ссылках"),
    "sender_root_domain": (60, "тот же корневой домен отправителя"),
    "gateway_reference": (55, "та же ссылка на сообщение в шлюзе"),
    "attachment_filename": (45, "то же имя вложения"),
    "protected_identity": (40, "тот же защищаемый получатель"),
    "body_similarity": (35, "похожее тело письма"),
    "recipient": (30, "тот же получатель"),
    "subject_fingerprint": (20, "похожая тема"),
}


@dataclass
class Related:
    message_id: str
    subject: str
    sender_address: str
    received_at: str
    classification: str | None
    reasons: list[str] = field(default_factory=list)
    score: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "subject": self.subject,
            "sender_address": self.sender_address,
            "received_at": self.received_at,
            "classification": self.classification,
            "reasons": self.reasons,
            "score": self.score,
        }


def find_related_v2(
    session: Session,
    *,
    organization_id: str,
    message_id: str,
    days: int = 90,
    limit: int = 100,
) -> list[Related]:
    """Everything connected to one message, across twelve relations (ТЗ 1.0.3B §19).

    Each relation runs as its own bounded query. One clever join would be faster and would lose
    the thing the analyst needs: *which* relation matched.
    """
    message = session.get(MailMessage, message_id)
    if message is None or message.organization_id != organization_id:
        return []

    since = utcnow() - timedelta(days=days)
    found: dict[str, Related] = {}

    def add(row: MailMessage, relation: str) -> None:
        if row.id == message_id:
            return
        entry = found.get(row.id)
        if entry is None:
            entry = Related(
                message_id=row.id,
                subject=row.subject[:200],
                sender_address=row.sender_address,
                received_at=row.received_at.isoformat(),
                classification=_classification_of(session, row.id),
            )
            found[row.id] = entry
        weight, label = RELATION_WEIGHTS[relation]
        if label not in entry.reasons:
            entry.reasons.append(label)
            entry.score += weight

    base = select(MailMessage).where(
        MailMessage.organization_id == organization_id,
        MailMessage.received_at >= since,
    )
    per_relation = max(10, limit)

    simple: list[tuple[str, Any]] = [
        ("message_id", MailMessage.internet_message_id == message.internet_message_id),
        ("sender", MailMessage.sender_address == message.sender_address),
        ("reply_to", MailMessage.reply_to_address == message.reply_to_address),
        ("campaign", MailMessage.campaign_fingerprint == message.campaign_fingerprint),
        ("subject_fingerprint", MailMessage.subject == message.subject),
        ("body_similarity", MailMessage.body_simhash == message.body_simhash),
    ]
    for relation, condition in simple:
        value = {
            "message_id": message.internet_message_id,
            "sender": message.sender_address,
            "reply_to": message.reply_to_address,
            "campaign": message.campaign_fingerprint,
            "subject_fingerprint": message.subject,
            "body_similarity": message.body_simhash,
        }[relation]
        if not value:
            continue
        for row in session.execute(base.where(condition).limit(per_relation)).scalars():
            add(row, relation)

    root = _root_domain(message.sender_domain)
    if root:
        for row in session.execute(
            base.where(
                or_(
                    MailMessage.sender_domain == root,
                    MailMessage.sender_domain.like(f"%.{root}"),
                )
            ).limit(per_relation)
        ).scalars():
            add(row, "sender_root_domain")

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
            .limit(per_relation)
        ).scalars():
            add(row, "attachment_hash")

    filenames = [
        row
        for row in session.execute(
            select(Attachment.normalized_filename).where(Attachment.message_id == message_id)
        )
        .scalars()
        .all()
        if row
    ]
    if filenames:
        for row in session.execute(
            base.join(Attachment, Attachment.message_id == MailMessage.id)
            .where(Attachment.normalized_filename.in_(filenames))
            .limit(per_relation)
        ).scalars():
            add(row, "attachment_filename")

    hosts = [
        value
        for value in session.execute(
            select(Indicator.value)
            .join(IndicatorObservation, IndicatorObservation.indicator_id == Indicator.id)
            .where(
                IndicatorObservation.message_id == message_id,
                Indicator.ioc_type.in_([IOCType.DOMAIN, IOCType.URL]),
            )
            .limit(30)
        )
        .scalars()
        .all()
        if value
    ]
    if hosts:
        for row in session.execute(
            base.join(IndicatorObservation, IndicatorObservation.message_id == MailMessage.id)
            .join(Indicator, Indicator.id == IndicatorObservation.indicator_id)
            .where(Indicator.value.in_(hosts))
            .limit(per_relation)
        ).scalars():
            add(row, "url_host")

    recipients = [
        row
        for row in session.execute(
            select(MailRecipient.address).where(MailRecipient.message_id == message_id)
        )
        .scalars()
        .all()
        if row
    ]
    if recipients:
        for row in session.execute(
            base.join(MailRecipient, MailRecipient.message_id == MailMessage.id)
            .where(MailRecipient.address.in_(recipients))
            .limit(per_relation)
        ).scalars():
            add(row, "recipient")
        protected = {
            value.lower()
            for value in session.execute(
                select(ProtectedIdentity.email).where(
                    ProtectedIdentity.organization_id == organization_id,
                    func.lower(ProtectedIdentity.email).in_([r.lower() for r in recipients]),
                )
            )
            .scalars()
            .all()
        }
        if protected:
            for row in session.execute(
                base.join(MailRecipient, MailRecipient.message_id == MailMessage.id)
                .where(func.lower(MailRecipient.address).in_(protected))
                .limit(per_relation)
            ).scalars():
                add(row, "protected_identity")

    gateway_refs = [
        row
        for row in session.execute(
            select(GatewayEvidenceRecord.raw_reference).where(GatewayEvidenceRecord.message_id == message_id)
        )
        .scalars()
        .all()
        if row
    ]
    if gateway_refs:
        for row in session.execute(
            base.join(GatewayEvidenceRecord, GatewayEvidenceRecord.message_id == MailMessage.id)
            .where(GatewayEvidenceRecord.raw_reference.in_(gateway_refs))
            .limit(per_relation)
        ).scalars():
            add(row, "gateway_reference")

    return sorted(found.values(), key=lambda item: (-item.score, item.received_at))[:limit]


def _root_domain(domain: str) -> str:
    """The registrable domain, so `mail.partner.test` relates to `partner.test`."""
    if not domain:
        return ""
    try:
        from msp_mail_parser import registrable_domain

        return registrable_domain(domain)
    except Exception:  # noqa: BLE001 - a malformed domain is not a reason to fail the search
        return domain


# ---------------------------------------------------------------------------------------------
# Campaign membership (ТЗ 1.0.3B §20, §21)
# ---------------------------------------------------------------------------------------------
def record_match(
    session: Session,
    *,
    organization_id: str,
    campaign_id: str,
    message_id: str,
    confidence: float,
    reasons: list[CampaignMatchReason],
    manual: bool = False,
    decided_by: str = "",
) -> CampaignMatch | None:
    """Record why a message is in a campaign.

    A manual decision is never overwritten by correlation: an engine that quietly re-adds a
    message an analyst removed teaches analysts that their decisions do not stick, and after
    that they stop making them.
    """
    existing = session.execute(
        select(CampaignMatch).where(
            CampaignMatch.campaign_id == campaign_id, CampaignMatch.message_id == message_id
        )
    ).scalar_one_or_none()

    if existing is not None:
        if existing.manual and not manual:
            return existing
        existing.confidence = confidence
        existing.reasons = [r.value for r in reasons]
        if manual:
            existing.manual = True
            existing.rejected = False
            existing.decided_by = decided_by
        return existing

    match = CampaignMatch(
        organization_id=organization_id,
        campaign_id=campaign_id,
        message_id=message_id,
        confidence=round(confidence, 3),
        reasons=[r.value for r in reasons],
        manual=manual,
        decided_by=decided_by,
    )
    session.add(match)
    return match


def reject_match(
    session: Session, *, campaign_id: str, message_id: str, decided_by: str
) -> CampaignMatch | None:
    """Mark a membership as wrong (ТЗ 1.0.3B §21).

    The row is kept rather than deleted, so the correlation engine can be measured against human
    judgement instead of silently forgetting where it was wrong.
    """
    match = session.execute(
        select(CampaignMatch).where(
            CampaignMatch.campaign_id == campaign_id, CampaignMatch.message_id == message_id
        )
    ).scalar_one_or_none()
    if match is None:
        return None
    match.rejected = True
    match.manual = True
    match.decided_by = decided_by
    link = session.execute(
        select(CampaignMessage).where(
            CampaignMessage.campaign_id == campaign_id,
            CampaignMessage.message_id == message_id,
        )
    ).scalar_one_or_none()
    if link is not None:
        session.delete(link)
    return match


def attach_message(
    session: Session,
    *,
    organization_id: str,
    campaign_id: str,
    message_id: str,
    decided_by: str,
) -> CampaignMatch | None:
    campaign = session.get(Campaign, campaign_id)
    message = session.get(MailMessage, message_id)
    if campaign is None or message is None:
        return None
    if campaign.organization_id != organization_id or message.organization_id != organization_id:
        return None
    existing = session.execute(
        select(CampaignMessage).where(
            CampaignMessage.campaign_id == campaign_id,
            CampaignMessage.message_id == message_id,
        )
    ).scalar_one_or_none()
    if existing is None:
        session.add(CampaignMessage(campaign_id=campaign_id, message_id=message_id))
        campaign.message_count += 1
    return record_match(
        session,
        organization_id=organization_id,
        campaign_id=campaign_id,
        message_id=message_id,
        confidence=1.0,
        reasons=[],
        manual=True,
        decided_by=decided_by,
    )


def match_quality(session: Session, organization_id: str) -> dict[str, Any]:
    """How often analysts disagree with correlation.

    The number exists to tune correlation, not to be ignored: a rejection rate climbing above a
    few per cent means the engine is grouping things people do not consider one wave.
    """
    rows = (
        session.execute(select(CampaignMatch).where(CampaignMatch.organization_id == organization_id))
        .scalars()
        .all()
    )
    total = len(rows)
    rejected = sum(1 for row in rows if row.rejected)
    manual = sum(1 for row in rows if row.manual and not row.rejected)
    return {
        "total_matches": total,
        "rejected_by_analyst": rejected,
        "manually_attached": manual,
        # Null rather than 0% when correlation has produced nothing yet.
        "rejection_rate": (rejected / total) if total else None,
    }


def signal_rule_ids(session: Session, message_id: str) -> list[str]:
    """Rule ids behind the latest verdict for a message, for the graph and the UI."""
    result = session.execute(
        select(AnalysisResult)
        .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
        .where(AnalysisResult.message_id == message_id)
        .order_by(AnalysisResult.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    if result is None:
        return []
    return [
        row
        for row in session.execute(
            select(DetectionSignal.rule_id)
            .where(DetectionSignal.result_id == result.id, DetectionSignal.rule_id.is_not(None))
            .distinct()
        )
        .scalars()
        .all()
        if row
    ]
