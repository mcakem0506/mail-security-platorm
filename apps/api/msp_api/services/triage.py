"""Analyst queue, priority and SLA (ТЗ 1.0.3 §17-§21).

**Priority is not risk.** A MALICIOUS message delivered to one person who already deleted it is
less urgent than a HIGH_RISK campaign aimed at the finance department, and a queue sorted by
risk score alone sends analysts to the wrong one first. Risk says how dangerous the mail is;
priority says how much is at stake if nobody looks at it in the next hour.

The factors below are therefore about *consequence and spread*, not about how confident the
detection was:

* who received it — a VIP or finance recipient changes what an attacker can do with a success;
* how many people got it — a campaign is a different problem from a single message;
* what the attacker is after — credential theft and payment fraud have immediate, irreversible
  outcomes, and malware spreads;
* whether a human already flagged it — an employee report means somebody is waiting;
* whether the sources disagree — a gateway/platform conflict needs a decision, not a verdict.

Every contribution is named in ``PriorityScore.factors`` so an analyst can see why something is
at the top of their queue. A priority nobody can explain is a priority nobody trusts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from msp_contracts import (
    PRIORITY_ORDER,
    AnalystClassification,
    IncidentStatus,
    Priority,
    RiskLevel,
    Severity,
    SlaState,
    utcnow,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db.models import (
    AnalysisResult,
    Campaign,
    CampaignMessage,
    GatewayConflict,
    Incident,
    IncidentAssignment,
    IncidentClassification,
    IncidentMessage,
    MailMessage,
    MailRecipient,
    ProtectedIdentity,
    User,
)

# ---------------------------------------------------------------------------------------------
# Priority
# ---------------------------------------------------------------------------------------------
#: Points per factor. Deliberately coarse: a finer scale would imply a precision the inputs do
#: not have, and would invite tuning the numbers instead of the detection.
WEIGHTS: dict[str, int] = {
    "verdict_malicious": 30,
    "verdict_high_risk": 20,
    "verdict_suspicious": 8,
    # One number per recipient, not a sum of ways to describe the same person. A protected
    # mailbox in the finance department used to score 12 + 15 = 27 — the same property counted
    # twice — which pushed practically every finance incident into P1 and made the band useless.
    "vip_finance_recipient": 30,
    "vip_recipient": 25,
    "protected_finance_recipient": 20,
    "finance_recipient": 15,
    "protected_recipient": 12,
    "credential_theft": 20,
    "payment_fraud": 20,
    "malware": 25,
    "multiple_recipients": 10,
    "campaign_small": 10,
    "campaign_large": 25,
    # Reporting says who noticed, not how bad it is. On a deployment where employees are the
    # main intake path this factor is present on nearly every incident, and a large weight for
    # something nearly constant only shifts the whole queue upwards.
    "employee_report": 5,
    "gateway_conflict": 10,
    "gateway_detection": 15,
}

#: Score at or above which each priority starts.
THRESHOLDS: list[tuple[int, Priority]] = [
    (70, Priority.P1),
    (45, Priority.P2),
    (20, Priority.P3),
]

#: Acknowledgement targets (ТЗ 1.0.3 §19). Configurable per deployment; these are the defaults.
DEFAULT_SLA: dict[Priority, timedelta] = {
    Priority.P1: timedelta(minutes=10),
    Priority.P2: timedelta(minutes=30),
    Priority.P3: timedelta(hours=4),
    Priority.P4: timedelta(hours=24),
}

#: Signal categories that mean the attacker is after credentials or money.
_CREDENTIAL_CATEGORIES = {"credential_phishing", "phishing_url", "credential_theft"}
_PAYMENT_CATEGORIES = {"invoice_payment_fraud", "payment_fraud", "delivery_scam"}
_MALWARE_CATEGORIES = {"malicious_attachment", "malware"}


@dataclass
class PriorityScore:
    """A priority with its reasoning attached."""

    priority: Priority = Priority.P4
    score: int = 0
    factors: list[str] = field(default_factory=list)

    #: Whether anything was found on the spread axis: more than one recipient, or a campaign.
    has_spread: bool = False
    #: Whether the consequence is irreversible once the recipient acts — malware delivered, or a
    #: VIP targeted. Such an incident is urgent even when it reached exactly one person.
    has_irreversible_consequence: bool = False

    def add(self, key: str, detail: str = "") -> None:
        points = WEIGHTS.get(key, 0)
        if not points:
            return
        self.score += points
        self.factors.append(f"{key}:{points}" + (f" ({detail})" if detail else ""))

    def finalise(self) -> PriorityScore:
        """Assign the band from the score, with one structural condition on P1.

        ТЗ 1.0.3 §18 derives priority from consequence **and** spread. A pure sum lets one axis
        reach the top band alone, and on a real deployment that is what happens: every serious
        verdict aimed at the finance department scores past the threshold, 80% of the queue
        becomes P1, and the band stops meaning anything. P1 therefore also requires evidence of
        spread — or a consequence that cannot be taken back, which is urgent even for a single
        recipient.
        """
        for minimum, priority in THRESHOLDS:
            if self.score < minimum:
                continue
            if priority is Priority.P1 and not (self.has_spread or self.has_irreversible_consequence):
                # Serious, but reaching one person and reversible: an hour, not ten minutes.
                self.priority = Priority.P2
                self.factors.append("single_recipient_reversible:P1→P2")
                return self
            self.priority = priority
            return self
        self.priority = Priority.P4
        return self

    def as_dict(self) -> dict[str, Any]:
        return {"priority": self.priority.value, "score": self.score, "factors": self.factors}


@dataclass
class IncidentContext:
    """What the priority engine needs to know about an incident.

    Assembled once and passed in, so the scoring itself is pure and testable without a database.
    """

    classification: RiskLevel | None = None
    severity: Severity = Severity.MEDIUM
    recipient_count: int = 0
    vip_recipient: bool = False
    finance_recipient: bool = False
    protected_recipient: bool = False
    signal_categories: set[str] = field(default_factory=set)
    campaign_size: int = 0
    employee_reported: bool = False
    gateway_conflict: bool = False
    gateway_detection: bool = False


def score_priority(context: IncidentContext) -> PriorityScore:
    """Compute a priority from consequence and spread, not from the risk score alone."""
    score = PriorityScore()

    match context.classification:
        case RiskLevel.MALICIOUS:
            score.add("verdict_malicious")
        case RiskLevel.HIGH_RISK:
            score.add("verdict_high_risk")
        case RiskLevel.SUSPICIOUS:
            score.add("verdict_suspicious")

    # Exactly one recipient factor: whichever describes the most consequential target.
    if context.vip_recipient and context.finance_recipient:
        score.add("vip_finance_recipient")
    elif context.vip_recipient:
        score.add("vip_recipient")
    elif context.protected_recipient and context.finance_recipient:
        score.add("protected_finance_recipient")
    elif context.finance_recipient:
        score.add("finance_recipient")
    elif context.protected_recipient:
        score.add("protected_recipient")

    if context.vip_recipient:
        score.has_irreversible_consequence = True

    if context.signal_categories & _CREDENTIAL_CATEGORIES:
        score.add("credential_theft")
    if context.signal_categories & _PAYMENT_CATEGORIES:
        score.add("payment_fraud")
    if context.signal_categories & _MALWARE_CATEGORIES:
        score.add("malware")
        # A delivered attachment cannot be un-run once it is opened.
        score.has_irreversible_consequence = True

    if context.recipient_count > 1:
        score.add("multiple_recipients", f"{context.recipient_count}")
        score.has_spread = True
    if context.campaign_size >= 10:
        score.add("campaign_large", f"{context.campaign_size} писем")
        score.has_spread = True
    elif context.campaign_size > 1:
        score.add("campaign_small", f"{context.campaign_size} писем")
        score.has_spread = True

    if context.employee_reported:
        score.add("employee_report")
    if context.gateway_detection:
        score.add("gateway_detection")
    elif context.gateway_conflict:
        score.add("gateway_conflict")

    return score.finalise()


def build_context(session: Session, incident: Incident) -> IncidentContext:
    """Collect the facts the priority engine needs for one incident."""
    context = IncidentContext(severity=incident.severity)

    message_ids = (
        session.execute(select(IncidentMessage.message_id).where(IncidentMessage.incident_id == incident.id))
        .scalars()
        .all()
    )
    if not message_ids:
        return context

    result = session.execute(
        select(AnalysisResult)
        .where(AnalysisResult.message_id.in_(message_ids))
        .order_by(AnalysisResult.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    if result is not None:
        context.classification = result.classification
        context.signal_categories = {
            str(reason.get("signal_id", "")).split(".")[0] for reason in (result.reasons or [])
        }
        from ..db.models import DetectionSignal

        context.signal_categories |= set(
            session.execute(
                select(DetectionSignal.category).where(
                    DetectionSignal.result_id == result.id,
                    DetectionSignal.suppressed.is_(False),
                )
            )
            .scalars()
            .all()
        )

    messages = session.execute(select(MailMessage).where(MailMessage.id.in_(message_ids))).scalars().all()
    context.employee_reported = any(m.reported_by for m in messages)
    context.recipient_count = sum(m.recipient_count for m in messages)

    recipients = (
        session.execute(select(MailRecipient.address).where(MailRecipient.message_id.in_(message_ids)))
        .scalars()
        .all()
    )
    addresses = {a.lower() for a in recipients if a}
    addresses |= {m.source_mailbox.lower() for m in messages if m.source_mailbox}
    if addresses:
        protected = (
            session.execute(
                select(ProtectedIdentity).where(
                    ProtectedIdentity.organization_id == incident.organization_id,
                    func.lower(ProtectedIdentity.email).in_(addresses),
                    ProtectedIdentity.enabled.is_(True),
                )
            )
            .scalars()
            .all()
        )
        context.protected_recipient = bool(protected)
        context.vip_recipient = any(p.vip or p.risk_class == "critical" for p in protected)
        context.finance_recipient = any(
            "finance" in (p.categories or []) or "procurement" in (p.categories or []) for p in protected
        )

    # An incident may span several campaigns: an analyst grouping two waves into one
    # investigation is ordinary, and a query that assumed at most one campaign failed the whole
    # queue for everybody as soon as it happened. The size that matters for priority is the
    # widest spread the incident touches, so the campaigns are taken together.
    campaign_ids = set(
        session.execute(
            select(CampaignMessage.campaign_id).where(CampaignMessage.message_id.in_(message_ids)).distinct()
        )
        .scalars()
        .all()
    )
    if campaign_ids:
        sizes = [
            campaign.message_count
            for campaign in (session.get(Campaign, campaign_id) for campaign_id in campaign_ids)
            if campaign is not None
        ]
        context.campaign_size = max(sizes, default=0)

    conflicts = (
        session.execute(
            select(GatewayConflict).where(
                GatewayConflict.message_id.in_(message_ids),
                GatewayConflict.resolved_at.is_(None),
            )
        )
        .scalars()
        .all()
    )
    context.gateway_conflict = bool(conflicts)
    context.gateway_detection = any(c.kind == "GATEWAY_MALICIOUS_PLATFORM_LOW" for c in conflicts)
    return context


def priority_for(session: Session, incident: Incident) -> PriorityScore:
    return score_priority(build_context(session, incident))


# ---------------------------------------------------------------------------------------------
# SLA (ТЗ 1.0.3 §19)
# ---------------------------------------------------------------------------------------------
@dataclass
class SlaStatus:
    state: SlaState = SlaState.NOT_APPLICABLE
    target: datetime | None = None
    remaining_seconds: int | None = None
    #: Timers of §19, in seconds, for the stages that have happened.
    timers: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "target": self.target.isoformat() if self.target else None,
            "remaining_seconds": self.remaining_seconds,
            "timers": self.timers,
        }


def sla_status(
    incident: Incident,
    priority: Priority,
    *,
    now: datetime | None = None,
    targets: dict[Priority, timedelta] | None = None,
    acknowledged_at: datetime | None = None,
) -> SlaStatus:
    """Where an incident stands against its acknowledgement target.

    Only acknowledgement carries a target. The later stages are measured and reported but not
    bounded: a complex investigation taking two days is not a failure, while nobody looking at
    a P1 for two hours is.
    """
    now = now or utcnow()
    targets = targets or DEFAULT_SLA
    status = SlaStatus()

    opened = incident.created_at
    status.timers["age_seconds"] = int((now - opened).total_seconds())
    acknowledged = acknowledged_at or incident.triaged_at
    if acknowledged is not None:
        status.timers["time_to_ack"] = int((acknowledged - opened).total_seconds())
    if incident.triaged_at is not None:
        status.timers["time_to_triage"] = int((incident.triaged_at - opened).total_seconds())
    if incident.remediated_at is not None:
        status.timers["time_to_remediate"] = int((incident.remediated_at - opened).total_seconds())
    if incident.closed_at is not None:
        status.timers["time_to_close"] = int((incident.closed_at - opened).total_seconds())

    if incident.status in {IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE}:
        status.state = SlaState.MET if acknowledged else SlaState.NOT_APPLICABLE
        return status

    window = targets.get(priority, DEFAULT_SLA[Priority.P4])
    status.target = opened + window
    if acknowledged is not None:
        status.state = SlaState.MET if acknowledged <= status.target else SlaState.BREACHED
        return status

    remaining = (status.target - now).total_seconds()
    status.remaining_seconds = int(remaining)
    if remaining < 0:
        status.state = SlaState.BREACHED
    elif remaining < window.total_seconds() * 0.25:
        status.state = SlaState.DUE_SOON
    else:
        status.state = SlaState.ON_TIME
    return status


# ---------------------------------------------------------------------------------------------
# Queue (ТЗ 1.0.3 §17)
# ---------------------------------------------------------------------------------------------
@dataclass
class QueueEntry:
    incident_id: str
    number: int
    title: str
    priority: PriorityScore
    sla: SlaStatus
    classification: str | None
    confidence: str
    status: str
    severity: str
    age_seconds: int
    affected_users: list[str]
    vip_involved: bool
    campaign_size: int
    gateway_conflict: bool
    employee_report: bool
    assignee: str | None
    analyst_classification: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "number": self.number,
            "title": self.title,
            "priority": self.priority.priority.value,
            "priority_score": self.priority.score,
            "priority_factors": self.priority.factors,
            "sla": self.sla.as_dict(),
            "classification": self.classification,
            "confidence": self.confidence,
            "status": self.status,
            "severity": self.severity,
            "age_seconds": self.age_seconds,
            "affected_users": self.affected_users,
            "vip_involved": self.vip_involved,
            "campaign_size": self.campaign_size,
            "gateway_conflict": self.gateway_conflict,
            "employee_report": self.employee_report,
            "assignee": self.assignee,
            "analyst_classification": self.analyst_classification,
        }


#: Incident states that are finished and should not occupy the queue.
_CLOSED_STATES = {
    IncidentStatus.CLOSED,
    IncidentStatus.FALSE_POSITIVE,
    IncidentStatus.BENIGN,
    IncidentStatus.REMEDIATED,
}


def build_queue(
    session: Session,
    organization_id: str,
    *,
    include_closed: bool = False,
    assignee: str | None = None,
    limit: int = 100,
) -> list[QueueEntry]:
    """The analyst work queue, ordered by priority then by age.

    Age breaks ties deliberately: among equally urgent work, the thing that has been waiting
    longest goes first, which is what stops a steady trickle of P2 from starving an old P3.
    """
    query = select(Incident).where(Incident.organization_id == organization_id)
    if not include_closed:
        query = query.where(Incident.status.not_in(list(_CLOSED_STATES)))
    incidents = session.execute(query.limit(limit * 3)).scalars().all()

    now = utcnow()
    entries: list[QueueEntry] = []
    for incident in incidents:
        context = build_context(session, incident)
        priority = score_priority(context)
        assignment = session.execute(
            select(IncidentAssignment)
            .where(
                IncidentAssignment.incident_id == incident.id,
                IncidentAssignment.released_at.is_(None),
            )
            .order_by(IncidentAssignment.assigned_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if assignee and (assignment is None or assignment.assignee_email != assignee):
            continue

        latest_classification = session.execute(
            select(IncidentClassification)
            .where(IncidentClassification.incident_id == incident.id)
            .order_by(IncidentClassification.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()

        entries.append(
            QueueEntry(
                incident_id=incident.id,
                number=incident.number,
                title=incident.title,
                priority=priority,
                sla=sla_status(incident, priority.priority, now=now),
                classification=context.classification.value if context.classification else None,
                confidence=incident.confidence,
                status=incident.status.value,
                severity=incident.severity.value,
                age_seconds=int((now - incident.created_at).total_seconds()),
                affected_users=list(incident.affected_users or []),
                vip_involved=context.vip_recipient,
                campaign_size=context.campaign_size,
                gateway_conflict=context.gateway_conflict,
                employee_report=context.employee_reported,
                assignee=assignment.assignee_email if assignment else None,
                analyst_classification=(
                    latest_classification.classification.value if latest_classification else None
                ),
            )
        )

    entries.sort(key=lambda e: (PRIORITY_ORDER[e.priority.priority], -e.age_seconds))
    return entries[:limit]


# ---------------------------------------------------------------------------------------------
# Assignment (ТЗ 1.0.3 §20)
# ---------------------------------------------------------------------------------------------
def assign(
    session: Session,
    incident: Incident,
    *,
    assignee_email: str,
    assigned_by: str,
    method: str = "manual",
) -> IncidentAssignment:
    """Assign an incident, releasing any previous holder."""
    previous = (
        session.execute(
            select(IncidentAssignment).where(
                IncidentAssignment.incident_id == incident.id,
                IncidentAssignment.released_at.is_(None),
            )
        )
        .scalars()
        .all()
    )
    for row in previous:
        row.released_at = utcnow()

    user = session.execute(
        select(User).where(func.lower(User.email) == assignee_email.lower())
    ).scalar_one_or_none()
    assignment = IncidentAssignment(
        incident_id=incident.id,
        assignee_id=user.id if user else None,
        assignee_email=assignee_email,
        assigned_by=assigned_by,
        method=method,
    )
    session.add(assignment)
    incident.assigned_to = user.id if user else incident.assigned_to
    return assignment


def auto_assign(
    session: Session, incident: Incident, *, candidates: list[str], assigned_by: str = "system"
) -> IncidentAssignment | None:
    """Round-robin over the available analysts.

    Chooses whoever currently holds the fewest open incidents rather than cycling blindly: a
    strict rotation hands work to someone already buried while a colleague sits idle.
    """
    if not candidates:
        return None
    counts = {
        email: session.execute(
            select(func.count(IncidentAssignment.id)).where(
                IncidentAssignment.assignee_email == email,
                IncidentAssignment.released_at.is_(None),
            )
        ).scalar_one()
        for email in candidates
    }
    chosen = min(candidates, key=lambda email: (counts.get(email, 0), email))
    return assign(session, incident, assignee_email=chosen, assigned_by=assigned_by, method="round_robin")


# ---------------------------------------------------------------------------------------------
# Timeline (ТЗ 1.0.3 §21)
# ---------------------------------------------------------------------------------------------
def build_timeline(session: Session, incident: Incident) -> list[dict[str, Any]]:
    """The life of an incident, assembled from what actually happened.

    Built from records rather than from a narrative field: a timeline somebody has to remember
    to write is a timeline that stops being written the first busy week.
    """
    events: list[dict[str, Any]] = []

    message_ids = (
        session.execute(select(IncidentMessage.message_id).where(IncidentMessage.incident_id == incident.id))
        .scalars()
        .all()
    )
    messages = (
        session.execute(select(MailMessage).where(MailMessage.id.in_(message_ids))).scalars().all()
        if message_ids
        else []
    )
    for message in messages:
        events.append(
            {
                "at": message.received_at.isoformat(),
                "event": "message_received",
                "detail": f"Письмо от {message.sender_address}",
            }
        )
        if message.reported_by:
            events.append(
                {
                    "at": message.created_at.isoformat(),
                    "event": "employee_reported",
                    "detail": f"Сообщил сотрудник {message.reported_by}",
                }
            )

    from ..db.models import GatewayEvidenceRecord

    for evidence in (
        session.execute(
            select(GatewayEvidenceRecord).where(GatewayEvidenceRecord.message_id.in_(message_ids))
        )
        .scalars()
        .all()
        if message_ids
        else []
    ):
        events.append(
            {
                "at": evidence.observed_at.isoformat(),
                "event": "gateway_scanned",
                "detail": (
                    f"{evidence.provider_id}: {evidence.verdict}"
                    + ("" if evidence.trusted else " (не подтверждено цепочкой)")
                ),
            }
        )

    for result in (
        session.execute(select(AnalysisResult).where(AnalysisResult.message_id.in_(message_ids)))
        .scalars()
        .all()
        if message_ids
        else []
    ):
        events.append(
            {
                "at": result.created_at.isoformat(),
                "event": "analyzed",
                "detail": f"Вердикт платформы: {result.classification.value} ({result.score})",
            }
        )

    # An incident can span several campaigns, so every one of them gets a timeline entry
    # rather than the query assuming there is at most one.
    campaign_ids = (
        set(
            session.execute(
                select(CampaignMessage.campaign_id)
                .where(CampaignMessage.message_id.in_(message_ids))
                .distinct()
            )
            .scalars()
            .all()
        )
        if message_ids
        else set()
    )
    for campaign_id in sorted(campaign_ids):
        campaign = session.get(Campaign, campaign_id)
        if campaign is not None:
            events.append(
                {
                    "at": campaign.first_seen.isoformat(),
                    "event": "campaign_created",
                    "detail": f"Кампания «{campaign.name}»: {campaign.message_count} писем",
                }
            )

    for assignment in (
        session.execute(select(IncidentAssignment).where(IncidentAssignment.incident_id == incident.id))
        .scalars()
        .all()
    ):
        events.append(
            {
                "at": assignment.assigned_at.isoformat(),
                "event": "analyst_assigned",
                "detail": f"{assignment.assignee_email} ({assignment.method})",
            }
        )

    for classification in (
        session.execute(
            select(IncidentClassification).where(IncidentClassification.incident_id == incident.id)
        )
        .scalars()
        .all()
    ):
        events.append(
            {
                "at": classification.created_at.isoformat(),
                "event": "classification_changed",
                "detail": (f"{classification.classification.value} — {classification.analyst_email}"),
            }
        )

    from ..db.models import RemediationAction

    for action in (
        session.execute(select(RemediationAction).where(RemediationAction.incident_id == incident.id))
        .scalars()
        .all()
    ):
        events.append(
            {
                "at": action.created_at.isoformat(),
                "event": "remediation_proposed",
                "detail": f"{action.action_type.value} ({action.state.value})",
            }
        )
        if action.executed_at:
            events.append(
                {
                    "at": action.executed_at.isoformat(),
                    "event": "remediation_executed",
                    "detail": f"{action.action_type.value} выполнено",
                }
            )

    if incident.closed_at:
        events.append({"at": incident.closed_at.isoformat(), "event": "closed", "detail": "Инцидент закрыт"})

    events.sort(key=lambda item: item["at"])
    return events


# ---------------------------------------------------------------------------------------------
# Employee feedback (ТЗ 1.0.3 §34)
# ---------------------------------------------------------------------------------------------
#: Wording returned to the employee who reported a message. Never says the message is safe:
#: "no threat was confirmed" is what the platform actually knows (ТЗ 1.0.3 §34, ТЗ 49.9).
EMPLOYEE_FEEDBACK: dict[AnalystClassification, str] = {
    AnalystClassification.CONFIRMED_PHISHING: (
        "Спасибо. Письмо подтверждено как фишинговое. Не переходите по ссылкам из него и не "
        "вводите учётные данные."
    ),
    AnalystClassification.CONFIRMED_BEC: (
        "Спасибо. Письмо подтверждено как попытка мошенничества с платежами. Любые просьбы о "
        "платеже или смене реквизитов подтверждайте по известному номеру телефона."
    ),
    AnalystClassification.CONFIRMED_MALWARE: (
        "Спасибо. Во вложении обнаружено вредоносное содержимое. Не открывайте его."
    ),
    AnalystClassification.SPAM: ("Спасибо. Письмо отнесено к нежелательной почте. Угрозы не выявлено."),
    AnalystClassification.LEGITIMATE: (
        "Письмо проверено службой информационной безопасности. Признаков угрозы не подтверждено."
    ),
    AnalystClassification.FALSE_POSITIVE: (
        "Письмо проверено службой информационной безопасности. Признаков угрозы не подтверждено, "
        "предупреждение было излишним."
    ),
    AnalystClassification.BENIGN_SIMULATION: (
        "Это письмо — часть учебной рассылки службы информационной безопасности. Вы поступили "
        "правильно, сообщив о нём."
    ),
    AnalystClassification.UNKNOWN: (
        "Письмо передано на проверку. Пока подтвердить или опровергнуть угрозу не удалось — "
        "отнеситесь к письму с осторожностью."
    ),
}


def employee_feedback(classification: AnalystClassification) -> str:
    return EMPLOYEE_FEEDBACK.get(classification, EMPLOYEE_FEEDBACK[AnalystClassification.UNKNOWN])
