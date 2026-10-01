"""Detection quality, rule lifecycle and the analyst workflow (ТЗ 1.0.3 §54).

Three rules shape the endpoints here:

* a simulation changes nothing, and a replay changes nothing unless the caller explicitly asks
  for it — so "what would we say now" can be answered safely at any time;
* an analyst's classification is a first-class record, because every quality metric is derived
  from it and a metric whose source cannot be shown is not defensible;
* a metric that cannot be computed is returned as ``null``, never as zero. Reporting 0% false
  positives because nobody has classified anything would be the most dangerous number in the
  product.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from msp_contracts import (
    CONFIRMED_BENIGN,
    CONFIRMED_THREAT,
    AnalystClassification,
    GapStatus,
    RuleStatus,
    utcnow,
)
from sqlalchemy import func, select

from ..db.models import (
    AnalysisJob,
    AnalysisResult,
    DetectionFeedback,
    DetectionGapRecord,
    DetectionSignal,
    Incident,
    IncidentClassification,
    MailMessage,
    RuleChange,
    RuleStatistic,
    ThreatScenario,
)
from ..deps import Actor, AppSettings, DbSession, client_ip, require_permission
from ..observability import false_positive_total
from ..schemas import (
    AssignRequest,
    ClassificationOut,
    ClassificationRequest,
    DetectionFeedbackOut,
    DetectionGapOut,
    DetectionQualityOut,
    GapUpdateRequest,
    MissedDetectionRequest,
    QueueItemOut,
    ReevaluationOut,
    ReevaluationRequest,
    ReplayOut,
    ReplayRequest,
    RuleOut,
    RuleStatusChangeRequest,
    SimulationOut,
    SimulationRequest,
    ThreatScenarioOut,
    TimelineEntryOut,
)
from ..security.audit import AuditAction, record
from ..security.rbac import Permission
from ..services import detection_ops, triage
from ..services.analysis import get_ruleset

logger = logging.getLogger(__name__)
router = APIRouter(tags=["detection"])

Viewer = Annotated[Actor, Depends(require_permission(Permission.VIEW_INCIDENTS))]
QualityReader = Annotated[Actor, Depends(require_permission(Permission.VIEW_DETECTION_QUALITY))]
Classifier = Annotated[Actor, Depends(require_permission(Permission.CLASSIFY_INCIDENT))]
MissReporter = Annotated[Actor, Depends(require_permission(Permission.REPORT_MISSED_DETECTION))]
Simulator = Annotated[Actor, Depends(require_permission(Permission.SIMULATE_DETECTION))]
RuleManager = Annotated[Actor, Depends(require_permission(Permission.MANAGE_DETECTION_RULES))]
GapManager = Annotated[Actor, Depends(require_permission(Permission.MANAGE_DETECTION_GAPS))]
Replayer = Annotated[Actor, Depends(require_permission(Permission.EXECUTE_REPLAY))]


def _incident_or_404(session: DbSession, actor: Actor, incident_id: str) -> Incident:
    incident = session.get(Incident, incident_id)
    if incident is None or incident.organization_id != actor.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "инцидент не найден")
    return incident


# ---------------------------------------------------------------------------------------------
# Analyst queue, assignment, timeline (ТЗ 1.0.3 §17–§21)
# ---------------------------------------------------------------------------------------------
@router.get("/investigations/queue", response_model=list[QueueItemOut])
def investigation_queue(
    actor: Viewer,
    session: DbSession,
    mine: Annotated[bool, Query(description="только назначенные мне")] = False,
    include_closed: bool = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[dict[str, Any]]:
    """The work queue, ordered by priority and then by age (ТЗ 1.0.3 §17, §18)."""
    entries = triage.build_queue(
        session,
        actor.organization_id,
        include_closed=include_closed,
        assignee=actor.email if mine else None,
        limit=limit,
    )
    return [entry.as_dict() for entry in entries]


@router.post("/incidents/{incident_id}/assign", response_model=dict)
def assign_incident(
    incident_id: str,
    payload: AssignRequest,
    actor: Classifier,
    session: DbSession,
    request: Request,
) -> dict[str, Any]:
    """Assign an incident, or let the platform pick the least-loaded analyst."""
    incident = _incident_or_404(session, actor, incident_id)
    if payload.assignee_email:
        assignment = triage.assign(
            session,
            incident,
            assignee_email=str(payload.assignee_email),
            assigned_by=actor.email,
        )
    else:
        chosen = triage.auto_assign(
            session,
            incident,
            candidates=[str(email) for email in payload.candidates],
            assigned_by=actor.email,
        )
        if chosen is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "не указан ни исполнитель, ни список кандидатов для автоназначения",
            )
        assignment = chosen
    record(
        session,
        action=AuditAction.INCIDENT_ASSIGNED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="incident",
        object_id=incident.id,
        detail={"assignee": assignment.assignee_email, "method": assignment.method},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return {
        "incident_id": incident.id,
        "assignee_email": assignment.assignee_email,
        "method": assignment.method,
    }


@router.get("/incidents/{incident_id}/timeline", response_model=list[TimelineEntryOut])
def incident_timeline(incident_id: str, actor: Viewer, session: DbSession) -> list[dict[str, Any]]:
    """Everything that happened, assembled from records rather than from notes (§21)."""
    incident = _incident_or_404(session, actor, incident_id)
    return triage.build_timeline(session, incident)


# ---------------------------------------------------------------------------------------------
# Classification and the feedback loop (ТЗ 1.0.3 §22, §23, §26, §34)
# ---------------------------------------------------------------------------------------------
@router.post("/incidents/{incident_id}/classification", response_model=ClassificationOut)
def classify(
    incident_id: str,
    payload: ClassificationRequest,
    actor: Classifier,
    session: DbSession,
    request: Request,
) -> ClassificationOut:
    """Record the analyst's verdict and feed it back into rule quality (§22, §23)."""
    incident = _incident_or_404(session, actor, incident_id)
    classification = payload.classification

    if classification in CONFIRMED_BENIGN and not payload.comment.strip():
        # Closing something as harmless is the decision most likely to be revisited after an
        # incident, so it is the one that must carry a reason.
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "при закрытии как безопасного требуется комментарий с обоснованием",
        )

    record_row = detection_ops.classify_incident(
        session,
        incident=incident,
        classification=classification,
        analyst_email=actor.email,
        analyst_id=actor.user_id,
        comment=payload.comment,
        offending_rules=payload.offending_rules,
        offending_signals=payload.offending_signals,
        confidence=payload.confidence,
    )

    if classification is AnalystClassification.FALSE_POSITIVE:
        false_positive_total.inc()
    if incident.triaged_at is None:
        incident.triaged_at = utcnow()

    record(
        session,
        action=AuditAction.INCIDENT_CLASSIFIED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="incident",
        object_id=incident.id,
        detail={
            "classification": classification.value,
            "previous": record_row.previous_classification,
            "confidence": payload.confidence,
            "offending_rules": payload.offending_rules,
        },
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    if classification in CONFIRMED_BENIGN:
        record(
            session,
            action=AuditAction.FALSE_POSITIVE_MARKED,
            actor_id=actor.user_id,
            actor_email=actor.email,
            actor_role=actor.role.value,
            organization_id=actor.organization_id,
            object_type="incident",
            object_id=incident.id,
            detail={"rules": payload.offending_rules},
            ip_address=client_ip(request),
            request_id=getattr(request.state, "request_id", ""),
        )
    session.commit()
    return ClassificationOut(
        classification_id=record_row.id,
        incident_id=incident.id,
        classification=record_row.classification,
        previous_classification=record_row.previous_classification,
        analyst_email=record_row.analyst_email,
        confidence=record_row.confidence,
        comment=record_row.comment,
        offending_rules=list(record_row.offending_rules or []),
        created_at=record_row.created_at,
    )


@router.get("/incidents/{incident_id}/employee-feedback", response_model=dict)
def employee_feedback(incident_id: str, actor: Viewer, session: DbSession) -> dict[str, Any]:
    """The wording to send the employee who reported it (ТЗ 1.0.3 §34).

    Offered as text for review rather than sent automatically, and deliberately never says a
    message is "100% safe": the platform can report that it found nothing, not that nothing is
    there.
    """
    incident = _incident_or_404(session, actor, incident_id)
    latest = session.execute(
        select(IncidentClassification)
        .where(IncidentClassification.incident_id == incident.id)
        .order_by(IncidentClassification.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    classification = latest.classification if latest else AnalystClassification.UNKNOWN
    return {
        "incident_id": incident.id,
        "classification": classification.value,
        "classified": latest is not None,
        "text": triage.employee_feedback(classification),
    }


@router.post("/detection/missed", response_model=DetectionFeedbackOut)
def report_missed_detection(
    payload: MissedDetectionRequest,
    actor: MissReporter,
    session: DbSession,
    request: Request,
) -> DetectionFeedbackOut:
    """Report something the platform should have caught (ТЗ 1.0.3 §26).

    The platform cannot find its own misses, so each of these is the only record that one
    happened. Naming the layer that failed matters: a miss caused by a parser limit is fixed in
    a different place from one caused by a rule that never fired.
    """
    if payload.message_id:
        message = session.get(MailMessage, payload.message_id)
        if message is None or message.organization_id != actor.organization_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "сообщение не найдено")
    if payload.incident_id:
        _incident_or_404(session, actor, payload.incident_id)
    if payload.gap_id:
        known = session.execute(
            select(DetectionGapRecord).where(
                DetectionGapRecord.organization_id == actor.organization_id,
                DetectionGapRecord.gap_id == payload.gap_id,
            )
        ).scalar_one_or_none()
        if known is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "указан неизвестный идентификатор пробела")

    feedback = detection_ops.record_false_negative(
        session,
        organization_id=actor.organization_id,
        message_id=payload.message_id,
        incident_id=payload.incident_id,
        analyst_email=actor.email,
        source=payload.source,
        root_cause=payload.root_cause,
        expected_detection=payload.expected_detection,
        missing_fact=payload.missing_fact,
        comment=payload.comment,
        gap_id=payload.gap_id,
    )
    record(
        session,
        action=AuditAction.FALSE_NEGATIVE_MARKED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="message",
        object_id=payload.message_id or payload.incident_id or "",
        detail={
            "source": payload.source.value,
            "root_cause": payload.root_cause.value,
            "gap_id": payload.gap_id,
        },
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return _feedback_out(feedback)


def _feedback_out(feedback: DetectionFeedback) -> DetectionFeedbackOut:
    return DetectionFeedbackOut(
        feedback_id=feedback.id,
        kind=feedback.kind,
        message_id=feedback.message_id,
        incident_id=feedback.incident_id,
        rule_id=feedback.rule_id,
        analyst_email=feedback.analyst_email,
        source=feedback.source,
        root_cause=feedback.root_cause,
        expected_detection=feedback.expected_detection,
        missing_fact=feedback.missing_fact,
        gap_id=feedback.gap_id,
        created_at=feedback.created_at,
    )


@router.get("/detection/feedback", response_model=list[DetectionFeedbackOut])
def list_feedback(
    actor: QualityReader,
    session: DbSession,
    kind: Annotated[str | None, Query(pattern="^(false_positive|false_negative)$")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[DetectionFeedbackOut]:
    query = select(DetectionFeedback).where(DetectionFeedback.organization_id == actor.organization_id)
    if kind:
        query = query.where(DetectionFeedback.kind == kind)
    rows = session.execute(query.order_by(DetectionFeedback.created_at.desc()).limit(limit)).scalars().all()
    return [_feedback_out(row) for row in rows]


# ---------------------------------------------------------------------------------------------
# Rule registry and lifecycle (ТЗ 1.0.3 §9, §10, §11)
# ---------------------------------------------------------------------------------------------
@router.get("/detection/rules", response_model=list[RuleOut])
def list_rules(
    actor: QualityReader,
    session: DbSession,
    rule_status: Annotated[RuleStatus | None, Query(alias="status")] = None,
    category: str | None = None,
) -> list[RuleOut]:
    """The deployed rule pack, with the quality numbers each rule has earned."""
    ruleset = get_ruleset()
    stats = {
        row.rule_id: row
        for row in session.execute(
            select(RuleStatistic).where(RuleStatistic.organization_id == actor.organization_id)
        )
        .scalars()
        .all()
    }
    out: list[RuleOut] = []
    for rule in ruleset.rules:
        if rule_status is not None and rule.status is not rule_status:
            continue
        if category and rule.category != category:
            continue
        stat = stats.get(rule.id)
        decided = (stat.confirmed_tp + stat.confirmed_fp) if stat else 0
        out.append(
            RuleOut(
                rule_id=rule.id,
                version=rule.version,
                title=rule.name,
                category=rule.category,
                severity=rule.severity,
                status=rule.status,
                owner=rule.owner,
                weight=rule.effective_weight,
                scores=rule.scores,
                hard=rule.hard,
                scenarios=list(rule.scenarios),
                condition=rule.conditions.render(),
                trigger_count=stat.trigger_count if stat else 0,
                confirmed_tp=stat.confirmed_tp if stat else 0,
                confirmed_fp=stat.confirmed_fp if stat else 0,
                # Null rather than 1.0 when nothing has been judged yet: an untested rule is
                # not a perfect rule.
                precision=(stat.confirmed_tp / decided) if stat and decided else None,
            )
        )
    return out


@router.post("/detection/rules/sync", response_model=dict)
def sync_registry(actor: RuleManager, session: DbSession, request: Request) -> dict[str, Any]:
    """Mirror the Git-managed rule pack, gap registry and scenario catalog into the database.

    The files stay the source of truth: each is reviewed in a pull request next to the code it
    describes. The tables exist so the console can show them beside live data.
    """
    rules = detection_ops.sync_rule_registry(session, actor.organization_id)
    gaps = detection_ops.sync_gap_registry(session, actor.organization_id)
    scenarios = detection_ops.sync_threat_scenarios(session, actor.organization_id)
    record(
        session,
        action=AuditAction.RULE_CHANGED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="ruleset",
        object_id=get_ruleset().version_fingerprint[:64],
        detail={"rules": rules, "gaps": gaps, "scenarios": scenarios, "action": "sync"},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return {"rules": rules, "gaps": gaps, "scenarios": scenarios}


@router.post("/detection/rules/{rule_id}/status", response_model=dict)
def change_rule_status(
    rule_id: str,
    payload: RuleStatusChangeRequest,
    actor: RuleManager,
    session: DbSession,
    request: Request,
) -> dict[str, Any]:
    """Request a lifecycle transition for a rule (ТЗ 1.0.3 §10).

    The rule file itself lives in Git and is changed by a reviewed commit — this endpoint
    records the intent, its reason and its author so the change is traceable from the console
    to the commit, and refuses a transition the lifecycle does not allow.
    """
    ruleset = get_ruleset()
    rule = next((r for r in ruleset.rules if r.id == rule_id), None)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "правило не найдено")
    if payload.status is rule.status:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "правило уже в этом состоянии")
    if not _transition_allowed(rule.status, payload.status):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"переход {rule.status.value} → {payload.status.value} не предусмотрен жизненным циклом правила",
        )
    if payload.status is RuleStatus.ACTIVE and not rule.owner:
        # An active rule with no owner has nobody to tune it the week it starts producing noise.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "правило нельзя активировать без владельца")

    stat = session.execute(
        select(RuleStatistic).where(
            RuleStatistic.organization_id == actor.organization_id,
            RuleStatistic.rule_id == rule_id,
        )
    ).scalar_one_or_none()
    change = RuleChange(
        organization_id=actor.organization_id,
        rule_id=rule_id,
        rule_version=rule.version,
        from_status=rule.status.value,
        to_status=payload.status.value,
        author=actor.email,
        reviewer=payload.reviewer,
        change_reason=payload.reason,
        before_metrics={
            "trigger_count": stat.trigger_count if stat else 0,
            "confirmed_tp": stat.confirmed_tp if stat else 0,
            "confirmed_fp": stat.confirmed_fp if stat else 0,
        },
    )
    session.add(change)
    record(
        session,
        action=AuditAction.RULE_STATUS_CHANGED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="rule",
        object_id=rule_id,
        detail={
            "from": rule.status.value,
            "to": payload.status.value,
            "reason": payload.reason[:500],
        },
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return {
        "rule_id": rule_id,
        "requested_status": payload.status.value,
        "current_status": rule.status.value,
        "change_id": change.id,
        "note": (
            "Статус правила задаётся в файле правил и применяется после ревью и деплоя. "
            "Запрос зафиксирован в журнале изменений."
        ),
    }


#: Allowed lifecycle transitions (ТЗ 1.0.3 §10). A rule reaches ACTIVE only through SHADOW,
#: so nothing starts affecting verdicts before it has been measured against real mail.
_TRANSITIONS: dict[RuleStatus, frozenset[RuleStatus]] = {
    RuleStatus.EXPERIMENTAL: frozenset({RuleStatus.SHADOW, RuleStatus.DISABLED}),
    RuleStatus.SHADOW: frozenset({RuleStatus.ACTIVE, RuleStatus.EXPERIMENTAL, RuleStatus.DISABLED}),
    RuleStatus.ACTIVE: frozenset(
        {RuleStatus.SHADOW, RuleStatus.DEGRADED, RuleStatus.DEPRECATED, RuleStatus.DISABLED}
    ),
    #: DEGRADED is where a rule that started producing false positives goes while its owner
    #: looks at it: it keeps running and keeps being measured, but it no longer decides
    #: anything on its own. Returning it to ACTIVE is a decision, not a timeout.
    RuleStatus.DEGRADED: frozenset(
        {RuleStatus.ACTIVE, RuleStatus.SHADOW, RuleStatus.DISABLED, RuleStatus.DEPRECATED}
    ),
    RuleStatus.DEPRECATED: frozenset({RuleStatus.DISABLED, RuleStatus.SHADOW}),
    RuleStatus.DISABLED: frozenset({RuleStatus.EXPERIMENTAL, RuleStatus.SHADOW}),
}


def _transition_allowed(current: RuleStatus, target: RuleStatus) -> bool:
    return target in _TRANSITIONS.get(current, frozenset())


@router.get("/detection/rules/changes", response_model=list[dict])
def list_rule_changes(
    actor: QualityReader,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[dict[str, Any]]:
    rows = (
        session.execute(
            select(RuleChange)
            .where(RuleChange.organization_id == actor.organization_id)
            .order_by(RuleChange.created_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return [
        {
            "change_id": row.id,
            "rule_id": row.rule_id,
            "from_status": row.from_status,
            "to_status": row.to_status,
            "author": row.author,
            "reviewer": row.reviewer,
            "reason": row.change_reason,
            "before_metrics": row.before_metrics,
            "created_at": row.created_at.isoformat(),
        }
        for row in rows
    ]


# ---------------------------------------------------------------------------------------------
# Simulation and replay (ТЗ 1.0.3 §13, §14, §49, §50)
# ---------------------------------------------------------------------------------------------
@router.post("/detection/simulate", response_model=SimulationOut)
def simulate_rules(
    payload: SimulationRequest,
    actor: Simulator,
    session: DbSession,
    settings: AppSettings,
    request: Request,
) -> SimulationOut:
    """Run the current rules against a stored message, changing nothing (§13)."""
    message = session.get(MailMessage, payload.message_id)
    if message is None or message.organization_id != actor.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "сообщение не найдено")
    result = detection_ops.simulate(session, settings, message_id=payload.message_id, rule_id=payload.rule_id)
    if result is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "исходное письмо недоступно: оно удалено по политике хранения",
        )
    record(
        session,
        action=AuditAction.RULE_SIMULATED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="message",
        object_id=payload.message_id,
        detail={"rule_id": payload.rule_id, "classification": result.classification.value},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return SimulationOut.model_validate(result.as_dict())


@router.post("/analysis/{job_id}/replay", response_model=ReplayOut)
def replay_analysis(
    job_id: str,
    payload: ReplayRequest,
    actor: Replayer,
    session: DbSession,
    settings: AppSettings,
    request: Request,
) -> ReplayOut:
    """Re-run one analysis with today's engine as a new revision (ТЗ 1.0.3 §49)."""
    job = session.get(AnalysisJob, job_id)
    if job is None or job.organization_id != actor.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "задание анализа не найдено")
    revision = detection_ops.replay(
        session, settings, job_id=job_id, requested_by=actor.email, apply=payload.apply
    )
    if revision is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "повторный анализ невозможен: нет исходного письма или прежнего результата",
        )
    record(
        session,
        action=AuditAction.ANALYSIS_REPLAYED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="analysis_job",
        object_id=job_id,
        detail={
            "dry_run": revision.dry_run,
            "before": revision.original_classification,
            "after": revision.new_classification,
        },
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return ReplayOut(
        revision_id=revision.id,
        analysis_job_id=revision.analysis_job_id,
        revision=revision.revision,
        dry_run=revision.dry_run,
        original_classification=revision.original_classification,
        new_classification=revision.new_classification,
        original_score=revision.original_score,
        new_score=revision.new_score,
        added_rules=list(revision.added_rules or []),
        removed_rules=list(revision.removed_rules or []),
        created_at=revision.created_at,
    )


@router.post("/detection/reevaluate", response_model=ReevaluationOut)
def reevaluate_history(
    payload: ReevaluationRequest,
    actor: Replayer,
    session: DbSession,
    settings: AppSettings,
    request: Request,
) -> ReevaluationOut:
    """Ask what today's rules would have said about recent mail (ТЗ 1.0.3 §50).

    A rule written to catch a live campaign is worth little if it only applies to tomorrow's
    mail. Dry-run by default: the answer is a proposal until someone decides to apply it.
    """
    run = detection_ops.reevaluate(
        session,
        settings,
        organization_id=actor.organization_id,
        days=payload.days,
        requested_by=actor.email,
        dry_run=payload.dry_run,
        limit=payload.limit,
    )
    record(
        session,
        action=AuditAction.REEVALUATION_STARTED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="reevaluation",
        object_id=run.id,
        detail={
            "days": payload.days,
            "dry_run": payload.dry_run,
            "examined": run.messages_examined,
            "changed": run.verdict_changed,
        },
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return ReevaluationOut(
        run_id=run.id,
        window_days=run.window_days,
        dry_run=run.dry_run,
        messages_examined=run.messages_examined,
        verdict_changed=run.verdict_changed,
        newly_suspicious=run.newly_suspicious,
        newly_cleared=run.newly_cleared,
        affected_campaigns=list(run.affected_campaigns or []),
        affected_users=list(run.affected_users or []),
        sample=list(run.sample or []),
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


# ---------------------------------------------------------------------------------------------
# Detection gap registry (ТЗ 1.0.3 §27)
# ---------------------------------------------------------------------------------------------
#: A gap stops being open when it is fixed or when the organisation decides not to fix it.
#: "Won't fix" is a terminal state on purpose: an accepted risk that stays on the open list
#: forever trains everyone to ignore the list.
_TERMINAL_GAP_STATES: frozenset[GapStatus] = frozenset({GapStatus.FIXED, GapStatus.WONT_FIX})


@router.get("/detection/gaps", response_model=list[DetectionGapOut])
def list_gaps(
    actor: QualityReader,
    session: DbSession,
    gap_status: Annotated[GapStatus | None, Query(alias="status")] = None,
) -> list[DetectionGapOut]:
    """What the platform knowingly does not catch (ТЗ 1.0.3 §27).

    Published rather than hidden: an unlisted gap is indistinguishable from a gap nobody knows
    about, and the second kind is what gets an organisation hurt.
    """
    query = select(DetectionGapRecord).where(DetectionGapRecord.organization_id == actor.organization_id)
    if gap_status is not None:
        query = query.where(DetectionGapRecord.status == gap_status)
    rows = session.execute(query.order_by(DetectionGapRecord.gap_id)).scalars().all()

    misses = dict(
        session.execute(
            select(DetectionFeedback.gap_id, func.count(DetectionFeedback.id))
            .where(
                DetectionFeedback.organization_id == actor.organization_id,
                DetectionFeedback.kind == "false_negative",
                DetectionFeedback.gap_id.is_not(None),
            )
            .group_by(DetectionFeedback.gap_id)
        ).all()
    )
    return [
        DetectionGapOut(
            gap_id=row.gap_id,
            category=row.category,
            description=row.description,
            root_cause=row.root_cause,
            severity=row.severity,
            status=row.status,
            owner=row.owner,
            target_release=row.target_release,
            examples=[str(e) for e in (row.examples or [])],
            mitigation=row.mitigation,
            planned_fix=row.planned_fix,
            reported_misses=int(misses.get(row.gap_id, 0)),
        )
        for row in rows
    ]


@router.post("/detection/gaps/{gap_id}/status", response_model=DetectionGapOut)
def update_gap(
    gap_id: str,
    payload: GapUpdateRequest,
    actor: GapManager,
    session: DbSession,
    request: Request,
) -> DetectionGapOut:
    gap = session.execute(
        select(DetectionGapRecord).where(
            DetectionGapRecord.organization_id == actor.organization_id,
            DetectionGapRecord.gap_id == gap_id,
        )
    ).scalar_one_or_none()
    if gap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "пробел не найден")
    previous = gap.status
    gap.status = payload.status
    if payload.status in _TERMINAL_GAP_STATES:
        gap.closed_at = utcnow()
    elif previous in _TERMINAL_GAP_STATES:
        gap.closed_at = None
    if payload.note:
        gap.planned_fix = (gap.planned_fix + "\n" + payload.note).strip()[:4000]
    record(
        session,
        action=AuditAction.GAP_CLOSED
        if payload.status in _TERMINAL_GAP_STATES
        else AuditAction.GAP_REGISTERED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="detection_gap",
        object_id=gap_id,
        detail={"from": previous.value, "to": payload.status.value},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return DetectionGapOut(
        gap_id=gap.gap_id,
        category=gap.category,
        description=gap.description,
        root_cause=gap.root_cause,
        severity=gap.severity,
        status=gap.status,
        owner=gap.owner,
        target_release=gap.target_release,
        examples=[str(e) for e in (gap.examples or [])],
        mitigation=gap.mitigation,
        planned_fix=gap.planned_fix,
    )


# ---------------------------------------------------------------------------------------------
# Threat scenario catalog and coverage (ТЗ 1.0.3 §28, §37)
# ---------------------------------------------------------------------------------------------
@router.get("/detection/scenarios", response_model=list[ThreatScenarioOut])
def list_scenarios(actor: QualityReader, session: DbSession) -> list[ThreatScenarioOut]:
    """The catalog, with the coverage each scenario actually has (§28, §37).

    Coverage is computed from the rule pack rather than stored: a catalog that claims coverage
    a rule no longer provides is worse than no catalog.
    """
    ruleset = get_ruleset()
    by_id = {rule.id: rule for rule in ruleset.rules}
    rows = (
        session.execute(
            select(ThreatScenario)
            .where(ThreatScenario.organization_id == actor.organization_id)
            .order_by(ThreatScenario.scenario_id)
        )
        .scalars()
        .all()
    )
    out: list[ThreatScenarioOut] = []
    for row in rows:
        declared = [str(r) for r in (row.rules or [])]
        linked = [by_id[r] for r in declared if r in by_id]
        active = [r for r in linked if r.status is RuleStatus.ACTIVE]
        shadow = [r for r in linked if r.status is RuleStatus.SHADOW]
        out.append(
            ThreatScenarioOut(
                scenario_id=row.scenario_id,
                title=row.title,
                category=row.category,
                description=row.description,
                severity=row.severity,
                rules=declared,
                fixtures=[str(f) for f in (row.fixtures or [])],
                playbook=row.playbook,
                enabled=row.enabled,
                covered=bool(active),
                active_rules=len(active),
                shadow_rules=len(shadow),
            )
        )
    return out


# ---------------------------------------------------------------------------------------------
# Detection quality dashboard (ТЗ 1.0.3 §35)
# ---------------------------------------------------------------------------------------------
@router.get("/detection/quality", response_model=DetectionQualityOut)
def detection_quality(
    actor: QualityReader,
    session: DbSession,
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> DetectionQualityOut:
    """Detection quality as measured, including what could not be measured (§35).

    Every ratio here can come back ``null``. That is the point: a dashboard that shows 0% false
    positives because nobody has classified anything would be read as success, and it is the
    one number in this product that must never be able to lie that way.
    """
    end = utcnow()
    start = end - timedelta(days=days)
    org = actor.organization_id

    total_analyzed = int(
        session.execute(
            select(func.count(AnalysisResult.id))
            .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
            .where(AnalysisJob.organization_id == org, AnalysisJob.created_at >= start)
        ).scalar_one()
        or 0
    )
    unscannable = int(
        session.execute(
            select(func.count(AnalysisResult.id))
            .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
            .where(
                AnalysisJob.organization_id == org,
                AnalysisJob.created_at >= start,
                AnalysisResult.scan_completeness != "FULL",
            )
        ).scalar_one()
        or 0
    )
    unknown = int(
        session.execute(
            select(func.count(AnalysisResult.id))
            .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
            .where(
                AnalysisJob.organization_id == org,
                AnalysisJob.created_at >= start,
                AnalysisResult.classification == "UNKNOWN",
            )
        ).scalar_one()
        or 0
    )

    classifications = (
        session.execute(
            select(IncidentClassification).where(
                IncidentClassification.organization_id == org,
                IncidentClassification.created_at >= start,
            )
        )
        .scalars()
        .all()
    )
    # One incident may be reclassified; only the newest verdict per incident counts.
    latest: dict[str, IncidentClassification] = {}
    for row in sorted(classifications, key=lambda r: r.created_at):
        latest[row.incident_id] = row
    threats = sum(1 for r in latest.values() if r.classification in CONFIRMED_THREAT)
    benign = sum(1 for r in latest.values() if r.classification in CONFIRMED_BENIGN)
    decided = threats + benign

    reported_misses = int(
        session.execute(
            select(func.count(DetectionFeedback.id)).where(
                DetectionFeedback.organization_id == org,
                DetectionFeedback.kind == "false_negative",
                DetectionFeedback.created_at >= start,
            )
        ).scalar_one()
        or 0
    )
    open_gaps = int(
        session.execute(
            select(func.count(DetectionGapRecord.id)).where(
                DetectionGapRecord.organization_id == org,
                DetectionGapRecord.status.not_in(list(_TERMINAL_GAP_STATES)),
            )
        ).scalar_one()
        or 0
    )

    ruleset = get_ruleset()
    stats = {
        row.rule_id: row
        for row in session.execute(select(RuleStatistic).where(RuleStatistic.organization_id == org))
        .scalars()
        .all()
    }
    noisy: list[dict[str, Any]] = []
    silent: list[str] = []
    for rule in ruleset.rules:
        stat = stats.get(rule.id)
        if rule.status is RuleStatus.ACTIVE and (stat is None or stat.trigger_count == 0):
            silent.append(rule.id)
            continue
        if stat is None:
            continue
        judged = stat.confirmed_tp + stat.confirmed_fp
        if judged >= 5 and stat.confirmed_fp / judged > 0.3:
            noisy.append(
                {
                    "rule_id": rule.id,
                    "owner": rule.owner,
                    "triggers": stat.trigger_count,
                    "confirmed_tp": stat.confirmed_tp,
                    "confirmed_fp": stat.confirmed_fp,
                    "precision": stat.confirmed_tp / judged,
                }
            )
    noisy.sort(key=lambda item: item["precision"])

    shadow_count = sum(1 for r in ruleset.rules if r.status is RuleStatus.SHADOW)
    unowned = [r.id for r in ruleset.rules if r.status is RuleStatus.ACTIVE and not r.owner]

    scenarios = (
        session.execute(select(ThreatScenario).where(ThreatScenario.organization_id == org)).scalars().all()
    )
    by_id = {rule.id: rule for rule in ruleset.rules}
    coverage = [
        {
            "scenario_id": scenario.scenario_id,
            "title": scenario.title,
            "severity": scenario.severity.value,
            "active_rules": sum(
                1 for rid in (scenario.rules or []) if rid in by_id and by_id[rid].status is RuleStatus.ACTIVE
            ),
            "covered": any(
                rid in by_id and by_id[rid].status is RuleStatus.ACTIVE for rid in (scenario.rules or [])
            ),
        }
        for scenario in scenarios
    ]

    return DetectionQualityOut(
        period_start=start,
        period_end=end,
        total_analyzed=total_analyzed,
        classified=len(latest),
        confirmed_threats=threats,
        confirmed_benign=benign,
        precision=(threats / decided) if decided else None,
        false_positive_rate=(benign / decided) if decided else None,
        reported_misses=reported_misses,
        unscannable=unscannable,
        unknown=unknown,
        open_gaps=open_gaps,
        shadow_rules=shadow_count,
        noisy_rules=noisy[:20],
        silent_rules=silent[:50],
        unowned_active_rules=unowned,
        coverage_by_scenario=coverage,
    )


@router.get("/detection/shadow", response_model=list[dict])
def shadow_rule_report(
    actor: QualityReader,
    session: DbSession,
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> list[dict[str, Any]]:
    """How shadow rules would have behaved on real mail (ТЗ 1.0.3 §11).

    This is the evidence that decides whether a candidate rule may go ACTIVE. It exists because
    the engine records shadow matches even though they contribute nothing to a score — a shadow
    rule nobody can measure is a rule nobody can ever promote.
    """
    start = utcnow() - timedelta(days=days)
    rows = session.execute(
        select(
            DetectionSignal.rule_id,
            func.count(DetectionSignal.id),
            func.max(DetectionSignal.observed_at),
        )
        .join(AnalysisResult, AnalysisResult.id == DetectionSignal.result_id)
        .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
        .where(
            AnalysisJob.organization_id == actor.organization_id,
            DetectionSignal.shadow.is_(True),
            DetectionSignal.observed_at >= start,
        )
        .group_by(DetectionSignal.rule_id)
        .order_by(func.count(DetectionSignal.id).desc())
    ).all()
    ruleset = get_ruleset()
    by_id = {rule.id: rule for rule in ruleset.rules}
    out: list[dict[str, Any]] = []
    for rule_id, matches, last_seen in rows:
        rule = by_id.get(rule_id or "")
        out.append(
            {
                "rule_id": rule_id,
                "title": rule.name if rule else "",
                "owner": rule.owner if rule else "",
                "status": rule.status.value if rule else "UNKNOWN",
                "matches": int(matches),
                "last_match_at": last_seen.isoformat() if last_seen else None,
                "would_have_scored": rule.weight if rule and rule.weight is not None else None,
            }
        )
    return out


@router.get("/detection/versions", response_model=dict)
def detection_versions(actor: QualityReader, settings: AppSettings) -> dict[str, Any]:
    """Everything needed to reproduce a verdict (ТЗ 1.0.3 §48)."""
    versions = detection_ops.engine_versions(settings)
    ruleset = get_ruleset()
    return {
        **versions.model_dump(mode="json"),
        "detection_engine_version": detection_ops.ENGINE_VERSION_INFO["detection_engine"],
        "rule_count": len(ruleset.rules),
        "active_rules": sum(1 for r in ruleset.rules if r.status is RuleStatus.ACTIVE),
        "shadow_rules": sum(1 for r in ruleset.rules if r.status is RuleStatus.SHADOW),
        "rule_pack_path": str(detection_ops.rule_pack_path()),
    }
