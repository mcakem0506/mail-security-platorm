"""Incidents, campaigns and analyst workflow (ТЗ 18, 19, 43)."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from msp_contracts import IncidentStatus, Severity
from sqlalchemy import desc, func, select

from ..db.base import utcnow
from ..db.models import (
    AnalysisResult,
    AnalystNote,
    Campaign,
    CampaignMessage,
    Incident,
    IncidentIndicator,
    IncidentMessage,
    Indicator,
    IndicatorObservation,
    MailMessage,
)
from ..deps import Actor, DbSession, client_ip, require_permission
from ..observability import false_positive_total, incidents_total
from ..schemas import (
    AnalystNoteRequest,
    CampaignOut,
    IncidentCreateRequest,
    IncidentOut,
    IncidentUpdateRequest,
    PaginatedResponse,
)
from ..security.audit import AuditAction, record
from ..security.rbac import Permission
from ..services.campaigns import campaign_summary

logger = logging.getLogger(__name__)
router = APIRouter(tags=["incidents"])

Viewer = Annotated[Actor, Depends(require_permission(Permission.VIEW_INCIDENTS))]
Manager = Annotated[Actor, Depends(require_permission(Permission.MANAGE_INCIDENTS))]
Classifier = Annotated[Actor, Depends(require_permission(Permission.CLASSIFY_MESSAGE))]

_CONFIRMED_STATUSES = {
    IncidentStatus.CONFIRMED_PHISHING,
    IncidentStatus.CONFIRMED_MALWARE,
    IncidentStatus.CONFIRMED_BEC,
}


def _incident_out(session, incident: Incident) -> IncidentOut:  # type: ignore[no-untyped-def]
    message_count = session.execute(
        select(func.count()).select_from(IncidentMessage).where(IncidentMessage.incident_id == incident.id)
    ).scalar_one()
    indicator_count = session.execute(
        select(func.count()).select_from(IncidentIndicator).where(IncidentIndicator.incident_id == incident.id)
    ).scalar_one()
    return IncidentOut(
        incident_id=incident.id,
        number=incident.number,
        title=incident.title,
        summary=incident.summary,
        status=incident.status,
        severity=incident.severity,
        confidence=incident.confidence,
        assigned_to=incident.assigned_to,
        opened_by=incident.opened_by,
        affected_users=list(incident.affected_users or []),
        message_count=int(message_count),
        indicator_count=int(indicator_count),
        created_at=incident.created_at,
        triaged_at=incident.triaged_at,
        remediated_at=incident.remediated_at,
        closed_at=incident.closed_at,
        timeline=list(incident.timeline or []),
    )


def _add_timeline(incident: Incident, event: str, actor_email: str, detail: str = "") -> None:
    timeline = list(incident.timeline or [])
    timeline.append(
        {"at": utcnow().isoformat(), "event": event, "actor": actor_email, "detail": detail[:500]}
    )
    incident.timeline = timeline[-200:]


# ---------------------------------------------------------------------------------------------
# Campaigns
# ---------------------------------------------------------------------------------------------
@router.get("/campaigns", response_model=PaginatedResponse)
def list_campaigns(
    actor: Annotated[Actor, Depends(require_permission(Permission.VIEW_CAMPAIGNS))],
    session: DbSession,
    confirmed_only: bool = False,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> PaginatedResponse:
    query = select(Campaign).where(Campaign.organization_id == actor.organization_id)
    if confirmed_only:
        query = query.where(Campaign.confirmed_malicious.is_(True))
    total = session.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    rows = session.execute(
        query.order_by(desc(Campaign.last_seen)).limit(limit).offset(offset)
    ).scalars().all()
    return PaginatedResponse(
        total=int(total),
        limit=limit,
        offset=offset,
        items=[CampaignOut(**campaign_summary(c)) for c in rows],
    )


@router.get("/campaigns/{campaign_id}", response_model=CampaignOut)
def get_campaign(
    campaign_id: str,
    actor: Annotated[Actor, Depends(require_permission(Permission.VIEW_CAMPAIGNS))],
    session: DbSession,
) -> CampaignOut:
    campaign = session.get(Campaign, campaign_id)
    if campaign is None or campaign.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Кампания не найдена")
    return CampaignOut(**campaign_summary(campaign))


# ---------------------------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------------------------
@router.get("/incidents", response_model=PaginatedResponse)
def list_incidents(
    actor: Viewer,
    session: DbSession,
    incident_status: IncidentStatus | None = Query(default=None, alias="status"),
    assigned_to_me: bool = False,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> PaginatedResponse:
    query = select(Incident).where(Incident.organization_id == actor.organization_id)
    if incident_status is not None:
        query = query.where(Incident.status == incident_status)
    if assigned_to_me:
        query = query.where(Incident.assigned_to == actor.user_id)
    total = session.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    rows = session.execute(
        query.order_by(desc(Incident.created_at)).limit(limit).offset(offset)
    ).scalars().all()
    return PaginatedResponse(
        total=int(total), limit=limit, offset=offset, items=[_incident_out(session, i) for i in rows]
    )


@router.post("/incidents", response_model=IncidentOut, status_code=status.HTTP_201_CREATED)
def create_incident(
    payload: IncidentCreateRequest, request: Request, actor: Manager, session: DbSession
) -> IncidentOut:
    next_number = int(
        session.execute(
            select(func.coalesce(func.max(Incident.number), 0)).where(
                Incident.organization_id == actor.organization_id
            )
        ).scalar_one()
    ) + 1

    incident = Incident(
        organization_id=actor.organization_id,
        number=next_number,
        title=payload.title,
        summary=payload.summary,
        severity=payload.severity,
        opened_by=actor.email,
        status=IncidentStatus.NEW,
    )
    session.add(incident)
    session.flush()
    _add_timeline(incident, "created", actor.email, payload.title)

    message_ids = list(payload.message_ids)
    if payload.campaign_id:
        campaign = session.get(Campaign, payload.campaign_id)
        if campaign is None or campaign.organization_id != actor.organization_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Кампания не найдена")
        campaign.incident_id = incident.id
        message_ids.extend(
            session.execute(
                select(CampaignMessage.message_id).where(CampaignMessage.campaign_id == campaign.id)
            ).scalars().all()
        )

    affected: set[str] = set()
    for message_id in dict.fromkeys(message_ids):
        message = session.get(MailMessage, message_id)
        if message is None or message.organization_id != actor.organization_id:
            continue
        session.add(IncidentMessage(incident_id=incident.id, message_id=message.id))
        if message.reported_by:
            affected.add(message.reported_by)
        for indicator_id in session.execute(
            select(IndicatorObservation.indicator_id).where(
                IndicatorObservation.message_id == message.id
            ).limit(100)
        ).scalars().all():
            exists = session.execute(
                select(IncidentIndicator).where(
                    IncidentIndicator.incident_id == incident.id,
                    IncidentIndicator.indicator_id == indicator_id,
                )
            ).scalar_one_or_none()
            if exists is None:
                session.add(
                    IncidentIndicator(incident_id=incident.id, indicator_id=indicator_id)
                )
    incident.affected_users = sorted(affected)[:500]

    incidents_total.labels(incident.severity.value).inc()
    record(
        session,
        action=AuditAction.INCIDENT_CREATED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="incident",
        object_id=incident.id,
        detail={"title": payload.title, "messages": len(message_ids)},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return _incident_out(session, incident)


@router.get("/incidents/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: str, actor: Viewer, session: DbSession) -> IncidentOut:
    incident = session.get(Incident, incident_id)
    if incident is None or incident.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Инцидент не найден")
    return _incident_out(session, incident)


@router.patch("/incidents/{incident_id}", response_model=IncidentOut)
def update_incident(
    incident_id: str,
    payload: IncidentUpdateRequest,
    request: Request,
    actor: Manager,
    session: DbSession,
) -> IncidentOut:
    incident = session.get(Incident, incident_id)
    if incident is None or incident.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Инцидент не найден")

    previous = incident.status
    if payload.status is not None and payload.status != previous:
        incident.status = payload.status
        _add_timeline(incident, "status_changed", actor.email, f"{previous.value} -> {payload.status.value}")
        now = utcnow()
        if payload.status is IncidentStatus.TRIAGE and incident.triaged_at is None:
            incident.triaged_at = now
        if payload.status is IncidentStatus.REMEDIATED:
            incident.remediated_at = now
        if payload.status is IncidentStatus.CLOSED:
            incident.closed_at = now
        if payload.status is IncidentStatus.FALSE_POSITIVE:
            false_positive_total.inc()
        if payload.status in _CONFIRMED_STATUSES:
            _mark_indicators_confirmed(session, incident)
    if payload.severity is not None:
        incident.severity = payload.severity
    if payload.assigned_to is not None:
        incident.assigned_to = payload.assigned_to or None
        _add_timeline(incident, "assigned", actor.email, payload.assigned_to or "unassigned")
    if payload.summary is not None:
        incident.summary = payload.summary

    record(
        session,
        action=AuditAction.INCIDENT_STATUS_CHANGED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="incident",
        object_id=incident.id,
        detail={
            "from": previous.value,
            "to": incident.status.value,
            "severity": incident.severity.value,
        },
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return _incident_out(session, incident)


def _mark_indicators_confirmed(session, incident: Incident) -> None:  # type: ignore[no-untyped-def]
    """A confirmed incident promotes its indicators, so later messages match them (ТЗ 17.2)."""
    indicator_ids = session.execute(
        select(IncidentIndicator.indicator_id).where(IncidentIndicator.incident_id == incident.id)
    ).scalars().all()
    for indicator_id in indicator_ids:
        indicator = session.get(Indicator, indicator_id)
        if indicator is not None:
            indicator.confirmed_malicious = True
    campaigns = session.execute(
        select(Campaign).where(Campaign.incident_id == incident.id)
    ).scalars().all()
    for campaign in campaigns:
        campaign.confirmed_malicious = True


@router.post("/incidents/{incident_id}/notes", status_code=status.HTTP_201_CREATED)
def add_note(
    incident_id: str,
    payload: AnalystNoteRequest,
    actor: Manager,
    session: DbSession,
) -> dict[str, str]:
    incident = session.get(Incident, incident_id)
    if incident is None or incident.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Инцидент не найден")
    note = AnalystNote(
        incident_id=incident.id,
        author_id=actor.user_id,
        author_email=actor.email,
        body=payload.body,
    )
    session.add(note)
    _add_timeline(incident, "note_added", actor.email)
    session.commit()
    return {"note_id": note.id}


@router.get("/incidents/{incident_id}/notes")
def list_notes(incident_id: str, actor: Viewer, session: DbSession) -> list[dict[str, str]]:
    incident = session.get(Incident, incident_id)
    if incident is None or incident.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Инцидент не найден")
    notes = session.execute(
        select(AnalystNote).where(AnalystNote.incident_id == incident_id).order_by(AnalystNote.created_at)
    ).scalars().all()
    return [
        {"note_id": n.id, "author": n.author_email, "body": n.body, "created_at": n.created_at.isoformat()}
        for n in notes
    ]


@router.post("/incidents/{incident_id}/messages/{message_id}", status_code=status.HTTP_204_NO_CONTENT)
def link_message(
    incident_id: str, message_id: str, actor: Manager, session: DbSession
) -> Response:
    """Link a related message to an incident (ТЗ 43.4)."""
    incident = session.get(Incident, incident_id)
    message = session.get(MailMessage, message_id)
    if (
        incident is None
        or message is None
        or incident.organization_id != actor.organization_id
        or message.organization_id != actor.organization_id
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Объект не найден")
    exists = session.execute(
        select(IncidentMessage).where(
            IncidentMessage.incident_id == incident_id, IncidentMessage.message_id == message_id
        )
    ).scalar_one_or_none()
    if exists is None:
        session.add(IncidentMessage(incident_id=incident_id, message_id=message_id))
        _add_timeline(incident, "message_linked", actor.email, message.subject[:100])
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/messages/{message_id}/classify", status_code=status.HTTP_204_NO_CONTENT)
def classify_message(
    message_id: str,
    request: Request,
    actor: Classifier,
    session: DbSession,
    classification: Annotated[str, Query(pattern="^(false_positive|confirmed_malicious|benign)$")],
    reason: Annotated[str, Query(max_length=1000)] = "",
) -> Response:
    """Analyst classification, including marking a false positive (ТЗ 43.5)."""
    message = session.get(MailMessage, message_id)
    if message is None or message.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Сообщение не найдено")

    if classification == "false_positive":
        false_positive_total.inc()
    if classification == "confirmed_malicious":
        for indicator_id in session.execute(
            select(IndicatorObservation.indicator_id).where(
                IndicatorObservation.message_id == message.id
            )
        ).scalars().all():
            indicator = session.get(Indicator, indicator_id)
            if indicator is not None:
                indicator.confirmed_malicious = True

    result = session.execute(
        select(AnalysisResult).where(AnalysisResult.message_id == message.id)
    ).scalar_one_or_none()
    record(
        session,
        action="message.classified",
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="mail_message",
        object_id=message.id,
        detail={
            "classification": classification,
            "reason": reason,
            "engine_verdict": result.classification.value if result else None,
        },
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
