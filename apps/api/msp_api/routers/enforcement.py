"""API принуждения и карантина (MSP 1.3, ТЗ §59–§61).

Две аудитории:

* **человек в консоли** — сессия, роль, право на каждое действие и запись в аудит на каждую мутацию;
* **узел шлюза** — токен области ``enforcement-policy``: забирает подписанную политику, присылает журнал решений
  и состояние, сдаёт письма в карантин и забирает согласованные выпуски.

Ни одна точка не включает принуждение глобально: включаются отдельные контроли, по двое, и только когда их не
блокирует известный пробел (409).
"""

from __future__ import annotations

import base64
import binascii
import logging
from datetime import timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from msp_enforcement.model import ControlState
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from ..db.models import Organization
from ..db.models_enforcement import EmergencyIncidentRecord, EnforcementExceptionRecord, IncidentState
from ..deps import Actor, AppSettings, DbSession, client_ip, require_permission
from ..security.audit import AuditAction, record
from ..security.rbac import Permission
from ..services import credentials, enforcement, quarantine
from ..services.enforcement import EnforcementError
from ..services.storage import build_storage
from .transport import PolicyAuth

logger = logging.getLogger(__name__)
router = APIRouter(tags=["enforcement"])
agent_router = APIRouter(prefix="/gateway-agent", tags=["enforcement agent"])

EnfReader = Annotated[Actor, Depends(require_permission(Permission.VIEW_ENFORCEMENT))]
EnfSimulator = Annotated[Actor, Depends(require_permission(Permission.SIMULATE_ENFORCEMENT))]
CanaryManager = Annotated[Actor, Depends(require_permission(Permission.CANARY_ENFORCEMENT))]
PilotManager = Annotated[Actor, Depends(require_permission(Permission.PILOT_ENFORCEMENT))]
Pauser = Annotated[Actor, Depends(require_permission(Permission.PAUSE_ENFORCEMENT))]
Rollbacker = Annotated[Actor, Depends(require_permission(Permission.ROLLBACK_ENFORCEMENT))]
KillSwitcher = Annotated[Actor, Depends(require_permission(Permission.KILL_SWITCH))]
QuarantineReader = Annotated[Actor, Depends(require_permission(Permission.VIEW_QUARANTINE))]
QuarantineReleaser = Annotated[Actor, Depends(require_permission(Permission.RELEASE_QUARANTINE))]
QuarantineDeleter = Annotated[Actor, Depends(require_permission(Permission.DELETE_QUARANTINE))]
ExceptionCreator = Annotated[Actor, Depends(require_permission(Permission.CREATE_EXCEPTION))]
ExceptionApprover = Annotated[Actor, Depends(require_permission(Permission.APPROVE_EXCEPTION))]
DecisionReviewer = Annotated[Actor, Depends(require_permission(Permission.REVIEW_REAL_FLOW))]


def _audit(
    session: DbSession,
    actor: Actor,
    request: Request,
    action: str,
    object_type: str,
    object_id: str,
    detail: dict[str, Any] | None = None,
    outcome: str = "success",
) -> None:
    record(
        session,
        action=action,
        actor_email=actor.email,
        actor_id=actor.user_id,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type=object_type,
        object_id=object_id,
        outcome=outcome,
        detail=detail or {},
        ip_address=client_ip(request),
    )


def _fail(exc: EnforcementError) -> HTTPException:
    detail: Any = str(exc) if exc.detail is None else {"message": str(exc), **dict(exc.detail)}
    return HTTPException(exc.status, detail)


def _organization(session: DbSession) -> Organization:
    org = session.execute(select(Organization)).scalars().first()
    if org is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "организация не настроена")
    return org


# ---------------------------------------------------------------------------------------------
# Контроли
# ---------------------------------------------------------------------------------------------
@router.get("/enforcement/controls")
def controls_list(session: DbSession, actor: EnfReader, settings: AppSettings) -> dict[str, Any]:
    rows = enforcement.ensure_controls(session, actor.organization_id)
    items = [enforcement.control_view(session, settings, actor.organization_id, r) for r in rows]
    session.commit()
    return {
        "items": items,
        "global_enforcement_flag": None,
        "warning": "MSP 1.3 IS NOT APPROVED FOR GLOBAL PRODUCTION MX CUTOVER.",
    }


@router.get("/enforcement/controls/{control_id}")
def control_get(
    control_id: str, session: DbSession, actor: EnfReader, settings: AppSettings
) -> dict[str, Any]:
    try:
        row = enforcement.get_control(session, actor.organization_id, control_id)
    except EnforcementError as exc:
        raise _fail(exc) from exc
    view = enforcement.control_view(session, settings, actor.organization_id, row)
    session.commit()
    return view


class SimulateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_id: str = Field(min_length=1, max_length=64)


@router.post("/enforcement/controls/{control_id}/simulate")
def control_simulate(
    control_id: str, body: SimulateBody, session: DbSession, actor: EnfSimulator, settings: AppSettings
) -> dict[str, Any]:
    try:
        row = enforcement.get_control(session, actor.organization_id, control_id)
        result = enforcement.simulate(session, settings, actor.organization_id, row, scan_id=body.scan_id)
    except EnforcementError as exc:
        raise _fail(exc) from exc
    session.commit()
    return result


class ReplayBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hours: int = Field(default=168, ge=1, le=24 * 90)
    limit: int = Field(default=2000, ge=1, le=10000)
    thresholds: dict[str, float] | None = None


@router.post("/enforcement/controls/{control_id}/replay")
def control_replay(
    control_id: str, body: ReplayBody, session: DbSession, actor: EnfSimulator, settings: AppSettings
) -> dict[str, Any]:
    try:
        row = enforcement.get_control(session, actor.organization_id, control_id)
        return enforcement.replay(
            session,
            settings,
            actor.organization_id,
            row,
            hours=body.hours,
            limit=body.limit,
            thresholds=body.thresholds,
        )
    except EnforcementError as exc:
        raise _fail(exc) from exc


class AttestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    value: bool
    ref: str = Field(min_length=1, max_length=200)


@router.post("/enforcement/controls/{control_id}/attest")
def control_attest(
    control_id: str,
    body: AttestBody,
    session: DbSession,
    actor: CanaryManager,
    request: Request,
    settings: AppSettings,
) -> dict[str, Any]:
    try:
        row = enforcement.get_control(session, actor.organization_id, control_id)
        enforcement.attest(row, name=body.name, value=body.value, actor_email=actor.email, ref=body.ref)
    except EnforcementError as exc:
        raise _fail(exc) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.ENFORCEMENT_CONTROL_STATE,
        "enforcement_control",
        row.id,
        {"attestation": body.name, "value": body.value, "ref": body.ref},
    )
    view = enforcement.control_view(session, settings, actor.organization_id, row)
    session.commit()
    return view


class ActivationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["request", "approve", "cancel"] = "request"
    scope: dict[str, Any] = Field(default_factory=dict)
    thresholds: dict[str, float] | None = None
    justification: str = Field(default="", max_length=1000)
    rollback_version: str = Field(default="", max_length=64)


def _activate(
    control_id: str,
    body: ActivationBody,
    session: DbSession,
    actor: Actor,
    request: Request,
    settings: Any,
    target: ControlState,
) -> dict[str, Any]:
    audit_ok = (
        AuditAction.ENFORCEMENT_CANARY_ACTIVATED
        if target is ControlState.CANARY
        else AuditAction.ENFORCEMENT_PILOT_ACTIVATED
    )
    try:
        row = enforcement.get_control(session, actor.organization_id, control_id)
        if body.action == "request":
            _, report = enforcement.request_activation(
                session,
                settings,
                actor.organization_id,
                row,
                target=target,
                scope=body.scope,
                thresholds=body.thresholds,
                justification=body.justification,
                rollback_version=body.rollback_version,
                actor_email=actor.email,
            )
            _audit(
                session,
                actor,
                request,
                AuditAction.ENFORCEMENT_CONTROL_STATE,
                "enforcement_control",
                row.id,
                {"requested": target.value, "readiness": report.status.value, "scope": body.scope},
            )
            session.commit()
            return {
                "status": "PENDING_APPROVAL",
                "control": enforcement.control_view(session, settings, actor.organization_id, row),
            }
        if body.action == "cancel":
            enforcement.cancel_request(row)
            _audit(
                session,
                actor,
                request,
                AuditAction.ENFORCEMENT_CONTROL_STATE,
                "enforcement_control",
                row.id,
                {"cancelled": True},
            )
            session.commit()
            return {"status": "CANCELLED"}
        if (row.pending_request or {}).get("target") not in (None, target.value):
            raise EnforcementError("ожидающий запрос относится к другому состоянию", 409)
        policy = enforcement.approve_activation(
            session, settings, actor.organization_id, row, actor_email=actor.email
        )
        _audit(
            session,
            actor,
            request,
            audit_ok,
            "enforcement_control",
            row.id,
            {
                "state": row.state,
                "policy_version": policy.version,
                "checksum": policy.checksum,
                "requested_by": row.activated_by,
                "scope": row.canary_scope,
                "justification": row.justification,
                "rollback_target": row.rollback_version,
            },
        )
        session.commit()
        return {
            "status": "ACTIVE",
            "policy": enforcement.policy_view(policy),
            "control": enforcement.control_view(session, settings, actor.organization_id, row),
        }
    except EnforcementError as exc:
        # Отказ в активации тоже в аудите: попытка включить заблокированный контроль — значимое событие.
        _audit(
            session,
            actor,
            request,
            AuditAction.ENFORCEMENT_ACTIVATION_REFUSED,
            "enforcement_control",
            control_id,
            {"target": target.value, "reason": str(exc), "action": body.action},
            outcome="denied",
        )
        session.commit()
        raise _fail(exc) from exc


@router.post("/enforcement/controls/{control_id}/canary")
def control_canary(
    control_id: str,
    body: ActivationBody,
    session: DbSession,
    actor: CanaryManager,
    request: Request,
    settings: AppSettings,
) -> dict[str, Any]:
    return _activate(control_id, body, session, actor, request, settings, ControlState.CANARY)


@router.post("/enforcement/controls/{control_id}/pilot")
def control_pilot(
    control_id: str,
    body: ActivationBody,
    session: DbSession,
    actor: PilotManager,
    request: Request,
    settings: AppSettings,
) -> dict[str, Any]:
    return _activate(control_id, body, session, actor, request, settings, ControlState.PILOT)


class ReasonBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=3, max_length=500)


@router.post("/enforcement/controls/{control_id}/pause")
def control_pause(
    control_id: str,
    body: ReasonBody,
    session: DbSession,
    actor: Pauser,
    request: Request,
    settings: AppSettings,
) -> dict[str, Any]:
    try:
        row = enforcement.get_control(session, actor.organization_id, control_id)
        policy = enforcement.pause(
            session, settings, actor.organization_id, row, actor_email=actor.email, reason=body.reason
        )
    except EnforcementError as exc:
        raise _fail(exc) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.ENFORCEMENT_CONTROL_PAUSED,
        "enforcement_control",
        row.id,
        {"reason": body.reason, "policy_version": policy.version},
    )
    session.commit()
    return {"status": "PAUSED", "policy": enforcement.policy_view(policy)}


class RollbackBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    to_version: str = Field(default="", max_length=64)
    reason: str = Field(default="", max_length=500)


@router.post("/enforcement/controls/{control_id}/rollback")
def control_rollback(
    control_id: str,
    body: RollbackBody,
    session: DbSession,
    actor: Rollbacker,
    request: Request,
    settings: AppSettings,
) -> dict[str, Any]:
    try:
        row = enforcement.get_control(session, actor.organization_id, control_id)
        policy = enforcement.rollback(
            session,
            settings,
            actor.organization_id,
            row,
            actor_email=actor.email,
            to_version=body.to_version,
        )
    except EnforcementError as exc:
        raise _fail(exc) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.ENFORCEMENT_CONTROL_ROLLED_BACK,
        "enforcement_control",
        row.id,
        {"policy_version": policy.version, "checksum": policy.checksum, "reason": body.reason},
    )
    session.commit()
    return {"status": "ROLLED_BACK", "policy": enforcement.policy_view(policy)}


# ---------------------------------------------------------------------------------------------
# Политика, решения, безопасность
# ---------------------------------------------------------------------------------------------
@router.get("/enforcement/policies")
def policies_list(
    session: DbSession, actor: EnfReader, limit: Annotated[int, Query(ge=1, le=100)] = 30
) -> dict[str, Any]:
    from ..db.models_enforcement import EnforcementPolicyRecord

    rows = session.execute(
        select(EnforcementPolicyRecord)
        .where(EnforcementPolicyRecord.organization_id == actor.organization_id)
        .order_by(EnforcementPolicyRecord.created_at.desc())
        .limit(limit)
    ).scalars()
    return {"items": [enforcement.policy_view(r) for r in rows]}


@router.get("/enforcement/policies/current")
def policy_current(session: DbSession, actor: EnfReader, settings: AppSettings) -> dict[str, Any]:
    row = enforcement.ensure_baseline(session, settings, actor.organization_id)
    session.commit()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "политика ещё не опубликована")
    return enforcement.policy_view(row, with_body=True)


@router.get("/enforcement/decisions")
def decisions_list(
    session: DbSession,
    actor: EnfReader,
    control: str | None = None,
    applied: str | None = None,
    policy_version: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100000)] = 0,
) -> dict[str, Any]:
    rows = enforcement.list_decisions(
        session,
        actor.organization_id,
        control=control,
        applied=applied,
        policy_version=policy_version,
        limit=limit,
        offset=offset,
    )
    return {"items": [enforcement.decision_view(r) for r in rows], "limit": limit, "offset": offset}


@router.get("/enforcement/decisions/{decision_id}")
def decision_get(decision_id: str, session: DbSession, actor: EnfReader) -> dict[str, Any]:
    from ..db.models_enforcement import EnforcementDecisionRecord

    row = session.get(EnforcementDecisionRecord, decision_id)
    if row is None or row.organization_id != actor.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "решение не найдено")
    return enforcement.decision_view(row)


class DecisionReviewBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    outcome: Literal["CORRECT", "FALSE_POSITIVE"]
    critical: bool = False


@router.post("/enforcement/decisions/{decision_id}/review")
def decision_review(
    decision_id: str,
    body: DecisionReviewBody,
    session: DbSession,
    actor: DecisionReviewer,
    request: Request,
    settings: AppSettings,
) -> dict[str, Any]:
    try:
        row, incident = enforcement.review_decision(
            session,
            settings,
            actor.organization_id,
            decision_id,
            outcome=body.outcome,
            critical=body.critical,
            actor_email=actor.email,
        )
    except EnforcementError as exc:
        raise _fail(exc) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.ENFORCEMENT_DECISION_REVIEWED,
        "enforcement_decision",
        row.id,
        {"outcome": body.outcome, "critical": row.review_critical, "control": row.control_type},
    )
    if incident is not None:
        _audit(
            session,
            actor,
            request,
            AuditAction.ENFORCEMENT_INCIDENT,
            "enforcement_incident",
            incident.id,
            {"opened": True, "control": incident.control_type},
        )
    session.commit()
    return {
        "decision": enforcement.decision_view(row),
        "incident": enforcement.incident_view(incident) if incident else None,
    }


@router.get("/enforcement/safety")
def safety(session: DbSession, actor: EnfReader, settings: AppSettings) -> dict[str, Any]:
    data = enforcement.safety_summary(session, settings, actor.organization_id)
    session.commit()
    return data


@router.get("/enforcement/metrics")
def metrics(session: DbSession, actor: EnfReader) -> dict[str, Any]:
    return enforcement.metrics_snapshot(session, actor.organization_id)


@router.get("/enforcement/credentials")
def credential_overview(session: DbSession, actor: EnfReader, settings: AppSettings) -> dict[str, Any]:
    return {"scopes": credentials.overview(session, settings), "split": credentials.split_status(settings)}


# ---------------------------------------------------------------------------------------------
# Общий выключатель
# ---------------------------------------------------------------------------------------------
def _switch_view(row: Any) -> dict[str, Any]:
    return {
        "active": row.kill_switch,
        "reason": row.reason,
        "activated_by": row.activated_by or None,
        "activated_at": row.activated_at.isoformat() if row.activated_at else None,
        "clear_requested_by": row.clear_requested_by or None,
        "cleared_by": row.cleared_by or None,
        "activation_count": row.activation_count,
    }


@router.get("/enforcement/kill-switch")
def kill_switch_get(session: DbSession, actor: EnfReader) -> dict[str, Any]:
    return _switch_view(enforcement.switch_row(session, actor.organization_id))


@router.post("/enforcement/kill-switch")
def kill_switch_on(
    body: ReasonBody, session: DbSession, actor: KillSwitcher, request: Request
) -> dict[str, Any]:
    row = enforcement.activate_kill_switch(
        session, actor.organization_id, actor_email=actor.email, reason=body.reason
    )
    _audit(
        session,
        actor,
        request,
        AuditAction.ENFORCEMENT_KILL_SWITCH_ON,
        "enforcement_switch",
        row.id,
        {"reason": body.reason},
    )
    session.commit()
    return _switch_view(row)


@router.post("/enforcement/kill-switch/clear")
def kill_switch_clear(
    body: ReasonBody, session: DbSession, actor: KillSwitcher, request: Request
) -> dict[str, Any]:
    try:
        row, cleared = enforcement.clear_kill_switch(session, actor.organization_id, actor_email=actor.email)
    except EnforcementError as exc:
        _audit(
            session,
            actor,
            request,
            AuditAction.ENFORCEMENT_KILL_SWITCH_CLEARED,
            "enforcement_switch",
            "",
            {"refused": str(exc)},
            outcome="denied",
        )
        session.commit()
        raise _fail(exc) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.ENFORCEMENT_KILL_SWITCH_CLEARED,
        "enforcement_switch",
        row.id,
        {"cleared": cleared, "reason": body.reason, "requested_by": row.clear_requested_by},
    )
    session.commit()
    return {**_switch_view(row), "status": "CLEARED" if cleared else "CLEAR_REQUESTED"}


# ---------------------------------------------------------------------------------------------
# Исключения
# ---------------------------------------------------------------------------------------------
class ExceptionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: Literal[
        "SENDER",
        "SENDER_DOMAIN",
        "RECIPIENT",
        "RECIPIENT_GROUP",
        "SOURCE_IP",
        "MESSAGE_ID",
        "CAMPAIGN",
        "CONTROL",
    ]
    control: str | None = None
    value: str = Field(min_length=1, max_length=512)
    reason: str = Field(min_length=5, max_length=1000)
    #: Срок обязателен; по умолчанию 7 дней, не больше 90.
    expires_in_hours: int = Field(default=24 * 7, ge=1, le=24 * 90)
    max_uses: int | None = Field(default=None, ge=1, le=100000)


def _republish(session: DbSession, settings: Any, actor: Actor, note: str) -> str:
    try:
        rec = enforcement.publish(
            session, settings, actor.organization_id, owner=actor.email, justification=note
        )
        return rec.version
    except EnforcementError:
        return ""  # без ключа подписи политика не публикуется; исключение вступит в силу со следующей публикацией


@router.get("/enforcement/exceptions")
def exceptions_list(session: DbSession, actor: EnfReader, active_only: bool = False) -> dict[str, Any]:
    rows = session.execute(
        select(EnforcementExceptionRecord)
        .where(EnforcementExceptionRecord.organization_id == actor.organization_id)
        .order_by(EnforcementExceptionRecord.created_at.desc())
        .limit(200)
    ).scalars()
    items = [enforcement.exception_view(r) for r in rows]
    return {"items": [i for i in items if i["active"]] if active_only else items}


@router.post("/enforcement/exceptions", status_code=status.HTTP_201_CREATED)
def exception_create(
    body: ExceptionBody, session: DbSession, actor: ExceptionCreator, request: Request, settings: AppSettings
) -> dict[str, Any]:
    from ..db.base import utcnow

    try:
        row = enforcement.create_exception(
            session,
            actor.organization_id,
            scope=body.scope,
            control=body.control,
            value=body.value,
            reason=body.reason,
            owner=actor.email,
            expires_at=utcnow() + timedelta(hours=body.expires_in_hours),
            max_uses=body.max_uses,
        )
    except (EnforcementError, ValueError) as exc:
        if isinstance(exc, EnforcementError):
            raise _fail(exc) from exc
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "исключение не принято") from exc
    view = enforcement.exception_view(row)
    version = _republish(session, settings, actor, f"исключение {row.id}") if view["approved"] else ""
    _audit(
        session,
        actor,
        request,
        AuditAction.ENFORCEMENT_EXCEPTION_CREATED,
        "enforcement_exception",
        row.id,
        {
            "scope": row.scope,
            "control": row.control_type,
            "expires_at": row.expires_at.isoformat(),
            "needs_four_eyes": view["needs_four_eyes"],
            "policy_version": version,
        },
    )
    session.commit()
    return {**view, "policy_version": version or None}


def _exception_or_404(session: DbSession, actor: Actor, exception_id: str) -> EnforcementExceptionRecord:
    row = session.get(EnforcementExceptionRecord, exception_id)
    if row is None or row.organization_id != actor.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "исключение не найдено")
    return row


@router.post("/enforcement/exceptions/{exception_id}/approve")
def exception_approve(
    exception_id: str, session: DbSession, actor: ExceptionApprover, request: Request, settings: AppSettings
) -> dict[str, Any]:
    row = _exception_or_404(session, actor, exception_id)
    try:
        enforcement.approve_exception(row, actor_email=actor.email)
    except EnforcementError as exc:
        _audit(
            session,
            actor,
            request,
            AuditAction.ENFORCEMENT_EXCEPTION_APPROVED,
            "enforcement_exception",
            row.id,
            {"refused": str(exc)},
            outcome="denied",
        )
        session.commit()
        raise _fail(exc) from exc
    version = _republish(session, settings, actor, f"согласовано исключение {row.id}")
    _audit(
        session,
        actor,
        request,
        AuditAction.ENFORCEMENT_EXCEPTION_APPROVED,
        "enforcement_exception",
        row.id,
        {"policy_version": version},
    )
    session.commit()
    return {**enforcement.exception_view(row), "policy_version": version or None}


@router.post("/enforcement/exceptions/{exception_id}/revoke")
def exception_revoke(
    exception_id: str, session: DbSession, actor: ExceptionCreator, request: Request, settings: AppSettings
) -> dict[str, Any]:
    from ..db.base import utcnow

    row = _exception_or_404(session, actor, exception_id)
    if row.revoked_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "исключение уже отозвано")
    row.revoked_at = utcnow()
    row.revoked_by = actor.email
    version = _republish(session, settings, actor, f"отозвано исключение {row.id}")
    _audit(
        session,
        actor,
        request,
        AuditAction.ENFORCEMENT_EXCEPTION_REVOKED,
        "enforcement_exception",
        row.id,
        {"policy_version": version},
    )
    session.commit()
    return enforcement.exception_view(row)


# ---------------------------------------------------------------------------------------------
# Инциденты ложных срабатываний
# ---------------------------------------------------------------------------------------------
class IncidentBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    control: str
    title: str = Field(min_length=5, max_length=300)
    impacted: list[str] = Field(default_factory=list, max_length=200)


@router.get("/enforcement/incidents")
def incidents_list(session: DbSession, actor: EnfReader) -> dict[str, Any]:
    rows = session.execute(
        select(EmergencyIncidentRecord)
        .where(EmergencyIncidentRecord.organization_id == actor.organization_id)
        .order_by(EmergencyIncidentRecord.created_at.desc())
        .limit(100)
    ).scalars()
    return {"items": [enforcement.incident_view(r) for r in rows]}


@router.post("/enforcement/incidents", status_code=status.HTTP_201_CREATED)
def incident_open(
    body: IncidentBody, session: DbSession, actor: Pauser, request: Request, settings: AppSettings
) -> dict[str, Any]:
    from msp_enforcement.model import ControlType

    try:
        incident = enforcement.open_incident(
            session,
            settings,
            actor.organization_id,
            control=ControlType(body.control),
            opened_by=actor.email,
            title=body.title,
            impacted=body.impacted,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "неизвестный контроль") from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.ENFORCEMENT_INCIDENT,
        "enforcement_incident",
        incident.id,
        {"opened": True, "control": incident.control_type},
    )
    session.commit()
    return enforcement.incident_view(incident)


class AdvanceBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    to: Literal["CONTAINED", "ROOT_CAUSE_FOUND", "REGRESSION_ADDED", "CLOSED"]
    root_cause: str = ""
    regression_case: str = ""


@router.post("/enforcement/incidents/{incident_id}/advance")
def incident_advance(
    incident_id: str, body: AdvanceBody, session: DbSession, actor: Rollbacker, request: Request
) -> dict[str, Any]:
    row = session.get(EmergencyIncidentRecord, incident_id)
    if row is None or row.organization_id != actor.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "инцидент не найден")
    try:
        enforcement.advance_incident(
            row,
            to=IncidentState(body.to),
            actor_email=actor.email,
            root_cause=body.root_cause,
            regression_case=body.regression_case,
        )
    except EnforcementError as exc:
        raise _fail(exc) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.ENFORCEMENT_INCIDENT,
        "enforcement_incident",
        row.id,
        {"state": row.state.value},
    )
    session.commit()
    return enforcement.incident_view(row)


# ---------------------------------------------------------------------------------------------
# Карантин (консоль)
# ---------------------------------------------------------------------------------------------
def _quarantine_item(session: DbSession, actor: Actor, item_id: str) -> Any:
    try:
        return quarantine.get_item(session, actor.organization_id, item_id)
    except EnforcementError as exc:
        raise _fail(exc) from exc


@router.get("/quarantine")
def quarantine_list(
    session: DbSession,
    actor: QuarantineReader,
    state: str | None = None,
    q: Annotated[str, Query(max_length=100)] = "",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100000)] = 0,
) -> dict[str, Any]:
    try:
        rows, total = quarantine.list_items(
            session, actor.organization_id, state=state, q=q, limit=limit, offset=offset
        )
    except EnforcementError as exc:
        raise _fail(exc) from exc
    return {
        "items": [quarantine.item_view(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
        "counts": quarantine.counts(session, actor.organization_id),
    }


@router.get("/quarantine/{item_id}")
def quarantine_get(
    item_id: str, session: DbSession, actor: QuarantineReader, request: Request
) -> dict[str, Any]:
    row = _quarantine_item(session, actor, item_id)
    _audit(session, actor, request, AuditAction.QUARANTINE_VIEWED, "quarantine_item", row.id)
    session.commit()
    return quarantine.item_view(row)


@router.get("/quarantine/{item_id}/preview")
def quarantine_preview(
    item_id: str, session: DbSession, actor: QuarantineReader, request: Request, settings: AppSettings
) -> dict[str, Any]:
    row = _quarantine_item(session, actor, item_id)
    try:
        data = quarantine.preview(settings, build_storage(settings), row)
    except EnforcementError as exc:
        raise _fail(exc) from exc
    _audit(
        session, actor, request, AuditAction.QUARANTINE_VIEWED, "quarantine_item", row.id, {"preview": True}
    )
    session.commit()
    return data


class ReleaseBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["request", "approve", "cancel"] = "request"
    reason: str = Field(default="", max_length=500)


@router.post("/quarantine/{item_id}/release")
def quarantine_release(
    item_id: str, body: ReleaseBody, session: DbSession, actor: QuarantineReleaser, request: Request
) -> dict[str, Any]:
    row = _quarantine_item(session, actor, item_id)
    try:
        if body.action == "request":
            quarantine.request_release(row, actor_email=actor.email)
            action = AuditAction.QUARANTINE_RELEASE_REQUESTED
        elif body.action == "approve":
            quarantine.approve_release(row, actor_email=actor.email)
            action = AuditAction.QUARANTINE_RELEASE_REQUESTED
        else:
            quarantine.cancel_release(row)
            action = AuditAction.QUARANTINE_RELEASE_REQUESTED
    except EnforcementError as exc:
        _audit(
            session,
            actor,
            request,
            AuditAction.QUARANTINE_RELEASE_REQUESTED,
            "quarantine_item",
            row.id,
            {"refused": str(exc), "action": body.action},
            outcome="denied",
        )
        session.commit()
        raise _fail(exc) from exc
    _audit(
        session,
        actor,
        request,
        action,
        "quarantine_item",
        row.id,
        {
            "action": body.action,
            "needs_approval": quarantine.needs_approval(row),
            "reason": body.reason,
            "approved": bool(row.release_approved_by),
        },
    )
    session.commit()
    return quarantine.item_view(row)


@router.post("/quarantine/{item_id}/delete")
def quarantine_delete(
    item_id: str,
    body: ReasonBody,
    session: DbSession,
    actor: QuarantineDeleter,
    request: Request,
    settings: AppSettings,
) -> dict[str, Any]:
    row = _quarantine_item(session, actor, item_id)
    try:
        quarantine.delete_item(build_storage(settings), row, actor_email=actor.email)
    except EnforcementError as exc:
        raise _fail(exc) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.QUARANTINE_DELETED,
        "quarantine_item",
        row.id,
        {"reason": body.reason},
    )
    session.commit()
    return quarantine.item_view(row)


# ---------------------------------------------------------------------------------------------
# Точки для узлов (область enforcement-policy)
# ---------------------------------------------------------------------------------------------
@agent_router.get("/enforcement/policy")
def agent_policy(session: DbSession, settings: AppSettings, _auth: PolicyAuth) -> dict[str, Any]:
    org = _organization(session)
    payload = enforcement.node_policy_payload(session, settings, org.id)
    session.commit()
    return payload


@agent_router.get("/enforcement/state")
def agent_state(session: DbSession, _auth: PolicyAuth) -> dict[str, Any]:
    """Лёгкий опрос: общий выключатель и контрольная сумма текущей политики."""
    org = _organization(session)
    switch = enforcement.switch_row(session, org.id)
    current = enforcement.current_policy(session, org.id)
    return {
        "kill_switch": bool(switch.kill_switch),
        "checksum": current.checksum if current else "",
        "policy_version": current.version if current else "",
        "server_time": enforcement.now().isoformat(),
    }


class DecisionsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    node_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    decisions: list[dict[str, Any]] = Field(max_length=500)


@agent_router.post("/enforcement/decisions")
def agent_decisions(body: DecisionsBody, session: DbSession, _auth: PolicyAuth) -> dict[str, Any]:
    org = _organization(session)
    outcome = enforcement.ingest_decisions(session, org.id, body.node_id, body.decisions)
    applied = [
        d
        for d in body.decisions
        if d.get("applied_action") in ("SMTP_REJECT", "SMTP_TEMPFAIL", "QUARANTINED", "HELD")
    ]
    for item in applied[:200]:
        record(
            session,
            action=AuditAction.ENFORCEMENT_DECISION_APPLIED,
            actor_email=f"node:{body.node_id}",
            organization_id=org.id,
            object_type="enforcement_decision",
            object_id=str(item.get("transport_message_id", ""))[:64],
            detail={
                "control": item.get("control_type"),
                "decision": item.get("decision"),
                "applied": item.get("applied_action"),
                "policy_version": item.get("policy_version"),
                "evidence_ids": list(item.get("evidence_ids") or [])[:5],
            },
        )
    session.commit()
    return outcome


class NodeStateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    node_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    state: dict[str, Any]


@agent_router.post("/enforcement/state")
def agent_node_state(body: NodeStateBody, session: DbSession, _auth: PolicyAuth) -> dict[str, Any]:
    org = _organization(session)
    bypass_started = enforcement.note_node_state(session, org.id, body.node_id, body.state)
    if bypass_started:
        record(
            session,
            action=AuditAction.ENFORCEMENT_LOCAL_BYPASS,
            actor_email=f"node:{body.node_id}",
            organization_id=org.id,
            object_type="transport_node",
            object_id=body.node_id,
            detail={"local_bypass": True},
        )
    session.commit()
    return {"ok": True}


class QuarantineStoreBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    node_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    transport_message_id: str = Field(min_length=1, max_length=64)
    internet_message_id: str = Field(default="", max_length=998)
    decision_ref: str = Field(default="", max_length=64)
    sender: str = Field(default="", max_length=320)
    recipients: list[str] = Field(default_factory=list, max_length=100)
    subject: str = Field(default="", max_length=998)
    reason_codes: list[str] = Field(default_factory=list, max_length=30)
    policy_version: str = Field(default="", max_length=64)
    original_route: str = Field(default="", max_length=255)
    raw_b64: str = Field(min_length=4)


@agent_router.post("/quarantine")
def agent_quarantine_store(
    body: QuarantineStoreBody, session: DbSession, settings: AppSettings, _auth: PolicyAuth
) -> dict[str, Any]:
    org = _organization(session)
    try:
        raw = base64.b64decode(body.raw_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "письмо не в base64") from exc
    try:
        item, already_released = quarantine.store(
            session,
            settings,
            build_storage(settings),
            org.id,
            node_id=body.node_id,
            transport_message_id=body.transport_message_id,
            internet_message_id=body.internet_message_id,
            decision_ref=body.decision_ref,
            sender=body.sender,
            recipients=body.recipients,
            subject=body.subject,
            reason_codes=body.reason_codes,
            policy_version=body.policy_version,
            raw=raw,
            original_route=body.original_route,
        )
    except EnforcementError as exc:
        raise _fail(exc) from exc
    if not already_released:
        record(
            session,
            action=AuditAction.QUARANTINE_STORED,
            actor_email=f"node:{body.node_id}",
            organization_id=org.id,
            object_type="quarantine_item",
            object_id=item.id,
            detail={
                "reasons": body.reason_codes[:10],
                "policy_version": body.policy_version,
                "size_bytes": item.size_bytes,
            },
        )
    session.commit()
    return {"id": item.id, "already_released": already_released, "state": item.state.value}


@agent_router.get("/quarantine/releases")
def agent_quarantine_releases(
    node_id: Annotated[str, Query(pattern=r"^[0-9a-f]{32}$")],
    session: DbSession,
    settings: AppSettings,
    _auth: PolicyAuth,
) -> dict[str, Any]:
    org = _organization(session)
    items = quarantine.pending_for_node(session, settings, org.id, node_id)
    session.commit()
    return {"items": items}


def _node_item(session: DbSession, item_id: str) -> Any:
    org = _organization(session)
    try:
        return quarantine.get_item(session, org.id, item_id), org
    except EnforcementError as exc:
        raise _fail(exc) from exc


@agent_router.get("/quarantine/{item_id}/content")
def agent_quarantine_content(
    item_id: str,
    token: Annotated[str, Query(min_length=16, max_length=128)],
    session: DbSession,
    settings: AppSettings,
    _auth: PolicyAuth,
) -> dict[str, Any]:
    row, _ = _node_item(session, item_id)
    try:
        raw = quarantine.content_for_release(settings, build_storage(settings), row, token)
    except EnforcementError as exc:
        raise _fail(exc) from exc
    return {"raw_b64": base64.b64encode(raw).decode(), "sha256": row.content_sha256}


class ConfirmBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=16, max_length=128)
    delivered: bool
    error: str = Field(default="", max_length=300)


@agent_router.post("/quarantine/{item_id}/confirm")
def agent_quarantine_confirm(
    item_id: str, body: ConfirmBody, session: DbSession, _auth: PolicyAuth
) -> dict[str, Any]:
    row, org = _node_item(session, item_id)
    try:
        quarantine.confirm_release(row, body.token, delivered=body.delivered, error=body.error)
    except EnforcementError as exc:
        raise _fail(exc) from exc
    if body.delivered:
        record(
            session,
            action=AuditAction.QUARANTINE_RELEASED,
            actor_email=row.released_by or "node",
            organization_id=org.id,
            object_type="quarantine_item",
            object_id=row.id,
            detail={
                "delivered": True,
                "requested_by": row.release_requested_by,
                "approved_by": row.release_approved_by,
            },
        )
    session.commit()
    return {"state": row.state.value, "delivered_count": row.delivered_count}


__all__ = ["agent_router", "router"]
