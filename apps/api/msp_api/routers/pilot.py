"""API пилота реального потока (MSP 1.3P, ТЗ 1.3P §24).

Точки только читают и записывают подтверждения, решения и остановки пилота. Ни одна не включает контроль
принуждения,
не меняет DNS, MX или Exchange: переключение SMTP-контролей остаётся на защищённых точках этапа 1.3.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from ..deps import Actor, AppSettings, DbSession, client_ip, require_permission
from ..security.audit import AuditAction, record
from ..security.rbac import Permission
from ..services import pilot
from ..services.pilot import PilotError

router = APIRouter(prefix="/pilot", tags=["pilot"])

PilotReader = Annotated[Actor, Depends(require_permission(Permission.VIEW_PILOT))]
PilotManager = Annotated[Actor, Depends(require_permission(Permission.MANAGE_PILOT))]
PilotApprover = Annotated[Actor, Depends(require_permission(Permission.APPROVE_PILOT))]


class AttestationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = Field(max_length=20)
    evidence_ref: str = Field(default="", max_length=500)
    note: str = Field(default="", max_length=1000)


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    outcome: str = Field(max_length=8)
    reasons: list[str] = Field(min_length=1, max_length=20)
    controls: list[str] = Field(default_factory=list, max_length=8)
    risk_accept: str = Field(default="", max_length=4000)


class ApprovalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str = Field(max_length=24)


class StopIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason_code: str = Field(max_length=48)
    description: str = Field(default="", max_length=2000)
    control_type: str = Field(default="", max_length=24)


class ResolveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rca_ref: str = Field(max_length=500)
    regression_ref: str = Field(max_length=500)


def _fail(exc: PilotError) -> HTTPException:
    detail: Any = str(exc) if exc.detail is None else {"message": str(exc), **dict(exc.detail)}
    return HTTPException(exc.status, detail)


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


@router.get("/readiness")
def pilot_readiness(session: DbSession, actor: PilotReader, settings: AppSettings) -> dict[str, Any]:
    """Условия каждой фазы, готовность каждого контроля и итог. Нулевая выборка — всегда ``NOT_READY``."""
    return pilot.readiness(session, settings, actor.organization_id)


@router.get("/metrics")
def pilot_metrics(session: DbSession, actor: PilotReader, settings: AppSettings) -> dict[str, Any]:
    """Реальные, синтетические и импортированные данные раздельно; нет знаменателя — ``null``."""
    return pilot.metrics(session, settings, actor.organization_id)


@router.get("/phases/{phase}/gate")
def phase_gate(
    phase: str,
    session: DbSession,
    actor: PilotReader,
    settings: AppSettings,
    controls: Annotated[list[str] | None, Query(max_length=8)] = None,
) -> dict[str, Any]:
    try:
        return pilot.gate(
            session, settings, actor.organization_id, pilot.parse_phase(phase), controls=controls or []
        )
    except PilotError as exc:
        raise _fail(exc) from exc


@router.get("/attestations")
def attestations(session: DbSession, actor: PilotReader) -> dict[str, Any]:
    latest = pilot.latest_attestations(session, actor.organization_id)
    return {"items": [pilot.attestation_view(latest.get(k), s) for k, s in pilot.ATTESTATIONS.items()]}


@router.post("/attestations/{key}")
def record_attestation(
    key: str, body: AttestationIn, request: Request, session: DbSession, actor: PilotManager
) -> dict[str, Any]:
    try:
        row = pilot.record_attestation(
            session,
            actor.organization_id,
            key=key,
            status=body.status,
            evidence_ref=body.evidence_ref,
            note=body.note,
            actor_email=actor.email,
        )
    except PilotError as exc:
        raise _fail(exc) from exc
    # В аудит идут ключ и статус; сам документ-доказательство не сохраняется.
    _audit(
        session,
        actor,
        request,
        AuditAction.PILOT_ATTESTATION,
        "pilot_attestation",
        row.id,
        {"key": key, "status": body.status},
    )
    session.commit()
    return pilot.attestation_view(row, pilot.ATTESTATIONS[key])


@router.get("/decisions")
def decisions(
    session: DbSession, actor: PilotReader, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> dict[str, Any]:
    rows = pilot.list_decisions(session, actor.organization_id)[-limit:]
    return {"items": [pilot.decision_view(r) for r in rows]}


@router.post("/phases/{phase}/decision")
def propose_decision(
    phase: str,
    body: DecisionIn,
    request: Request,
    session: DbSession,
    actor: PilotManager,
    settings: AppSettings,
) -> dict[str, Any]:
    """Предложить решение о входе в фазу. GO вступает в силу после подтверждений нужных ролей."""
    try:
        row = pilot.propose_decision(
            session,
            settings,
            actor.organization_id,
            phase=phase,
            outcome=body.outcome,
            reasons=body.reasons,
            controls=body.controls,
            risk_accept=body.risk_accept,
            actor_email=actor.email,
        )
    except PilotError as exc:
        _audit(
            session,
            actor,
            request,
            AuditAction.PILOT_DECISION_REFUSED,
            "pilot_phase",
            phase,
            {"outcome": body.outcome, "controls": body.controls, "error": str(exc)},
            outcome="denied",
        )
        session.commit()
        raise _fail(exc) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.PILOT_DECISION_PROPOSED,
        "pilot_decision",
        row.id,
        {"phase": row.phase, "outcome": row.outcome, "controls": body.controls},
    )
    session.commit()
    return pilot.decision_view(row)


@router.post("/decisions/{decision_id}/approve")
def approve_decision(
    decision_id: str,
    body: ApprovalIn,
    request: Request,
    session: DbSession,
    actor: PilotApprover,
    settings: AppSettings,
) -> dict[str, Any]:
    try:
        row = pilot.approve_decision(
            session,
            settings,
            actor.organization_id,
            decision_id=decision_id,
            role=body.role,
            actor_email=actor.email,
        )
    except PilotError as exc:
        _audit(
            session,
            actor,
            request,
            AuditAction.PILOT_DECISION_REFUSED,
            "pilot_decision",
            decision_id,
            {"role": body.role, "error": str(exc)},
            outcome="denied",
        )
        session.commit()
        raise _fail(exc) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.PILOT_DECISION_APPROVED,
        "pilot_decision",
        row.id,
        {"phase": row.phase, "role": body.role, "state": row.state},
    )
    session.commit()
    return pilot.decision_view(row)


@router.get("/stops")
def stops(session: DbSession, actor: PilotReader) -> dict[str, Any]:
    return {"items": [pilot.stop_view(s) for s in pilot.list_stops(session, actor.organization_id)]}


@router.post("/stop")
def open_stop(body: StopIn, request: Request, session: DbSession, actor: PilotManager) -> dict[str, Any]:
    """Записать аварийную остановку. SMTP-контроли запись не переключает — см. ``next_actions``."""
    try:
        row = pilot.open_stop(
            session,
            actor.organization_id,
            reason_code=body.reason_code,
            description=body.description,
            control_type=body.control_type,
            actor_email=actor.email,
        )
    except PilotError as exc:
        raise _fail(exc) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.PILOT_STOP_OPENED,
        "pilot_stop",
        row.id,
        {"reason": body.reason_code, "control": body.control_type},
    )
    session.commit()
    return pilot.stop_view(row)


@router.post("/stops/{stop_id}/resolve")
def resolve_stop(
    stop_id: str, body: ResolveIn, request: Request, session: DbSession, actor: PilotApprover
) -> dict[str, Any]:
    try:
        row = pilot.resolve_stop(
            session,
            actor.organization_id,
            stop_id=stop_id,
            rca_ref=body.rca_ref,
            regression_ref=body.regression_ref,
            actor_email=actor.email,
        )
    except PilotError as exc:
        raise _fail(exc) from exc
    _audit(session, actor, request, AuditAction.PILOT_STOP_RESOLVED, "pilot_stop", row.id, {})
    session.commit()
    return pilot.stop_view(row)


@router.get("/evidence")
def evidence(
    request: Request, session: DbSession, actor: PilotReader, settings: AppSettings
) -> dict[str, Any]:
    """Выгрузка доказательств: агрегаты, критерии и решения. Без тел писем и персональных данных."""
    data = pilot.evidence_export(session, settings, actor.organization_id)
    _audit(session, actor, request, AuditAction.PILOT_EVIDENCE_EXPORTED, "pilot_evidence", "export", {})
    session.commit()
    return data
