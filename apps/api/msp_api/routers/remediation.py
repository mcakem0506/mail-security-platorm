"""Controlled Exchange remediation (ТЗ 20, 43.7-43.8, 49.10).

Invariants enforced here, not by convention:
* every action starts as a proposal with a dry-run report — nothing executes on proposal;
* the proposer can never approve their own request;
* bulk operations (above the configured mailbox threshold) require two distinct approvers;
* execution is refused entirely while the deployment is in dry-run-only mode;
* every transition is audited.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from msp_contracts import RemediationState, RemediationType
from msp_exchange import ExchangeMessageRef, MockExchangeProvider, RemediationRequest
from sqlalchemy import desc, func, select

from ..db.base import utcnow
from ..db.models import (
    Approval,
    Campaign,
    CampaignMessage,
    Incident,
    MailMessage,
    MailRecipient,
    RemediationAction,
)
from ..deps import Actor, AppSettings, DbSession, client_ip, require_permission
from ..observability import remediation_actions
from ..schemas import ApprovalRequest, PaginatedResponse, RemediationOut, RemediationProposeRequest
from ..security.audit import AuditAction, record
from ..security.rbac import Permission, can_approve, required_approvals

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/remediation", tags=["remediation"])

Proposer = Annotated[Actor, Depends(require_permission(Permission.PROPOSE_REMEDIATION))]
Approver = Annotated[Actor, Depends(require_permission(Permission.APPROVE_REMEDIATION))]

_DESTRUCTIVE = {RemediationType.DELETE, RemediationType.QUARANTINE}


def _exchange_provider(settings):  # type: ignore[no-untyped-def]
    """Only the mock provider is wired in v1; EWS requires the environment inventory (ТЗ 51)."""
    if settings.exchange_provider == "ews":
        from msp_exchange import EwsConfig, OnPremEwsExchangeProvider

        return OnPremEwsExchangeProvider(
            EwsConfig(
                endpoint=settings.ews_endpoint,
                username=settings.ews_username,
                password=settings.ews_password,
                ca_file=settings.ews_ca_file,
                remediation_account_enabled=settings.remediation_enabled,
            )
        )
    return MockExchangeProvider(remediation_enabled=settings.remediation_enabled)


def _resolve_targets(session, actor: Actor, payload: RemediationProposeRequest) -> list[MailMessage]:  # type: ignore[no-untyped-def]
    messages: list[MailMessage] = []
    ids = list(payload.message_ids)
    if payload.campaign_id:
        campaign = session.get(Campaign, payload.campaign_id)
        if campaign is None or campaign.organization_id != actor.organization_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Кампания не найдена")
        ids.extend(
            session.execute(
                select(CampaignMessage.message_id).where(CampaignMessage.campaign_id == campaign.id)
            ).scalars().all()
        )
    for message_id in dict.fromkeys(ids):
        message = session.get(MailMessage, message_id)
        if message is not None and message.organization_id == actor.organization_id:
            messages.append(message)
    return messages


def _out(session, action: RemediationAction) -> RemediationOut:  # type: ignore[no-untyped-def]
    approvals = session.execute(
        select(Approval).where(Approval.action_id == action.id).order_by(Approval.decided_at)
    ).scalars().all()
    return RemediationOut(
        action_id=action.id,
        action_type=action.action_type,
        state=action.state,
        proposed_by=action.proposed_by,
        reason=action.reason,
        affected_message_count=action.affected_message_count,
        affected_mailboxes=list(action.affected_mailboxes or []),
        required_approvals=action.required_approvals,
        approvals=[
            {
                "approver": a.approver_email,
                "decision": a.decision,
                "comment": a.comment,
                "decided_at": a.decided_at.isoformat(),
            }
            for a in approvals
        ],
        dry_run_report=dict(action.dry_run_report or {}),
        rollback_supported=action.rollback_supported,
        executed_at=action.executed_at,
        executed_by=action.executed_by,
        result=dict(action.result or {}),
        created_at=action.created_at,
    )


@router.post("", response_model=RemediationOut, status_code=status.HTTP_201_CREATED)
def propose(
    payload: RemediationProposeRequest,
    request: Request,
    actor: Proposer,
    session: DbSession,
    settings: AppSettings,
) -> RemediationOut:
    """Propose a remediation action and produce its dry-run impact report (ТЗ 20.2)."""
    messages = _resolve_targets(session, actor, payload)
    if not messages and payload.action_type not in {
        RemediationType.BLOCK_SENDER,
        RemediationType.BLOCK_DOMAIN,
        RemediationType.TRANSPORT_RULE_PROPOSAL,
    }:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Не выбрано ни одного сообщения"
        )

    mailboxes: set[str] = set()
    for message in messages:
        mailboxes.update(
            session.execute(
                select(MailRecipient.address).where(MailRecipient.message_id == message.id)
            ).scalars().all()
        )
        if message.source_mailbox:
            mailboxes.add(message.source_mailbox)

    idempotency_source = "|".join(
        [
            actor.organization_id,
            payload.action_type.value,
            ",".join(sorted(m.id for m in messages)),
            payload.sender or "",
            payload.domain or "",
        ]
    )
    idempotency_key = hashlib.sha256(idempotency_source.encode("utf-8")).hexdigest()
    existing = session.execute(
        select(RemediationAction).where(RemediationAction.idempotency_key == idempotency_key)
    ).scalar_one_or_none()
    if existing is not None and existing.state in {RemediationState.PROPOSED, RemediationState.APPROVED}:
        return _out(session, existing)

    provider = _exchange_provider(settings)
    dry_run = provider.request_remediation(
        RemediationRequest(
            action=payload.action_type,
            targets=[
                ExchangeMessageRef(
                    mailbox=m.source_mailbox or "",
                    message_id=m.internet_message_id,
                    item_id=m.exchange_item_id,
                    subject=m.subject,
                    sender=m.sender_address,
                )
                for m in messages
            ],
            reason=payload.reason,
            requested_by=actor.email,
            dry_run=True,
            sender=payload.sender or "",
            domain=payload.domain or "",
        )
    )

    action = RemediationAction(
        organization_id=actor.organization_id,
        incident_id=payload.incident_id,
        campaign_id=payload.campaign_id,
        action_type=payload.action_type,
        state=RemediationState.PROPOSED,
        proposed_by=actor.email,
        reason=payload.reason,
        target_selector={
            "message_ids": [m.id for m in messages][:1000],
            "sender": payload.sender,
            "domain": payload.domain,
        },
        affected_message_count=len(messages),
        affected_mailboxes=sorted(mailboxes)[:500],
        required_approvals=required_approvals(
            len(mailboxes), settings.remediation_second_approver_threshold
        ),
        rollback_supported=dry_run.rollback_supported,
        dry_run_report={
            "affected_messages": dry_run.affected_messages,
            "affected_mailboxes": dry_run.affected_mailboxes,
            "rollback_supported": dry_run.rollback_supported,
            "warnings": dry_run.warnings,
            "errors": dry_run.errors,
            "provider": getattr(provider, "provider_id", "unknown"),
            "destructive": payload.action_type in _DESTRUCTIVE,
        },
        idempotency_key=idempotency_key,
    )
    session.add(action)
    session.flush()

    remediation_actions.labels(action.action_type.value, action.state.value).inc()
    record(
        session,
        action=AuditAction.REMEDIATION_PROPOSED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="remediation_action",
        object_id=action.id,
        detail={
            "action_type": action.action_type.value,
            "messages": action.affected_message_count,
            "mailboxes": len(mailboxes),
            "required_approvals": action.required_approvals,
            "reason": payload.reason,
        },
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return _out(session, action)


@router.post("/{action_id}/approve", response_model=RemediationOut)
def approve(
    action_id: str,
    payload: ApprovalRequest,
    request: Request,
    actor: Approver,
    session: DbSession,
) -> RemediationOut:
    action = session.get(RemediationAction, action_id)
    if action is None or action.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Запрос не найден")
    if action.state not in {RemediationState.PROPOSED, RemediationState.APPROVED}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Запрос в состоянии {action.state.value} не может быть согласован",
        )

    approvals = session.execute(
        select(Approval).where(Approval.action_id == action.id)
    ).scalars().all()
    allowed, reason = can_approve(
        role=actor.role,
        approver_id=actor.user_id,
        proposer_id=_proposer_user_id(session, action),
        existing_approvers={a.approver_id for a in approvals},
    )
    if not allowed:
        record(
            session,
            action=AuditAction.REMEDIATION_APPROVED,
            actor_id=actor.user_id,
            actor_email=actor.email,
            actor_role=actor.role.value,
            organization_id=actor.organization_id,
            object_type="remediation_action",
            object_id=action.id,
            outcome="denied",
            detail={"reason": reason},
            ip_address=client_ip(request),
            request_id=getattr(request.state, "request_id", ""),
        )
        session.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)

    session.add(
        Approval(
            action_id=action.id,
            approver_id=actor.user_id,
            approver_email=actor.email,
            decision=payload.decision,
            comment=payload.comment,
        )
    )
    session.flush()

    if payload.decision == "rejected":
        action.state = RemediationState.REJECTED
        audit_action = AuditAction.REMEDIATION_REJECTED
    else:
        approved_count = (
            session.execute(
                select(func.count())
                .select_from(Approval)
                .where(Approval.action_id == action.id, Approval.decision == "approved")
            ).scalar_one()
        )
        if int(approved_count) >= action.required_approvals:
            action.state = RemediationState.APPROVED
        audit_action = AuditAction.REMEDIATION_APPROVED

    remediation_actions.labels(action.action_type.value, action.state.value).inc()
    record(
        session,
        action=audit_action,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="remediation_action",
        object_id=action.id,
        detail={"decision": payload.decision, "state": action.state.value},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return _out(session, action)


def _proposer_user_id(session, action: RemediationAction) -> str:  # type: ignore[no-untyped-def]
    from ..db.models import User

    user = session.execute(
        select(User).where(func.lower(User.email) == (action.proposed_by or "").lower())
    ).scalar_one_or_none()
    return user.id if user is not None else ""


@router.post("/{action_id}/execute", response_model=RemediationOut)
def execute(
    action_id: str,
    request: Request,
    actor: Annotated[Actor, Depends(require_permission(Permission.EXECUTE_REMEDIATION))],
    session: DbSession,
    settings: AppSettings,
    confirm: Annotated[bool, Query()] = False,
) -> RemediationOut:
    """Execute an approved action. Refused while the deployment is dry-run-only (ТЗ 2.5)."""
    action = session.get(RemediationAction, action_id)
    if action is None or action.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Запрос не найден")
    if action.state is not RemediationState.APPROVED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Выполнение возможно только после получения необходимых согласований",
        )
    if not confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Требуется явное подтверждение выполнения (confirm=true)",
        )
    if settings.remediation_dry_run_only or not settings.remediation_enabled:
        record(
            session,
            action=AuditAction.REMEDIATION_FAILED,
            actor_id=actor.user_id,
            actor_email=actor.email,
            actor_role=actor.role.value,
            organization_id=actor.organization_id,
            object_type="remediation_action",
            object_id=action.id,
            outcome="blocked",
            detail={"reason": "deployment is in dry-run-only mode"},
            ip_address=client_ip(request),
            request_id=getattr(request.state, "request_id", ""),
        )
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Выполнение действий в Exchange отключено в этой конфигурации "
                "(режим dry-run). Действие остаётся согласованным предложением."
            ),
        )

    provider = _exchange_provider(settings)
    message_ids = list((action.target_selector or {}).get("message_ids", []))
    targets = []
    for message_id in message_ids:
        message = session.get(MailMessage, message_id)
        if message is not None:
            targets.append(
                ExchangeMessageRef(
                    mailbox=message.source_mailbox or "",
                    message_id=message.internet_message_id,
                    item_id=message.exchange_item_id,
                )
            )
    approvers = session.execute(
        select(Approval.approver_email).where(
            Approval.action_id == action.id, Approval.decision == "approved"
        )
    ).scalars().all()

    outcome = provider.request_remediation(
        RemediationRequest(
            action=action.action_type,
            targets=targets,
            reason=action.reason,
            requested_by=action.proposed_by,
            approved_by=list(approvers),
            dry_run=False,
            sender=(action.target_selector or {}).get("sender") or "",
            domain=(action.target_selector or {}).get("domain") or "",
        )
    )
    action.state = RemediationState.EXECUTED if outcome.executed else RemediationState.FAILED
    action.executed_at = utcnow()
    action.executed_by = actor.email
    action.rollback_token = outcome.rollback_token
    action.result = {
        "executed": outcome.executed,
        "affected_messages": outcome.affected_messages,
        "affected_mailboxes": outcome.affected_mailboxes,
        "warnings": outcome.warnings,
        "errors": outcome.errors,
    }
    if action.incident_id:
        incident = session.get(Incident, action.incident_id)
        if incident is not None and outcome.executed:
            incident.remediated_at = utcnow()

    remediation_actions.labels(action.action_type.value, action.state.value).inc()
    record(
        session,
        action=AuditAction.REMEDIATION_EXECUTED if outcome.executed else AuditAction.REMEDIATION_FAILED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="remediation_action",
        object_id=action.id,
        outcome="success" if outcome.executed else "failure",
        detail=action.result,
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return _out(session, action)


@router.get("", response_model=PaginatedResponse)
def list_actions(
    actor: Annotated[Actor, Depends(require_permission(Permission.VIEW_INCIDENTS))],
    session: DbSession,
    state: RemediationState | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> PaginatedResponse:
    query = select(RemediationAction).where(RemediationAction.organization_id == actor.organization_id)
    if state is not None:
        query = query.where(RemediationAction.state == state)
    total = session.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    rows = session.execute(
        query.order_by(desc(RemediationAction.created_at)).limit(limit).offset(offset)
    ).scalars().all()
    return PaginatedResponse(
        total=int(total), limit=limit, offset=offset, items=[_out(session, a) for a in rows]
    )


@router.get("/{action_id}", response_model=RemediationOut)
def get_action(
    action_id: str,
    actor: Annotated[Actor, Depends(require_permission(Permission.VIEW_INCIDENTS))],
    session: DbSession,
) -> RemediationOut:
    action = session.get(RemediationAction, action_id)
    if action is None or action.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Запрос не найден")
    return _out(session, action)
