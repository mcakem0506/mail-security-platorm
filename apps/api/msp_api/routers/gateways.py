"""Mail gateway administration and evidence (ТЗ 1.0.2 §24, §25, §28, §33).

Two audiences:

* an **analyst** looking at one message wants the Upstream Protection card — what each gateway
  said, whether it can be believed, and where it disagrees with the platform;
* an **administrator** in Settings → Mail Gateways wants to register a gateway, describe the
  hops that prove a message passed it, and see what each one is actually capable of.

Every mutation is audited, and none of them accepts a credential value: a gateway API
credential is referenced by where it is stored, never by what it is (ТЗ 28).
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from msp_contracts import GatewayCapability, GatewayDirection
from msp_mail_gateway import PROVIDER_TYPES, skeleton_summary
from sqlalchemy import select

from ..db.models import (
    GatewayCapabilityState,
    GatewayConflict,
    GatewayEvidenceRecord,
    MailGateway,
    MailGatewayNode,
    MailMessage,
    SyslogDeadLetter,
    TrustedHop,
)
from ..deps import Actor, AppSettings, DbSession, client_ip, require_permission
from ..schemas import (
    GatewayConflictOut,
    GatewayEvidenceOut,
    GatewayOut,
    GatewayUpsertRequest,
    TrustedHopOut,
    TrustedHopUpsertRequest,
    UpstreamProtectionResponse,
)
from ..security.audit import AuditAction, record
from ..security.rbac import Permission
from ..services.gateways import build_registry, refresh_capabilities

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/gateways", tags=["mail gateways"])

# Reading gateway evidence is part of an investigation; changing the trust topology decides
# which headers the platform believes, so it needs the policy permission.
Viewer = Annotated[Actor, Depends(require_permission(Permission.VIEW_INVESTIGATIONS))]
PolicyAdmin = Annotated[Actor, Depends(require_permission(Permission.MANAGE_POLICIES))]


def _gateway_out(session: Any, gateway: MailGateway) -> GatewayOut:
    capabilities = (
        session.execute(select(GatewayCapabilityState).where(GatewayCapabilityState.gateway_id == gateway.id))
        .scalars()
        .all()
    )
    hops = session.execute(select(TrustedHop).where(TrustedHop.gateway_id == gateway.id)).scalars().all()
    nodes = (
        session.execute(select(MailGatewayNode).where(MailGatewayNode.gateway_id == gateway.id))
        .scalars()
        .all()
    )
    return GatewayOut(
        gateway_id=gateway.id,
        provider_id=gateway.provider_id,
        provider_type=gateway.provider_type,
        display_name=gateway.display_name or gateway.provider_id,
        vendor=gateway.vendor,
        direction=gateway.direction,
        enabled=gateway.enabled,
        # Settings hold header mappings and syslog sources — never a secret value.
        settings=dict(gateway.settings or {}),
        capabilities=sorted(c.capability for c in capabilities if c.available),
        trusted_hops=[_hop_out(h) for h in hops],
        nodes=[
            {"hostname": n.hostname, "ip_networks": list(n.ip_networks or []), "role": n.role} for n in nodes
        ],
        last_event_at=gateway.last_event_at,
        last_error=gateway.last_error,
        last_error_at=gateway.last_error_at,
    )


def _hop_out(hop: TrustedHop) -> TrustedHopOut:
    return TrustedHopOut(
        hop_id=hop.id,
        hop_type=hop.hop_type,
        hostname=hop.hostname,
        ip_networks=list(hop.ip_networks or []),
        expected_headers=list(hop.expected_headers or []),
        authserv_ids=list(hop.authserv_ids or []),
        position_in_chain=hop.position_in_chain,
        direction=hop.direction,
        enabled=hop.enabled,
        gateway_id=hop.gateway_id,
    )


# ---------------------------------------------------------------------------------------------
# Settings → Mail Gateways (ТЗ 1.0.2 §25)
# ---------------------------------------------------------------------------------------------
@router.get("", response_model=dict)
def list_gateways(actor: Viewer, session: DbSession, settings: AppSettings) -> dict[str, Any]:
    """Configured gateways, their health and what they can do.

    An empty list is a valid answer, not an error: ``state`` is ``NOT_PRESENT`` and the platform
    works exactly the same without any gateway (ТЗ 1.0.2 §31).
    """
    gateways = (
        session.execute(
            select(MailGateway)
            .where(MailGateway.organization_id == actor.organization_id)
            .order_by(MailGateway.created_at)
        )
        .scalars()
        .all()
    )
    registry = build_registry(session, settings, actor.organization_id)
    health = {h.provider_id: h.model_dump(mode="json") for h in registry.health()}
    return {
        "state": registry.state().value,
        "gateways": [
            {
                **_gateway_out(session, gateway).model_dump(mode="json"),
                "health": health.get(gateway.provider_id),
            }
            for gateway in gateways
        ],
        "supported_provider_types": sorted(PROVIDER_TYPES),
        # Vendors whose header format is implemented but whose API is not yet (ТЗ 1.0.2 §36).
        "available_skeletons": skeleton_summary(),
        "syslog_enabled": settings.gateway_syslog_enabled,
    }


@router.post("", response_model=GatewayOut, status_code=201)
def create_gateway(
    payload: GatewayUpsertRequest,
    request: Request,
    actor: PolicyAdmin,
    session: DbSession,
) -> GatewayOut:
    if payload.provider_type not in PROVIDER_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Неизвестный тип провайдера. Доступны: {', '.join(sorted(PROVIDER_TYPES))}",
        )
    existing = session.execute(
        select(MailGateway).where(
            MailGateway.organization_id == actor.organization_id,
            MailGateway.provider_id == payload.provider_id,
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Шлюз с таким идентификатором уже настроен"
        )

    gateway = MailGateway(
        organization_id=actor.organization_id,
        provider_id=payload.provider_id,
        provider_type=payload.provider_type,
        display_name=payload.display_name or payload.provider_id,
        vendor=payload.vendor,
        direction=payload.direction.value
        if isinstance(payload.direction, GatewayDirection)
        else str(payload.direction),
        enabled=payload.enabled,
        settings=_sanitise_settings(payload.settings),
        updated_by=actor.email,
    )
    session.add(gateway)
    session.flush()
    record(
        session,
        action=AuditAction.GATEWAY_ADDED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="mail_gateway",
        object_id=gateway.id,
        detail={"provider_id": gateway.provider_id, "provider_type": gateway.provider_type},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return _gateway_out(session, gateway)


#: Keys that would smuggle a secret into a settings blob. Rejected rather than redacted, so an
#: administrator does not believe a credential was saved when it was dropped (ТЗ 28).
_FORBIDDEN_SETTING_KEYS = frozenset(
    {"password", "secret", "token", "api_key", "apikey", "credential", "credentials", "key"}
)


def _sanitise_settings(settings: dict[str, Any] | None) -> dict[str, Any]:
    payload = dict(settings or {})
    offending = sorted(k for k in payload if k.strip().lower() in _FORBIDDEN_SETTING_KEYS)
    if offending:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Поля {', '.join(offending)} не сохраняются в настройках шлюза. Секреты задаются "
                "ссылкой на хранилище (secret_ref), а не значением."
            ),
        )
    return payload


@router.put("/{gateway_id}", response_model=GatewayOut)
def update_gateway(
    gateway_id: str,
    payload: GatewayUpsertRequest,
    request: Request,
    actor: PolicyAdmin,
    session: DbSession,
) -> GatewayOut:
    gateway = session.get(MailGateway, gateway_id)
    if gateway is None or gateway.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Шлюз не найден")

    was_enabled = gateway.enabled
    gateway.display_name = payload.display_name or gateway.display_name
    gateway.vendor = payload.vendor or gateway.vendor
    gateway.direction = (
        payload.direction.value if isinstance(payload.direction, GatewayDirection) else str(payload.direction)
    )
    gateway.enabled = payload.enabled
    gateway.settings = _sanitise_settings(payload.settings)
    gateway.updated_by = actor.email

    record(
        session,
        action=AuditAction.GATEWAY_DISABLED
        if was_enabled and not payload.enabled
        else AuditAction.GATEWAY_UPDATED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="mail_gateway",
        object_id=gateway.id,
        detail={"enabled": payload.enabled, "provider_id": gateway.provider_id},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return _gateway_out(session, gateway)


@router.post("/{gateway_id}/hops", response_model=TrustedHopOut, status_code=201)
def add_trusted_hop(
    gateway_id: str,
    payload: TrustedHopUpsertRequest,
    request: Request,
    actor: PolicyAdmin,
    session: DbSession,
) -> TrustedHopOut:
    """Register a hop whose headers may be believed once the chain proves the message passed it.

    This is the entity that makes ``MSP_TRUSTED_GATEWAYS`` mean something: without a hop, a
    gateway's headers are parsed and displayed but never trusted (ТЗ 1.0.1 §4.3).
    """
    gateway = session.get(MailGateway, gateway_id)
    if gateway is None or gateway.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Шлюз не найден")
    if not payload.hostname and not payload.ip_networks:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Узел без имени и без сетей нечем сопоставить с цепочкой доставки: "
                "укажите hostname или ip_networks."
            ),
        )

    hop = TrustedHop(
        organization_id=actor.organization_id,
        gateway_id=gateway.id,
        hop_type=payload.hop_type,
        hostname=payload.hostname,
        ip_networks=list(payload.ip_networks),
        expected_headers=list(payload.expected_headers),
        authserv_ids=[a.lower() for a in payload.authserv_ids],
        position_in_chain=payload.position_in_chain,
        direction=gateway.direction,
        enabled=payload.enabled,
        updated_by=actor.email,
    )
    session.add(hop)
    session.flush()
    record(
        session,
        action=AuditAction.TRUSTED_HOP_CHANGED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="trusted_mail_hop",
        object_id=hop.id,
        detail={
            "gateway": gateway.provider_id,
            "hostname": hop.hostname,
            "networks": len(hop.ip_networks or []),
            "authserv_ids": hop.authserv_ids,
        },
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return _hop_out(hop)


@router.delete("/hops/{hop_id}", status_code=204)
def delete_trusted_hop(hop_id: str, request: Request, actor: PolicyAdmin, session: DbSession) -> None:
    hop = session.get(TrustedHop, hop_id)
    if hop is None or hop.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Узел не найден")
    record(
        session,
        action=AuditAction.TRUSTED_HOP_CHANGED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="trusted_mail_hop",
        object_id=hop.id,
        outcome="deleted",
        detail={"hostname": hop.hostname},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.delete(hop)
    session.commit()


@router.post("/probe", response_model=dict)
def probe_capabilities(
    request: Request, actor: PolicyAdmin, session: DbSession, settings: AppSettings
) -> dict[str, Any]:
    """Re-probe what each gateway supports and record the result (ТЗ 1.0.2 §22)."""
    registry = build_registry(session, settings, actor.organization_id)
    written = refresh_capabilities(session, registry, actor.organization_id)
    record(
        session,
        action=AuditAction.GATEWAY_CAPABILITY_CHANGED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="mail_gateway",
        object_id="all",
        detail={"capabilities_recorded": written, "providers": len(registry.providers)},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return {
        "state": registry.state().value,
        "capabilities": registry.capabilities(),
        "health": [h.model_dump(mode="json") for h in registry.health()],
    }


@router.get("/dead-letters", response_model=list[dict])
def list_dead_letters(
    actor: PolicyAdmin,
    session: DbSession,
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict[str, Any]]:
    """Gateway events that could not be accepted (ТЗ 1.0.2 §20).

    An empty list does not mean the gateway is quiet — check ``last_event_at`` for that. This
    list is what the platform refused, and why.
    """
    rows = (
        session.execute(
            select(SyslogDeadLetter)
            .where(SyslogDeadLetter.organization_id == actor.organization_id)
            .order_by(SyslogDeadLetter.received_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return [
        {
            "provider_id": row.provider_id,
            "source_ip": row.source_ip,
            "reason": row.reason,
            "detail": row.detail,
            "received_at": row.received_at.isoformat(),
            # The raw line is shown to an administrator so an unknown format can be recognised.
            "raw": row.raw[:500],
        }
        for row in rows
    ]


# ---------------------------------------------------------------------------------------------
# Upstream Protection card (ТЗ 1.0.2 §24)
# ---------------------------------------------------------------------------------------------
@router.get("/messages/{message_id}", response_model=UpstreamProtectionResponse)
def upstream_protection(message_id: str, actor: Viewer, session: DbSession) -> UpstreamProtectionResponse:
    """What upstream protection said about this message, and where it disagrees with us."""
    message = session.get(MailMessage, message_id)
    if message is None or message.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Сообщение не найдено")

    evidence = (
        session.execute(
            select(GatewayEvidenceRecord)
            .where(GatewayEvidenceRecord.message_id == message_id)
            .order_by(GatewayEvidenceRecord.observed_at.desc())
        )
        .scalars()
        .all()
    )
    conflicts = (
        session.execute(
            select(GatewayConflict)
            .where(GatewayConflict.message_id == message_id)
            .order_by(GatewayConflict.detected_at.desc())
        )
        .scalars()
        .all()
    )
    return UpstreamProtectionResponse(
        message_id=message_id,
        present=bool(evidence),
        evidence=[
            GatewayEvidenceOut(
                provider_id=row.provider_id,
                provider_type=row.provider_type,
                verdict=row.verdict,
                category=row.category,
                engine=row.engine,
                threat_name=row.threat_name,
                score=row.score,
                policy=row.policy,
                source=row.evidence_source,
                trusted=row.trusted,
                trust_state=row.trust_state,
                trust_reason=row.trust_reason,
                observed_at=row.observed_at,
                detail=dict(row.normalized_detail or {}),
            )
            for row in evidence
        ],
        conflicts=[
            GatewayConflictOut(
                conflict_id=row.id,
                kind=row.kind,
                summary=row.summary,
                providers=list(row.providers or []),
                detail=dict(row.detail or {}),
                detected_at=row.detected_at,
                resolved_at=row.resolved_at,
                resolution=row.resolution,
            )
            for row in conflicts
        ],
        note=(
            "Вердикт шлюза — дополнительный источник. Обнаружение повышает риск; отсутствие "
            "обнаружения его не снижает и не подтверждает безопасность письма."
        ),
    )


@router.post("/conflicts/{conflict_id}/resolve", response_model=GatewayConflictOut)
def resolve_conflict(
    conflict_id: str,
    request: Request,
    actor: PolicyAdmin,
    session: DbSession,
    resolution: str = Query(default="", max_length=500),
) -> GatewayConflictOut:
    conflict = session.get(GatewayConflict, conflict_id)
    if conflict is None or conflict.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Расхождение не найдено")
    from ..db.base import utcnow

    conflict.resolved_at = utcnow()
    conflict.resolved_by = actor.email
    conflict.resolution = resolution
    record(
        session,
        action=AuditAction.GATEWAY_CONFLICT_RESOLVED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="gateway_conflict",
        object_id=conflict.id,
        detail={"kind": conflict.kind, "resolution": resolution[:200]},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return GatewayConflictOut(
        conflict_id=conflict.id,
        kind=conflict.kind,
        summary=conflict.summary,
        providers=list(conflict.providers or []),
        detail=dict(conflict.detail or {}),
        detected_at=conflict.detected_at,
        resolved_at=conflict.resolved_at,
        resolution=conflict.resolution,
    )


@router.get("/capabilities", response_model=dict)
def capability_matrix(actor: Viewer, session: DbSession, settings: AppSettings) -> dict[str, Any]:
    """Which capability each configured gateway actually has, for UI capability probing."""
    registry = build_registry(session, settings, actor.organization_id)
    per_provider = registry.capabilities()
    return {
        "state": registry.state().value,
        "by_provider": per_provider,
        "by_capability": {
            capability.value: registry.supports(capability) for capability in GatewayCapability
        },
    }
