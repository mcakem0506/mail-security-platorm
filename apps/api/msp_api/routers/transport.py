"""API транспорта почты: консоль администратора и точки для узлов (ТЗ 1.1 §42, §43, §44).

Две разные аудитории и два способа проверки доступа:

* **Человек в консоли** — сессия, роль и право на каждое действие. Изменяющие действия пишут
  отдельные события аудита («применил конфигурацию», «слил узел»), а не «изменил запись».
* **Узел шлюза** — общий секрет в заголовке. Узел не пользователь: у него нет роли, и всё, что он
  может, — прислать свои сигналы, забрать назначенную ему конфигурацию и передать копию письма.
  Пока секрет на панели не задан, эти точки закрыты (503), а не открыты для всех.

Очередь по умолчанию показывается без содержимого писем (§43): метаданные видны, тела нет.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from msp_contracts import IntakeSource
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from ..config import Settings, get_settings
from ..db.models import Organization
from ..db.models_transport import (
    MailTransportEvent,
    TransportConfigStatus,
    TransportConfigVersion,
    TransportMessage,
    TransportMessageState,
    TransportNode,
)
from ..deps import Actor, AppSettings, DbSession, client_ip, require_permission
from ..security.audit import AuditAction, record
from ..security.rbac import Permission
from ..services import transport, transport_alerts
from ..services.storage import build_storage

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/gateway", tags=["mail transport"])
agent_router = APIRouter(prefix="/gateway-agent", tags=["mail transport agent"])

GatewayReader = Annotated[Actor, Depends(require_permission(Permission.VIEW_GATEWAY))]
ConfigReader = Annotated[Actor, Depends(require_permission(Permission.VIEW_GATEWAY_CONFIG))]
ConfigValidator = Annotated[Actor, Depends(require_permission(Permission.VALIDATE_GATEWAY_CONFIG))]
ConfigActivator = Annotated[Actor, Depends(require_permission(Permission.ACTIVATE_GATEWAY_CONFIG))]
ConfigRoller = Annotated[Actor, Depends(require_permission(Permission.ROLLBACK_GATEWAY_CONFIG))]
QueueReader = Annotated[Actor, Depends(require_permission(Permission.VIEW_GATEWAY_QUEUE))]
NodeDrainer = Annotated[Actor, Depends(require_permission(Permission.DRAIN_GATEWAY_NODE))]
RecipientSyncer = Annotated[Actor, Depends(require_permission(Permission.SYNC_GATEWAY_RECIPIENTS))]
TlsReader = Annotated[Actor, Depends(require_permission(Permission.VIEW_GATEWAY_TLS))]
QueueAdmin = Annotated[Actor, Depends(require_permission(Permission.ADMIN_GATEWAY_QUEUE))]


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


# ---------------------------------------------------------------------------------------------
# Узлы
# ---------------------------------------------------------------------------------------------
def _node_out(node: TransportNode, settings: Settings) -> dict[str, Any]:
    return {
        "id": node.id,
        "node_id": node.node_id,
        "name": node.name,
        "role": node.role.value,
        "state": transport.node_state(node, settings),
        "last_heartbeat_at": node.last_heartbeat_at,
        "config_version": node.config_version,
        "queue_messages": node.queue_messages,
        "pressure": node.pressure_state,
        "unparsed_log_lines": node.unparsed_log_lines,
        "drain_requested": node.drain_requested,
        "drain_requested_by": node.drain_requested_by,
        "drain_requested_at": node.drain_requested_at,
        "flush_requested": node.flush_requested,
        "oldest_message_seconds": node.oldest_message_seconds,
        "exchange_ok": node.exchange_ok,
        "open_relay_safe": node.open_relay_safe,
        "config_drift": node.config_drift,
        "collector_report_age": node.collector_report_age,
        "shadow_pending_seconds": node.shadow_pending_seconds,
        "probes": (node.details or {}).get("probes", {}),
        "last_apply": (node.details or {}).get("last_apply"),
    }


def _node_or_404(session: DbSession, actor: Actor, node_id: str) -> TransportNode:
    node = session.get(TransportNode, node_id)
    if node is None or node.organization_id != actor.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "узел не найден")
    return node


@router.get("/nodes")
def list_nodes(session: DbSession, actor: GatewayReader, settings: AppSettings) -> dict[str, Any]:
    nodes = session.execute(
        select(TransportNode)
        .where(TransportNode.organization_id == actor.organization_id)
        .order_by(TransportNode.name)
    ).scalars()
    return {"items": [_node_out(n, settings) for n in nodes], "deployment_note": transport.NOT_FOR_PRODUCTION}


@router.get("/nodes/{node_id}")
def get_node(node_id: str, session: DbSession, actor: GatewayReader, settings: AppSettings) -> dict[str, Any]:
    node = _node_or_404(session, actor, node_id)
    events = (
        session.execute(
            select(MailTransportEvent)
            .where(
                MailTransportEvent.organization_id == actor.organization_id,
                MailTransportEvent.node_id == node.node_id,
            )
            .order_by(MailTransportEvent.occurred_at.desc())
            .limit(50)
        )
        .scalars()
        .all()
    )
    return {
        **_node_out(node, settings),
        "events": [{"type": e.event_type, "at": e.occurred_at, "data": e.data} for e in events],
    }


@router.post("/nodes/{node_id}/drain")
def drain_node(node_id: str, request: Request, session: DbSession, actor: NodeDrainer) -> dict[str, Any]:
    node = _node_or_404(session, actor, node_id)
    node.drain_requested = True
    node.drain_requested_by = actor.email
    node.drain_requested_at = transport.now()
    _audit(
        session,
        actor,
        request,
        AuditAction.TRANSPORT_NODE_DRAIN,
        "transport_node",
        node.id,
        {"node": node.node_id},
    )
    return {"node_id": node.node_id, "drain_requested": True}


@router.post("/nodes/{node_id}/resume")
def resume_node(node_id: str, request: Request, session: DbSession, actor: NodeDrainer) -> dict[str, Any]:
    node = _node_or_404(session, actor, node_id)
    node.drain_requested = False
    node.drain_requested_by = actor.email
    node.drain_requested_at = transport.now()
    _audit(
        session,
        actor,
        request,
        AuditAction.TRANSPORT_NODE_RESUME,
        "transport_node",
        node.id,
        {"node": node.node_id},
    )
    return {"node_id": node.node_id, "drain_requested": False}


@router.post("/nodes/{node_id}/flush")
def flush_node(node_id: str, request: Request, session: DbSession, actor: QueueAdmin) -> dict[str, Any]:
    """Повторить доставку отложенной почты. Безопасно: письма не удаляются и не изменяются."""
    node = _node_or_404(session, actor, node_id)
    node.flush_requested = True
    node.flush_requested_by = actor.email
    node.flush_requested_at = transport.now()
    _audit(
        session,
        actor,
        request,
        AuditAction.TRANSPORT_NODE_FLUSH,
        "transport_node",
        node.id,
        {"node": node.node_id},
    )
    return {"node_id": node.node_id, "flush_requested": True}


@router.get("/alerts")
def list_alerts(session: DbSession, actor: GatewayReader, settings: AppSettings) -> dict[str, Any]:
    alerts = transport_alerts.compute(session, actor.organization_id, settings)
    return {
        "items": [alert.as_dict() for alert in alerts],
        "counts": {
            level: sum(1 for a in alerts if a.severity == level)
            for level in (transport_alerts.CRITICAL, transport_alerts.WARNING, transport_alerts.INFO)
        },
    }


# ---------------------------------------------------------------------------------------------
# Очередь и письма
# ---------------------------------------------------------------------------------------------
@router.get("/queue/summary")
def queue_summary(session: DbSession, actor: QueueReader, settings: AppSettings) -> dict[str, Any]:
    return transport.queue_summary(session, actor.organization_id, settings)


def _message_out(message: TransportMessage) -> dict[str, Any]:
    # Содержимого письма здесь нет намеренно (§43): только то, что нужно, чтобы найти письмо.
    return {
        "id": message.id,
        "node_id": message.node_id,
        "direction": message.direction,
        "queue_id": message.queue_id,
        "internet_message_id": message.internet_message_id,
        "content_sha256": message.content_sha256,
        "size_bytes": message.size_bytes,
        "state": message.state.value,
        "analysis_job_id": message.analysis_job_id,
        "duplicate_count": message.duplicate_count,
        "collected_at": message.created_at,
    }


@router.get("/messages")
def list_messages(
    session: DbSession,
    actor: QueueReader,
    direction: Literal["INBOUND", "OUTBOUND", "UNKNOWN"] | None = None,
    state: TransportMessageState | None = None,
    internet_message_id: Annotated[str | None, Query(max_length=998)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    query = select(TransportMessage).where(TransportMessage.organization_id == actor.organization_id)
    if direction:
        query = query.where(TransportMessage.direction == direction)
    if state:
        query = query.where(TransportMessage.state == state)
    if internet_message_id:
        query = query.where(TransportMessage.internet_message_id == internet_message_id)
    total = session.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    rows = session.execute(
        query.order_by(TransportMessage.created_at.desc(), TransportMessage.id).limit(limit).offset(offset)
    ).scalars()
    return {"total": total, "items": [_message_out(m) for m in rows]}


@router.get("/messages/{message_id}")
def get_message(message_id: str, request: Request, session: DbSession, actor: QueueReader) -> dict[str, Any]:
    message = session.get(TransportMessage, message_id)
    if message is None or message.organization_id != actor.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "письмо не найдено")
    _audit(session, actor, request, AuditAction.TRANSPORT_QUEUE_VIEWED, "transport_message", message.id)
    return _message_out(message)


# ---------------------------------------------------------------------------------------------
# Маршруты и конфигурация
# ---------------------------------------------------------------------------------------------
def _version_out(row: TransportConfigVersion, *, with_spec: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "version": row.version,
        "status": row.status.value,
        "checksum": row.checksum,
        "created_by": row.created_by,
        "created_at": row.created_at,
        "activated_by": row.activated_by,
        "activated_at": row.activated_at,
        "note": row.note,
        "errors": row.validation_errors,
    }
    if with_spec:
        out["spec"] = row.spec
    return out


@router.get("/routes")
def list_routes(session: DbSession, actor: ConfigReader) -> dict[str, Any]:
    current = transport.active_version(session, actor.organization_id)
    if current is None:
        return {"version": None, "routes": [], "relay_domains": []}
    spec = current.spec
    return {
        "version": current.version,
        "routes": [
            {
                "name": r.get("name"),
                "tls": r.get("tls"),
                "targets": [
                    {"host": t.get("host"), "port": t.get("port"), "priority": t.get("priority")}
                    for t in r.get("targets", [])
                ],
            }
            for r in spec.get("routes", [])
        ],
        "relay_domains": [
            {"domain": d.get("domain"), "route": d.get("route")} for d in spec.get("relay_domains", [])
        ],
    }


class SpecRequest(BaseModel):
    spec: dict[str, Any]
    note: str = Field(default="", max_length=500)


class ActivateRequest(BaseModel):
    version: int = Field(ge=1)


@router.post("/config/validate")
def validate_config(
    body: SpecRequest, request: Request, session: DbSession, actor: ConfigValidator
) -> dict[str, Any]:
    row = transport.create_version(
        session,
        organization_id=actor.organization_id,
        raw_spec=body.spec,
        actor_email=actor.email,
        note=body.note,
    )
    ok = row.status is TransportConfigStatus.VALIDATED
    _audit(
        session,
        actor,
        request,
        AuditAction.TRANSPORT_CONFIG_VALIDATED,
        "transport_config",
        row.id,
        {"version": row.version, "ok": ok, "errors": len(row.validation_errors)},
        outcome="success" if ok else "rejected",
    )
    return {"ok": ok, **_version_out(row)}


@router.post("/config/activate")
def activate_config(
    body: ActivateRequest, request: Request, session: DbSession, actor: ConfigActivator
) -> dict[str, Any]:
    row = transport.get_version(session, actor.organization_id, body.version)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "версия не найдена")
    try:
        transport.activate(session, row, actor_email=actor.email)
    except transport.ConfigStateError as error:
        _audit(
            session,
            actor,
            request,
            AuditAction.TRANSPORT_CONFIG_ACTIVATED,
            "transport_config",
            row.id,
            {"version": row.version, "reason": str(error)},
            outcome="rejected",
        )
        session.commit()  # отказ в журнале должен остаться, даже если запрос завершается ошибкой
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    _audit(
        session,
        actor,
        request,
        AuditAction.TRANSPORT_CONFIG_ACTIVATED,
        "transport_config",
        row.id,
        {"version": row.version},
    )
    return _version_out(row)


@router.get("/config/versions")
def list_versions(session: DbSession, actor: ConfigReader) -> dict[str, Any]:
    rows = session.execute(
        select(TransportConfigVersion)
        .where(TransportConfigVersion.organization_id == actor.organization_id)
        .order_by(TransportConfigVersion.version.desc())
        .limit(100)
    ).scalars()
    return {"items": [_version_out(r) for r in rows]}


@router.post("/config/{version}/rollback")
def rollback_config(
    version: int, request: Request, session: DbSession, actor: ConfigRoller
) -> dict[str, Any]:
    row = transport.get_version(session, actor.organization_id, version)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "версия не найдена")
    try:
        transport.rollback(session, row, actor_email=actor.email)
    except transport.ConfigStateError as error:
        _audit(
            session,
            actor,
            request,
            AuditAction.TRANSPORT_CONFIG_ROLLED_BACK,
            "transport_config",
            row.id,
            {"version": row.version, "reason": str(error)},
            outcome="rejected",
        )
        session.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    _audit(
        session,
        actor,
        request,
        AuditAction.TRANSPORT_CONFIG_ROLLED_BACK,
        "transport_config",
        row.id,
        {"version": row.version},
    )
    return _version_out(row)


# ---------------------------------------------------------------------------------------------
# Справочник получателей и TLS
# ---------------------------------------------------------------------------------------------
class RecipientSyncRequest(BaseModel):
    format: Literal["csv", "json"]
    content: str = Field(max_length=64 * 1024 * 1024)
    source: str = Field(default="manual", max_length=64)
    source_generated_at: datetime | None = None
    confirm_shrink: bool = False


@router.get("/recipients/status")
def recipients_status(session: DbSession, actor: GatewayReader, settings: AppSettings) -> dict[str, Any]:
    return transport.recipients_status(session, actor.organization_id, settings)


@router.post("/recipients/sync")
def sync_recipients(
    body: RecipientSyncRequest, request: Request, session: DbSession, actor: RecipientSyncer
) -> dict[str, Any]:
    result = transport.sync_recipients(
        session,
        organization_id=actor.organization_id,
        text=body.content,
        fmt=body.format,
        source=body.source,
        actor_email=actor.email,
        source_generated_at=body.source_generated_at,
        confirm_shrink=body.confirm_shrink,
    )
    run = result.run
    _audit(
        session,
        actor,
        request,
        AuditAction.TRANSPORT_RECIPIENTS_SYNC,
        "recipient_sync",
        run.id,
        {
            "status": run.status.value,
            "count": run.recipient_count,
            "previous": run.previous_count,
            "rejected": run.rejected_count,
            "reason": run.reason,
        },
        outcome="success" if run.status.value == "ACCEPTED" else "rejected",
    )
    if run.status.value != "ACCEPTED":
        # Журнал и запись о попытке сохраняются, а клиент получает отказ с причиной.
        session.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, run.reason or "справочник не принят")
    return {
        "status": run.status.value,
        "recipient_count": run.recipient_count,
        "rejected_count": run.rejected_count,
        "conflict_count": run.conflict_count,
        "activated_version": result.activated_version,
    }


@router.get("/tls/status")
def tls_status(session: DbSession, actor: TlsReader) -> dict[str, Any]:
    return {"items": transport.tls_status(session, actor.organization_id)}


# ---------------------------------------------------------------------------------------------
# Точки для узлов
# ---------------------------------------------------------------------------------------------
def node_auth(
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    scheme, _, presented = (authorization or "").partition(" ")
    # Схема обязательна: токен без неё — не тот способ предъявления, который мы выдавали.
    verdict = transport.node_token_valid(settings, presented.strip() if scheme == "Bearer" else "")
    if verdict is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "приём от узлов не настроен")
    if not verdict:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "неверный токен узла")


NodeAuth = Annotated[None, Depends(node_auth)]


def _organization(session: DbSession) -> Organization:
    org = session.execute(select(Organization)).scalars().first()
    if org is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "организация не настроена")
    return org


class EventsRequest(BaseModel):
    node_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    role: str = Field(default="LAB", max_length=16)
    events: list[dict[str, Any]] = Field(max_length=transport.MAX_EVENTS_PER_BATCH)


@agent_router.post("/events")
def agent_events(body: EventsRequest, session: DbSession, _auth: NodeAuth) -> dict[str, Any]:
    org = _organization(session)
    result = transport.ingest_events(
        session, organization_id=org.id, node_id=body.node_id, events=list(body.events), role=body.role
    )
    return {"accepted": result.accepted, "rejected": result.rejected}


@agent_router.get("/config")
def agent_config(
    session: DbSession, _auth: NodeAuth, node_id: Annotated[str, Query(pattern=r"^[0-9a-f]{32}$")]
) -> dict[str, Any]:
    """Что должен выполнять этот узел: действующий пакет и команда слива."""
    org = _organization(session)
    node = transport.get_or_create_node(session, org.id, node_id)
    current = transport.active_version(session, org.id)
    return {
        "version": current.version if current else None,
        "checksum": current.checksum if current else None,
        "bundle": current.bundle if current else None,
        "drain": node.drain_requested,
        "flush": node.flush_requested,
    }


def _shadow_key(content_sha256: str, direction: str, message_id: str, fingerprint: str) -> str:
    return hashlib.sha256(
        "\x1f".join((direction, message_id, content_sha256, fingerprint)).encode()
    ).hexdigest()


async def raw_body(request: Request) -> bytes:
    """Тело запроса как есть. Читается отдельной зависимостью, чтобы сам обработчик был обычной
    функцией и работал в пуле потоков: запись в базу и хранилище не должна стоять в цикле событий,
    иначе один медленный приём копии задерживает все остальные запросы панели, в том числе сигналы
    других узлов."""
    return await request.body()


RawBody = Annotated[bytes, Depends(raw_body)]


@agent_router.post("/shadow")
def agent_shadow(
    raw: RawBody,
    session: DbSession,
    settings: AppSettings,
    _auth: NodeAuth,
    x_msp_idempotency_key: Annotated[str, Header(pattern=r"^[0-9a-f]{64}$")],
    x_msp_node_id: Annotated[str, Header(pattern=r"^[0-9a-f]{32}$")],
    x_msp_direction: Annotated[Literal["INBOUND", "OUTBOUND", "UNKNOWN"], Header()] = "UNKNOWN",
    x_msp_message_id: Annotated[str, Header(max_length=998)] = "",
    x_msp_queue_id: Annotated[str, Header(max_length=40)] = "",
    x_msp_envelope_fingerprint: Annotated[str, Header(max_length=64)] = "",
    x_msp_client_address: Annotated[str, Header(max_length=64)] = "",
) -> dict[str, Any]:
    """Принять копию письма от узла. Повтор с тем же ключом не создаёт второго анализа."""
    org = _organization(session)
    if not raw:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "пустое письмо")
    if len(raw) > settings.limit_message_size:
        raise HTTPException(413, "письмо больше предела анализа")
    sha = hashlib.sha256(raw).hexdigest()

    existing = session.execute(
        select(TransportMessage).where(
            TransportMessage.organization_id == org.id,
            TransportMessage.idempotency_key == x_msp_idempotency_key,
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.duplicate_count += 1
        return {"id": existing.id, "duplicate": True, "state": existing.state.value}

    message = TransportMessage(
        organization_id=org.id,
        node_id=x_msp_node_id,
        idempotency_key=x_msp_idempotency_key,
        direction=x_msp_direction,
        queue_id=x_msp_queue_id,
        internet_message_id=x_msp_message_id,
        content_sha256=sha,
        envelope_fingerprint=x_msp_envelope_fingerprint,
        size_bytes=len(raw),
        client_address=x_msp_client_address,
    )
    session.add(message)
    session.flush()
    try:
        from ..services.intake import begin_intake

        outcome = begin_intake(
            session,
            settings,
            organization_id=org.id,
            source=IntakeSource.SHADOW,
            source_id=f"gateway:{x_msp_node_id}",
            mailbox_uid=x_msp_idempotency_key[:64],
            raw=raw,
            internet_message_id=x_msp_message_id,
            content_sha256=sha,
            storage=build_storage(settings),
        )
        message.raw_storage_key = outcome.record.raw_storage_key
    except Exception as exc:  # noqa: BLE001 - потеря копии для анализа не должна ронять приём узла
        logger.warning("transport.shadow_store_failed", extra={"error": type(exc).__name__})
        message.note = f"копия не сохранена: {type(exc).__name__}"
        return {"id": message.id, "duplicate": False, "state": message.state.value, "stored": False}

    from ..tasks import _send

    queued = _send("msp.analyze_transport_message", "mail_parse", message.id)
    message.state = TransportMessageState.ANALYSIS_QUEUED if queued else TransportMessageState.COLLECTED
    return {"id": message.id, "duplicate": False, "state": message.state.value, "stored": True}
