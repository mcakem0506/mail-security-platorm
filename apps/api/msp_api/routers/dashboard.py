"""Security dashboard, health probes and metrics (ТЗ 22.1, 31)."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Response
from msp_contracts import IncidentStatus, RiskLevel
from msp_mail_parser.images import component_health as qr_component_health_report
from sqlalchemy import desc, func, select, text

from ..db.base import utcnow
from ..db.models import (
    AnalysisJob,
    AnalysisResult,
    Campaign,
    DetectionSignal,
    Incident,
    Indicator,
    MailMessage,
    Notification,
)
from ..deps import Actor, AppSettings, DbSession, get_scanner, get_ti_hub, require_permission
from ..observability import QR_HEALTH_LEVEL, qr_component_health, render_metrics
from ..schemas import DashboardResponse
from ..security.rbac import Permission
from ..services.storage import build_storage

logger = logging.getLogger(__name__)
router = APIRouter(tags=["dashboard"])

Viewer = Annotated[Actor, Depends(require_permission(Permission.VIEW_INVESTIGATIONS))]


@router.get("/dashboard", response_model=DashboardResponse)
def dashboard(actor: Viewer, session: DbSession) -> DashboardResponse:
    org = actor.organization_id
    day_ago = utcnow() - timedelta(days=1)
    week_ago = utcnow() - timedelta(days=7)

    def count_by_class(level: RiskLevel) -> int:
        return int(
            session.execute(
                select(func.count())
                .select_from(AnalysisResult)
                .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
                .where(
                    AnalysisJob.organization_id == org,
                    AnalysisResult.classification == level,
                    AnalysisResult.created_at >= day_ago,
                )
            ).scalar_one()
        )

    analyses_today = int(
        session.execute(
            select(func.count())
            .select_from(AnalysisJob)
            .where(AnalysisJob.organization_id == org, AnalysisJob.created_at >= day_ago)
        ).scalar_one()
    )
    open_incidents = int(
        session.execute(
            select(func.count())
            .select_from(Incident)
            .where(
                Incident.organization_id == org,
                Incident.status.notin_([IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE]),
            )
        ).scalar_one()
    )
    active_campaigns = int(
        session.execute(
            select(func.count())
            .select_from(Campaign)
            .where(Campaign.organization_id == org, Campaign.last_seen >= week_ago)
        ).scalar_one()
    )
    reports_today = int(
        session.execute(
            select(func.count())
            .select_from(AnalysisJob)
            .where(
                AnalysisJob.organization_id == org,
                AnalysisJob.is_report.is_(True),
                AnalysisJob.created_at >= day_ago,
            )
        ).scalar_one()
    )

    impersonated = session.execute(
        select(DetectionSignal.title, func.count().label("hits"))
        .join(AnalysisResult, AnalysisResult.id == DetectionSignal.result_id)
        .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
        .where(
            AnalysisJob.organization_id == org,
            DetectionSignal.category.in_(
                ["executive_impersonation", "display_name_impersonation", "corporate_identity_impersonation"]
            ),
            DetectionSignal.suppressed.is_(False),
            DetectionSignal.observed_at >= week_ago,
        )
        .group_by(DetectionSignal.title)
        .order_by(desc("hits"))
        .limit(10)
    ).all()

    malicious_domains = session.execute(
        select(Indicator.value, Indicator.sighting_count)
        .where(
            Indicator.organization_id == org,
            Indicator.ioc_type == "domain",
            Indicator.confirmed_malicious.is_(True),
        )
        .order_by(desc(Indicator.sighting_count))
        .limit(10)
    ).all()

    reported_senders = session.execute(
        select(MailMessage.sender_address, func.count().label("reports"))
        .where(
            MailMessage.organization_id == org,
            MailMessage.reported_by.is_not(None),
            MailMessage.received_at >= week_ago,
        )
        .group_by(MailMessage.sender_address)
        .order_by(desc("reports"))
        .limit(10)
    ).all()

    return DashboardResponse(
        analyses_today=analyses_today,
        suspicious=count_by_class(RiskLevel.SUSPICIOUS),
        high_risk=count_by_class(RiskLevel.HIGH_RISK),
        malicious=count_by_class(RiskLevel.MALICIOUS),
        unknown=count_by_class(RiskLevel.UNKNOWN),
        open_incidents=open_incidents,
        active_campaigns=active_campaigns,
        employee_reports_today=reports_today,
        top_impersonated_identities=[{"signal": t, "count": int(c)} for t, c in impersonated],
        top_malicious_domains=[{"domain": d, "sightings": int(c)} for d, c in malicious_domains],
        top_reported_senders=[{"sender": s, "reports": int(c)} for s, c in reported_senders],
        provider_health=[
            {"provider_id": h.provider_id, "status": h.status, "mode": h.mode, "detail": h.detail}
            for h in get_ti_hub().health()
        ],
        generated_at=utcnow(),
    )


# ---------------------------------------------------------------------------------------------
# Health (ТЗ 31)
# ---------------------------------------------------------------------------------------------
health_router = APIRouter(prefix="/health", tags=["health"])


@health_router.get("/live")
def liveness() -> dict[str, str]:
    return {"status": "ok"}


@health_router.get("/ready")
def readiness(session: DbSession, settings: AppSettings, response: Response) -> dict[str, Any]:
    """Readiness depends only on components the platform cannot work without.

    An optional VirusTotal outage must never make the service unready (ТЗ 31).
    """
    checks: dict[str, Any] = {}
    ready = True

    try:
        session.execute(text("SELECT 1"))
        checks["database"] = {"status": "ok", "required": True}
    except Exception as exc:  # noqa: BLE001
        checks["database"] = {"status": "unavailable", "required": True, "detail": type(exc).__name__}
        ready = False

    try:
        from ..deps import _redis_client

        client = _redis_client()
        if client is not None:
            client.ping()
            checks["redis"] = {"status": "ok", "required": True}
        else:
            checks["redis"] = {"status": "degraded", "required": True, "detail": "in-process fallback"}
    except Exception as exc:  # noqa: BLE001
        checks["redis"] = {"status": "unavailable", "required": True, "detail": type(exc).__name__}
        ready = False

    try:
        ok, detail = build_storage(settings).health()
        checks["object_storage"] = {
            "status": "ok" if ok else "unavailable",
            "required": True,
            "detail": detail,
        }
        ready = ready and ok
    except Exception as exc:  # noqa: BLE001
        checks["object_storage"] = {"status": "unavailable", "required": True, "detail": type(exc).__name__}
        ready = False

    if not ready:
        response.status_code = 503
    return {"status": "ready" if ready else "not_ready", "checks": checks}


@health_router.get("/dependencies")
def dependencies(session: DbSession, settings: AppSettings) -> dict[str, Any]:
    """Full dependency view, including optional components that never affect readiness."""
    required = readiness(session, settings, Response())
    optional: dict[str, Any] = {}
    for health in get_ti_hub().health():
        optional[health.provider_id] = {
            "status": health.status,
            "mode": health.mode,
            "detail": health.detail,
            "required": False,
        }
    if not get_ti_hub().providers:
        optional["virustotal"] = {
            "status": "disabled",
            "detail": "VirusTotal not configured",
            "required": False,
        }
    scanner = get_scanner().health()
    optional[scanner.provider_id] = {
        "status": scanner.status,
        "mode": scanner.mode,
        "detail": scanner.detail,
        "required": False,
    }
    # Профиль чтения QR-кодов. В обязательные проверки он не входит: его отсутствие — это
    # сознательный выбор при сборке образа, а не неисправность, и готовность платформы от него
    # не зависит. Но видимым он быть обязан — иначе администратор узнаёт о выключенном декодере
    # из письма, в котором код остался непрочитанным.
    qr = qr_component_health_report()
    optional["qr_analysis"] = {
        "status": qr.status.value,
        "detail": qr.detail,
        "probe_seconds": qr.probe_seconds,
        "limits": qr.limits,
        "required": False,
    }
    qr_component_health.set(QR_HEALTH_LEVEL.get(qr.status.value, 3))
    if settings.ad_enabled:
        from msp_ad import ActiveDirectoryConfig, ActiveDirectoryProvider

        ad_health = ActiveDirectoryProvider(
            ActiveDirectoryConfig(
                server=settings.ad_server,
                port=settings.ad_port,
                use_ssl=settings.ad_use_ssl,
                bind_dn=settings.ad_bind_dn,
                bind_password=settings.ad_bind_password,
                base_dn=settings.ad_base_dn,
                ca_file=settings.ad_ca_file,
            )
        ).health()
        optional["active_directory"] = {
            "status": ad_health.status,
            "detail": ad_health.detail,
            "required": False,
        }
    return {
        "status": required["status"],
        "required": required["checks"],
        "optional": optional,
        "checked_at": utcnow().isoformat(),
    }


@router.get("/notifications")
def list_notifications(
    actor: Viewer,
    session: DbSession,
    unread_only: bool = False,
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    """The dashboard notification channel (ТЗ 36).

    Notifications are stored defanged: malicious URLs are never rendered as live links, so the
    notification itself cannot become a delivery path.
    """
    query = select(Notification).where(
        Notification.organization_id == actor.organization_id,
        Notification.channel.in_(["dashboard", "email"]),
    )
    if unread_only:
        query = query.where(Notification.read_at.is_(None))
    rows = session.execute(query.order_by(desc(Notification.created_at)).limit(limit)).scalars().all()
    unread = int(
        session.execute(
            select(func.count())
            .select_from(Notification)
            .where(
                Notification.organization_id == actor.organization_id,
                Notification.read_at.is_(None),
            )
        ).scalar_one()
    )
    return {
        "unread": unread,
        "items": [
            {
                "notification_id": n.id,
                "event": n.event,
                "subject": n.subject,
                "body": n.body,
                "payload": n.payload,
                "state": n.state,
                "created_at": n.created_at.isoformat(),
                "read_at": n.read_at.isoformat() if n.read_at else None,
            }
            for n in rows
        ],
    }


@router.post("/notifications/{notification_id}/read", status_code=204)
def mark_notification_read(notification_id: str, actor: Viewer, session: DbSession) -> Response:
    notification = session.get(Notification, notification_id)
    if notification is None or notification.organization_id != actor.organization_id:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Уведомление не найдено")
    if notification.read_at is None:
        notification.read_at = utcnow()
    session.commit()
    return Response(status_code=204)


metrics_router = APIRouter(tags=["metrics"])


@metrics_router.get("/metrics")
def metrics(settings: AppSettings) -> Response:
    if not settings.metrics_enabled:
        return Response(status_code=404)
    return Response(content=render_metrics(), media_type="text/plain; version=0.0.4; charset=utf-8")
