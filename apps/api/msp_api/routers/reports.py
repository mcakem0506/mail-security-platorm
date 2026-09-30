"""Reporting endpoints with CSV and JSON export (ТЗ 37)."""

from __future__ import annotations

import logging
import re
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from ..deps import Actor, DbSession, client_ip, require_permission
from ..security.audit import AuditAction, record
from ..security.rbac import Permission
from ..services.reporting import REPORTS

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/reports", tags=["reports"])

Viewer = Annotated[Actor, Depends(require_permission(Permission.VIEW_INVESTIGATIONS))]
Exporter = Annotated[Actor, Depends(require_permission(Permission.EXPORT_DATA))]
AuditViewer = Annotated[Actor, Depends(require_permission(Permission.VIEW_AUDIT))]

# Reports that reveal more than investigation data and therefore need their own permission.
_AUDIT_ONLY = {"audit"}
_SAFE_NAME = re.compile(r"^[a-z_]{1,40}$")


@router.get("")
def list_reports(actor: Viewer) -> dict[str, list[str]]:
    available = [name for name in sorted(REPORTS) if name not in _AUDIT_ONLY]
    if actor.can(Permission.VIEW_AUDIT):
        available.extend(sorted(_AUDIT_ONLY))
    return {"reports": available}


@router.get("/pilot-metrics")
def pilot_metrics(
    request: Request,
    actor: Viewer,
    session: DbSession,
    days: Annotated[int, Query(ge=1, le=400)] = 14,
) -> dict[str, Any]:
    """Detection quality metrics for the shadow pilot (ТЗ 1.0.1 §11).

    Two of the numbers here need reading carefully, and the field names say so:

    * ``precision_estimate`` is ``null`` for a rule no analyst has triaged. An unexamined rule
      has no precision, rather than a perfect one.
    * ``false_negative_discovered`` counts only the misses somebody found afterwards. The
      platform cannot know what it never saw, so this is a lower bound and not recall.
    """
    from ..services.pilot_metrics import Period, collect, rule_quality

    period = Period.last_days(days)
    metrics = collect(session, actor.organization_id, period)
    record(
        session,
        action=AuditAction.EXPORT,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="report",
        object_id="pilot-metrics",
        detail={"days": days},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return {
        **metrics,
        "rules": rule_quality(session, actor.organization_id),
        "notes": {
            "precision_estimate": (
                "null означает, что правило ещё не разбиралось аналитиком. "
                "Непроверенное правило не имеет precision, а не имеет идеальную."
            ),
            "false_negative_discovered": (
                "нижняя оценка: учитываются только пропуски, которые кто-то обнаружил. "
                "Это не recall — платформа не знает, чего она не видела."
            ),
        },
    }


@router.get("/{name}")
def get_report(
    name: str,
    request: Request,
    actor: Viewer,
    session: DbSession,
    fmt: Annotated[Literal["json", "csv"], Query(alias="format")] = "json",
    days: Annotated[int, Query(ge=1, le=400)] = 7,
    confirmed_only: Annotated[bool, Query()] = True,
) -> Response:
    if not _SAFE_NAME.match(name) or name not in REPORTS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Отчёт не найден")
    if name in _AUDIT_ONLY and not actor.can(Permission.VIEW_AUDIT):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Недостаточно прав")
    if fmt == "csv" and not actor.can(Permission.EXPORT_DATA):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Экспорт данных требует отдельного права"
        )

    builder = REPORTS[name]
    kwargs: dict[str, object] = {}
    if name == "indicators":
        kwargs["confirmed_only"] = confirmed_only
    else:
        kwargs["days"] = days
    report = builder(session, actor.organization_id, **kwargs)  # type: ignore[arg-type]

    if fmt == "csv":
        # Every export is audited: it moves data outside the platform (ТЗ 25).
        record(
            session,
            action=AuditAction.EXPORT,
            actor_id=actor.user_id,
            actor_email=actor.email,
            actor_role=actor.role.value,
            organization_id=actor.organization_id,
            object_type="report",
            object_id=name,
            detail={"format": "csv", "rows": len(report.rows), "period": report.period.as_dict()},
            ip_address=client_ip(request),
            request_id=getattr(request.state, "request_id", ""),
        )
        session.commit()
        body = report.as_csv()
        return Response(
            content=body.encode("utf-8-sig"),  # BOM so Excel opens Cyrillic correctly
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{name}.csv"',
                "X-Content-Type-Options": "nosniff",
            },
        )

    from fastapi.responses import JSONResponse

    return JSONResponse(content=report.as_json())
