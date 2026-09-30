"""Mail investigations: search, message detail, safe preview, attachments (ТЗ 22.2, 22.3)."""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from msp_contracts import RiskLevel, TIResult
from sqlalchemy import desc, func, or_, select

from ..db.models import (
    AnalysisResult,
    Attachment,
    CampaignMessage,
    IncidentMessage,
    Indicator,
    IndicatorObservation,
    MailContent,
    MailHeader,
    MailMessage,
    MailRecipient,
    ProviderLookup,
)
from ..deps import Actor, AppSettings, DbSession, client_ip, require_permission
from ..schemas import (
    AttachmentOut,
    MessageDetailResponse,
    MessageSummary,
    PaginatedResponse,
    SafePreviewResponse,
)
from ..security.audit import AuditAction, record
from ..security.rbac import Permission
from ..services.storage import build_storage

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/investigations", tags=["investigations"])

Viewer = Annotated[Actor, Depends(require_permission(Permission.VIEW_INVESTIGATIONS))]
ContentViewer = Annotated[Actor, Depends(require_permission(Permission.VIEW_MESSAGE_CONTENT))]
Downloader = Annotated[Actor, Depends(require_permission(Permission.DOWNLOAD_ATTACHMENT))]

# File types that must never be served straight to a browser (ТЗ 22.3).
_DANGEROUS_TYPES = frozenset(
    {"pe_executable", "elf_executable", "macho_executable", "jar", "apk", "lnk", "script", "html", "svg"}
)


def _summary(session, message: MailMessage) -> MessageSummary:  # type: ignore[no-untyped-def]
    result = session.execute(
        select(AnalysisResult)
        .where(AnalysisResult.message_id == message.id)
        .order_by(desc(AnalysisResult.created_at))
        .limit(1)
    ).scalar_one_or_none()
    campaign_id = session.execute(
        select(CampaignMessage.campaign_id).where(CampaignMessage.message_id == message.id)
    ).scalar_one_or_none()
    return MessageSummary(
        message_id=message.id,
        subject=message.subject,
        sender_address=message.sender_address,
        sender_display_name=message.sender_display_name,
        sender_domain=message.sender_domain,
        recipient_count=message.recipient_count,
        received_at=message.received_at,
        classification=result.classification if result else None,
        score=result.score if result else None,
        has_attachments=message.has_attachments,
        url_count=message.url_count,
        source=message.source.value,
        reported_by=message.reported_by,
        campaign_id=campaign_id,
        job_id=result.job_id if result else None,
    )


@router.get("/messages", response_model=PaginatedResponse)
def search_messages(
    actor: Viewer,
    session: DbSession,
    sender: str | None = Query(default=None, max_length=320),
    recipient: str | None = Query(default=None, max_length=320),
    subject: str | None = Query(default=None, max_length=500),
    verdict: RiskLevel | None = None,
    sha256: str | None = Query(default=None, pattern=r"^[0-9a-fA-F]{64}$"),
    domain: str | None = Query(default=None, max_length=255),
    url: str | None = Query(default=None, max_length=2048),
    campaign_id: str | None = Query(default=None, max_length=32),
    incident_id: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=100_000),
) -> PaginatedResponse:
    """Search across investigations. Every filter is parameterised — no string-built SQL."""
    query = select(MailMessage).where(MailMessage.organization_id == actor.organization_id)

    if sender:
        query = query.where(func.lower(MailMessage.sender_address).contains(sender.lower()))
    if subject:
        query = query.where(func.lower(MailMessage.subject).contains(subject.lower()))
    if domain:
        query = query.where(
            or_(
                func.lower(MailMessage.sender_domain) == domain.lower(),
                func.lower(MailMessage.sender_domain).endswith("." + domain.lower()),
            )
        )
    if recipient:
        query = query.where(
            MailMessage.id.in_(
                select(MailRecipient.message_id).where(
                    func.lower(MailRecipient.address).contains(recipient.lower())
                )
            )
        )
    if sha256:
        query = query.where(
            or_(
                MailMessage.raw_sha256 == sha256.lower(),
                MailMessage.id.in_(select(Attachment.message_id).where(Attachment.sha256 == sha256.lower())),
            )
        )
    if url:
        query = query.where(
            MailMessage.id.in_(
                select(IndicatorObservation.message_id)
                .join(Indicator, Indicator.id == IndicatorObservation.indicator_id)
                .where(Indicator.value.contains(url.lower()))
            )
        )
    if verdict is not None:
        query = query.where(
            MailMessage.id.in_(
                select(AnalysisResult.message_id).where(AnalysisResult.classification == verdict)
            )
        )
    if campaign_id:
        query = query.where(
            MailMessage.id.in_(
                select(CampaignMessage.message_id).where(CampaignMessage.campaign_id == campaign_id)
            )
        )
    if incident_id:
        query = query.where(
            MailMessage.id.in_(
                select(IncidentMessage.message_id).where(IncidentMessage.incident_id == incident_id)
            )
        )

    total = session.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    rows = (
        session.execute(query.order_by(desc(MailMessage.received_at)).limit(limit).offset(offset))
        .scalars()
        .all()
    )
    return PaginatedResponse(
        total=int(total), limit=limit, offset=offset, items=[_summary(session, m) for m in rows]
    )


def _auth_note(session, message: MailMessage) -> str | None:  # type: ignore[no-untyped-def]
    """Explain refused Authentication-Results (ТЗ 1.0.1 §4.4).

    Showing nothing would read as "the sender never authenticated", which is a different claim
    from "the sender asserted a pass and we could not verify who wrote it".
    """
    result = session.execute(
        select(AnalysisResult)
        .where(AnalysisResult.message_id == message.id)
        .order_by(desc(AnalysisResult.created_at))
        .limit(1)
    ).scalar_one_or_none()
    facts = (result.facts or {}) if result is not None else {}
    if facts.get("authentication_results_forged"):
        return (
            "В письме есть заголовок Authentication-Results с успешным результатом, но он "
            "записан сервером, который не входит в инфраструктуру организации, либо цепочка "
            "доставки через этот сервер не подтверждается. Результаты не учитывались."
        )
    if facts.get("authentication_results_untrusted"):
        return (
            "Заголовок Authentication-Results записан сервером вне топологии организации "
            "(например, при пересылке), поэтому его результаты не учитывались."
        )
    refused = int((message.auth_summary or {}).get("_refused_headers") or 0)
    if refused:
        return f"Не учтено заголовков Authentication-Results: {refused}."
    return None


@router.get("/messages/{message_id}", response_model=MessageDetailResponse)
def get_message(
    message_id: str, request: Request, actor: Viewer, session: DbSession
) -> MessageDetailResponse:
    message = session.get(MailMessage, message_id)
    if message is None or message.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Сообщение не найдено")

    headers = (
        session.execute(
            select(MailHeader).where(MailHeader.message_id == message.id).order_by(MailHeader.position)
        )
        .scalars()
        .all()
    )
    recipients = (
        session.execute(select(MailRecipient).where(MailRecipient.message_id == message.id)).scalars().all()
    )
    attachments = (
        session.execute(
            select(Attachment).where(Attachment.message_id == message.id).order_by(Attachment.depth)
        )
        .scalars()
        .all()
    )
    urls = session.execute(
        select(Indicator.value, IndicatorObservation.context)
        .join(IndicatorObservation, IndicatorObservation.indicator_id == Indicator.id)
        .where(
            IndicatorObservation.message_id == message.id,
            Indicator.ioc_type == "url",
        )
        .limit(500)
    ).all()
    content = session.execute(
        select(MailContent).where(MailContent.message_id == message.id)
    ).scalar_one_or_none()

    record(
        session,
        action=AuditAction.MESSAGE_VIEW,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="mail_message",
        object_id=message.id,
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()

    return MessageDetailResponse(
        message=_summary(session, message),
        headers=[{"name": h.name, "value": h.value} for h in headers],
        recipients=[
            {"address": r.address, "kind": r.kind, "display_name": r.display_name} for r in recipients
        ],
        attachments=[
            AttachmentOut(
                attachment_id=a.id,
                filename=a.normalized_filename,
                detected_type=a.detected_type,
                size_bytes=a.size_bytes,
                sha256=a.sha256,
                depth=a.depth,
                is_archive=a.is_archive,
                encrypted=a.encrypted,
                flags=list(a.flags or []),
                downloadable=bool(a.storage_key) and a.purged_at is None,
                scan_result=dict(a.scan_result or {}),
            )
            for a in attachments
        ],
        urls=[{"url": value, "context": context} for value, context in urls],
        auth_summary={k: v for k, v in (message.auth_summary or {}).items() if not k.startswith("_")},
        auth_note=_auth_note(session, message),
        verdict=None,
        preview_available=content is not None
        and (content.sanitized_html is not None or content.normalized_text is not None),
    )


@router.get("/messages/{message_id}/preview", response_model=SafePreviewResponse)
def safe_preview(
    message_id: str, request: Request, actor: ContentViewer, session: DbSession
) -> SafePreviewResponse:
    """Sanitised preview: no scripts, no remote loads, links are inert text (ТЗ 22.3)."""
    message = session.get(MailMessage, message_id)
    if message is None or message.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Сообщение не найдено")
    content = session.execute(
        select(MailContent).where(MailContent.message_id == message.id)
    ).scalar_one_or_none()
    if content is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Содержимое недоступно")

    urls = session.execute(
        select(Indicator.value, IndicatorObservation.context)
        .join(IndicatorObservation, IndicatorObservation.indicator_id == Indicator.id)
        .where(IndicatorObservation.message_id == message.id, Indicator.ioc_type == "url")
        .limit(500)
    ).all()

    record(
        session,
        action=AuditAction.MESSAGE_CONTENT_VIEW,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="mail_message",
        object_id=message.id,
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()

    # Re-sanitise on read: stored HTML was sanitised at ingest, but the rendering path must not
    # depend on data written by an older version of the sanitiser.
    from msp_mail_parser import sanitize_html

    return SafePreviewResponse(
        message_id=message.id,
        sanitized_html=sanitize_html(content.sanitized_html) if content.sanitized_html else None,
        plain_text=content.normalized_text,
        urls=[{"url": value, "context": context} for value, context in urls],
    )


@router.get("/attachments/{attachment_id}/download")
def download_attachment(
    attachment_id: str,
    request: Request,
    actor: Downloader,
    session: DbSession,
    settings: AppSettings,
    confirm_dangerous: bool = Query(default=False),
) -> Response:
    """Download an attachment. Dangerous types require an explicit analyst confirmation."""
    attachment = session.get(Attachment, attachment_id)
    if attachment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Вложение не найдено")
    message = session.get(MailMessage, attachment.message_id)
    if message is None or message.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Вложение не найдено")
    if not attachment.storage_key or attachment.purged_at is not None:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Файл удалён политикой хранения")

    dangerous = attachment.detected_type in _DANGEROUS_TYPES or bool(
        {"EXECUTABLE", "SCRIPT", "SHORTCUT", "DOUBLE_EXTENSION"} & set(attachment.flags or [])
    )
    if dangerous and not confirm_dangerous:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Файл относится к потенциально опасному типу. Повторите запрос с "
                "confirm_dangerous=true, чтобы подтвердить осознанное скачивание."
            ),
        )

    try:
        data = build_storage(settings).get(attachment.storage_key)
    except Exception as exc:
        logger.warning("attachment.read_failed", extra={"error": type(exc).__name__})
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Хранилище недоступно"
        ) from exc

    record(
        session,
        action=AuditAction.ATTACHMENT_DOWNLOAD,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="attachment",
        object_id=attachment.id,
        detail={
            "sha256": attachment.sha256,
            "filename": attachment.normalized_filename,
            "dangerous": dangerous,
        },
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()

    # Always served as an inert download: never a type the browser would render or execute.
    safe_name = f"{attachment.sha256[:16]}.bin"
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}"',
            "X-Original-Filename-Sha256": attachment.sha256,
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
        },
    )


@router.get("/indicators/{ioc_type}/{value:path}")
def search_indicator(ioc_type: str, value: str, actor: Viewer, session: DbSession) -> dict[str, Any]:
    """Look up an indicator and the messages it was seen in (ТЗ 43.3)."""
    indicator = session.execute(
        select(Indicator).where(
            Indicator.organization_id == actor.organization_id,
            Indicator.ioc_type == ioc_type,
            func.lower(Indicator.value) == value.lower()[:1024],
        )
    ).scalar_one_or_none()
    if indicator is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Индикатор не найден")

    message_ids = (
        session.execute(
            select(IndicatorObservation.message_id)
            .where(IndicatorObservation.indicator_id == indicator.id)
            .limit(200)
        )
        .scalars()
        .all()
    )
    messages = (
        session.execute(
            select(MailMessage).where(MailMessage.id.in_([m for m in message_ids if m])).limit(100)
        )
        .scalars()
        .all()
    )
    return {
        "indicator": {
            "indicator_id": indicator.id,
            "ioc_type": indicator.ioc_type.value,
            "value": indicator.value,
            "first_seen": indicator.first_seen.isoformat(),
            "last_seen": indicator.last_seen.isoformat(),
            "sighting_count": indicator.sighting_count,
            "worst_status": indicator.worst_status.value if indicator.worst_status else None,
            "confirmed_malicious": indicator.confirmed_malicious,
        },
        "internal_sightings": indicator.sighting_count,
        "related_messages": [_summary(session, m) for m in messages],
        "provider_results": _provider_results(session, indicator.value),
        "related_campaigns": _related_campaigns(session, [m for m in message_ids if m]),
    }


def _provider_results(session, indicator_value: str) -> list[dict[str, Any]]:  # type: ignore[no-untyped-def]
    """Latest verdict per provider, with the age of the data (ТЗ 22.4).

    Cache age is shown because an old verdict is weaker evidence than a fresh one — the analyst
    must be able to see when a provider last actually looked at this indicator.
    """
    from msp_ti import cache_age_label

    lookups = (
        session.execute(
            select(ProviderLookup)
            .where(func.lower(ProviderLookup.indicator_value) == indicator_value.lower())
            .order_by(desc(ProviderLookup.fetched_at))
            .limit(50)
        )
        .scalars()
        .all()
    )
    latest: dict[str, Any] = {}
    for lookup in lookups:
        if lookup.provider_id in latest:
            continue
        result = TIResult(
            provider_id=lookup.provider_id,
            ioc_type=lookup.ioc_type,
            indicator=lookup.indicator_value,
            status=lookup.status,
            fetched_at=lookup.fetched_at,
        )
        latest[lookup.provider_id] = {
            "provider_id": lookup.provider_id,
            "status": lookup.status.value,
            "malicious_count": lookup.malicious_count,
            "total_count": lookup.total_count,
            "categories": list(lookup.categories or []),
            "summary": dict(lookup.summary or {}),
            "from_cache": lookup.from_cache,
            "fetched_at": lookup.fetched_at.isoformat(),
            "cache_age": cache_age_label(result),
            "error": lookup.error,
        }
    return list(latest.values())


def _related_campaigns(session, message_ids: list[str]) -> list[str]:  # type: ignore[no-untyped-def]
    if not message_ids:
        return []
    rows = (
        session.execute(
            select(CampaignMessage.campaign_id)
            .where(CampaignMessage.message_id.in_(message_ids))
            .distinct()
            .limit(50)
        )
        .scalars()
        .all()
    )
    return list(rows)
