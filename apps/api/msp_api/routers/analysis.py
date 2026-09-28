"""Analysis endpoints — the path used by the Outlook add-in (ТЗ 6, 30, 40)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from msp_contracts import AnalysisStatus, IntakeSource, JobState, RiskLevel
from sqlalchemy import desc, func, select

from ..db.base import utcnow
from ..db.models import AnalysisJob, AnalysisResult, DetectionSignal, MailMessage, User
from ..deps import (
    Actor,
    AppSettings,
    CurrentActor,
    DbSession,
    client_ip,
    rate_limit,
    require_permission,
)
from ..observability import analyses_total, analysis_duration, employee_reports, job_id_var
from ..schemas import (
    AnalysisDetailResponse,
    AnalysisStatusResponse,
    AnalystReasonOut,
    AnalyzeRequest,
    ReasonOut,
    SignalOut,
)
from ..security.audit import AuditAction, record
from ..security.rbac import Permission, can_access_job
from ..services.analysis import employee_view, run_local_analysis
from ..services.storage import build_storage
from ..tasks import enqueue_enrichment

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analysis", tags=["analysis"])


def _decode_eml(payload: str, max_bytes: int) -> bytes:
    try:
        raw = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="raw_eml_base64 не является корректным base64"
        ) from exc
    if not raw:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Пустое сообщение")
    if len(raw) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Размер письма превышает допустимый лимит",
        )
    return raw


@router.post("", response_model=AnalysisStatusResponse, status_code=status.HTTP_202_ACCEPTED)
def submit_analysis(
    payload: AnalyzeRequest,
    request: Request,
    actor: CurrentActor,
    session: DbSession,
    settings: AppSettings,
) -> AnalysisStatusResponse:
    """Submit a message for analysis.

    Idempotent per (user, content): re-submitting the same message returns the existing job
    instead of creating a duplicate (ТЗ 30).
    """
    if not actor.can(Permission.ANALYZE_OWN_MESSAGE):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Недостаточно прав")
    rate_limit(f"analysis:{actor.user_id}", settings.rate_limit_analysis_per_minute)

    if not payload.raw_eml_base64:
        # Fetching by Exchange reference requires a verified Exchange provider (ТЗ 51).
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(
                "Получение письма по ссылке Exchange недоступно в этой конфигурации. "
                "Передайте письмо в службу ИБ через кнопку «Сообщить о фишинге»."
            ),
        )
    raw = _decode_eml(payload.raw_eml_base64, settings.max_upload_bytes)

    user = session.get(User, actor.user_id)
    mailbox = (payload.mailbox or (user.email if user else "")).lower()[:320]
    if not actor.can(Permission.VIEW_INVESTIGATIONS) and user is not None and mailbox != user.email.lower():
        # An employee may only submit messages from their own mailbox.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Можно анализировать только собственные письма"
        )

    digest = hashlib.sha256(raw).hexdigest()
    idempotency_key = f"{actor.user_id}:{digest}:{int(payload.report_as_phishing)}"
    existing = session.execute(
        select(AnalysisJob).where(AnalysisJob.idempotency_key == idempotency_key)
    ).scalar_one_or_none()
    if existing is not None:
        return _status_response(session, existing)

    job = AnalysisJob(
        organization_id=actor.organization_id,
        requested_by=actor.user_id,
        requester_mailbox=mailbox,
        source=IntakeSource.ADDIN_REPORT if payload.report_as_phishing else IntakeSource.ADDIN,
        is_report=payload.report_as_phishing,
        user_note=payload.note[:2000],
        idempotency_key=idempotency_key,
    )
    session.add(job)
    session.flush()
    job_id_var.set(job.id)

    storage = build_storage(settings)
    try:
        outcome = run_local_analysis(session, settings, job=job, raw=raw, storage=storage)
    except Exception as exc:  # noqa: BLE001 - a backend failure must not break Outlook (ТЗ 40.9)
        logger.exception("analysis.failed", extra={"analysis_job_id": job.id})
        job.state = JobState.FAILED
        job.status = AnalysisStatus.ERROR
        job.error = f"{type(exc).__name__}"[:500]
        job.finished_at = utcnow()
        session.commit()
        return AnalysisStatusResponse(
            job_id=job.id,
            status=AnalysisStatus.ERROR,
            message="Не удалось выполнить анализ письма. Обратитесь в службу информационной безопасности.",
        )

    analyses_total.labels(outcome.verdict.classification.value, job.source.value).inc()
    analysis_duration.labels("local").observe(outcome.duration_ms / 1000)
    if payload.report_as_phishing:
        employee_reports.inc()

    record(
        session,
        action=AuditAction.ANALYSIS_REPORTED if payload.report_as_phishing else AuditAction.ANALYSIS_REQUESTED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="analysis_job",
        object_id=job.id,
        detail={
            "classification": outcome.verdict.classification.value,
            "score": outcome.verdict.score,
            "sha256": digest,
            "source": job.source.value,
        },
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()

    enqueue_enrichment(job.id)
    return _status_response(session, job)


@router.get("/{job_id}", response_model=AnalysisStatusResponse)
def get_analysis_status(job_id: str, actor: CurrentActor, session: DbSession) -> AnalysisStatusResponse:
    """Employee-facing status. Cross-user access is refused (ТЗ 40.6)."""
    job = session.get(AnalysisJob, job_id)
    if job is None or job.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Анализ не найден")
    user = session.get(User, actor.user_id)
    if not can_access_job(
        role=actor.role,
        actor_user_id=actor.user_id,
        actor_mailbox=user.email if user else "",
        job_owner_id=job.requested_by,
        job_mailbox=job.requester_mailbox,
    ):
        # 404 rather than 403: existence of another user's analysis is not disclosed.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Анализ не найден")
    return _status_response(session, job)


@router.get("/{job_id}/detail", response_model=AnalysisDetailResponse)
def get_analysis_detail(
    job_id: str,
    request: Request,
    session: DbSession,
    actor: Annotated[Actor, Depends(require_permission(Permission.VIEW_INVESTIGATIONS))],
) -> AnalysisDetailResponse:
    """Analyst-facing detail with full evidence and rule versions."""
    job = session.get(AnalysisJob, job_id)
    if job is None or job.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Анализ не найден")
    result = session.execute(
        select(AnalysisResult).where(AnalysisResult.job_id == job.id)
    ).scalar_one_or_none()
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Результат ещё не готов")

    signals = session.execute(
        select(DetectionSignal).where(DetectionSignal.result_id == result.id).order_by(
            desc(DetectionSignal.weight)
        )
    ).scalars().all()
    record(
        session,
        action=AuditAction.MESSAGE_VIEW,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="analysis_job",
        object_id=job.id,
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()

    campaign_id = None
    if job.message_id:
        from ..db.models import CampaignMessage

        campaign_id = session.execute(
            select(CampaignMessage.campaign_id).where(CampaignMessage.message_id == job.message_id)
        ).scalar_one_or_none()

    return AnalysisDetailResponse(
        job_id=job.id,
        message_id=job.message_id,
        status=job.status,
        state=job.state.value,
        ti_state=job.ti_state.value,
        classification=result.classification,
        score=result.score,
        confidence=result.confidence,
        recommendation=result.recommendation,
        reasons=[AnalystReasonOut(**r) for r in result.reasons],
        hard_signals=[AnalystReasonOut(**r) for r in result.hard_signals],
        suppressed_signals=[AnalystReasonOut(**r) for r in result.suppressed_signals],
        sources=list(result.sources or []),
        missing_evidence=list(result.missing_evidence or []),
        signals=[
            SignalOut(
                signal_id=s.signal_id,
                rule_id=s.rule_id,
                rule_version=s.rule_version,
                category=s.category,
                title=s.title,
                explanation=s.explanation,
                severity=s.severity,
                confidence=s.confidence,
                weight=s.weight,
                source=s.source,
                evidence=s.evidence,
                hard=s.hard,
                internal=s.internal,
                suppressed=s.suppressed,
                suppressed_by=s.suppressed_by,
            )
            for s in signals
        ],
        engine_version=result.engine_version,
        risk_engine_version=result.risk_engine_version,
        duration_ms=job.duration_ms,
        campaign_id=campaign_id,
    )


@router.get("", response_model=list[AnalysisStatusResponse])
def list_my_analyses(
    actor: CurrentActor, session: DbSession, limit: int = 20
) -> list[AnalysisStatusResponse]:
    """An employee's own analyses (ТЗ 23)."""
    limit = max(1, min(limit, 100))
    jobs = session.execute(
        select(AnalysisJob)
        .where(
            AnalysisJob.organization_id == actor.organization_id,
            AnalysisJob.requested_by == actor.user_id,
        )
        .order_by(desc(AnalysisJob.created_at))
        .limit(limit)
    ).scalars().all()
    return [_status_response(session, job) for job in jobs]


def _status_response(session, job: AnalysisJob) -> AnalysisStatusResponse:  # type: ignore[no-untyped-def]
    result = session.execute(
        select(AnalysisResult).where(AnalysisResult.job_id == job.id)
    ).scalar_one_or_none()
    if result is None:
        return AnalysisStatusResponse(
            job_id=job.id,
            status=job.status,
            reported_to_security=job.is_report,
            ti_state=job.ti_state.value,
            message="Анализ выполняется" if job.state != JobState.FAILED else "Анализ завершился ошибкой",
        )
    reasons = [
        ReasonOut(title=r["title"], explanation=r["explanation"], severity=r["severity"])
        for r in (result.reasons or [])
        if not r.get("internal")
    ][:5]
    return AnalysisStatusResponse(
        job_id=job.id,
        status=job.status,
        classification=result.classification,
        confidence=result.confidence,
        recommendation=result.recommendation,
        reasons=reasons,
        analysis_incomplete=bool(result.missing_evidence),
        analyzed_at=job.finished_at or job.started_at,
        reported_to_security=job.is_report,
        ti_state=job.ti_state.value,
    )
