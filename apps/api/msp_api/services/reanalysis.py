"""Bulk re-evaluation of historical mail (ТЗ 1.0.3B §23).

Re-running a month of mail through new rules is the single operation most able to flood an
organisation with alarms about messages people dealt with weeks ago. Every control here exists to
keep it an analysis rather than an event:

* **dry run by default** — the answer is a proposal until someone decides to apply it;
* **no notifications and no remediation**, ever, regardless of what the new verdicts say;
* **a hard ceiling** on how many messages one job may touch;
* **pause, resume and cancel**, because a job that cannot be stopped will be stopped by killing
  a worker, and that leaves the state nobody can reason about;
* **a cursor**, so a paused job continues where it stopped instead of starting over.

The job runs in bounded slices. A slice is small enough that pausing takes effect quickly and
large enough that the per-slice overhead stays irrelevant.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from msp_contracts import RISK_ORDER, ReanalysisState, utcnow
from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.models import AnalysisJob, AnalysisResult, MailMessage, ReanalysisJob
from ..observability import replay_duration, replay_jobs_total
from . import detection_ops

logger = logging.getLogger(__name__)

#: Messages processed per slice. Keeps a pause responsive without making the loop chatty.
SLICE_SIZE = 50
#: Hard ceiling on one job, whatever the caller asks for.
MAX_MESSAGES = 20_000
#: Longest window a single job may cover.
MAX_WINDOW_DAYS = 365


class ReanalysisError(ValueError):
    """A job that cannot be created or driven, with the reason in the message."""


@dataclass
class Window:
    start: datetime
    end: datetime


def _window(days: int | None, start: datetime | None, end: datetime | None) -> Window:
    now = utcnow()
    if start and end:
        if end <= start:
            raise ReanalysisError("конец окна должен быть позже начала")
        if (end - start).days > MAX_WINDOW_DAYS:
            raise ReanalysisError(f"окно больше {MAX_WINDOW_DAYS} дней")
        return Window(start=start, end=end)
    if not days or days <= 0:
        raise ReanalysisError("укажите период в днях или границы окна")
    if days > MAX_WINDOW_DAYS:
        raise ReanalysisError(f"окно больше {MAX_WINDOW_DAYS} дней")
    return Window(start=now - timedelta(days=days), end=now)


def create_job(
    session: Session,
    *,
    organization_id: str,
    requested_by: str,
    days: int | None = 7,
    window_from: datetime | None = None,
    window_to: datetime | None = None,
    dry_run: bool = True,
    filters: dict[str, Any] | None = None,
    max_messages: int = 5000,
    ruleset_source: str = "",
) -> ReanalysisJob:
    """Queue a re-evaluation. Nothing runs until it is driven."""
    window = _window(days, window_from, window_to)
    if max_messages <= 0 or max_messages > MAX_MESSAGES:
        raise ReanalysisError(f"предел сообщений — от 1 до {MAX_MESSAGES}")

    running = (
        session.execute(
            select(ReanalysisJob).where(
                ReanalysisJob.organization_id == organization_id,
                ReanalysisJob.state.in_([ReanalysisState.QUEUED, ReanalysisState.RUNNING]),
            )
        )
        .scalars()
        .first()
    )
    if running is not None:
        # One at a time per organisation. Two concurrent bulk jobs would compete for the same
        # workers and make both of them slow for no benefit.
        raise ReanalysisError("для организации уже выполняется переоценка")

    job = ReanalysisJob(
        organization_id=organization_id,
        state=ReanalysisState.QUEUED,
        dry_run=dry_run,
        window_from=window.start,
        window_to=window.end,
        filters=filters or {},
        ruleset_source=ruleset_source[:512],
        max_messages=max_messages,
        requested_by=requested_by,
    )
    session.add(job)
    session.flush()
    job.total_messages = _count_candidates(session, job)
    replay_jobs_total.labels("dry_run" if dry_run else "applied").inc()
    logger.info(
        "reanalysis.created",
        extra={"job_id": job.id, "dry_run": dry_run, "messages": job.total_messages},
    )
    return job


def _candidate_query(job: ReanalysisJob) -> Select[Any]:
    query = (
        select(AnalysisJob)
        .join(MailMessage, MailMessage.id == AnalysisJob.message_id)
        .where(
            AnalysisJob.organization_id == job.organization_id,
            AnalysisJob.message_id.is_not(None),
            MailMessage.received_at >= job.window_from,
            MailMessage.received_at <= job.window_to,
        )
    )
    filters = job.filters or {}
    if sender := filters.get("sender"):
        query = query.where(MailMessage.sender_address == str(sender).lower())
    if domain := filters.get("sender_domain"):
        query = query.where(MailMessage.sender_domain == str(domain).lower())
    if campaign := filters.get("campaign_fingerprint"):
        query = query.where(MailMessage.campaign_fingerprint == str(campaign))
    if recipient := filters.get("recipient_mailbox"):
        query = query.where(MailMessage.source_mailbox == str(recipient).lower())
    return query.order_by(MailMessage.received_at, AnalysisJob.id)


def _count_candidates(session: Session, job: ReanalysisJob) -> int:
    rows: list[AnalysisJob] = list(
        session.execute(_candidate_query(job).limit(job.max_messages + 1)).scalars().all()
    )
    return min(len(rows), job.max_messages)


def start(job: ReanalysisJob) -> ReanalysisJob:
    if job.state not in {ReanalysisState.QUEUED, ReanalysisState.PAUSED}:
        raise ReanalysisError("задание нельзя запустить из текущего состояния")
    job.state = ReanalysisState.RUNNING
    job.started_at = job.started_at or utcnow()
    return job


def pause(job: ReanalysisJob, *, actor: str = "") -> ReanalysisJob:
    if job.state is not ReanalysisState.RUNNING:
        raise ReanalysisError("приостановить можно только выполняющееся задание")
    job.state = ReanalysisState.PAUSED
    logger.info("reanalysis.paused", extra={"job_id": job.id, "actor": actor})
    return job


def cancel(job: ReanalysisJob, *, actor: str) -> ReanalysisJob:
    if job.state in {ReanalysisState.COMPLETED, ReanalysisState.CANCELLED}:
        raise ReanalysisError("задание уже завершено")
    job.state = ReanalysisState.CANCELLED
    job.cancelled_by = actor
    job.finished_at = utcnow()
    logger.info("reanalysis.cancelled", extra={"job_id": job.id, "actor": actor})
    return job


def run_slice(
    session: Session,
    settings: Settings,
    job: ReanalysisJob,
    *,
    size: int = SLICE_SIZE,
) -> ReanalysisJob:
    """Process the next slice of a running job.

    Returns after at most ``size`` messages so that a pause or a cancel takes effect quickly.
    Nothing here notifies anyone or proposes remediation, whatever the new verdicts say.
    """
    if job.state is not ReanalysisState.RUNNING:
        raise ReanalysisError("задание не выполняется")

    remaining = max(0, min(job.max_messages - job.cursor, size))
    if remaining == 0:
        return finish(job)

    analyses: list[AnalysisJob] = list(
        session.execute(_candidate_query(job).offset(job.cursor).limit(remaining)).scalars().all()
    )
    if not analyses:
        return finish(job)

    sample = list(job.sample or [])
    for analysis in analyses:
        job.cursor += 1
        job.processed += 1
        previous = session.execute(
            select(AnalysisResult).where(AnalysisResult.job_id == analysis.id)
        ).scalar_one_or_none()
        if previous is None or not analysis.message_id:
            continue
        simulation = detection_ops.simulate(session, settings, message_id=analysis.message_id)
        if simulation is None:
            continue
        if simulation.classification is previous.classification:
            continue

        job.verdict_changed += 1
        escalated = RISK_ORDER[simulation.classification] > RISK_ORDER[previous.classification]
        if escalated:
            job.newly_suspicious += 1
        else:
            job.newly_cleared += 1
        if len(sample) < 100:
            message = session.get(MailMessage, analysis.message_id)
            sample.append(
                {
                    "analysis_id": analysis.id,
                    "message_id": analysis.message_id,
                    "subject": (message.subject if message else "")[:120],
                    "before": previous.classification.value,
                    "after": simulation.classification.value,
                    "escalated": escalated,
                }
            )
        if not job.dry_run:
            previous.classification = simulation.classification
            previous.score = simulation.score

    job.sample = sample
    if job.cursor >= min(job.total_messages, job.max_messages):
        return finish(job)
    return job


def finish(job: ReanalysisJob) -> ReanalysisJob:
    job.state = ReanalysisState.COMPLETED
    job.finished_at = utcnow()
    if job.started_at is not None:
        replay_duration.observe((job.finished_at - job.started_at).total_seconds())
    logger.info(
        "reanalysis.finished",
        extra={
            "job_id": job.id,
            "processed": job.processed,
            "changed": job.verdict_changed,
            "dry_run": job.dry_run,
        },
    )
    return job


def run_to_completion(
    session: Session, settings: Settings, job: ReanalysisJob, *, max_slices: int = 1000
) -> ReanalysisJob:
    """Drive a job to the end, honouring pause and cancel between slices."""
    start(job)
    for _ in range(max_slices):
        if job.state is not ReanalysisState.RUNNING:
            break
        run_slice(session, settings, job)
    return job


def as_dict(job: ReanalysisJob) -> dict[str, Any]:
    return {
        "job_id": job.id,
        "state": job.state.value,
        "dry_run": job.dry_run,
        "window_from": job.window_from.isoformat(),
        "window_to": job.window_to.isoformat(),
        "filters": job.filters,
        "max_messages": job.max_messages,
        "total_messages": job.total_messages,
        "processed": job.processed,
        # Null until the batch size is known, rather than 0% — "not started" and "nothing to do"
        # look the same otherwise.
        "progress": job.progress,
        "verdict_changed": job.verdict_changed,
        "newly_suspicious": job.newly_suspicious,
        "newly_cleared": job.newly_cleared,
        "sample": job.sample,
        "requested_by": job.requested_by,
        "cancelled_by": job.cancelled_by,
        "created_at": job.created_at.isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }
