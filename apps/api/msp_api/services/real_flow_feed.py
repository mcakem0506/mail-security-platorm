"""Приём журнального отчёта Exchange в набор валидации реального потока (MSP 1.3P, ТЗ 1.3P §10, §15, §16).

До этого этапа в набор валидации ничего не попадало из рабочего кода: функция ``real_flow.ingest`` вызывалась только
тестами. Здесь она подключена к двум существующим механизмам, а не заменена третьим:

* **надёжный приём** — ``intake.begin_intake``: запись и содержимое сохраняются до подтверждения; повтор того же письма
  узнаётся и не запускает анализ второй раз;
* **анализ** — ``analysis.run_local_analysis`` тем же путём, что и теневая копия шлюза; сбой не теряет письмо, а оставляет
  запись в состоянии, которое можно повторить.

Письмо, которое проверить нельзя (оригинал сверх предела, нет вложения, отчёт в отчёте), не пропадает и не получает
вердикт «чисто»: оно записывается как непроверенное и попадает в долю ``UNKNOWN/UNSCANNABLE`` на 1000.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from msp_contracts import AnalysisStatus, IntakeSource, JobState, RiskLevel, ValidationSource
from msp_mail_parser.anonymize import fingerprint
from msp_mail_parser.journal import JournalExtraction, extract_journal_report
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.models import AnalysisJob, AnalysisResult
from . import real_flow
from .analysis import run_local_analysis
from .intake import attach_job, begin_intake, mark_acknowledged, mark_failed, unscannable_job
from .storage import ObjectStorage

logger = logging.getLogger(__name__)

#: Размер отчёта сверх оригинала: заголовки, текстовая часть, кодирование вложения.
REPORT_OVERHEAD_FACTOR = 1.5


class FeedError(Exception):
    def __init__(self, message: str, status: int = 409) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class FeedOutcome:
    #: ANALYSED | DUPLICATE | UNSCANNABLE | FAILED
    status: str
    validation_id: str | None = None
    intake_id: str | None = None
    created: bool = False
    problems: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "validation_id": self.validation_id,
            "intake_id": self.intake_id,
            "created": self.created,
            "problems": list(self.problems),
        }


def require_ready(settings: Settings) -> None:
    """Приём реальной почты начинается только в теневом режиме и с заданной солью отпечатка."""
    if not settings.real_flow_shadow:
        raise FeedError("приём реальной почты разрешён только при MSP_REAL_FLOW_SHADOW=true")
    if len((settings.real_flow_fingerprint_salt or "").strip()) < 16:
        raise FeedError("не задана соль отпечатка (MSP_REAL_FLOW_FINGERPRINT_SALT, не менее 16 символов)")


def _corporate(settings: Settings) -> tuple[str, ...]:
    return tuple(d.strip().lower() for d in (settings.corporate_domains or "").split(",") if d.strip())


def _verdict(session: Session, job: AnalysisJob) -> tuple[RiskLevel | None, list[str], str, str]:
    result = session.execute(
        select(AnalysisResult).where(AnalysisResult.job_id == job.id)
    ).scalar_one_or_none()
    if result is None:
        return None, [], "", ""
    rules = sorted({s.rule_id for s in result.signals if s.rule_id})
    return result.classification, rules, result.ruleset_fingerprint[:64], result.risk_engine_version


def ingest_journal_report(
    session: Session,
    settings: Settings,
    organization_id: str,
    raw_report: bytes,
    *,
    storage: ObjectStorage,
    source: ValidationSource = ValidationSource.JOURNAL_COPY,
    source_id: str = "journal",
    received_at: datetime | None = None,
) -> FeedOutcome:
    """Принять один журнальный отчёт: оригинал → надёжный приём → анализ → запись набора валидации."""
    require_ready(settings)
    if len(raw_report) > int(settings.limit_message_size * REPORT_OVERHEAD_FACTOR):
        # Отчёт слишком велик, чтобы его разбирать: оригинал внутри заведомо сверх предела.
        extraction = JournalExtraction(
            True,
            report_sha256=hashlib.sha256(raw_report).hexdigest(),
            problems=("ORIGINAL_OVERSIZED",),
        )
    else:
        extraction = extract_journal_report(raw_report, max_original_bytes=settings.limit_message_size)

    if extraction.usable:
        return _ingest_usable(
            session, settings, organization_id, extraction, storage, source, source_id, received_at
        )
    return _ingest_unscannable(
        session, settings, organization_id, raw_report, extraction, storage, source, source_id, received_at
    )


def _identity(structural: str, message_id: str, salt: bytes) -> str:
    """Идентичность письма в выборке: структурный отпечаток плюс Message-ID оригинала.

    Структурный отпечаток устойчив к обезличиванию, но у типовых рассылок (счета, уведомления одного отправителя) он
    одинаков для разных писем, и выборка занижалась бы. Message-ID различает такие письма и по-прежнему одинаков, когда то же
    письмо пришло из двух источников. Письмо без Message-ID определяется только структурой: это ограничение записано в
    документации пилота.
    """
    mid = (message_id or "").strip().strip("<>").lower()
    if not mid:
        return structural
    return "j1:" + hmac.new(salt, f"{structural}|{mid}".encode(), hashlib.sha256).hexdigest()[:32]


def _sampling(source: ValidationSource, extraction: JournalExtraction) -> list[str]:
    reasons = [f"source:{source.value}"]
    if extraction.envelope_recipients:
        reasons.append(f"envelope_recipients:{min(len(extraction.envelope_recipients), 99)}")
    return reasons


def _ingest_usable(
    session: Session,
    settings: Settings,
    organization_id: str,
    extraction: JournalExtraction,
    storage: ObjectStorage,
    source: ValidationSource,
    source_id: str,
    received_at: datetime | None,
) -> FeedOutcome:
    salt = settings.real_flow_fingerprint_salt.encode()
    print_ = _identity(
        fingerprint(extraction.original, salt, corporate_domains=_corporate(settings)),
        extraction.original_message_id,
        salt,
    )
    outcome = begin_intake(
        session,
        settings,
        organization_id=organization_id,
        source=IntakeSource.SHADOW,
        source_id=f"journal:{source_id}",
        mailbox_uid=extraction.original_sha256[:48],
        raw=extraction.original,
        internet_message_id=extraction.original_message_id,
        content_sha256=extraction.original_sha256,
        actual_size=extraction.original_size,
        warnings=list(extraction.problems),
        storage=storage,
    )
    record = outcome.record
    sampling = _sampling(source, extraction)
    if outcome.is_duplicate or (not outcome.created and record.analysis_job_id):
        # То же письмо из другого источника или повторная доставка: выборка не растёт, дополняется происхождение.
        validation, created = real_flow.ingest(
            session,
            real_flow.IngestRequest(
                organization_id=organization_id,
                source=source,
                message_fingerprint=print_,
                received_at=received_at,
                sampling_reasons=sampling,
                raw_retention_days=settings.raw_message_retention_days,
            ),
        )
        return FeedOutcome("DUPLICATE", validation.id, record.id, created)

    key = f"intake:{record.id}"
    # Повтор после сбоя использует прежнюю задачу: ключ идемпотентности уникален, вторая запись упала бы.
    job = session.execute(
        select(AnalysisJob).where(
            AnalysisJob.organization_id == organization_id, AnalysisJob.idempotency_key == key
        )
    ).scalar_one_or_none()
    if job is None:
        job = AnalysisJob(
            organization_id=organization_id,
            source=IntakeSource.SHADOW,
            requester_mailbox="",
            is_report=False,
            idempotency_key=key,
        )
        session.add(job)
        session.flush()
    else:
        job.state, job.status, job.error = JobState.QUEUED, AnalysisStatus.QUEUED, None
    try:
        run_local_analysis(session, settings, job=job, raw=extraction.original, storage=storage)
    except Exception as exc:
        logger.exception("real_flow.journal_analysis_failed", extra={"analysis_job_id": job.id})
        job.state = JobState.FAILED
        job.status = AnalysisStatus.ERROR
        job.error = type(exc).__name__
        mark_failed(record, type(exc).__name__)
        return FeedOutcome("FAILED", None, record.id, False, ("ANALYSIS_FAILED",))
    attach_job(record, job)
    verdict, rules, ruleset, engine = _verdict(session, job)
    validation, created = real_flow.ingest(
        session,
        real_flow.IngestRequest(
            organization_id=organization_id,
            source=source,
            message_fingerprint=print_,
            received_at=received_at,
            production_verdict=verdict,
            ruleset_version=ruleset,
            risk_engine_version=engine,
            triggered_rules=rules,
            sampling_reasons=sampling,
            raw_retention_days=settings.raw_message_retention_days,
        ),
    )
    mark_acknowledged(record)
    return FeedOutcome("ANALYSED", validation.id, record.id, created, tuple(extraction.problems))


def _ingest_unscannable(
    session: Session,
    settings: Settings,
    organization_id: str,
    raw_report: bytes,
    extraction: JournalExtraction,
    storage: ObjectStorage,
    source: ValidationSource,
    source_id: str,
    received_at: datetime | None,
) -> FeedOutcome:
    """Непригодный отчёт: сохраняется, считается непроверенным и никогда не получает вердикт «чисто»."""
    report_sha = extraction.report_sha256 or hashlib.sha256(raw_report).hexdigest()
    reasons = list(extraction.problems) or ["NOT_ANALYSED"]
    outcome = begin_intake(
        session,
        settings,
        organization_id=organization_id,
        source=IntakeSource.SHADOW,
        source_id=f"journal:{source_id}",
        mailbox_uid=report_sha[:48],
        raw=raw_report,
        internet_message_id=extraction.report_message_id,
        content_sha256=report_sha,
        oversized="ORIGINAL_OVERSIZED" in reasons,
        actual_size=extraction.original_size or len(raw_report),
        warnings=reasons,
        storage=storage,
    )
    record = outcome.record
    # Отпечаток отчёта: у письма без оригинала другого отпечатка нет. Он не пересекается с отпечатками писем.
    print_ = (
        "report:"
        + hashlib.sha256(settings.real_flow_fingerprint_salt.encode() + report_sha.encode()).hexdigest()[:32]
    )
    if not (outcome.is_duplicate or (not outcome.created and record.analysis_job_id)):
        unscannable_job(
            session,
            organization_id=organization_id,
            record=record,
            reason="журнальный отчёт не проанализирован: " + ", ".join(reasons),
        )
    validation, created = real_flow.ingest(
        session,
        real_flow.IngestRequest(
            organization_id=organization_id,
            source=source,
            message_fingerprint=print_,
            received_at=received_at,
            production_verdict=None,
            unscannable_reasons=reasons,
            sampling_reasons=[f"source:{source.value}", "unscannable"],
            raw_retention_days=settings.raw_message_retention_days,
        ),
    )
    return FeedOutcome("UNSCANNABLE", validation.id, record.id, created, tuple(reasons))
