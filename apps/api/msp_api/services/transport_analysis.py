"""Анализ теневой копии письма, снятой шлюзом (ТЗ 1.1 §35, §58).

Копия уже принята в хранилище, а письмо давно ушло получателю независимо от того, что здесь
произойдёт. Поэтому любой сбой анализа — это потеря *наблюдения*, и он записывается и считается
(``ANALYSIS_FAILED``, а не молчаливое «проверено»), но никогда не возвращается к узлу и не
влияет на доставку (политика ``DETECTION_FAILS_OPEN_FOR_DELIVERY``).

Вердикт здесь не меняет судьбу письма: даже ``MALICIOUS`` не отклоняет, не удаляет и не откладывает
его (§58). Реагирование — отдельная, явно включаемая подсистема, и в режиме теневой валидации она
выключена на уровне настроек.
"""

from __future__ import annotations

import logging

from msp_contracts import AnalysisStatus, IntakeSource, JobState
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.models import AnalysisJob
from ..db.models_transport import TransportMessage, TransportMessageState
from .analysis import run_local_analysis
from .storage import ObjectStorage

logger = logging.getLogger(__name__)


def analyze_transport_message(
    session: Session, settings: Settings, message_id: str, storage: ObjectStorage
) -> tuple[str, str | None]:
    """Вернуть (итог, идентификатор задачи анализа). Итог: ANALYSED, FAILED, SKIPPED."""
    message = session.get(TransportMessage, message_id)
    if message is None:
        return "SKIPPED", None
    if message.analysis_job_id and message.state is TransportMessageState.ANALYSED:
        return "SKIPPED", message.analysis_job_id
    if not message.raw_storage_key:
        message.state = TransportMessageState.ANALYSIS_FAILED
        message.note = "копия письма не сохранена: анализировать нечего"
        return "FAILED", None
    try:
        raw = storage.get(message.raw_storage_key)
    except Exception as exc:  # noqa: BLE001 - хранилище недоступно: копия остаётся, анализ повторят
        logger.warning("transport.analysis_raw_unavailable", extra={"error": type(exc).__name__})
        message.state = TransportMessageState.ANALYSIS_FAILED
        message.note = f"копия недоступна в хранилище: {type(exc).__name__}"
        return "FAILED", None

    # Повтор после сбоя использует ту же задачу: ключ идемпотентности уникален, вторая запись упала бы.
    job = session.get(AnalysisJob, message.analysis_job_id) if message.analysis_job_id else None
    if job is None:
        job = AnalysisJob(
            organization_id=message.organization_id,
            source=IntakeSource.SHADOW,
            requester_mailbox="",
            is_report=False,
            idempotency_key=f"shadow:{message.idempotency_key}",
        )
        session.add(job)
        session.flush()
    else:
        job.state, job.status, job.error = JobState.QUEUED, AnalysisStatus.QUEUED, None
    message.analysis_job_id = job.id
    try:
        run_local_analysis(session, settings, job=job, raw=raw, storage=storage)
    except Exception as exc:
        logger.exception("transport.analysis_failed", extra={"analysis_job_id": job.id})
        job.state = JobState.FAILED
        job.status = AnalysisStatus.ERROR
        job.error = type(exc).__name__
        message.state = TransportMessageState.ANALYSIS_FAILED
        message.note = f"анализ не выполнен: {type(exc).__name__}"
        return "FAILED", job.id
    message.state = TransportMessageState.ANALYSED
    return "ANALYSED", job.id
