"""Анализ теневой копии со шлюза (ТЗ 1.1 §35, §58, §68.16).

Главное свойство: сбой или вердикт анализа не касаются судьбы письма. Письмо к этому моменту
доставлено; здесь проверяется, что отказы анализа видны (а не «проверено, чисто») и что даже
самый плохой вердикт ничего не отклоняет, не удаляет и не откладывает.
"""

from __future__ import annotations

import hashlib

import pytest

PHISH = (
    b'From: "Security" <it-support@corp-example-login.test>\r\n'
    b"To: buh@corp.example\r\nSubject: Urgent: confirm your password\r\n"
    b"Message-ID: <phish1@evil.test>\r\nMIME-Version: 1.0\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n\r\n"
    b"<html><body>Your password expires today. "
    b'<a href="http://corp-example-login.test/verify">Confirm now</a></body></html>\r\n'
)
CLEAN = (
    b"From: colleague@corp.example\r\nTo: buh@corp.example\r\nSubject: lunch\r\n"
    b"Message-ID: <lunch1@corp.example>\r\nMIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\nLunch at noon?\r\n"
)


@pytest.fixture
def storage(storage_dir):  # type: ignore[no-untyped-def]
    from msp_api.config import get_settings
    from msp_api.services.storage import build_storage

    return build_storage(get_settings())


def make_message(db, organization, storage, raw: bytes | None, key: str = "k" * 64):  # type: ignore[no-untyped-def]
    from msp_api.db.models_transport import TransportMessage

    storage_key = None
    if raw is not None:
        storage_key = f"eml/{organization.id}/{hashlib.sha256(raw).hexdigest()}.eml"
        storage.put(storage_key, raw, content_type="message/rfc822")
    message = TransportMessage(
        organization_id=organization.id,
        node_id="a" * 32,
        idempotency_key=key,
        direction="INBOUND",
        content_sha256=hashlib.sha256(raw or b"").hexdigest(),
        size_bytes=len(raw or b""),
        raw_storage_key=storage_key,
    )
    db.add(message)
    db.commit()
    return message


def analyse(db, settings, message, storage):  # type: ignore[no-untyped-def]
    from msp_api.services.transport_analysis import analyze_transport_message

    return analyze_transport_message(db, settings, message.id, storage)


def test_a_copy_becomes_an_analysis_job_from_the_shadow_source(db, organization, settings, storage) -> None:  # type: ignore[no-untyped-def]
    from msp_api.db.models import AnalysisJob, AnalysisResult
    from msp_api.db.models_transport import TransportMessageState
    from msp_contracts import IntakeSource
    from sqlalchemy import select

    message = make_message(db, organization, storage, CLEAN)
    outcome, job_id = analyse(db, settings, message, storage)
    db.commit()
    assert outcome == "ANALYSED"
    assert message.state is TransportMessageState.ANALYSED
    job = db.get(AnalysisJob, job_id)
    assert job.source is IntakeSource.SHADOW
    assert db.execute(select(AnalysisResult).where(AnalysisResult.job_id == job_id)).scalar_one_or_none()


def test_a_second_run_does_not_create_a_second_analysis(db, organization, settings, storage) -> None:  # type: ignore[no-untyped-def]
    from msp_api.db.models import AnalysisJob
    from sqlalchemy import func, select

    message = make_message(db, organization, storage, CLEAN)
    first = analyse(db, settings, message, storage)
    db.commit()
    second = analyse(db, settings, message, storage)
    assert second[0] == "SKIPPED"
    assert second[1] == first[1]
    assert db.execute(select(func.count()).select_from(AnalysisJob)).scalar_one() == 1


def test_the_worst_verdict_changes_nothing_about_the_message(db, organization, settings, storage) -> None:  # type: ignore[no-untyped-def]
    """§58: даже MALICIOUS не отклоняет, не удаляет и не откладывает письмо — реагирования нет."""
    from msp_api.db.models import RemediationAction
    from msp_api.db.models_transport import TransportMessageState
    from sqlalchemy import func, select

    message = make_message(db, organization, storage, PHISH)
    outcome, _ = analyse(db, settings, message, storage)
    db.commit()
    assert outcome == "ANALYSED"
    assert message.state is TransportMessageState.ANALYSED
    assert db.execute(select(func.count()).select_from(RemediationAction)).scalar_one() == 0


def test_a_copy_that_was_never_stored_is_a_visible_failure(db, organization, settings, storage) -> None:  # type: ignore[no-untyped-def]
    from msp_api.db.models_transport import TransportMessageState

    message = make_message(db, organization, storage, None)
    outcome, job_id = analyse(db, settings, message, storage)
    assert (outcome, job_id) == ("FAILED", None)
    assert message.state is TransportMessageState.ANALYSIS_FAILED
    assert "не сохранена" in message.note


def test_unavailable_storage_is_a_visible_failure_not_a_clean_verdict(
    db, organization, settings, storage
) -> None:  # type: ignore[no-untyped-def]
    from msp_api.db.models_transport import TransportMessageState

    message = make_message(db, organization, storage, CLEAN)
    storage.delete(message.raw_storage_key)
    outcome, _ = analyse(db, settings, message, storage)
    assert outcome == "FAILED"
    assert message.state is TransportMessageState.ANALYSIS_FAILED


def test_an_analysis_crash_is_recorded_and_a_retry_reuses_the_same_job(  # type: ignore[no-untyped-def]
    db, organization, settings, storage, monkeypatch
) -> None:
    from msp_api.db.models import AnalysisJob
    from msp_api.db.models_transport import TransportMessageState
    from msp_api.services import transport_analysis
    from msp_contracts import JobState
    from sqlalchemy import func, select

    message = make_message(db, organization, storage, CLEAN)
    real = transport_analysis.run_local_analysis

    def boom(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("сбой разбора")

    monkeypatch.setattr(transport_analysis, "run_local_analysis", boom)
    outcome, job_id = analyse(db, settings, message, storage)
    db.commit()
    assert outcome == "FAILED"
    assert message.state is TransportMessageState.ANALYSIS_FAILED
    assert db.get(AnalysisJob, job_id).state is JobState.FAILED
    assert "RuntimeError" in message.note

    monkeypatch.setattr(transport_analysis, "run_local_analysis", real)
    outcome, retry_job = analyse(db, settings, message, storage)
    db.commit()
    assert outcome == "ANALYSED"
    assert retry_job == job_id
    assert db.execute(select(func.count()).select_from(AnalysisJob)).scalar_one() == 1


def test_an_unknown_message_is_skipped(db, organization, settings, storage) -> None:  # type: ignore[no-untyped-def]
    from msp_api.services.transport_analysis import analyze_transport_message

    assert analyze_transport_message(db, settings, "missing", storage) == ("SKIPPED", None)
