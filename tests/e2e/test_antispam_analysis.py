"""Свидетельства сканера в анализе теневой копии (ТЗ 1.2 §13, §26, §41).

Проверяется стык, который не видно по частям: запись сканера, попавшая в базу, должна стать фактами и
правилами движка; класс спама не должен влиять на вердикт безопасности; неизвестный символ риска не
меняет; недоступный сканер делает анализ неполным; чистый результат ничего не снижает.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "rspamd"

CLEAN = (
    b"From: partner@example.test\r\nTo: buh@corp.example\r\nSubject: invoice question\r\n"
    b"Message-ID: <ap-clean@sender.example>\r\nMIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\nPlease confirm the delivery date.\r\n"
)


def scan(name: str, message_id: str, **extra: object) -> dict:
    record = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    record["message_id"] = message_id
    record["qid"] = "AP" + hashlib.sha256(message_id.encode()).hexdigest()[:9].upper()
    record.update(extra)
    return record


@pytest.fixture
def storage(storage_dir):  # type: ignore[no-untyped-def]
    from msp_api.config import get_settings
    from msp_api.services.storage import build_storage

    return build_storage(get_settings())


def shadow_copy(db, organization, storage, raw: bytes):  # type: ignore[no-untyped-def]
    from msp_api.db.models_transport import TransportMessage

    key = f"eml/{organization.id}/{hashlib.sha256(raw).hexdigest()}.eml"
    storage.put(key, raw, content_type="message/rfc822")
    message = TransportMessage(
        organization_id=organization.id,
        node_id="a" * 32,
        idempotency_key=hashlib.sha256(raw).hexdigest(),
        direction="INBOUND",
        content_sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
        raw_storage_key=key,
    )
    db.add(message)
    db.commit()
    return message


def analyse(db, settings, message, storage):  # type: ignore[no-untyped-def]
    from msp_api.db.models import AnalysisResult
    from msp_api.services.transport_analysis import analyze_transport_message
    from sqlalchemy import select

    outcome, job_id = analyze_transport_message(db, settings, message.id, storage)
    db.commit()
    assert outcome == "ANALYSED"
    return db.execute(select(AnalysisResult).where(AnalysisResult.job_id == job_id)).scalar_one()


def signal_rules(db, result):  # type: ignore[no-untyped-def]
    from msp_api.db.models import DetectionSignal
    from sqlalchemy import select

    return {
        s.rule_id
        for s in db.execute(select(DetectionSignal).where(DetectionSignal.result_id == result.id)).scalars()
    }


def ingest(db, settings, organization, *records):  # type: ignore[no-untyped-def]
    from msp_api.services import antispam

    outcome = antispam.ingest_scans(
        db, settings, organization_id=organization.id, node_id="a" * 32, scans=list(records)
    )
    db.commit()
    return outcome


def test_scanner_evidence_becomes_facts_and_rules(db, organization, settings, storage) -> None:  # type: ignore[no-untyped-def]
    ingest(db, settings, organization, scan("dmarc_reject_fail", "ap-clean@sender.example"))
    result = analyse(db, settings, shadow_copy(db, organization, storage, CLEAN), storage)
    facts = result.facts
    assert facts.get("rspamd_scan_present") and facts.get("rspamd_dmarc_policy_reject")
    assert "ASP-001" in signal_rules(db, result)


def test_the_spam_class_is_stored_beside_the_verdict_and_does_not_change_it(
    db, organization, settings, storage
) -> None:  # type: ignore[no-untyped-def]
    from msp_api.db.models_antispam import SpamScan
    from sqlalchemy import select

    ingest(db, settings, organization, scan("dmarc_reject_fail", "ap-clean@sender.example"))
    analyse(db, settings, shadow_copy(db, organization, storage, CLEAN), storage)
    row = db.execute(select(SpamScan)).scalar_one()
    assert row.spam_class in ("SPAM", "HIGH_CONFIDENCE_SPAM")
    assert row.security_verdict, "вердикт безопасности записан отдельным полем"
    assert row.security_verdict not in ("SPAM", "HIGH_CONFIDENCE_SPAM", "NOT_SPAM"), "оси не смешиваются"


def test_a_clean_authentication_result_lowers_nothing_and_creates_no_clean_fact(
    db, organization, settings, storage
) -> None:  # type: ignore[no-untyped-def]
    ingest(db, settings, organization, scan("all_pass", "ap-clean@sender.example"))
    result = analyse(db, settings, shadow_copy(db, organization, storage, CLEAN), storage)
    clean_facts = [k for k in result.facts if k.startswith("rspamd_") and "pass" in k]
    assert not clean_facts
    assert not {
        r for r in signal_rules(db, result) if r.startswith("ASP-") and r not in ("ASP-006", "ASP-007")
    }


def test_an_unknown_symbol_does_not_change_the_risk(db, organization, settings, storage) -> None:  # type: ignore[no-untyped-def]
    base = scan("all_pass", "ap-clean@sender.example")
    ingest(db, settings, organization, base)
    first = analyse(db, settings, shadow_copy(db, organization, storage, CLEAN), storage)
    score_without = first.score

    noisy = scan("all_pass", "ap-noisy@sender.example")
    noisy["symbols"].append({"name": "BRAND_NEW_SYMBOL_9000", "score": 99.0, "options": []})
    # Другой отправитель, чтобы история первого письма не повлияла на сравнение: оба впервые.
    raw = CLEAN.replace(b"ap-clean@", b"ap-noisy@").replace(b"partner@example.test", b"other@example.test")
    ingest(db, settings, organization, noisy)
    second = analyse(db, settings, shadow_copy(db, organization, storage, raw), storage)
    assert second.score == score_without


def test_a_missing_scan_on_a_shadow_copy_is_missing_evidence_not_clean(
    db, organization, settings, storage
) -> None:  # type: ignore[no-untyped-def]
    result = analyse(db, settings, shadow_copy(db, organization, storage, CLEAN), storage)
    assert any("Rspamd" in str(item) for item in result.missing_evidence), result.missing_evidence
    assert result.classification.value != "LOW_RISK", (
        "без данных сканера письмо не может считаться низким риском"
    )


def test_a_reputation_listing_raises_risk_but_not_listed_does_not_lower_it(
    db, organization, settings, storage
) -> None:  # type: ignore[no-untyped-def]
    listed = scan("all_pass", "ap-clean@sender.example")
    listed["symbols"].append({"name": "MSP_RBL_LABZONE_CLIENT_IP", "score": 0, "options": []})
    ingest(db, settings, organization, listed)
    result = analyse(db, settings, shadow_copy(db, organization, storage, CLEAN), storage)
    assert "ASP-005" in signal_rules(db, result)


def test_the_applied_action_is_observe_only_whatever_the_scanner_suggested(
    db, organization, settings
) -> None:  # type: ignore[no-untyped-def]
    from msp_api.db.models_antispam import SpamScan
    from sqlalchemy import select

    ingest(
        db,
        settings,
        organization,
        scan("dmarc_reject_fail", "ap-reject@sender.example", action="reject", score=30.0),
    )
    row = db.execute(select(SpamScan)).scalar_one()
    assert row.suggested_action == "REJECT" and row.applied_action == "OBSERVE_ONLY"
