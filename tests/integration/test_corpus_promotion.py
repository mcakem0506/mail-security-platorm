"""Продвижение письма реального потока в золотой корпус (ТЗ 1.0.4 §10).

Проверяется главное свойство: продвинуть письмо нельзя ни одним действием. Каждый шаг требует
предыдущего, двух разных людей и явного повышения версии датасета, а вердикт, не воспроизводимый
по обезличенной копии, закрывает путь целиком.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from msp_api.services import corpus_promotion, real_flow
from msp_contracts import (
    AnalystClassification,
    PiiStatus,
    PromotionState,
    RiskLevel,
    ValidationSource,
)

SERVICE = pathlib.Path("apps/api/msp_api/services/corpus_promotion.py")
CURRENT_VERSION = "2026.09.1"
NEXT_VERSION = "2026.10.1"


def _record(db, organization, *, ready: bool = True):  # type: ignore[no-untyped-def]
    """Письмо, прошедшее всё, что должно быть пройдено до заявки."""
    record, _ = real_flow.ingest(
        db,
        real_flow.IngestRequest(
            organization_id=organization.id,
            source=ValidationSource.SECURITY_MAILBOX,
            message_fingerprint="promote-1",
            production_verdict=RiskLevel.HIGH_RISK,
            triggered_rules=["SND-024", "URL-010"],
        ),
    )
    if ready:
        real_flow.review(
            db,
            record=record,
            classification=AnalystClassification.CONFIRMED_PHISHING,
            analyst="analyst@corp.example",
        )
        record.anonymized = True
        record.pii_status = PiiStatus.REVIEWED
        record.anonymized_object_key = "validation/anon/abc123.eml"
    db.commit()
    return record


def _reproduce(record, *, verdict=RiskLevel.HIGH_RISK, rules=("SND-024", "URL-010")):  # type: ignore[no-untyped-def]
    return corpus_promotion.check_reproducibility(
        record, anonymized_verdict=verdict, anonymized_rules=list(rules)
    )


class TestNecessaryConditions:
    def test_an_unreviewed_message_cannot_be_requested(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """В корпусе нет кейсов без известного ответа: мерить было бы нечем."""
        record = _record(db, organization, ready=False)
        with pytest.raises(corpus_promotion.PromotionError):
            corpus_promotion.request(record, analyst="analyst@corp.example", case_id="CASE-1")

    def test_automatic_anonymization_is_not_enough(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """``ANONYMIZED`` значит «замены сделаны», а не «проверено, что ничего не осталось»."""
        record = _record(db, organization)
        record.pii_status = PiiStatus.ANONYMIZED
        db.commit()
        assert any("не проверено человеком" in reason for reason in corpus_promotion.blockers(record))
        with pytest.raises(corpus_promotion.PromotionError):
            corpus_promotion.request(record, analyst="analyst@corp.example", case_id="CASE-1")

    def test_a_rejected_check_closes_the_path(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        record = _record(db, organization)
        record.pii_status = PiiStatus.REJECTED
        db.commit()
        assert corpus_promotion.blockers(record) != []

    def test_without_an_anonymized_copy_there_is_nothing_to_verify(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        record = _record(db, organization)
        record.anonymized_object_key = ""
        db.commit()
        assert any("воспроизводимость нечем" in reason for reason in corpus_promotion.blockers(record))

    def test_all_blockers_are_listed_at_once(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Аналитику нужно знать всё, что придётся сделать, а не по одному отказу за раз."""
        record = _record(db, organization, ready=False)
        assert len(corpus_promotion.blockers(record)) >= 3

    def test_a_ready_message_has_no_blockers(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Проверка самой проверки: условия выполнимы, а не запрещают всё."""
        assert corpus_promotion.blockers(_record(db, organization)) == []


class TestTwoDifferentPeople:
    def test_a_request_needs_a_case_number(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Кейс без ссылки на разбор через год не объяснить и не оспорить."""
        record = _record(db, organization)
        with pytest.raises(corpus_promotion.PromotionError):
            corpus_promotion.request(record, analyst="analyst@corp.example", case_id="  ")

    def test_the_requester_cannot_approve_their_own_request(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Заявка и согласование проверяют разное; один человек, делающий оба шага, делает один."""
        record = _record(db, organization)
        corpus_promotion.request(record, analyst="analyst@corp.example", case_id="CASE-1")
        db.commit()
        with pytest.raises(corpus_promotion.PromotionError):
            corpus_promotion.approve(record, approver="Analyst@Corp.Example")
        assert record.promotion_state is PromotionState.REQUESTED

    def test_another_person_can_approve(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        record = _record(db, organization)
        corpus_promotion.request(record, analyst="analyst@corp.example", case_id="CASE-1")
        corpus_promotion.approve(record, approver="lead@corp.example")
        db.commit()
        assert record.promotion_state is PromotionState.APPROVED
        assert record.promotion_approved_by == "lead@corp.example"

    def test_approving_what_was_not_requested_is_refused(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        record = _record(db, organization)
        with pytest.raises(corpus_promotion.PromotionError):
            corpus_promotion.approve(record, approver="lead@corp.example")

    def test_a_refusal_needs_a_reason(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Отказ без причины повторят."""
        record = _record(db, organization)
        corpus_promotion.request(record, analyst="analyst@corp.example", case_id="CASE-1")
        with pytest.raises(corpus_promotion.PromotionError):
            corpus_promotion.reject(record, approver="lead@corp.example", reason="")

    def test_a_refused_message_can_be_proposed_again(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Отказ — не приговор: обстоятельства меняются, а повторная заявка видна в состоянии."""
        record = _record(db, organization)
        corpus_promotion.request(record, analyst="analyst@corp.example", case_id="CASE-1")
        corpus_promotion.reject(record, approver="lead@corp.example", reason="слишком похоже на SDN-004")
        db.commit()
        assert record.promotion_state is PromotionState.REJECTED
        corpus_promotion.request(record, analyst="analyst@corp.example", case_id="CASE-2")
        assert record.promotion_state is PromotionState.REQUESTED


class TestReproducibility:
    def test_a_matching_verdict_and_ruleset_reproduces(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        record = _record(db, organization)
        result = _reproduce(record)
        assert result.reproduced is True
        assert record.reproducibility_report["reproduced"] is True

    def test_a_changed_verdict_does_not_reproduce(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Замены задели то, на чём держался вердикт. Это ограничение обезличивания, не сбой."""
        record = _record(db, organization)
        result = _reproduce(record, verdict=RiskLevel.LOW_RISK, rules=())
        assert result.reproduced is False
        assert result.lost_rules == ["SND-024", "URL-010"]

    def test_the_same_verdict_from_other_rules_does_not_reproduce(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Самое неприятное расхождение: кейс выглядел бы правильным, а проверял бы другое."""
        record = _record(db, organization)
        result = _reproduce(record, rules=("SND-024", "ATT-003"))
        assert result.reproduced is False
        assert result.lost_rules == ["URL-010"]
        assert result.gained_rules == ["ATT-003"]


class TestPromotionIsExplicit:
    def _approved(self, db, organization):  # type: ignore[no-untyped-def]
        record = _record(db, organization)
        corpus_promotion.request(record, analyst="analyst@corp.example", case_id="CASE-1")
        corpus_promotion.approve(record, approver="lead@corp.example")
        db.commit()
        return record

    def test_promotion_requires_a_reproducibility_check(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        record = self._approved(db, organization)
        with pytest.raises(corpus_promotion.PromotionError, match="воспроизводимость"):
            corpus_promotion.promote(
                record,
                dataset_version=NEXT_VERSION,
                current_dataset_version=CURRENT_VERSION,
                promoted_by="lead@corp.example",
            )

    def test_a_non_reproducible_message_is_never_promoted(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        record = self._approved(db, organization)
        _reproduce(record, verdict=RiskLevel.LOW_RISK, rules=())
        with pytest.raises(corpus_promotion.PromotionError, match="последствия замен"):
            corpus_promotion.promote(
                record,
                dataset_version=NEXT_VERSION,
                current_dataset_version=CURRENT_VERSION,
                promoted_by="lead@corp.example",
            )
        assert record.promotion_state is PromotionState.APPROVED

    def test_the_dataset_version_must_be_raised(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Два разных набора измерений не могут называться одинаково: сравнение выпусков
        потеряло бы смысл (ТЗ §10)."""
        record = self._approved(db, organization)
        _reproduce(record)
        with pytest.raises(corpus_promotion.PromotionError, match="повышена"):
            corpus_promotion.promote(
                record,
                dataset_version=CURRENT_VERSION,
                current_dataset_version=CURRENT_VERSION,
                promoted_by="lead@corp.example",
            )

    def test_promotion_skipping_approval_is_refused(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        record = _record(db, organization)
        _reproduce(record)
        with pytest.raises(corpus_promotion.PromotionError):
            corpus_promotion.promote(
                record,
                dataset_version=NEXT_VERSION,
                current_dataset_version=CURRENT_VERSION,
                promoted_by="lead@corp.example",
            )

    def test_the_full_path_ends_in_a_recorded_version(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Проверка самой проверки: путь проходим целиком, иначе тесты выше ничего не значат."""
        record = self._approved(db, organization)
        _reproduce(record)
        corpus_promotion.promote(
            record,
            dataset_version=NEXT_VERSION,
            current_dataset_version=CURRENT_VERSION,
            promoted_by="lead@corp.example",
        )
        db.commit()
        assert record.promotion_state is PromotionState.PROMOTED
        assert record.promoted_dataset_version == NEXT_VERSION
        assert record.promotion_requested_by == "analyst@corp.example"
        assert record.promotion_approved_by == "lead@corp.example"


class TestTheDraftIsNotAWayBackToTheOriginal:
    def test_the_draft_carries_no_raw_key_and_no_body(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        record = _record(db, organization)
        record.raw_object_key = "validation/raw/secret.eml"
        corpus_promotion.request(record, analyst="analyst@corp.example", case_id="CASE-1")
        corpus_promotion.approve(record, approver="lead@corp.example")
        db.commit()

        draft = corpus_promotion.corpus_case_draft(record)
        serialized = repr(draft)
        assert "validation/raw" not in serialized
        assert draft["anonymized_object_key"] == "validation/anon/abc123.eml"
        assert draft["dataset_version_required"] is True

    def test_no_draft_before_approval(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        record = _record(db, organization)
        with pytest.raises(corpus_promotion.PromotionError):
            corpus_promotion.corpus_case_draft(record)


class TestNothingPromotesItself:
    def test_the_module_never_writes_to_the_corpus(self) -> None:
        """Золотой корпус — код, и кейс появляется в нём коммитом человека.

        Проверяется по исходнику: модуль не импортирует ни сборщик корпуса, ни файловую запись.
        Поведенческий тест на отсутствие записи был бы тестом на то, чего не случилось.
        """
        tree = ast.parse(SERVICE.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        assert not any(
            name.startswith(("msp_detection_eval", "pathlib", "shutil", "os")) for name in imported
        ), "продвижение не пишет ни в корпус, ни в файлы"

    def test_the_state_summary_says_promotion_is_not_automatic(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        record = _record(db, organization)
        summary = corpus_promotion.state_summary([record])
        assert summary["automatic_promotion"] is False
        assert summary["by_state"][PromotionState.NOT_REQUESTED.value] == 1
        assert summary["awaiting_approval"] == 0

    def test_the_summary_counts_what_did_not_reproduce(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Невоспроизводимые письма — это найденные ограничения обезличивания, и их надо видеть."""
        record = _record(db, organization)
        _reproduce(record, verdict=RiskLevel.LOW_RISK, rules=())
        assert corpus_promotion.state_summary([record])["not_reproducible"] == 1
