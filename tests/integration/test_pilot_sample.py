"""Выборка пилота: одно письмо — одна единица, и реальное отделено от лабораторного (MSP 1.3P, ТЗ §10, §13).

Дефект, который закрепляет этот файл: просмотр кандидата на отказ записывается и в журнал сканирования, и в
журнал решений
принуждения. Если считать обе записи, одно письмо засчитывается дважды, и порог «не менее 100 просмотренных
кандидатов»
достигается 50 письмами. Выборка, надутая вдвое, — это ложное основание для включения отказа.
"""

from __future__ import annotations

from msp_api.config import get_settings
from msp_api.db.models_antispam import SpamReview, SpamScan
from msp_api.db.models_enforcement import EnforcementDecisionRecord
from msp_api.db.models_transport import TransportNode, TransportNodeRole
from msp_api.services import enforcement
from msp_enforcement.model import ControlType


def _node(db, organization, node_id: str, role: TransportNodeRole) -> None:  # type: ignore[no-untyped-def]
    db.add(TransportNode(organization_id=organization.id, node_id=node_id, name=node_id, role=role))
    db.flush()


def _reviewed_pair(
    db, organization, index: int, *, node_id: str, scan_verdict: str, decision_outcome: str
) -> None:  # type: ignore[no-untyped-def]
    """Одно письмо, просмотренное дважды: как скан и как решение принуждения."""
    message_id = f"dup-{index}@x"
    scan = SpamScan(
        organization_id=organization.id,
        node_id=node_id,
        queue_id=f"Q{index:06d}",
        internet_message_id=message_id,
        score=18.0,
        suggested_action="REJECT",
        spam_class="HIGH_CONFIDENCE_SPAM",
    )
    db.add(scan)
    db.flush()
    db.add(
        SpamReview(
            organization_id=organization.id,
            scan_id=scan.id,
            verdict=scan_verdict,
            selection="SUGGESTED_REJECT",
            reviewed_by="analyst@corp.example",
        )
    )
    db.add(
        EnforcementDecisionRecord(
            organization_id=organization.id,
            node_id=node_id,
            transport_message_id=f"tm-{index}",
            internet_message_id=message_id,
            control_type=ControlType.SPAM_REJECT.value,
            decision="REJECT",
            suggested_action="REJECT",
            review_outcome=decision_outcome,
        )
    )


class TestOneMessageIsCountedOnce:
    def test_a_message_reviewed_as_scan_and_as_decision_is_one_reviewed_candidate(
        self, db, organization
    ) -> None:  # type: ignore[no-untyped-def]
        _node(db, organization, "N-REAL", TransportNodeRole.INBOUND)
        for i in range(3):
            _reviewed_pair(
                db, organization, i, node_id="N-REAL", scan_verdict="SPAM", decision_outcome="CORRECT"
            )
        db.commit()

        report, _ = enforcement.reject_evidence(db, get_settings(), organization.id, ControlType.SPAM_REJECT)

        assert report.reviewed_rejects == 3, "три письма, просмотренных дважды, засчитаны как шесть"

    def test_a_disagreement_between_the_two_reviews_counts_as_a_false_positive(
        self, db, organization
    ) -> None:  # type: ignore[no-untyped-def]
        """Осторожный исход: если одна из двух записей говорит «ошибка», письмо — ложное срабатывание."""
        _node(db, organization, "N-REAL", TransportNodeRole.INBOUND)
        _reviewed_pair(
            db, organization, 1, node_id="N-REAL", scan_verdict="SPAM", decision_outcome="FALSE_POSITIVE"
        )
        db.commit()

        report, _ = enforcement.reject_evidence(db, get_settings(), organization.id, ControlType.SPAM_REJECT)

        assert report.reviewed_rejects == 1
        assert report.confirmed_fp == 1
        assert report.confirmed_correct == 0
