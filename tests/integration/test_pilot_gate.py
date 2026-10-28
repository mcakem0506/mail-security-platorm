"""Условия входа в P4 по отдельным контролям (MSP 1.3P, ТЗ §13, §17, §18).

Вход в P4 целиком проверить через HTTP нельзя: он требует всех подтверждений среды. Поэтому здесь проверяются сами условия по
контролям на реальной выборке: граница Вильсона и принятие риска, блокировка пробелом, отдельность реального от лабораторного.
"""

from __future__ import annotations

import pytest
from msp_api.config import get_settings
from msp_api.db.models_enforcement import EnforcementDecisionRecord
from msp_api.db.models_transport import TransportNode, TransportNodeRole
from msp_api.services import pilot
from msp_api.services.pilot import PilotError
from msp_enforcement.model import ControlType


@pytest.fixture
def real_node(db, organization):  # type: ignore[no-untyped-def]
    db.add(
        TransportNode(
            organization_id=organization.id, node_id="REAL", name="REAL", role=TransportNodeRole.INBOUND
        )
    )
    db.commit()


def seed(db, organization, node_id: str, correct: int, wrong: int, control: str = "SPAM_REJECT") -> None:  # type: ignore[no-untyped-def]
    for i in range(correct + wrong):
        db.add(
            EnforcementDecisionRecord(
                organization_id=organization.id,
                node_id=node_id,
                internet_message_id=f"{control}-{node_id}-{i}@x",
                control_type=control,
                decision="REJECT",
                suggested_action="REJECT",
                review_outcome="CORRECT" if i < correct else "FALSE_POSITIVE",
            )
        )
    db.commit()


def row(db, organization, control: str) -> dict:  # type: ignore[no-untyped-def]
    rows = pilot.control_rows(db, get_settings(), organization.id)
    return next(r for r in rows if r["control"] == control)


class TestStatisticsPerControl:
    def test_a_clean_minimum_sample_is_not_enough_without_a_written_risk_acceptance(
        self, db, organization, real_node
    ) -> None:  # type: ignore[no-untyped-def]
        seed(db, organization, "REAL", 120, 0)

        statistics = row(db, organization, "SPAM_REJECT")["statistics"]
        assert statistics["status"] == "RISK_ACCEPT_REQUIRED"
        assert statistics["observed_fp_rate"] == 0.0
        assert statistics["wilson_upper_95"] > 0.01

        with pytest.raises(PilotError) as refused:
            pilot._guard_controls_for_p4(db, get_settings(), organization.id, ["SPAM_REJECT"], "")
        assert refused.value.status == 409
        pilot._guard_controls_for_p4(
            db, get_settings(), organization.id, ["SPAM_REJECT"], "Риск принят: изолированный пилотный домен"
        )

    def test_a_large_clean_sample_needs_no_risk_acceptance(self, db, organization, real_node) -> None:  # type: ignore[no-untyped-def]
        seed(db, organization, "REAL", 400, 0)

        assert row(db, organization, "SPAM_REJECT")["statistics"]["status"] == "PASS"
        pilot._guard_controls_for_p4(db, get_settings(), organization.id, ["SPAM_REJECT"], "")

    def test_false_positives_above_the_threshold_fail_the_statistics_condition(
        self, db, organization, real_node
    ) -> None:  # type: ignore[no-untyped-def]
        seed(db, organization, "REAL", 395, 5)

        assert row(db, organization, "SPAM_REJECT")["statistics"]["status"] == "FAIL"
        facts = pilot.platform_facts(db, get_settings(), organization.id)
        checks = pilot._p4_checks(db, get_settings(), organization.id, facts, ["SPAM_REJECT"])
        statistics = next(c for c in checks if c.key == "control:SPAM_REJECT:statistics")
        assert statistics.passed is False

    def test_lab_reviews_never_reach_the_real_statistics(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        seed(db, organization, "LAB-OR-UNKNOWN", 500, 0)

        assert row(db, organization, "SPAM_REJECT")["statistics"]["status"] == "NO_DATA"


class TestBlockedAndNonRejectControls:
    def test_dmarc_reject_cannot_enter_while_the_gap_is_open(self, db, organization, real_node) -> None:  # type: ignore[no-untyped-def]
        seed(db, organization, "REAL", 500, 0, control="DMARC_REJECT")

        assert row(db, organization, "DMARC_REJECT")["blocked_by_gap"] is True
        with pytest.raises(PilotError) as refused:
            pilot._guard_controls_for_p4(db, get_settings(), organization.id, ["DMARC_REJECT"], "риск принят")
        assert refused.value.status == 409 and refused.value.detail["reason"] == "BLOCKED_BY_GAP"

    def test_the_gate_names_a_blocked_control_as_a_blocker(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        facts = pilot.platform_facts(db, get_settings(), organization.id)
        checks = pilot._p4_checks(db, get_settings(), organization.id, facts, ["DMARC_REJECT"])
        blocker = next(c for c in checks if c.key == "control:DMARC_REJECT")
        assert blocker.passed is False and blocker.value == "BLOCKED_BY_GAP"

    def test_only_reject_controls_need_the_false_positive_statistics(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        facts = pilot.platform_facts(db, get_settings(), organization.id)
        checks = pilot._p4_checks(
            db, get_settings(), organization.id, facts, ["QUARANTINE", "TEMPFAIL_ABUSE", "SPAM_REJECT"]
        )
        keys = {c.key for c in checks}

        assert "control:SPAM_REJECT:statistics" in keys
        assert "control:QUARANTINE:statistics" not in keys
        assert "control:TEMPFAIL_ABUSE:statistics" not in keys

    def test_the_list_of_controls_is_kept_minimal(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        facts = pilot.platform_facts(db, get_settings(), organization.id)
        everything = [c.value for c in ControlType]
        checks = pilot._p4_checks(db, get_settings(), organization.id, facts, everything)
        assert next(c for c in checks if c.key == "controls_selected").passed is False

    def test_an_empty_list_of_controls_does_not_pass(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        facts = pilot.platform_facts(db, get_settings(), organization.id)
        checks = pilot._p4_checks(db, get_settings(), organization.id, facts, [])
        assert next(c for c in checks if c.key == "controls_selected").passed is False


class TestPlatformFacts:
    def test_the_shared_token_is_a_blocker_while_it_is_allowed(self, db, organization, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr(get_settings(), "gateway_shared_token_allowed", True)
        facts = pilot.platform_facts(db, get_settings(), organization.id)
        checks = pilot._p4_checks(db, get_settings(), organization.id, facts, [])
        assert next(c for c in checks if c.key == "shared_token_disabled").passed is False

        monkeypatch.setattr(get_settings(), "gateway_shared_token_allowed", False)
        facts = pilot.platform_facts(db, get_settings(), organization.id)
        checks = pilot._p4_checks(db, get_settings(), organization.id, facts, [])
        assert next(c for c in checks if c.key == "shared_token_disabled").passed is True

    def test_two_nodes_are_not_ready_without_a_fresh_report_and_a_matching_policy(
        self, db, organization
    ) -> None:  # type: ignore[no-untyped-def]
        for name in ("A", "B"):
            db.add(
                TransportNode(
                    organization_id=organization.id, node_id=name, name=name, role=TransportNodeRole.INBOUND
                )
            )
        db.commit()

        facts = pilot.platform_facts(db, get_settings(), organization.id)

        assert len(facts["nodes"]) == 2
        assert facts["nodes_ready"] == 0, "узлы без отчёта засчитаны готовыми"

    def test_lab_nodes_are_not_counted_among_the_pilot_nodes(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        db.add(
            TransportNode(organization_id=organization.id, node_id="L", name="L", role=TransportNodeRole.LAB)
        )
        db.commit()
        assert pilot.platform_facts(db, get_settings(), organization.id)["nodes"] == []
