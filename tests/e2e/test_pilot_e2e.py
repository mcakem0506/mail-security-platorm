"""API пилота реального потока через HTTP (MSP 1.3P, ТЗ 1.3P §13, §21, §24, §28, §29).

Проверяется то, что нельзя увидеть модульным тестом: роль, которой нельзя вести пилот; автор, подтверждающий
сам себя; решение, которое остановка делает недействительным; выгрузка, в которой не должно быть писем; итог,
который при нулевой выборке не может быть ничем, кроме ``NOT_READY``.
"""

from __future__ import annotations

import json

import pytest
from msp_contracts import Role, ValidationSource

from .test_transport_e2e import Person, as_, client, people  # noqa: F401

BASE = "/api/v1/pilot"
P1_KEYS = (
    "data_approval",
    "scope_approved",
    "mailflow_plan",
    "exchange_inventory",
    "roles_assigned",
    "service_account_minimal",
    "secrets_clean",
    "retention_approved",
    "monitoring_alerts_tested",
)
P2_KEYS = (
    "p1_journal_smoke",
    "p1_tls_verified",
    "p1_open_relay_tests",
    "p1_outage_recovery",
    "p1_backup_restore_test",
    "production_mx_unchanged",
)


@pytest.fixture
def team(client, engine, organization):  # type: ignore[no-untyped-def]
    """Три дополнительных администратора: подтверждающие решение о фазе — не его автор."""
    from msp_api.db.models import User
    from msp_api.security.auth import hash_password
    from sqlalchemy.orm import sessionmaker

    password = "Transport-Test-Password-4"
    accounts = {}
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        for name in ("mail", "secops", "owner"):
            email = f"{name}@corp.example"
            session.add(
                User(
                    organization_id=organization.id,
                    email=email,
                    display_name=name,
                    role=Role.SECURITY_ADMIN,
                    password_hash=hash_password(password),
                )
            )
            accounts[name] = {"email": email, "password": password}
        session.commit()
    return accounts


def person(client, account) -> Person:  # type: ignore[no-untyped-def]
    client.cookies.clear()
    return Person(client, account["email"], account["password"])


def attest_all(admin: Person, keys: tuple[str, ...]) -> None:
    for key in keys:
        response = admin.post(
            f"{BASE}/attestations/{key}", {"status": "PASS", "evidence_ref": f"docs://{key}"}
        )
        assert response.status_code == 200, response.text


def seed_node(engine, organization, node_id: str, role: str) -> None:  # type: ignore[no-untyped-def]
    from msp_api.db.models_transport import TransportNode, TransportNodeRole
    from sqlalchemy.orm import sessionmaker

    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        session.add(
            TransportNode(
                organization_id=organization.id, node_id=node_id, name=node_id, role=TransportNodeRole(role)
            )
        )
        session.commit()


def seed_validation(engine, organization, source: ValidationSource, count: int, **extra):  # type: ignore[no-untyped-def]
    from msp_api.db.models import ValidationMessage
    from sqlalchemy.orm import sessionmaker

    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        for i in range(count):
            session.add(
                ValidationMessage(
                    organization_id=organization.id,
                    source=source,
                    message_fingerprint=f"{source.value}-{extra.get('tag', '')}-{i}",
                    **{k: v for k, v in extra.items() if k != "tag"},
                )
            )
        session.commit()


def seed_decision(engine, organization, node_id: str, index: int, **over):  # type: ignore[no-untyped-def]
    from msp_api.db.models_enforcement import EnforcementDecisionRecord
    from sqlalchemy.orm import sessionmaker

    fields = {
        "organization_id": organization.id,
        "node_id": node_id,
        "transport_message_id": f"tm-{node_id}-{index}",
        "internet_message_id": f"m-{node_id}-{index}@x",
        "control_type": "SPAM_REJECT",
        "decision": "REJECT",
        "suggested_action": "REJECT",
        "applied_action": "OBSERVE_ONLY",
    }
    fields.update(over)
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        session.add(EnforcementDecisionRecord(**fields))
        session.commit()


class TestEmptyPilotIsNotReady:
    def test_zero_real_messages_gives_not_ready_whatever_else_is_green(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        attest_all(admin, P1_KEYS + P2_KEYS)

        ready = admin.get(f"{BASE}/readiness").json()

        assert ready["decision"] == "NOT_READY"
        assert "REAL_MESSAGES_ZERO" in ready["decision_reasons"]
        assert ready["global_production_mx_cutover"] is False

    def test_rates_without_a_denominator_are_null_and_never_zero(self, client, people) -> None:  # type: ignore[no-untyped-def]
        metrics = as_(client, people, "viewer").get(f"{BASE}/metrics").json()

        assert metrics["sample"]["real_unique"] == 0
        assert metrics["sample"]["unknown_per_1000"] is None
        assert metrics["sample"]["unscannable_per_1000"] is None
        assert metrics["applied"]["applied_rejects_review_coverage"] is None
        spam = metrics["controls"]["SPAM_REJECT"]["statistics"]
        assert spam["status"] == "NO_DATA"
        assert spam["observed_fp_rate"] is None and spam["wilson_upper_95"] is None

    def test_unproven_criteria_are_not_tested_and_not_passed(self, client, people) -> None:  # type: ignore[no-untyped-def]
        export = as_(client, people, "admin").get(f"{BASE}/evidence").json()
        status = {c["n"]: c["status"] for c in export["criteria"]}

        for number in (1, 2, 3, 5, 6, 7, 8, 14, 16, 17, 18, 20, 23):
            assert status[number] == "NOT_TESTED", number
        assert status[21] == "PASS"

    def test_dmarc_reject_stays_blocked_by_the_open_gap(self, client, people) -> None:  # type: ignore[no-untyped-def]
        controls = {
            c["control"]: c for c in as_(client, people, "admin").get(f"{BASE}/readiness").json()["controls"]
        }

        assert controls["DMARC_REJECT"]["pilot_readiness"] == "BLOCKED_BY_GAP"
        assert controls["DMARC_REJECT"]["blocked_by_gap"] is True
        assert all(c["pilot_readiness"] != "READY" for c in controls.values())


class TestRoles:
    def test_a_viewer_reads_but_does_not_keep_the_pilot(self, client, people) -> None:  # type: ignore[no-untyped-def]
        viewer = as_(client, people, "viewer")
        assert viewer.get(f"{BASE}/readiness").status_code == 200
        assert (
            viewer.post(
                f"{BASE}/attestations/data_approval", {"status": "PASS", "evidence_ref": "d"}
            ).status_code
            == 403
        )
        assert viewer.post(f"{BASE}/stop", {"reason_code": "OTHER"}).status_code == 403
        assert (
            viewer.post(f"{BASE}/phases/P1/decision", {"outcome": "NO_GO", "reasons": ["x"]}).status_code
            == 403
        )

    def test_an_analyst_cannot_approve_a_phase_decision(self, client, people) -> None:  # type: ignore[no-untyped-def]
        analyst = as_(client, people, "analyst")
        assert analyst.post(f"{BASE}/decisions/none/approve", {"role": "MAIL_ADMIN"}).status_code == 403

    def test_an_employee_does_not_see_the_pilot(self, client, people) -> None:  # type: ignore[no-untyped-def]
        assert as_(client, people, "employee").get(f"{BASE}/readiness").status_code == 403


class TestAttestations:
    def test_pass_without_evidence_is_refused(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        assert admin.post(f"{BASE}/attestations/data_approval", {"status": "PASS"}).status_code == 422

    def test_an_unknown_key_and_status_are_refused(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        assert admin.post(f"{BASE}/attestations/made_up", {"status": "NOT_TESTED"}).status_code == 404
        assert admin.post(f"{BASE}/attestations/data_approval", {"status": "OK"}).status_code == 422

    def test_the_latest_attestation_counts_and_the_history_is_kept(self, client, people, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models_pilot import PilotAttestationRecord
        from sqlalchemy import func, select
        from sqlalchemy.orm import sessionmaker

        admin = as_(client, people, "admin")
        admin.post(f"{BASE}/attestations/kill_switch_real", {"status": "PASS", "evidence_ref": "run-1"})
        admin.post(
            f"{BASE}/attestations/kill_switch_real",
            {"status": "FAIL", "evidence_ref": "run-2", "note": "узел B"},
        )

        items = {i["key"]: i for i in admin.get(f"{BASE}/attestations").json()["items"]}
        assert items["kill_switch_real"]["status"] == "FAIL"
        with sessionmaker(bind=engine)() as session:
            count = session.execute(
                select(func.count())
                .select_from(PilotAttestationRecord)
                .where(PilotAttestationRecord.attestation_key == "kill_switch_real")
            ).scalar_one()
        assert count == 2

    def test_nothing_is_attested_by_default(self, client, people) -> None:  # type: ignore[no-untyped-def]
        items = as_(client, people, "viewer").get(f"{BASE}/attestations").json()["items"]
        assert items and all(i["status"] == "NOT_TESTED" for i in items)

    def test_attesting_is_audited_without_the_document(self, client, people, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import AuditEvent as AuditLog
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        as_(client, people, "admin").post(
            f"{BASE}/attestations/data_approval",
            {"status": "PASS", "evidence_ref": "docs://approval-7", "note": "n"},
        )
        with sessionmaker(bind=engine)() as session:
            rows = (
                session.execute(select(AuditLog).where(AuditLog.action == "pilot.attestation_recorded"))
                .scalars()
                .all()
            )
        assert rows and rows[0].detail == {"key": "data_approval", "status": "PASS"}


class TestPhaseDecisions:
    def test_go_is_refused_while_the_conditions_are_not_met(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        response = admin.post(f"{BASE}/phases/P1/decision", {"outcome": "GO", "reasons": ["готовы"]})

        assert response.status_code == 409
        blocking = response.json()["detail"]["blocking"]
        assert "att:data_approval" in blocking

    def test_the_gate_lists_every_condition_with_its_fact(self, client, people) -> None:  # type: ignore[no-untyped-def]
        gate = as_(client, people, "admin").get(f"{BASE}/phases/P1/gate").json()

        assert gate["go_possible"] is False
        assert gate["required_roles"] == ["MAIL_ADMIN", "SECURITY_OWNER"]
        keys = {c["key"] for c in gate["checks"]}
        assert {"no_open_stop", "no_enforcement_before_p4"} <= keys
        assert all(c["state"] in ("passed", "failed", "unknown") for c in gate["checks"])

    def test_a_go_takes_effect_only_after_two_other_people_confirm_it(self, client, people, team) -> None:
        # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        attest_all(admin, P1_KEYS)
        proposed = admin.post(
            f"{BASE}/phases/P1/decision", {"outcome": "GO", "reasons": ["P0 пройдена"]}
        ).json()
        assert proposed["state"] == "PROPOSED"

        own = admin.post(f"{BASE}/decisions/{proposed['id']}/approve", {"role": "MAIL_ADMIN"})
        assert own.status_code == 409, "автор подтвердил своё решение сам"

        mail = person(client, team["mail"])
        first = mail.post(f"{BASE}/decisions/{proposed['id']}/approve", {"role": "MAIL_ADMIN"}).json()
        assert first["state"] == "PROPOSED"
        again = mail.post(f"{BASE}/decisions/{proposed['id']}/approve", {"role": "SECURITY_OWNER"})
        assert again.status_code == 409, "один человек закрыл две роли"

        secops = person(client, team["secops"])
        done = secops.post(f"{BASE}/decisions/{proposed['id']}/approve", {"role": "SECURITY_OWNER"}).json()
        assert done["state"] == "EFFECTIVE"
        assert {a["role"] for a in done["approvals"]} == {"MAIL_ADMIN", "SECURITY_OWNER"}
        ready = secops.get(f"{BASE}/readiness").json()
        assert next(p for p in ready["phases"] if p["phase"] == "P1")["decision"]["state"] == "EFFECTIVE"

    def test_a_role_that_the_decision_does_not_need_is_refused(self, client, people, team) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        attest_all(admin, P1_KEYS)
        proposed = admin.post(f"{BASE}/phases/P1/decision", {"outcome": "GO", "reasons": ["ok"]}).json()
        response = person(client, team["owner"]).post(
            f"{BASE}/decisions/{proposed['id']}/approve", {"role": "BUSINESS_OWNER"}
        )
        assert response.status_code == 422

    def test_the_next_phase_needs_the_previous_go(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        attest_all(admin, P2_KEYS)
        response = admin.post(f"{BASE}/phases/P2/decision", {"outcome": "GO", "reasons": ["ok"]})

        assert response.status_code == 409
        assert "previous_phase_go" in response.json()["detail"]["blocking"]

    def test_no_go_needs_no_confirmation_and_takes_effect_at_once(self, client, people) -> None:  # type: ignore[no-untyped-def]
        decision = (
            as_(client, people, "admin")
            .post(f"{BASE}/phases/P3/decision", {"outcome": "NO_GO", "reasons": ["выборка мала"]})
            .json()
        )
        assert decision["state"] == "EFFECTIVE"
        assert decision["outcome"] == "NO_GO"

    def test_a_no_go_withdraws_the_effective_go_for_the_same_phase(self, client, people, team) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        attest_all(admin, P1_KEYS)
        decision = admin.post(f"{BASE}/phases/P1/decision", {"outcome": "GO", "reasons": ["ok"]}).json()
        person(client, team["mail"]).post(
            f"{BASE}/decisions/{decision['id']}/approve", {"role": "MAIL_ADMIN"}
        )
        person(client, team["secops"]).post(
            f"{BASE}/decisions/{decision['id']}/approve", {"role": "SECURITY_OWNER"}
        )
        admin = as_(client, people, "admin")
        phases = admin.get(f"{BASE}/readiness").json()["phases"]
        assert next(p for p in phases if p["phase"] == "P1")["decision"]["state"] == "EFFECTIVE"

        admin.post(f"{BASE}/phases/P1/decision", {"outcome": "NO_GO", "reasons": ["новое обстоятельство"]})

        phases = admin.get(f"{BASE}/readiness").json()["phases"]
        assert next(p for p in phases if p["phase"] == "P1")["decision"] is None, (
            "NO_GO не отменил действующее GO"
        )

    def test_p0_cannot_be_decided(self, client, people) -> None:  # type: ignore[no-untyped-def]
        assert (
            as_(client, people, "admin")
            .post(f"{BASE}/phases/P0/decision", {"outcome": "NO_GO", "reasons": ["x"]})
            .status_code
            == 422
        )

    def test_dmarc_reject_cannot_enter_the_canary_decision(self, client, people, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """Даже если все остальные условия P4 выполнены, контроль, заблокированный пробелом, не попадает в решение."""
        from msp_api.services import pilot

        monkeypatch.setattr(
            pilot, "gate", lambda *a, **k: {"go_possible": True, "checks": [], "blocking": [], "phase": "P4"}
        )
        response = as_(client, people, "admin").post(
            f"{BASE}/phases/P4/decision", {"outcome": "GO", "reasons": ["ok"], "controls": ["DMARC_REJECT"]}
        )
        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "BLOCKED_BY_GAP"

    def test_controls_can_be_named_only_by_the_canary_decision(self, client, people) -> None:  # type: ignore[no-untyped-def]
        response = as_(client, people, "admin").post(
            f"{BASE}/phases/P2/decision", {"outcome": "NO_GO", "reasons": ["x"], "controls": ["SPAM_REJECT"]}
        )
        assert response.status_code == 422

    def test_a_refused_decision_is_audited(self, client, people, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import AuditEvent as AuditLog
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        as_(client, people, "admin").post(f"{BASE}/phases/P1/decision", {"outcome": "GO", "reasons": ["x"]})
        with sessionmaker(bind=engine)() as session:
            rows = (
                session.execute(select(AuditLog).where(AuditLog.action == "pilot.decision_refused"))
                .scalars()
                .all()
            )
        assert rows and rows[0].outcome == "denied"


class TestStop:
    def test_an_open_stop_closes_every_gate(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        attest_all(admin, P1_KEYS)
        admin.post(f"{BASE}/stop", {"reason_code": "CRITICAL_FALSE_POSITIVE", "control_type": "SPAM_REJECT"})

        ready = admin.get(f"{BASE}/readiness").json()
        assert ready["stopped"] is True
        assert ready["decision"] == "NOT_READY" and "OPEN_STOP" in ready["decision_reasons"]
        refused = admin.post(f"{BASE}/phases/P1/decision", {"outcome": "GO", "reasons": ["ok"]})
        assert refused.status_code == 409 and "no_open_stop" in refused.json()["detail"]["blocking"]

    def test_the_stop_record_does_not_touch_the_smtp_controls(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        before = {c["control"]: c["state"] for c in admin.get(f"{BASE}/readiness").json()["controls"]}
        stop = admin.post(f"{BASE}/stop", {"reason_code": "OPEN_RELAY"}).json()
        after = {c["control"]: c["state"] for c in admin.get(f"{BASE}/readiness").json()["controls"]}

        assert before == after
        assert any("kill-switch" in action for action in stop["next_actions"])

    def test_an_unknown_reason_is_refused(self, client, people) -> None:  # type: ignore[no-untyped-def]
        assert as_(client, people, "admin").post(f"{BASE}/stop", {"reason_code": "BORED"}).status_code == 422

    def test_a_stop_is_closed_by_another_person_with_a_root_cause_and_a_regression_case(
        self, client, people, team
    ) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        stop = admin.post(f"{BASE}/stop", {"reason_code": "INVALID_POLICY"}).json()

        assert (
            admin.post(
                f"{BASE}/stops/{stop['id']}/resolve", {"rca_ref": "r", "regression_ref": "t"}
            ).status_code
            == 409
        )
        other = person(client, team["mail"])
        assert (
            other.post(
                f"{BASE}/stops/{stop['id']}/resolve", {"rca_ref": " ", "regression_ref": "t"}
            ).status_code
            == 422
        )
        assert (
            other.post(
                f"{BASE}/stops/{stop['id']}/resolve", {"rca_ref": "rca-9", "regression_ref": "tests/x"}
            ).status_code
            == 200
        )
        assert other.get(f"{BASE}/readiness").json()["stopped"] is False

    def test_a_go_given_before_a_stop_does_not_survive_it(self, client, people, team) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        attest_all(admin, P1_KEYS)
        decision = admin.post(f"{BASE}/phases/P1/decision", {"outcome": "GO", "reasons": ["ok"]}).json()
        person(client, team["mail"]).post(
            f"{BASE}/decisions/{decision['id']}/approve", {"role": "MAIL_ADMIN"}
        )
        person(client, team["secops"]).post(
            f"{BASE}/decisions/{decision['id']}/approve", {"role": "SECURITY_OWNER"}
        )
        secops = person(client, team["secops"])
        assert next(p for p in secops.get(f"{BASE}/readiness").json()["phases"] if p["phase"] == "P1")[
            "decision"
        ]

        stop = secops.post(f"{BASE}/stop", {"reason_code": "UNCONTROLLED_REJECT"}).json()
        mail = person(client, team["mail"])
        mail.post(f"{BASE}/stops/{stop['id']}/resolve", {"rca_ref": "rca-1", "regression_ref": "tests/y"})

        phases = mail.get(f"{BASE}/readiness").json()["phases"]
        assert next(p for p in phases if p["phase"] == "P1")["decision"] is None, (
            "старое GO пережило остановку"
        )


class TestSeparationOfDataClasses:
    def test_real_biased_imported_and_drill_messages_are_counted_apart(
        self, client, people, engine, organization
    ) -> None:  # type: ignore[no-untyped-def]
        from msp_contracts import RiskLevel

        seed_validation(engine, organization, ValidationSource.JOURNAL_COPY, 3, tag="j")
        seed_validation(engine, organization, ValidationSource.EWS_READONLY, 2, tag="e")
        seed_validation(engine, organization, ValidationSource.SECURITY_MAILBOX, 4, tag="s")
        seed_validation(engine, organization, ValidationSource.ANALYST_UPLOAD, 1, tag="u")
        seed_validation(
            engine,
            organization,
            ValidationSource.JOURNAL_COPY,
            2,
            tag="d",
            expected_classification=RiskLevel.HIGH_RISK,
        )

        sample = as_(client, people, "viewer").get(f"{BASE}/metrics").json()["sample"]

        assert sample["real_unique"] == 5
        assert sample["real_by_source"] == {"JOURNAL_COPY": 3, "EWS_READONLY": 2}
        assert sample["biased_real_security_mailbox"] == 4
        assert sample["imported_analyst_upload"] == 1
        assert sample["drills"] == 2

    def test_a_non_empty_sample_below_the_minimum_is_still_not_ready(
        self, client, people, engine, organization
    ) -> None:  # type: ignore[no-untyped-def]
        seed_validation(engine, organization, ValidationSource.JOURNAL_COPY, 30, tag="j")
        admin = as_(client, people, "admin")

        ready = admin.get(f"{BASE}/readiness").json()

        assert ready["decision"] == "READY_WITH_WARNINGS", "реальный поток есть, но критерии не выполнены"
        status = {c["n"]: c["status"] for c in admin.get(f"{BASE}/evidence").json()["criteria"]}
        assert status[5] == "FAIL"

    def test_lab_node_decisions_do_not_count_as_real_evidence(
        self, client, people, engine, organization
    ) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models_enforcement import EnforcementDecisionRecord
        from sqlalchemy.orm import sessionmaker

        seed_node(engine, organization, "LABNODE", "LAB")
        seed_node(engine, organization, "REALNODE", "INBOUND")
        with sessionmaker(bind=engine, expire_on_commit=False)() as session:
            for i in range(120):
                session.add(
                    EnforcementDecisionRecord(
                        organization_id=organization.id,
                        node_id="LABNODE",
                        internet_message_id=f"lab-{i}@x",
                        control_type="SPAM_REJECT",
                        decision="REJECT",
                        suggested_action="REJECT",
                        review_outcome="CORRECT",
                    )
                )
            session.commit()
        for i in range(3):
            seed_decision(engine, organization, "REALNODE", i, review_outcome="CORRECT")

        spam = as_(client, people, "admin").get(f"{BASE}/metrics").json()["controls"]["SPAM_REJECT"]

        assert spam["reviewed"] == 3, "лабораторные просмотры попали в реальную выборку"
        control = next(
            c
            for c in as_(client, people, "admin").get(f"{BASE}/readiness").json()["controls"]
            if c["control"] == "SPAM_REJECT"
        )
        assert control["can_canary_on_real"] is False

    def test_an_unregistered_node_is_treated_as_lab(self, client, people, engine, organization) -> None:  # type: ignore[no-untyped-def]
        seed_decision(engine, organization, "GHOST", 1, review_outcome="CORRECT")
        spam = as_(client, people, "admin").get(f"{BASE}/metrics").json()["controls"]["SPAM_REJECT"]
        assert spam["reviewed"] == 0


class TestAppliedActionsAreReviewed:
    def test_review_coverage_is_the_share_of_applied_actions_that_were_reviewed(
        self, client, people, engine, organization
    ) -> None:  # type: ignore[no-untyped-def]
        seed_node(engine, organization, "REALNODE", "INBOUND")
        seed_decision(
            engine, organization, "REALNODE", 1, applied_action="SMTP_REJECT", review_outcome="CORRECT"
        )
        seed_decision(engine, organization, "REALNODE", 2, applied_action="SMTP_REJECT")
        seed_decision(
            engine, organization, "REALNODE", 3, applied_action="QUARANTINED", review_outcome="CORRECT"
        )

        applied = as_(client, people, "admin").get(f"{BASE}/metrics").json()["applied"]

        assert applied["applied_rejects"] == 2 and applied["applied_rejects_reviewed"] == 1
        assert applied["applied_rejects_review_coverage"] == 0.5
        assert applied["applied_quarantines_review_coverage"] == 1.0
        status = {
            c["n"]: c["status"]
            for c in as_(client, people, "admin").get(f"{BASE}/evidence").json()["criteria"]
        }
        assert status[6] == "FAIL"

    def test_a_critical_false_positive_makes_the_pilot_not_ready(
        self, client, people, engine, organization
    ) -> None:  # type: ignore[no-untyped-def]
        seed_validation(engine, organization, ValidationSource.JOURNAL_COPY, 5, tag="j")
        seed_node(engine, organization, "REALNODE", "INBOUND")
        seed_decision(
            engine, organization, "REALNODE", 1, review_outcome="FALSE_POSITIVE", review_critical=True
        )

        ready = as_(client, people, "admin").get(f"{BASE}/readiness").json()

        assert ready["decision"] == "NOT_READY" and "CRITICAL_FP" in ready["decision_reasons"]


class TestEnforcementWithoutApproval:
    def test_an_active_control_without_the_canary_decision_is_a_violation(
        self, client, people, engine, organization
    ) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models_enforcement import EnforcementControlRecord
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        admin = as_(client, people, "admin")
        admin.get("/api/v1/enforcement/controls")
        seed_validation(engine, organization, ValidationSource.JOURNAL_COPY, 5, tag="j")
        with sessionmaker(bind=engine, expire_on_commit=False)() as session:
            row = session.execute(
                select(EnforcementControlRecord).where(EnforcementControlRecord.control_type == "SPAM_REJECT")
            ).scalar_one()
            row.state = "CANARY"
            session.commit()

        ready = admin.get(f"{BASE}/readiness").json()

        assert ready["decision"] == "NOT_READY"
        assert "ENFORCEMENT_ACTIVE_WITHOUT_P4_GO" in ready["decision_reasons"]
        gate = admin.get(f"{BASE}/phases/P1/gate").json()
        assert "no_enforcement_before_p4" in gate["blocking"]


class TestEvidenceExport:
    def test_the_export_contains_no_message_bodies_or_addresses(self, client, people, team) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        attest_all(admin, P1_KEYS)
        proposed = admin.post(f"{BASE}/phases/P1/decision", {"outcome": "GO", "reasons": ["ok"]}).json()
        person(client, team["mail"]).post(
            f"{BASE}/decisions/{proposed['id']}/approve", {"role": "MAIL_ADMIN"}
        )
        admin = as_(client, people, "admin")
        stop = admin.post(
            f"{BASE}/stop", {"reason_code": "OTHER", "description": "ivan@corp.example жалуется"}
        ).json()
        assert stop["state"] == "OPEN"

        export = as_(client, people, "analyst").get(f"{BASE}/evidence").json()
        text = json.dumps(export, ensure_ascii=False)

        assert export["contains_message_bodies"] is False
        assert "@corp.example" not in text, "адрес учётной записи попал в выгрузку"
        assert "ivan" not in text

        def keys(node):  # type: ignore[no-untyped-def]
            if isinstance(node, dict):
                for key, value in node.items():
                    yield key
                    yield from keys(value)
            elif isinstance(node, list):
                for item in node:
                    yield from keys(item)

        from msp_api.services.pilot import FORBIDDEN_EXPORT_KEYS

        assert not (set(keys(export)) & FORBIDDEN_EXPORT_KEYS)

    def test_the_export_is_audited(self, client, people, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import AuditEvent as AuditLog
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        as_(client, people, "admin").get(f"{BASE}/evidence")
        with sessionmaker(bind=engine)() as session:
            rows = (
                session.execute(select(AuditLog).where(AuditLog.action == "pilot.evidence_exported"))
                .scalars()
                .all()
            )
        assert len(rows) == 1

    def test_the_decision_cannot_be_set_by_hand(self, client, people) -> None:  # type: ignore[no-untyped-def]
        """Итог вычисляется; ни одной точки, которая записывала бы его, нет."""
        admin = as_(client, people, "admin")
        ready = admin.get(f"{BASE}/readiness").json()
        assert admin.get(f"{BASE}/evidence").json()["decision"] == ready["decision"]
        for method in ("put", "patch"):
            response = getattr(admin.client, method)(
                f"{BASE}/readiness", json={"decision": "READY_FOR_MSP_1_4"}
            )
            assert response.status_code in (404, 405)
