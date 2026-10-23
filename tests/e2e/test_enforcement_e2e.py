"""API принуждения MSP 1.3 через HTTP: права, четыре глаза, пробелы, выключатель, карантин, токены.

Интересное живёт между частями: роль, которая не вправе включать; автор, согласующий сам себя; контроль,
заблокированный пробелом; политика, которую узел обязан проверить; письмо, выпущенное дважды. Модульный тест
не видит ни сессии, ни базы, ни роли.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import timedelta
from typing import ClassVar

import pytest
from msp_contracts import Role
from msp_enforcement.model import ControlState
from msp_enforcement.policy import PolicyBundle, verify_bundle

from .test_transport_e2e import NODE, TOKEN, Person, as_, client, node_headers, people  # noqa: F401

BASE = "/api/v1/enforcement"
KEY = "p" * 48
POLICY_TOKEN = "e" * 40
SHADOW_TOKEN = "s" * 40
AGENT_TOKEN = "g" * 40


@pytest.fixture
def enf(client, people, engine, organization, monkeypatch):  # type: ignore[no-untyped-def]
    from msp_api.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "enforcement_policy_signing_key", KEY)
    monkeypatch.setattr(settings, "quarantine_encryption_key", "q" * 48)
    monkeypatch.setattr(settings, "enforcement_lab_mode", True)
    return settings


@pytest.fixture
def second_admin(client, engine, organization, people):  # type: ignore[no-untyped-def]
    from msp_api.db.models import User
    from msp_api.security.auth import hash_password
    from sqlalchemy.orm import sessionmaker

    password = "Transport-Test-Password-4"
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        session.add(
            User(
                organization_id=organization.id,
                email="admin2@corp.example",
                display_name="admin2",
                role=Role.SECURITY_ADMIN,
                password_hash=hash_password(password),
            )
        )
        session.commit()
    return {"email": "admin2@corp.example", "password": password}


def second(client, account) -> Person:  # type: ignore[no-untyped-def]
    client.cookies.clear()
    return Person(client, account["email"], account["password"])


def control_id(admin: Person, kind: str) -> str:
    items = admin.get(f"{BASE}/controls").json()["items"]
    return next(i["id"] for i in items if i["type"] == kind)


def report_clean_node(client, clean: bool = True) -> None:  # type: ignore[no-untyped-def]
    response = client.post(
        "/api/v1/gateway-agent/rspamd-status",
        json={
            "node_id": NODE,
            "state": {
                "up": True,
                "effective_actions": {"clean": clean, "unknown": 0 if clean else 2, "audited": True},
            },
        },
        headers=node_headers(),
    )
    assert response.status_code == 200, response.text


def seed_reviewed_rejects(engine, organization, count=120, false_positives=0):  # type: ignore[no-untyped-def]
    from msp_api.db.models_antispam import SpamReview, SpamScan
    from sqlalchemy.orm import sessionmaker

    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        for i in range(count):
            scan = SpamScan(
                organization_id=organization.id,
                node_id=NODE,
                queue_id=f"Q{i:06d}",
                internet_message_id=f"seed-{i}@x",
                score=18.0,
                suggested_action="REJECT",
                spam_class="HIGH_CONFIDENCE_SPAM",
            )
            session.add(scan)
            session.flush()
            session.add(
                SpamReview(
                    organization_id=organization.id,
                    scan_id=scan.id,
                    verdict="HAM" if i < false_positives else "SPAM",
                    selection="SUGGESTED_REJECT",
                    reviewed_by="analyst@corp.example",
                )
            )
        session.commit()


def make_spam_ready(client, admin: Person, engine, organization, count=120, false_positives=0) -> str:  # type: ignore[no-untyped-def]
    cid = control_id(admin, "SPAM_REJECT")
    report_clean_node(client)
    seed_reviewed_rejects(engine, organization, count, false_positives)
    for name in ("control_tests_green", "rspamd_failopen_tested"):
        assert (
            admin.post(
                f"{BASE}/controls/{cid}/attest", {"name": name, "value": True, "ref": "ci-run-1"}
            ).status_code
            == 200
        )
    return cid


SCOPE = {"recipients": ["pilot@corp.example"]}


def request_canary(admin: Person, cid: str, **over: object):  # type: ignore[no-untyped-def]
    body = {
        "action": "request",
        "scope": SCOPE,
        "justification": "лабораторная канарейка спама",
        "rollback_version": "",
        **over,
    }
    response = admin.post(f"{BASE}/controls/{cid}/canary", body)
    response.text
    return response


# --- права ------------------------------------------------------------------------------------
class TestWhoMayDoWhat:
    READ = (
        f"{BASE}/controls",
        f"{BASE}/decisions",
        f"{BASE}/safety",
        f"{BASE}/kill-switch",
        f"{BASE}/exceptions",
        f"{BASE}/policies",
        f"{BASE}/metrics",
        "/api/v1/quarantine",
    )

    @pytest.mark.parametrize("path", READ)
    def test_an_employee_sees_nothing(self, client, people, enf, path: str) -> None:  # type: ignore[no-untyped-def]
        assert as_(client, people, "employee").get(path).status_code == 403

    @pytest.mark.parametrize("who", ["viewer", "analyst", "admin", "platform"])
    def test_security_and_platform_roles_read_controls(self, client, people, enf, who: str) -> None:  # type: ignore[no-untyped-def]
        assert as_(client, people, who).get(f"{BASE}/controls").status_code == 200

    def test_the_quarantine_is_closed_to_viewer_and_platform(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        for who in ("viewer", "platform"):
            assert as_(client, people, who).get("/api/v1/quarantine").status_code == 403, who
        for who in ("analyst", "admin"):
            assert as_(client, people, who).get("/api/v1/quarantine").status_code == 200, who

    def test_only_the_security_admin_activates_and_rolls_back(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        cid = control_id(admin, "SPAM_REJECT")
        for who in ("viewer", "analyst", "platform"):
            person = as_(client, people, who)
            assert person.post(f"{BASE}/controls/{cid}/canary", {}).status_code == 403, who
            assert person.post(f"{BASE}/controls/{cid}/pilot", {}).status_code == 403, who
            assert person.post(f"{BASE}/controls/{cid}/rollback", {}).status_code == 403, who

    def test_the_platform_admin_can_stop_but_not_start(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        platform = as_(client, people, "platform")
        assert platform.post(f"{BASE}/kill-switch", {"reason": "тест выключателя"}).status_code == 200
        cid = control_id(platform, "SPAM_REJECT")
        assert platform.post(f"{BASE}/controls/{cid}/canary", {}).status_code == 403

    def test_an_analyst_simulates_but_cannot_pause_or_switch(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        analyst = as_(client, people, "analyst")
        cid = control_id(analyst, "SPAM_REJECT")
        assert analyst.post(f"{BASE}/controls/{cid}/pause", {"reason": "тест"}).status_code == 403
        assert analyst.post(f"{BASE}/kill-switch", {"reason": "тест выключателя"}).status_code == 403


# --- контроли и пробелы -----------------------------------------------------------------------
class TestControls:
    def test_all_controls_start_without_enforcement_and_there_is_no_global_flag(
        self, client, people, enf
    ) -> None:  # type: ignore[no-untyped-def]
        body = as_(client, people, "admin").get(f"{BASE}/controls").json()
        assert [i["type"] for i in body["items"]] == [
            "SPAM_REJECT",
            "DMARC_REJECT",
            "RBL_REJECT",
            "MALWARE_REJECT",
            "PHISHING_REJECT",
            "TEMPFAIL_ABUSE",
            "QUARANTINE",
            "OUTBOUND_BLOCK",
        ]
        assert all(i["state"] == "SHADOW" for i in body["items"])
        assert body["global_enforcement_flag"] is None
        assert "NOT APPROVED FOR GLOBAL PRODUCTION MX CUTOVER" in body["warning"]

    def test_dmarc_reject_is_blocked_by_the_open_gap(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        view = admin.get(f"{BASE}/controls/DMARC_REJECT").json()
        assert view["readiness_status"] == "BLOCKED_BY_GAP" and view["blocking_gaps"] == ["GAP-006"]

    def test_activating_a_gap_blocked_control_is_409_and_audited(self, client, people, enf, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import AuditEvent
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        admin = as_(client, people, "admin")
        response = admin.post(
            f"{BASE}/controls/DMARC_REJECT/canary",
            {"action": "request", "scope": SCOPE, "justification": "попытка включить заблокированный"},
        )
        assert response.status_code == 409
        assert response.json()["detail"]["readiness"] == "BLOCKED_BY_GAP"
        with sessionmaker(bind=engine)() as session:
            denied = (
                session.execute(
                    select(AuditEvent).where(AuditEvent.action == "enforcement.activation_refused")
                )
                .scalars()
                .all()
            )
        assert denied and denied[-1].outcome == "denied"

    def test_even_a_forged_pending_request_cannot_activate_a_blocked_control(
        self, client, people, enf, engine
    ) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models_enforcement import EnforcementControlRecord
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        admin = as_(client, people, "admin")
        cid = control_id(admin, "DMARC_REJECT")
        with sessionmaker(bind=engine, expire_on_commit=False)() as session:
            row = session.execute(
                select(EnforcementControlRecord).where(EnforcementControlRecord.id == cid)
            ).scalar_one()
            row.pending_request = {
                "target": "CANARY",
                "scope": SCOPE,
                "thresholds": {},
                "justification": "x" * 12,
                "rollback_version": "v1",
                "requested_by": "someone@corp.example",
            }
            session.commit()
        response = admin.post(f"{BASE}/controls/{cid}/canary", {"action": "approve"})
        assert response.status_code == 409 and response.json()["detail"]["readiness"] == "BLOCKED_BY_GAP"

    def test_spam_reject_is_not_ready_without_a_reviewed_sample(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        view = admin.get(f"{BASE}/controls/SPAM_REJECT").json()
        assert view["readiness_status"] == "NOT_READY"
        assert any(r.startswith("INSUFFICIENT_SAMPLE") for r in view["readiness_reasons"])
        response = request_canary(admin, view["id"])
        assert response.status_code == 409

    def test_a_node_with_hidden_actions_keeps_the_control_not_ready(
        self, client, people, enf, engine, organization
    ) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        cid = make_spam_ready(client, admin, engine, organization)
        report_clean_node(client, clean=False)
        view = admin.get(f"{BASE}/controls/{cid}").json()
        assert view["readiness_status"] == "NOT_READY"
        assert "EFFECTIVE_ACTIONS_NOT_AUDITED_OR_UNKNOWN_SOURCE" in view["readiness_reasons"]

    def test_critical_false_positives_in_the_sample_block(
        self, client, people, enf, engine, organization
    ) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        cid = make_spam_ready(client, admin, engine, organization, count=150, false_positives=5)
        view = admin.get(f"{BASE}/controls/{cid}").json()
        assert view["readiness_status"] == "NOT_READY"
        assert any(r.startswith("FP_ABOVE_THRESHOLD") for r in view["readiness_reasons"])

    def test_an_attestation_needs_a_reference(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        cid = control_id(admin, "SPAM_REJECT")
        response = admin.post(
            f"{BASE}/controls/{cid}/attest", {"name": "control_tests_green", "value": True, "ref": ""}
        )
        assert response.status_code == 422
        assert (
            admin.post(
                f"{BASE}/controls/{cid}/attest", {"name": "bogus", "value": True, "ref": "r"}
            ).status_code
            == 422
        )


# --- четыре глаза и политика ------------------------------------------------------------------
class TestActivation:
    def test_the_author_cannot_approve_their_own_request(
        self, client, people, enf, engine, organization
    ) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        cid = make_spam_ready(client, admin, engine, organization)
        first = request_canary(admin, cid)
        assert first.status_code == 200, first.text
        assert first.json()["status"] == "PENDING_APPROVAL"
        mine = admin.post(f"{BASE}/controls/{cid}/canary", {"action": "approve"})
        assert mine.status_code == 403
        assert admin.get(f"{BASE}/controls/{cid}").json()["state"] == "SHADOW"

    def test_a_second_admin_activates_and_a_signed_policy_is_published(  # type: ignore[no-untyped-def]
        self, client, people, enf, engine, organization, second_admin
    ) -> None:
        admin = as_(client, people, "admin")
        cid = make_spam_ready(client, admin, engine, organization)
        before = admin.get(f"{BASE}/policies/current").json()
        assert request_canary(admin, cid).status_code == 200
        other = second(client, second_admin)
        result = other.post(f"{BASE}/controls/{cid}/canary", {"action": "approve"})
        assert result.status_code == 200, result.text
        view = result.json()["control"]
        assert view["state"] == "CANARY" and view["approved_by"] == "admin2@corp.example"
        assert view["activated_by"] == "admin@corp.example"
        current = other.get(f"{BASE}/policies/current").json()
        assert current["version"] != before["version"] and current["checksum"] != before["checksum"]
        spam = next(c for c in current["body"]["controls"] if c["control_type"] == "SPAM_REJECT")
        assert spam["state"] == "CANARY" and spam["canary_scope"]["recipients"] == ["pilot@corp.example"]
        # Узел получает пакет, который проверяется ключом подписи.
        payload = client.get("/api/v1/gateway-agent/enforcement/policy", headers=node_headers()).json()
        policy = verify_bundle(PolicyBundle.model_validate(payload["bundle"]), KEY.encode())
        assert policy.checksum() == current["checksum"] and payload["kill_switch"] is False

    def test_the_node_bundle_is_rejected_with_a_wrong_key(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        as_(client, people, "admin").get(f"{BASE}/controls")
        payload = client.get("/api/v1/gateway-agent/enforcement/policy", headers=node_headers()).json()
        with pytest.raises(ValueError):
            verify_bundle(PolicyBundle.model_validate(payload["bundle"]), b"w" * 48)

    def test_an_empty_scope_and_a_missing_justification_are_refused(
        self, client, people, enf, engine, organization
    ) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        cid = make_spam_ready(client, admin, engine, organization)
        assert request_canary(admin, cid, scope={}).status_code == 422
        assert request_canary(admin, cid, justification="коротко").status_code == 422

    def test_a_pilot_needs_real_evidence_not_a_lab_sample(
        self, client, people, enf, engine, organization, second_admin
    ) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        cid = make_spam_ready(client, admin, engine, organization)
        response = admin.post(
            f"{BASE}/controls/{cid}/pilot",
            {"action": "request", "scope": SCOPE, "justification": "пилот на лабораторной выборке"},
        )
        assert response.status_code == 409
        assert "LAB_EVIDENCE_ONLY" in str(admin.get(f"{BASE}/controls/{cid}").json()["readiness_warnings"])

    def test_outside_lab_mode_the_lab_sample_does_not_allow_even_a_canary(
        self, client, people, enf, engine, organization, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr(enf, "enforcement_lab_mode", False)
        admin = as_(client, people, "admin")
        cid = make_spam_ready(client, admin, engine, organization)
        assert request_canary(admin, cid).status_code == 409

    def test_activation_without_a_signing_key_is_refused(
        self, client, people, enf, engine, organization, second_admin, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        cid = make_spam_ready(client, admin, engine, organization)
        assert request_canary(admin, cid).status_code == 200
        monkeypatch.setattr(enf, "enforcement_policy_signing_key", "")
        response = second(client, second_admin).post(f"{BASE}/controls/{cid}/canary", {"action": "approve"})
        assert response.status_code == 503
        assert admin.get(f"{BASE}/controls/{cid}").json()["state"] == "SHADOW"

    def test_pause_and_rollback_return_the_previous_policy(
        self, client, people, enf, engine, organization, second_admin
    ) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        cid = make_spam_ready(client, admin, engine, organization)
        first = admin.get(f"{BASE}/policies/current").json()
        assert request_canary(admin, cid, rollback_version=first["version"]).status_code == 200
        other = second(client, second_admin)
        assert other.post(f"{BASE}/controls/{cid}/canary", {"action": "approve"}).status_code == 200
        canary = other.get(f"{BASE}/policies/current").json()
        assert canary["checksum"] != first["checksum"]
        rolled = other.post(f"{BASE}/controls/{cid}/rollback", {"reason": "ложные срабатывания"})
        assert rolled.status_code == 200
        now_current = other.get(f"{BASE}/policies/current").json()
        # Узлы возвращаются к контрольной сумме прежней версии, а не к новой копии.
        assert now_current["checksum"] == first["checksum"] and now_current["version"] == first["version"]
        assert other.get(f"{BASE}/controls/{cid}").json()["state"] == "ROLLED_BACK"

    def test_pause_republishes_a_policy_without_the_active_control(
        self, client, people, enf, engine, organization, second_admin
    ) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        cid = make_spam_ready(client, admin, engine, organization)
        assert request_canary(admin, cid).status_code == 200
        other = second(client, second_admin)
        assert other.post(f"{BASE}/controls/{cid}/canary", {"action": "approve"}).status_code == 200
        paused = other.post(f"{BASE}/controls/{cid}/pause", {"reason": "проверка паузы"})
        assert paused.status_code == 200
        spam = next(
            c
            for c in other.get(f"{BASE}/policies/current").json()["body"]["controls"]
            if c["control_type"] == "SPAM_REJECT"
        )
        assert spam["state"] == ControlState.PAUSED.value


# --- общий выключатель ------------------------------------------------------------------------
class TestKillSwitch:
    def test_one_person_activates_it_at_once_and_nodes_see_it(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        platform = as_(client, people, "platform")
        assert (
            platform.post(f"{BASE}/kill-switch", {"reason": "массовые ложные срабатывания"}).status_code
            == 200
        )
        state = client.get("/api/v1/gateway-agent/enforcement/state", headers=node_headers()).json()
        assert state["kill_switch"] is True

    def test_clearing_needs_a_second_person(self, client, people, enf, second_admin) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        admin.post(f"{BASE}/kill-switch", {"reason": "тест выключателя"})
        first = admin.post(f"{BASE}/kill-switch/clear", {"reason": "всё починили"})
        assert first.json()["status"] == "CLEAR_REQUESTED"
        again = admin.post(f"{BASE}/kill-switch/clear", {"reason": "всё починили"})
        assert again.status_code == 403
        assert admin.get(f"{BASE}/kill-switch").json()["active"] is True
        done = second(client, second_admin).post(f"{BASE}/kill-switch/clear", {"reason": "подтверждаю"})
        assert done.json()["status"] == "CLEARED" and done.json()["active"] is False
        state = client.get("/api/v1/gateway-agent/enforcement/state", headers=node_headers()).json()
        assert state["kill_switch"] is False

    def test_the_switch_and_its_clearing_are_audited(self, client, people, enf, engine, second_admin) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import AuditEvent
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        admin = as_(client, people, "admin")
        admin.post(f"{BASE}/kill-switch", {"reason": "тест выключателя"})
        admin.post(f"{BASE}/kill-switch/clear", {"reason": "запрос"})
        admin.post(f"{BASE}/kill-switch/clear", {"reason": "сам же"})
        with sessionmaker(bind=engine)() as session:
            actions = [e.action for e in session.execute(select(AuditEvent)).scalars()]
        assert "enforcement.kill_switch_activated" in actions
        assert actions.count("enforcement.kill_switch_cleared") >= 2


# --- исключения -------------------------------------------------------------------------------
class TestExceptions:
    BODY: ClassVar[dict[str, str]] = {
        "scope": "SENDER",
        "control": "SPAM_REJECT",
        "value": "boss@partner.example",
        "reason": "известный партнёр",
    }

    def test_an_exception_has_an_expiry_and_cannot_be_open_ended(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        analyst = as_(client, people, "analyst")
        too_long = analyst.post(f"{BASE}/exceptions", {**self.BODY, "expires_in_hours": 24 * 400})
        assert too_long.status_code == 422
        ok = analyst.post(f"{BASE}/exceptions", self.BODY)
        assert ok.status_code == 201 and ok.json()["active"] is True and ok.json()["expires_at"]

    def test_a_sensitive_control_exception_needs_a_second_person(
        self, client, people, enf, second_admin
    ) -> None:  # type: ignore[no-untyped-def]
        analyst = as_(client, people, "analyst")
        created = analyst.post(f"{BASE}/exceptions", {**self.BODY, "control": "MALWARE_REJECT"})
        assert created.status_code == 201 and created.json()["active"] is False
        assert created.json()["needs_four_eyes"] is True
        eid = created.json()["id"]
        approved = as_(client, people, "admin").post(f"{BASE}/exceptions/{eid}/approve", {})
        assert approved.status_code == 200 and approved.json()["active"] is True

    def test_the_owner_cannot_approve_their_own_exception(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        created = admin.post(f"{BASE}/exceptions", {**self.BODY, "control": "MALWARE_REJECT"}).json()
        assert admin.post(f"{BASE}/exceptions/{created['id']}/approve", {}).status_code == 403

    def test_an_active_exception_enters_the_policy_and_revocation_removes_it(
        self, client, people, enf
    ) -> None:  # type: ignore[no-untyped-def]
        analyst = as_(client, people, "analyst")
        created = analyst.post(f"{BASE}/exceptions", self.BODY).json()
        assert created["policy_version"]
        policy = analyst.get(f"{BASE}/policies/current").json()
        assert [e["value"] for e in policy["body"]["exceptions"]] == ["boss@partner.example"]
        assert analyst.post(f"{BASE}/exceptions/{created['id']}/revoke", {}).status_code == 200
        policy = analyst.get(f"{BASE}/policies/current").json()
        assert policy["body"]["exceptions"] == []


# --- решения, разбор и инциденты --------------------------------------------------------------
def decision(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "transport_message_id": "QABC123",
        "control_type": "SPAM_REJECT",
        "decision": "REJECT",
        "smtp_action": "550 5.7.1 Message rejected by local policy",
        "suggested_action": "REJECT",
        "applied_action": "SMTP_REJECT",
        "reason_codes": ["SPAM_HIGH_SCORE"],
        "evidence_ids": ["scan-1"],
        "policy_version": "v2",
        "policy_checksum": "c" * 64,
        "engine_versions": {"rspamd": "3.12.1"},
        "latency_ms": 12.5,
        "recipient_count": 1,
        "decided_at": "2026-10-23T12:00:00+00:00",
    }
    base.update(over)
    return base


def post_decisions(client, *items: dict) -> dict:  # type: ignore[no-untyped-def]
    response = client.post(
        "/api/v1/gateway-agent/enforcement/decisions",
        json={"node_id": NODE, "decisions": list(items)},
        headers=node_headers(),
    )
    assert response.status_code == 200, response.text
    return response.json()


class TestDecisions:
    def test_decisions_are_stored_idempotently_with_suggested_and_applied_apart(
        self, client, people, enf
    ) -> None:  # type: ignore[no-untyped-def]
        assert post_decisions(client, decision())["accepted"] == 1
        assert post_decisions(client, decision())["duplicate"] == 1
        items = as_(client, people, "analyst").get(f"{BASE}/decisions").json()["items"]
        assert len(items) == 1
        assert items[0]["suggested_action"] == "REJECT" and items[0]["applied_action"] == "SMTP_REJECT"
        assert items[0]["policy_version"] == "v2" and items[0]["evidence_ids"] == ["scan-1"]

    def test_each_applied_reject_is_audited(self, client, people, enf, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import AuditEvent
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        post_decisions(
            client, decision(), decision(transport_message_id="QOTHER", applied_action="OBSERVE_ONLY")
        )
        with sessionmaker(bind=engine)() as session:
            events = (
                session.execute(select(AuditEvent).where(AuditEvent.action == "enforcement.decision_applied"))
                .scalars()
                .all()
            )
        assert len(events) == 1 and events[0].detail["policy_version"] == "v2"

    def test_malformed_decisions_are_rejected_not_stored(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        outcome = post_decisions(client, {"control_type": "NOPE"}, {"decided_at": "x"})
        assert outcome == {"accepted": 0, "duplicate": 0, "rejected": 2}

    def test_a_critical_false_positive_pauses_the_control_and_opens_an_incident(  # type: ignore[no-untyped-def]
        self, client, people, enf, engine, organization, second_admin
    ) -> None:
        admin = as_(client, people, "admin")
        cid = make_spam_ready(client, admin, engine, organization)
        assert request_canary(admin, cid).status_code == 200
        assert (
            second(client, second_admin)
            .post(f"{BASE}/controls/{cid}/canary", {"action": "approve"})
            .status_code
            == 200
        )
        post_decisions(client, decision())
        analyst = as_(client, people, "analyst")
        did = analyst.get(f"{BASE}/decisions").json()["items"][0]["id"]
        result = analyst.post(
            f"{BASE}/decisions/{did}/review", {"outcome": "FALSE_POSITIVE", "critical": True}
        )
        assert result.status_code == 200 and result.json()["incident"]["state"] == "OPEN"
        assert analyst.get(f"{BASE}/controls/{cid}").json()["state"] == "PAUSED"
        # Пока инцидент не закрыт, включить контроль снова нельзя.
        admin = as_(client, people, "admin")
        again = request_canary(admin, cid)
        assert again.status_code == 409

    def test_the_incident_goes_through_every_step_before_the_control_can_return(  # type: ignore[no-untyped-def]
        self, client, people, enf, engine, organization
    ) -> None:
        admin = as_(client, people, "admin")
        incident = admin.post(
            f"{BASE}/incidents", {"control": "SPAM_REJECT", "title": "ложные отказы партнёрам"}
        ).json()
        iid = incident["id"]
        skip = admin.post(f"{BASE}/incidents/{iid}/advance", {"to": "CLOSED"})
        assert skip.status_code == 409
        assert admin.post(f"{BASE}/incidents/{iid}/advance", {"to": "CONTAINED"}).status_code == 200
        short = admin.post(
            f"{BASE}/incidents/{iid}/advance", {"to": "ROOT_CAUSE_FOUND", "root_cause": "мало"}
        )
        assert short.status_code == 422
        steps = [
            ("ROOT_CAUSE_FOUND", {"root_cause": "порог слишком низкий для рассылок поставщика"}),
            ("REGRESSION_ADDED", {"regression_case": "tests/spam/regression-001"}),
            ("CLOSED", {}),
        ]
        for to, extra in steps:
            assert admin.post(f"{BASE}/incidents/{iid}/advance", {"to": to, **extra}).status_code == 200, to
        assert admin.get(f"{BASE}/incidents").json()["items"][0]["state"] == "CLOSED"


class TestSimulatorAndReplay:
    def seed_scan(self, engine, organization, **over):  # type: ignore[no-untyped-def]
        from msp_api.db.models_antispam import SpamScan
        from sqlalchemy.orm import sessionmaker

        with sessionmaker(bind=engine, expire_on_commit=False)() as session:
            scan = SpamScan(
                organization_id=organization.id,
                node_id=NODE,
                queue_id="QSIM001",
                internet_message_id="sim@x",
                score=19.0,
                suggested_action="REJECT",
                spam_class="HIGH_CONFIDENCE_SPAM",
                client_ip="203.0.113.5",
                signals=[{"code": "BAYES_SPAM", "kind": "SPAM", "risk_effect": "INCREASE"}],
                details={"source_record": {"from": "x@evil.example", "rcpt": ["pilot@corp.example"]}},
                **over,
            )
            session.add(scan)
            session.commit()
            return scan.id

    def test_the_simulator_shows_a_hypothetical_action_and_changes_nothing(
        self, client, people, enf, engine, organization
    ) -> None:  # type: ignore[no-untyped-def]
        sid = self.seed_scan(engine, organization)
        analyst = as_(client, people, "analyst")
        cid = control_id(analyst, "SPAM_REJECT")
        result = analyst.post(f"{BASE}/controls/{cid}/simulate", {"scan_id": sid}).json()
        assert result["suggested_action"] == "REJECT"
        assert result["hypothetical_applied_action"] == "SMTP_REJECT"
        assert result["current_applied_action"] == "OBSERVE_ONLY"
        assert as_(client, people, "admin").get(f"{BASE}/controls/{cid}").json()["state"] == "SHADOW"

    def test_the_simulator_reports_the_gap_blocker_for_dmarc(
        self, client, people, enf, engine, organization
    ) -> None:  # type: ignore[no-untyped-def]
        sid = self.seed_scan(engine, organization)
        analyst = as_(client, people, "analyst")
        cid = control_id(analyst, "DMARC_REJECT")
        result = analyst.post(f"{BASE}/controls/{cid}/simulate", {"scan_id": sid}).json()
        assert result["gap_blockers"] == ["GAP-006"] and result["readiness"] == "BLOCKED_BY_GAP"
        assert "AUTH_SPF_FAIL" in result["restricted_reasons"]

    def test_replay_counts_what_the_policy_would_do_without_acting(
        self, client, people, enf, engine, organization
    ) -> None:  # type: ignore[no-untyped-def]
        self.seed_scan(engine, organization)
        analyst = as_(client, people, "analyst")
        cid = control_id(analyst, "SPAM_REJECT")
        result = analyst.post(f"{BASE}/controls/{cid}/replay", {"hours": 24}).json()
        assert result["evaluated"] == 1 and result["decisions"] == {"REJECT": 1}
        assert "без действий" in result["note"]

    def test_replay_with_a_stricter_threshold_rejects_less(
        self, client, people, enf, engine, organization
    ) -> None:  # type: ignore[no-untyped-def]
        self.seed_scan(engine, organization)
        analyst = as_(client, people, "analyst")
        cid = control_id(analyst, "SPAM_REJECT")
        result = analyst.post(f"{BASE}/controls/{cid}/replay", {"thresholds": {"reject_score": 25.0}}).json()
        assert result["decisions"].get("REJECT", 0) == 0


# --- карантин ---------------------------------------------------------------------------------
RAW = (
    b"From: bad@evil.example\r\nTo: ivan@corp.example\r\nSubject: Open http://evil.example/x now\r\n"
    b"Message-ID: <q1@evil.example>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
    b"Click http://evil.example/login immediately. SECRET-BODY-MARKER\r\n"
)


def store(client, raw: bytes = RAW, **over: object):  # type: ignore[no-untyped-def]
    body = {
        "node_id": NODE,
        "transport_message_id": "QTEST001",
        "internet_message_id": "q1@evil.example",
        "decision_ref": "d1",
        "sender": "bad@evil.example",
        "recipients": ["ivan@corp.example"],
        "subject": "Open http://evil.example/x now",
        "reason_codes": ["RISK_HIGH_RISK"],
        "policy_version": "v2",
        "original_route": "exchange",
        "raw_b64": base64.b64encode(raw).decode(),
        **over,
    }
    return client.post("/api/v1/gateway-agent/quarantine", json=body, headers=node_headers())


def item_key(engine, item_id: str) -> str:  # type: ignore[no-untyped-def]
    from msp_api.db.models_enforcement import QuarantineItemRecord
    from sqlalchemy.orm import sessionmaker

    with sessionmaker(bind=engine)() as session:
        return session.get(QuarantineItemRecord, item_id).content_object_ref


class TestQuarantine:
    def test_stored_mail_is_encrypted_and_listed_without_active_content(
        self, client, people, enf, storage_dir, engine
    ) -> None:  # type: ignore[no-untyped-def]
        import pathlib

        stored = store(client)
        assert stored.status_code == 200, stored.text
        qid = stored.json()["id"]
        key = item_key(engine, qid)
        path = pathlib.Path(storage_dir) / key
        assert key.startswith("quarantine/") and path.is_file(), (
            "письмо должно лежать под отдельным префиксом"
        )
        assert b"SECRET-BODY-MARKER" not in path.read_bytes(), "письмо хранится открытым текстом"
        analyst = as_(client, people, "analyst")
        listing = analyst.get("/api/v1/quarantine").json()
        item = next(i for i in listing["items"] if i["id"] == qid)
        assert "http://" not in item["subject"] and item["state"] == "QUARANTINED"
        assert item["sha256"] == hashlib.sha256(RAW).hexdigest()

    def test_the_preview_is_defanged_and_has_no_html(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        qid = store(client).json()["id"]
        preview = as_(client, people, "analyst").get(f"/api/v1/quarantine/{qid}/preview").json()
        assert "hxxp://evil.example/login" in preview["text"] and "http://" not in preview["text"]
        assert preview["active_content_removed"] is True

    def test_a_wrong_key_cannot_read_the_stored_mail(self, client, people, enf, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        qid = store(client).json()["id"]
        monkeypatch.setattr(enf, "quarantine_encryption_key", "z" * 48)
        assert as_(client, people, "analyst").get(f"/api/v1/quarantine/{qid}/preview").status_code == 500

    def test_without_an_encryption_key_the_node_gets_503_and_fails_open(
        self, client, enf, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr(enf, "quarantine_encryption_key", "")
        assert store(client).status_code == 503

    def test_storing_is_idempotent_for_the_same_decision(self, client, enf) -> None:  # type: ignore[no-untyped-def]
        first = store(client).json()["id"]
        assert store(client).json()["id"] == first

    def test_release_end_to_end_delivers_once(self, client, people, enf, second_admin) -> None:  # type: ignore[no-untyped-def]
        qid = store(client, reason_codes=["RISK_HIGH_RISK"]).json()["id"]
        analyst = as_(client, people, "analyst")
        requested = analyst.post(f"/api/v1/quarantine/{qid}/release", {"action": "request"})
        assert requested.status_code == 200 and requested.json()["state"] == "RELEASE_PENDING"
        pending = client.get(
            f"/api/v1/gateway-agent/quarantine/releases?node_id={NODE}", headers=node_headers()
        ).json()["items"]
        assert [p["id"] for p in pending] == [qid]
        token = pending[0]["token"]
        content = client.get(
            f"/api/v1/gateway-agent/quarantine/{qid}/content?token={token}", headers=node_headers()
        )
        assert base64.b64decode(content.json()["raw_b64"]) == RAW
        done = client.post(
            f"/api/v1/gateway-agent/quarantine/{qid}/confirm",
            json={"token": token, "delivered": True},
            headers=node_headers(),
        )
        assert done.json() == {"state": "RELEASED", "delivered_count": 1}
        # Повтор ссылки не принимается и не доставляет письмо второй раз.
        replay = client.post(
            f"/api/v1/gateway-agent/quarantine/{qid}/confirm",
            json={"token": token, "delivered": True},
            headers=node_headers(),
        )
        assert replay.status_code == 409
        assert (
            client.get(
                f"/api/v1/gateway-agent/quarantine/{qid}/content?token={token}", headers=node_headers()
            ).status_code
            == 409
        )
        again = client.get(
            f"/api/v1/gateway-agent/quarantine/releases?node_id={NODE}", headers=node_headers()
        ).json()["items"]
        assert again == []

    def test_a_malicious_item_needs_a_second_person_to_release(
        self, client, people, enf, second_admin
    ) -> None:  # type: ignore[no-untyped-def]
        qid = store(client, reason_codes=["MALWARE_HIGH_CONFIDENCE"]).json()["id"]
        analyst = as_(client, people, "analyst")
        assert (
            analyst.post(f"/api/v1/quarantine/{qid}/release", {"action": "request"}).json()["needs_approval"]
            is True
        )
        # Без согласования узел ничего не получает.
        none = client.get(
            f"/api/v1/gateway-agent/quarantine/releases?node_id={NODE}", headers=node_headers()
        ).json()["items"]
        assert none == []
        assert analyst.post(f"/api/v1/quarantine/{qid}/release", {"action": "approve"}).status_code == 403
        approver = second(client, second_admin)
        assert approver.post(f"/api/v1/quarantine/{qid}/release", {"action": "approve"}).status_code == 200
        pending = client.get(
            f"/api/v1/gateway-agent/quarantine/releases?node_id={NODE}", headers=node_headers()
        ).json()["items"]
        assert len(pending) == 1

    def test_a_wrong_or_expired_token_does_not_release(self, client, people, enf, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.base import utcnow
        from msp_api.db.models_enforcement import QuarantineItemRecord
        from sqlalchemy.orm import sessionmaker

        qid = store(client).json()["id"]
        as_(client, people, "analyst").post(f"/api/v1/quarantine/{qid}/release", {"action": "request"})
        token = client.get(
            f"/api/v1/gateway-agent/quarantine/releases?node_id={NODE}", headers=node_headers()
        ).json()["items"][0]["token"]
        bad = client.get(
            f"/api/v1/gateway-agent/quarantine/{qid}/content?token={'x' * 43}", headers=node_headers()
        )
        assert bad.status_code == 403
        with sessionmaker(bind=engine)() as session:
            row = session.get(QuarantineItemRecord, qid)
            row.release_token_expires_at = utcnow() - timedelta(minutes=1)
            session.commit()
        assert (
            client.get(
                f"/api/v1/gateway-agent/quarantine/{qid}/content?token={token}", headers=node_headers()
            ).status_code
            == 410
        )

    def test_a_failed_delivery_leaves_the_release_pending_and_issues_a_new_token_next_time(
        self, client, people, enf
    ) -> None:  # type: ignore[no-untyped-def]
        qid = store(client).json()["id"]
        as_(client, people, "analyst").post(f"/api/v1/quarantine/{qid}/release", {"action": "request"})
        first = client.get(
            f"/api/v1/gateway-agent/quarantine/releases?node_id={NODE}", headers=node_headers()
        ).json()["items"][0]["token"]
        failed = client.post(
            f"/api/v1/gateway-agent/quarantine/{qid}/confirm",
            json={"token": first, "delivered": False, "error": "relay down"},
            headers=node_headers(),
        )
        assert failed.json()["state"] == "RELEASE_PENDING"
        second_token = client.get(
            f"/api/v1/gateway-agent/quarantine/releases?node_id={NODE}", headers=node_headers()
        ).json()["items"][0]["token"]
        assert second_token != first
        assert (
            client.get(
                f"/api/v1/gateway-agent/quarantine/{qid}/content?token={first}", headers=node_headers()
            ).status_code
            == 403
        )

    def test_a_released_message_does_not_go_back_into_quarantine(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        qid = store(client).json()["id"]
        as_(client, people, "analyst").post(f"/api/v1/quarantine/{qid}/release", {"action": "request"})
        token = client.get(
            f"/api/v1/gateway-agent/quarantine/releases?node_id={NODE}", headers=node_headers()
        ).json()["items"][0]["token"]
        client.post(
            f"/api/v1/gateway-agent/quarantine/{qid}/confirm",
            json={"token": token, "delivered": True},
            headers=node_headers(),
        )
        loop = store(client, transport_message_id="QTEST002", decision_ref="d2").json()
        assert loop["already_released"] is True
        listing = as_(client, people, "analyst").get("/api/v1/quarantine?state=QUARANTINED").json()
        assert listing["items"] == []

    def test_delete_removes_the_content_and_is_admin_only(
        self, client, people, enf, storage_dir, engine
    ) -> None:  # type: ignore[no-untyped-def]
        import pathlib

        qid = store(client).json()["id"]
        key = item_key(engine, qid)
        assert (
            as_(client, people, "analyst")
            .post(f"/api/v1/quarantine/{qid}/delete", {"reason": "тест"})
            .status_code
            == 403
        )
        deleted = as_(client, people, "admin").post(
            f"/api/v1/quarantine/{qid}/delete", {"reason": "нежелательное письмо"}
        )
        assert deleted.status_code == 200 and deleted.json()["state"] == "DELETED"
        assert not (pathlib.Path(storage_dir) / key).exists()
        assert as_(client, people, "analyst").get(f"/api/v1/quarantine/{qid}/preview").status_code == 410

    def test_expired_items_lose_their_content(self, client, people, enf, engine, storage_dir) -> None:  # type: ignore[no-untyped-def]
        import pathlib

        from msp_api.config import get_settings
        from msp_api.db.base import utcnow
        from msp_api.db.models_enforcement import QuarantineItemRecord
        from msp_api.services import quarantine
        from msp_api.services.storage import build_storage
        from sqlalchemy.orm import sessionmaker

        qid = store(client).json()["id"]
        key = item_key(engine, qid)
        with sessionmaker(bind=engine)() as session:
            row = session.get(QuarantineItemRecord, qid)
            row.expires_at = utcnow() - timedelta(days=1)
            session.commit()
            assert quarantine.expire_due(session, build_storage(get_settings()), row.organization_id) == 1
            session.commit()
            assert session.get(QuarantineItemRecord, qid).state.value == "EXPIRED"
        assert not (pathlib.Path(storage_dir) / key).exists()

    def test_quarantined_mail_is_not_reachable_through_other_endpoints(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        qid = store(client).json()["id"]
        analyst = as_(client, people, "analyst")
        assert analyst.get(f"/api/v1/quarantine/{qid}").json().get("raw") is None
        for path in (f"/api/v1/quarantine/{qid}/raw", f"/api/v1/quarantine/{qid}/download"):
            assert analyst.get(path).status_code in (404, 405)

    def test_view_and_release_are_audited(self, client, people, enf, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import AuditEvent
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        qid = store(client).json()["id"]
        analyst = as_(client, people, "analyst")
        analyst.get(f"/api/v1/quarantine/{qid}")
        analyst.post(f"/api/v1/quarantine/{qid}/release", {"action": "request"})
        token = client.get(
            f"/api/v1/gateway-agent/quarantine/releases?node_id={NODE}", headers=node_headers()
        ).json()["items"][0]["token"]
        client.post(
            f"/api/v1/gateway-agent/quarantine/{qid}/confirm",
            json={"token": token, "delivered": True},
            headers=node_headers(),
        )
        with sessionmaker(bind=engine)() as session:
            actions = {e.action for e in session.execute(select(AuditEvent)).scalars()}
        assert {
            "quarantine.stored",
            "quarantine.viewed",
            "quarantine.release_requested",
            "quarantine.released",
        } <= actions


# --- раздельные токены компонентов ------------------------------------------------------------
class TestCredentialScopes:
    @pytest.fixture
    def split(self, enf, monkeypatch):  # type: ignore[no-untyped-def]
        monkeypatch.setattr(enf, "gateway_shared_token_allowed", False)
        monkeypatch.setattr(enf, "enforcement_policy_token", POLICY_TOKEN)
        monkeypatch.setattr(enf, "shadow_collector_token", SHADOW_TOKEN)
        monkeypatch.setattr(enf, "gateway_agent_token", AGENT_TOKEN)
        return enf

    def get_policy(self, client, token):  # type: ignore[no-untyped-def]
        return client.get("/api/v1/gateway-agent/enforcement/policy", headers=node_headers(token))

    def test_each_component_uses_only_its_own_token(self, client, split) -> None:  # type: ignore[no-untyped-def]
        assert self.get_policy(client, POLICY_TOKEN).status_code == 200
        for other in (SHADOW_TOKEN, AGENT_TOKEN, TOKEN):
            assert self.get_policy(client, other).status_code == 401, other
        events = client.post(
            "/api/v1/gateway-agent/events",
            json={"node_id": NODE, "events": []},
            headers=node_headers(AGENT_TOKEN),
        )
        assert events.status_code == 200
        assert (
            client.post(
                "/api/v1/gateway-agent/events",
                json={"node_id": NODE, "events": []},
                headers=node_headers(POLICY_TOKEN),
            ).status_code
            == 401
        )

    def test_the_shadow_collector_token_cannot_read_policy_or_post_decisions(self, client, split) -> None:  # type: ignore[no-untyped-def]
        assert self.get_policy(client, SHADOW_TOKEN).status_code == 401
        denied = client.post(
            "/api/v1/gateway-agent/enforcement/decisions",
            json={"node_id": NODE, "decisions": []},
            headers=node_headers(SHADOW_TOKEN),
        )
        assert denied.status_code == 401

    def test_the_scan_endpoint_takes_the_collector_token_only(self, client, split) -> None:  # type: ignore[no-untyped-def]
        body = {"node_id": NODE, "scans": []}
        assert (
            client.post(
                "/api/v1/gateway-agent/spam-scans", json=body, headers=node_headers(SHADOW_TOKEN)
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/api/v1/gateway-agent/spam-scans", json=body, headers=node_headers(POLICY_TOKEN)
            ).status_code
            == 401
        )

    def test_rotation_accepts_old_and_new_together_and_audits_the_new_one(
        self, client, split, engine, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import AuditEvent
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        new = "n" * 40
        monkeypatch.setattr(split, "enforcement_policy_token", f"{POLICY_TOKEN},{new}")
        assert self.get_policy(client, POLICY_TOKEN).status_code == 200
        assert self.get_policy(client, new).status_code == 200
        monkeypatch.setattr(split, "enforcement_policy_token", new)
        assert self.get_policy(client, POLICY_TOKEN).status_code == 401
        assert self.get_policy(client, new).status_code == 200
        with sessionmaker(bind=engine)() as session:
            events = (
                session.execute(select(AuditEvent).where(AuditEvent.action == "credential.first_use"))
                .scalars()
                .all()
            )
        assert len(events) >= 2 and all("n" * 5 not in str(e.detail) for e in events)

    def test_the_shared_token_is_accepted_only_while_allowed(self, client, enf, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        assert self.get_policy(client, TOKEN).status_code == 200
        monkeypatch.setattr(enf, "gateway_shared_token_allowed", False)
        assert self.get_policy(client, TOKEN).status_code == 503

    def test_the_overview_shows_the_split_state_without_token_values(self, client, people, split) -> None:  # type: ignore[no-untyped-def]
        body = as_(client, people, "admin").get(f"{BASE}/credentials").json()
        assert body["split"]["shared_token_accepted"] is False
        assert set(body["split"]["scopes_without_own_token"]) == {"recipient-sync", "metrics"}
        text = str(body)
        for secret in (POLICY_TOKEN, SHADOW_TOKEN, AGENT_TOKEN):
            assert secret not in text


# --- безопасность и метрики -------------------------------------------------------------------
class TestSafetyAndMetrics:
    def test_the_safety_dashboard_shows_samples_nodes_and_no_global_cutover(
        self, client, people, enf, engine, organization
    ) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        make_spam_ready(client, admin, engine, organization, count=130, false_positives=0)
        body = admin.get(f"{BASE}/safety").json()
        spam = next(c for c in body["controls"] if c["control"] == "SPAM_REJECT")
        assert spam["reject_safety"]["reviewed_rejects"] == 130 and spam["reject_safety"]["fp_rate"] == 0.0
        assert spam["real_flow_sample"] is False
        assert body["global_production_mx_cutover"] is False and "NOT APPROVED" in body["warning"]

    def test_without_a_denominator_the_rates_are_null_not_zero(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        body = as_(client, people, "admin").get(f"{BASE}/safety").json()
        for control in body["controls"]:
            assert control["reject_safety"]["fp_rate"] is None

    def test_node_policy_drift_is_visible(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        current = admin.get(f"{BASE}/policies/current").json()
        client.post(
            "/api/v1/gateway-agent/enforcement/state",
            json={"node_id": NODE, "state": {"policy_checksum": "0" * 64, "policy_status": "FRESH"}},
            headers=node_headers(),
        )
        node = admin.get(f"{BASE}/safety").json()["nodes"][0]
        assert node["in_sync"] is False
        client.post(
            "/api/v1/gateway-agent/enforcement/state",
            json={
                "node_id": NODE,
                "state": {"policy_checksum": current["checksum"], "policy_status": "FRESH"},
            },
            headers=node_headers(),
        )
        assert admin.get(f"{BASE}/safety").json()["nodes"][0]["in_sync"] is True

    def test_a_local_bypass_report_is_audited_once(self, client, people, enf, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import AuditEvent
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        for _ in range(2):
            client.post(
                "/api/v1/gateway-agent/enforcement/state",
                json={"node_id": NODE, "state": {"local_bypass": True}},
                headers=node_headers(),
            )
        with sessionmaker(bind=engine)() as session:
            events = (
                session.execute(
                    select(AuditEvent).where(AuditEvent.action == "enforcement.local_bypass_reported")
                )
                .scalars()
                .all()
            )
        assert len(events) == 1
        body = as_(client, people, "admin").get(f"{BASE}/safety").json()
        assert body["emergency_bypass_nodes"] == [NODE]

    def test_metrics_split_decisions_by_control_and_action(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        post_decisions(
            client,
            decision(),
            decision(transport_message_id="Q2", applied_action="OBSERVE_ONLY", decision="ALLOW"),
            decision(transport_message_id="Q3", applied_action="BYPASS_KILL_SWITCH", decision="BYPASS"),
        )
        body = as_(client, people, "admin").get(f"{BASE}/metrics").json()["per_control"]["SPAM_REJECT"]
        assert (body["evaluated"], body["applied"], body["bypassed"]) == (3, 1, 1)


class TestAlertsAndMetrics:
    def alerts(self, client, people) -> dict[str, dict]:  # type: ignore[no-untyped-def]
        body = as_(client, people, "admin").get("/api/v1/gateway/alerts").json()
        return {a["code"]: a for a in body["items"]} if "items" in body else {a["code"]: a for a in body}

    def test_the_kill_switch_raises_a_critical_alert(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        as_(client, people, "admin").get(f"{BASE}/controls")
        assert "KILL_SWITCH_ACTIVE" not in self.alerts(client, people)
        as_(client, people, "platform").post(f"{BASE}/kill-switch", {"reason": "проверка тревоги"})
        found = self.alerts(client, people)["KILL_SWITCH_ACTIVE"]
        assert found["severity"] == "CRITICAL"

    def test_a_local_bypass_and_policy_drift_are_alerted(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        admin.get(f"{BASE}/policies/current")
        client.post(
            "/api/v1/gateway-agent/enforcement/state",
            json={
                "node_id": NODE,
                "state": {"local_bypass": True, "policy_checksum": "0" * 64, "policy_status": "STALE"},
            },
            headers=node_headers(),
        )
        codes = set(self.alerts(client, people))
        assert {"LOCAL_BYPASS_ACTIVE", "POLICY_DRIFT", "POLICY_STALE"} <= codes

    def test_a_hidden_rspamd_action_source_is_alerted(self, client, people, enf) -> None:  # type: ignore[no-untyped-def]
        as_(client, people, "admin").get(f"{BASE}/controls")
        report_clean_node(client, clean=False)
        assert self.alerts(client, people)["HIDDEN_RSPAMD_ACTION"]["severity"] == "CRITICAL"

    def test_an_open_incident_is_a_critical_alert_and_a_gap_blocked_active_control_too(  # type: ignore[no-untyped-def]
        self, client, people, enf, engine
    ) -> None:
        from msp_api.db.models_enforcement import EnforcementControlRecord
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        admin = as_(client, people, "admin")
        admin.post(f"{BASE}/incidents", {"control": "SPAM_REJECT", "title": "проверка тревоги инцидента"})
        cid = control_id(admin, "DMARC_REJECT")
        with sessionmaker(bind=engine, expire_on_commit=False)() as session:
            row = session.execute(
                select(EnforcementControlRecord).where(EnforcementControlRecord.id == cid)
            ).scalar_one()
            row.state = "CANARY"
            session.commit()
        codes = self.alerts(client, people)
        assert codes["CRITICAL_FALSE_POSITIVE"]["severity"] == "CRITICAL"
        assert codes["CONTROL_ACTIVE_WHILE_GAP_BLOCKED"]["severity"] == "CRITICAL"

    def test_the_metrics_endpoint_reports_control_state_policy_and_the_switch(
        self, client, people, enf
    ) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        admin.get(f"{BASE}/policies/current")
        as_(client, people, "platform").post(f"{BASE}/kill-switch", {"reason": "проверка метрик"})
        post_decisions(
            client,
            decision(),
            decision(transport_message_id="Q9", applied_action="OBSERVE_ONLY", decision="ALLOW"),
        )
        text = client.get("/metrics").text
        assert 'msp_enforcement_control_state{control="SPAM_REJECT",state="SHADOW"} 1.0' in text
        assert "msp_enforcement_policy_info{" in text and "msp_kill_switch_active 1.0" in text
        assert 'msp_enforcement_decisions_total{control="SPAM_REJECT",decision="REJECT"}' in text
        assert 'msp_enforcement_actions_total{action="SMTP_REJECT",control="SPAM_REJECT"}' in text


class TestRecipientSyncScope:
    ROWS: ClassVar[dict[str, str]] = {
        "format": "csv",
        "content": "address,kind,aliases\n" + "\n".join(f"user{i}@corp.example,USER," for i in range(3)),
        "source": "e2e",
    }

    def test_the_machine_endpoint_takes_only_the_recipient_sync_token(self, client, enf, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr(enf, "gateway_shared_token_allowed", False)
        monkeypatch.setattr(enf, "recipient_sync_token", "r" * 40)
        monkeypatch.setattr(enf, "enforcement_policy_token", POLICY_TOKEN)
        ok = client.post(
            "/api/v1/gateway-agent/recipients/sync", json=self.ROWS, headers=node_headers("r" * 40)
        )
        assert ok.status_code == 200, ok.text
        assert ok.json()["status"] == "ACCEPTED" and ok.json()["recipient_count"] == 3
        for other in (POLICY_TOKEN, TOKEN):
            denied = client.post(
                "/api/v1/gateway-agent/recipients/sync", json=self.ROWS, headers=node_headers(other)
            )
            assert denied.status_code in (401, 503), other

    def test_the_sync_is_audited_as_the_node_component(self, client, enf, engine, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import AuditEvent
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        monkeypatch.setattr(enf, "recipient_sync_token", "r" * 40)
        client.post("/api/v1/gateway-agent/recipients/sync", json=self.ROWS, headers=node_headers("r" * 40))
        with sessionmaker(bind=engine)() as session:
            events = (
                session.execute(select(AuditEvent).where(AuditEvent.actor_email == "node:recipient-sync"))
                .scalars()
                .all()
            )
        assert events
