"""API анти-спама через HTTP (ТЗ 1.2 §33–§35, §42).

Интересное живёт между частями: роль, которая не вправе одобрять; человек, одобряющий собственный
запрос; ключ, который активируют до публикации в DNS; неизвестный символ, влияющий на риск; секрет,
оказавшийся в ответе API. Модульный тест не видит ни сессии, ни базы, ни роли.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from msp_contracts import Role

from .test_transport_e2e import NODE, TOKEN, Person, as_, client, node_headers, people  # noqa: F401

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "rspamd"
BASE = "/api/v1/gateway"


def scan_record(name: str, message_id: str | None = None, **changes: object) -> dict:
    record = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    if message_id:
        record["message_id"] = message_id if "@" in message_id else f"{message_id}@sender.example"
        record["qid"] = (message_id.replace("-", "").upper() + "AAAAAAAAAA")[:11]
    record.update(changes)
    return record


def push(client: TestClient, *records: dict, token: str = TOKEN) -> dict:
    response = client.post(
        "/api/v1/gateway-agent/spam-scans",
        json={"node_id": NODE, "scans": list(records)},
        headers=node_headers(token),
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture
def second_admin(client, engine, organization, people):  # type: ignore[no-untyped-def]
    from msp_api.db.models import User
    from msp_api.security.auth import hash_password
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    password = "Transport-Test-Password-4"
    with factory() as session:
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


def second(client: TestClient, account: dict[str, str]) -> Person:
    client.cookies.clear()
    return Person(client, account["email"], account["password"])


class TestWhoMayDoWhat:
    READ = (
        f"{BASE}/spam/summary",
        f"{BASE}/spam/messages",
        f"{BASE}/spam/rules",
        f"{BASE}/spam/providers",
        f"{BASE}/spam/policies",
        f"{BASE}/auth/distribution",
        f"{BASE}/auth/conflicts",
        f"{BASE}/spam/validation",
        f"{BASE}/spam/bayes",
    )

    @pytest.mark.parametrize("path", READ)
    def test_an_employee_sees_nothing(self, client, people, path: str) -> None:  # type: ignore[no-untyped-def]
        assert as_(client, people, "employee").get(path).status_code == 403

    @pytest.mark.parametrize("who", ["viewer", "analyst", "admin", "platform"])
    def test_security_and_platform_roles_read_the_overview(self, client, people, who: str) -> None:  # type: ignore[no-untyped-def]
        person = as_(client, people, who)
        for path in (f"{BASE}/spam/summary", f"{BASE}/auth/distribution"):
            assert person.get(path).status_code == 200, (who, path)

    def test_only_the_security_admin_edits_policy_providers_and_keys(self, client, people) -> None:  # type: ignore[no-untyped-def]
        for who in ("viewer", "analyst", "platform"):
            person = as_(client, people, who)
            assert person.post(f"{BASE}/spam/policies", {}).status_code == 403, who
            assert person.post(f"{BASE}/spam/providers", {"id": "x"}).status_code == 403, who
            assert (
                person.post(f"{BASE}/dkim/keys", {"domain": "corp.example", "selector": "s1"}).status_code
                == 403
            ), who

    def test_dkim_keys_are_visible_to_the_platform_admin_but_not_to_the_viewer(self, client, people) -> None:  # type: ignore[no-untyped-def]
        assert as_(client, people, "platform").get(f"{BASE}/dkim/keys").status_code == 200
        assert as_(client, people, "viewer").get(f"{BASE}/dkim/keys").status_code == 403

    def test_the_analyst_simulates_but_does_not_edit(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        policy = admin.post(f"{BASE}/spam/policies", {}).json()
        analyst = as_(client, people, "analyst")
        assert analyst.post(f"{BASE}/spam/policies/{policy['id']}/simulate").status_code == 200
        assert (
            analyst.post(f"{BASE}/spam/policies/{policy['id']}/transition", {"target": "SHADOW"}).status_code
            == 403
        )


class TestNodeEndpoints:
    def test_scan_ingest_needs_the_node_token(self, client) -> None:  # type: ignore[no-untyped-def]
        body = {"node_id": NODE, "scans": []}
        assert client.post("/api/v1/gateway-agent/spam-scans", json=body).status_code == 401
        assert (
            client.post(
                "/api/v1/gateway-agent/spam-scans", json=body, headers=node_headers("x" * 40)
            ).status_code
            == 401
        )
        assert client.get("/api/v1/gateway-agent/rspamd-config").status_code == 401

    def test_a_scan_is_stored_normalised_and_never_applied(self, client, people) -> None:  # type: ignore[no-untyped-def]
        assert push(client, scan_record("dmarc_reject_fail", "api-1"))["accepted"] == 1
        admin = as_(client, people, "admin")
        detail = admin.get(f"{BASE}/spam/messages/api-1@sender.example").json()
        assert detail["applied_action"] == "OBSERVE_ONLY"
        assert detail["suggested_action"] in ("ADD_HEADER", "REJECT", "GREYLIST", "NO_ACTION")
        assert detail["auth"]["dmarc"]["suggested_disposition"] == "REJECT"
        assert detail["auth"]["spf"]["result"] == "FAIL"
        assert detail["symbol_mapping_version"] == "1"

    def test_the_same_scan_twice_is_one_record(self, client, people) -> None:  # type: ignore[no-untyped-def]
        record = scan_record("all_pass", "api-dup")
        assert push(client, record)["accepted"] == 1
        assert push(client, record)["duplicate"] == 1
        items = as_(client, people, "admin").get(f"{BASE}/spam/messages").json()["items"]
        assert sum(1 for i in items if i["message_id"].startswith("api-dup")) == 1

    def test_garbage_does_not_stop_the_good_records(self, client) -> None:  # type: ignore[no-untyped-def]
        result = push(client, {"symbols": "x"}, 5, scan_record("all_pass", "api-good"))  # type: ignore[arg-type]
        assert result["accepted"] == 1 and result["rejected"] >= 1

    def test_unknown_symbols_are_kept_but_do_not_enter_the_signals(self, client, people) -> None:  # type: ignore[no-untyped-def]
        record = scan_record("all_pass", "api-unknown")
        record["symbols"].append({"name": "BRAND_NEW_SYMBOL_9000", "score": 50.0, "options": []})
        push(client, record)
        detail = as_(client, people, "admin").get(f"{BASE}/spam/messages/api-unknown@sender.example").json()
        assert "BRAND_NEW_SYMBOL_9000" in detail["unmapped_symbols"]
        assert all(s["symbol"] != "BRAND_NEW_SYMBOL_9000" for s in detail["signals"])
        assert any(s["name"] == "BRAND_NEW_SYMBOL_9000" for s in detail["symbols"])

    def test_spam_class_and_security_verdict_are_separate_fields(self, client, people) -> None:  # type: ignore[no-untyped-def]
        push(client, scan_record("dmarc_reject_fail", "api-axes"))
        detail = as_(client, people, "admin").get(f"{BASE}/spam/messages/api-axes@sender.example").json()
        assert "spam_class" in detail and "security_verdict" in detail
        assert detail["spam_class"] in ("SPAM", "HIGH_CONFIDENCE_SPAM", "SUSPECTED_SPAM")

    def test_a_secret_provider_zone_is_not_stored_from_the_scan(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        admin.post(
            f"{BASE}/spam/providers",
            {
                "id": "priv",
                "provider_name": "Частный",
                "license_mode": "SELF_HOSTED",
                "privacy_class": "INTERNAL",
                "query_types": ["CLIENT_IP"],
                "zone_secret_file": "/run/secrets/rspamd/rbl_priv.inc",
            },
        )
        record = scan_record("all_pass", "api-secret")
        record["symbols"].append(
            {"name": "MSP_RBL_PRIV_CLIENT_IP", "score": 0, "options": ["1.2.3.4.tok3nsecret.zone.example"]}
        )
        push(client, record)
        text = json.dumps(admin.get(f"{BASE}/spam/messages/api-secret@sender.example").json())
        assert "tok3nsecret" not in text

    def test_scanner_state_is_remembered(self, client, people) -> None:  # type: ignore[no-untyped-def]
        response = client.post(
            "/api/v1/gateway-agent/rspamd-status",
            json={
                "node_id": NODE,
                "state": {"up": True, "version": "3.12.1", "config_checksum": "abc", "redis_up": True},
            },
            headers=node_headers(),
        )
        assert response.status_code == 200
        health = as_(client, people, "admin").get(f"{BASE}/spam/summary").json()["health"]
        assert any(h["rspamd"] and h["rspamd"]["version"] == "3.12.1" for h in health)


class TestProviders:
    def payload(self, **extra: object) -> dict:
        return {
            "id": "pubbl",
            "provider_name": "Публичный список",
            "license_mode": "PUBLIC_NONCOMMERCIAL",
            "privacy_class": "EXTERNAL_DNS",
            "query_types": ["CLIENT_IP"],
            "zone": "zen.publicbl.example",
            **extra,
        }

    def test_a_new_provider_is_always_disabled_and_never_in_the_node_config(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        created = admin.post(f"{BASE}/spam/providers", self.payload(enabled=True)).json()
        assert created["status"] == "DISABLED" and created["approval_state"] == "DRAFT"
        overlay = client.get("/api/v1/gateway-agent/rspamd-config", headers=node_headers()).json()
        assert overlay["providers"] == []

    def test_a_public_list_needs_a_licence_scope(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        admin.post(f"{BASE}/spam/providers", self.payload())
        assert admin.post(f"{BASE}/spam/providers/pubbl/request-activation", {}).status_code == 409

    def test_nobody_approves_their_own_request(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        admin.post(f"{BASE}/spam/providers", self.payload())
        assert (
            admin.post(
                f"{BASE}/spam/providers/pubbl/request-activation", {"usage_scope": "почта организации"}
            ).status_code
            == 200
        )
        denied = admin.post(f"{BASE}/spam/providers/pubbl/approve")
        assert denied.status_code == 409 and "другой человек" in denied.json()["detail"]
        assert (
            client.get("/api/v1/gateway-agent/rspamd-config", headers=node_headers()).json()["providers"]
            == []
        )

    def test_a_second_person_approves_and_the_provider_reaches_the_node(  # type: ignore[no-untyped-def]
        self, client, people, second_admin
    ) -> None:
        admin = as_(client, people, "admin")
        admin.post(f"{BASE}/spam/providers", self.payload())
        expires = (datetime.now(UTC) + timedelta(days=30)).isoformat()
        admin.post(
            f"{BASE}/spam/providers/pubbl/request-activation",
            {"usage_scope": "почта организации", "expires_at": expires},
        )
        other = second(client, second_admin)
        approved = other.post(f"{BASE}/spam/providers/pubbl/approve")
        assert approved.status_code == 200 and approved.json()["status"] == "ACTIVE"
        providers = client.get("/api/v1/gateway-agent/rspamd-config", headers=node_headers()).json()[
            "providers"
        ]
        assert [p["id"] for p in providers] == ["pubbl"]
        # Приостановленный провайдер из конфигурации узла исчезает.
        assert other.post(f"{BASE}/spam/providers/pubbl/suspend").status_code == 200
        assert (
            client.get("/api/v1/gateway-agent/rspamd-config", headers=node_headers()).json()["providers"]
            == []
        )

    def test_the_approval_is_audited_including_the_refusal(self, client, people, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import AuditEvent as AuditLog
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        admin = as_(client, people, "admin")
        admin.post(f"{BASE}/spam/providers", self.payload())
        admin.post(f"{BASE}/spam/providers/pubbl/request-activation", {"usage_scope": "почта организации"})
        admin.post(f"{BASE}/spam/providers/pubbl/approve")
        with sessionmaker(bind=engine)() as session:
            rows = (
                session.execute(select(AuditLog).where(AuditLog.action == "antispam.provider_approved"))
                .scalars()
                .all()
            )
        assert rows and rows[0].outcome == "denied"

    def test_the_view_never_contains_a_secret_zone(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        created = admin.post(
            f"{BASE}/spam/providers",
            {
                "id": "priv",
                "provider_name": "Частный",
                "license_mode": "SELF_HOSTED",
                "privacy_class": "INTERNAL",
                "query_types": ["CLIENT_IP"],
                "zone_secret_file": "/run/secrets/rspamd/rbl_priv.inc",
            },
        ).json()
        assert created["has_secret_zone"] is True and created["zone"] is None
        assert "rbl_priv" not in json.dumps(created)


class TestPolicy:
    def test_enforcement_cannot_be_enabled_through_the_api(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        response = admin.post(f"{BASE}/spam/policies", {"enforcement_enabled": True})
        assert response.status_code in (422,), response.text
        created = admin.post(f"{BASE}/spam/policies", {}).json()
        assert created["enforcement_enabled"] is False
        assert admin.get(f"{BASE}/spam/policies").json()["enforcement_enabled"] is False

    def test_there_is_no_enforcing_state(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        policy = admin.post(f"{BASE}/spam/policies", {}).json()
        response = admin.post(
            f"{BASE}/spam/policies/{policy['id']}/transition", {"target": "ACTIVE_ENFORCING"}
        )
        assert response.status_code == 409

    def test_thresholds_must_ascend(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        response = admin.post(f"{BASE}/spam/policies", {"thresholds": {"suspected": 9, "spam": 3}})
        assert response.status_code == 422

    def test_the_candidate_walks_the_ladder_and_a_second_person_approves(
        self, client, people, second_admin
    ) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        policy = admin.post(f"{BASE}/spam/policies", {"thresholds": {"spam": 5}}).json()
        for target in ("SHADOW", "VALIDATION"):
            assert (
                admin.post(f"{BASE}/spam/policies/{policy['id']}/transition", {"target": target}).status_code
                == 200
            )
        assert (
            admin.post(f"{BASE}/spam/policies/{policy['id']}/transition", {"target": "APPROVED"}).status_code
            == 409
        )
        other = second(client, second_admin)
        assert (
            other.post(f"{BASE}/spam/policies/{policy['id']}/transition", {"target": "APPROVED"}).status_code
            == 200
        )
        activated = other.post(f"{BASE}/spam/policies/{policy['id']}/activate-shadow")
        assert activated.status_code == 200 and activated.json()["state"] == "ACTIVE_SHADOW"
        assert other.get(f"{BASE}/spam/policies").json()["active_version"] == policy["version"]

    def test_steps_cannot_be_skipped(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        policy = admin.post(f"{BASE}/spam/policies", {}).json()
        assert (
            admin.post(
                f"{BASE}/spam/policies/{policy['id']}/transition", {"target": "ACTIVE_SHADOW"}
            ).status_code
            == 409
        )

    def test_the_simulator_changes_nothing_and_shows_the_hypothesis(self, client, people) -> None:  # type: ignore[no-untyped-def]
        push(client, scan_record("dmarc_reject_fail", "sim-1"), scan_record("all_pass", "sim-2"))
        admin = as_(client, people, "admin")
        policy = admin.post(
            f"{BASE}/spam/policies",
            {"thresholds": {"suspected": 1, "spam": 2, "high_confidence": 3, "suggest_reject": 4}},
        ).json()
        result = admin.post(f"{BASE}/spam/policies/{policy['id']}/simulate").json()
        assert result["evaluated"] >= 2 and result["applied_action"] == "OBSERVE_ONLY"
        assert all(item["applied_action"] == "OBSERVE_ONLY" for item in result["items"])
        assert any(item["hypothetical_action"] == "REJECT" for item in result["items"])
        # Реальный список писем не изменился.
        items = admin.get(f"{BASE}/spam/messages").json()["items"]
        assert all(i["applied_action"] == "OBSERVE_ONLY" for i in items)

    def test_the_active_policy_changes_classification_of_new_scans(
        self, client, people, second_admin
    ) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        policy = admin.post(
            f"{BASE}/spam/policies",
            {"thresholds": {"suspected": 1, "spam": 2, "high_confidence": 3, "suggest_reject": 4}},
        ).json()
        for target in ("SHADOW", "VALIDATION"):
            admin.post(f"{BASE}/spam/policies/{policy['id']}/transition", {"target": target})
        other = second(client, second_admin)
        other.post(f"{BASE}/spam/policies/{policy['id']}/transition", {"target": "APPROVED"})
        other.post(f"{BASE}/spam/policies/{policy['id']}/activate-shadow")
        push(client, scan_record("all_pass", "pol-1"))
        detail = other.get(f"{BASE}/spam/messages/pol-1@sender.example").json()
        assert detail["spam_class"] == "HIGH_CONFIDENCE_SPAM"


class TestDkimKeys:
    @pytest.fixture(autouse=True)
    def signing_domain(self, monkeypatch):  # type: ignore[no-untyped-def]
        from msp_api.config import get_settings

        monkeypatch.setattr(get_settings(), "antispam_dkim_signing_domains", "corp.example")

    def test_the_private_key_is_returned_once_and_never_stored(self, client, people, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models_antispam import DkimKeyRecord
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        admin = as_(client, people, "admin")
        created = admin.post(f"{BASE}/dkim/keys", {"domain": "corp.example", "selector": "s2026"})
        assert created.status_code == 201
        body = created.json()
        assert body["private_key_pem"].startswith("-----BEGIN") and body["private_key_returned_once"] is True
        assert created.headers["cache-control"] == "no-store"
        listed = json.dumps(admin.get(f"{BASE}/dkim/keys").json())
        assert "PRIVATE KEY" not in listed and "private_key_pem" not in listed
        with sessionmaker(bind=engine)() as session:
            for key in session.execute(select(DkimKeyRecord)).scalars():
                assert "PRIVATE" not in json.dumps(
                    {c.name: str(getattr(key, c.name)) for c in key.__table__.columns}
                )

    def test_signing_is_refused_for_a_domain_that_is_not_a_lab_or_pilot_domain(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        assert (
            admin.post(f"{BASE}/dkim/keys", {"domain": "other.example", "selector": "s1"}).status_code == 409
        )

    def test_activation_is_forbidden_until_dns_is_verified(self, client, people, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        key = admin.post(f"{BASE}/dkim/keys", {"domain": "corp.example", "selector": "s2026"}).json()
        monkeypatch.setattr("msp_api.routers.antispam.txt_records", lambda *a, **k: (None, False))
        assert admin.post(f"{BASE}/dkim/keys/{key['id']}/activate").status_code == 409
        checked = admin.post(f"{BASE}/dkim/keys/{key['id']}/verify-dns").json()
        assert checked["status"] == "DNS_PENDING" and "TXT_MISSING" in checked["failure"]

    def test_a_dns_record_with_another_key_does_not_pass(self, client, people, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        key = admin.post(f"{BASE}/dkim/keys", {"domain": "corp.example", "selector": "s2026"}).json()
        monkeypatch.setattr(
            "msp_api.routers.antispam.txt_records", lambda *a, **k: (["v=DKIM1; k=rsa; p=AAAA"], False)
        )
        checked = admin.post(f"{BASE}/dkim/keys/{key['id']}/verify-dns").json()
        assert checked["status"] == "DNS_PENDING" and "KEY_MISMATCH" in checked["failure"]

    def test_a_dns_outage_does_not_mark_the_key_ready(self, client, people, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        key = admin.post(f"{BASE}/dkim/keys", {"domain": "corp.example", "selector": "s2026"}).json()
        monkeypatch.setattr("msp_api.routers.antispam.txt_records", lambda *a, **k: (None, True))
        checked = admin.post(f"{BASE}/dkim/keys/{key['id']}/verify-dns").json()
        assert checked["status"] == "DNS_PENDING" and "DNS_NOT_VISIBLE" in checked["failure"]

    def test_the_full_lifecycle_with_four_eyes(self, client, people, second_admin, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        key = admin.post(f"{BASE}/dkim/keys", {"domain": "corp.example", "selector": "s2026"}).json()
        monkeypatch.setattr(
            "msp_api.routers.antispam.txt_records", lambda *a, **k: ([key["public_record"]], False)
        )
        assert admin.post(f"{BASE}/dkim/keys/{key['id']}/verify-dns").json()["status"] == "READY"
        own = admin.post(f"{BASE}/dkim/keys/{key['id']}/activate")
        assert own.status_code == 409 and "четыре глаза" in own.json()["detail"]
        other = second(client, second_admin)
        assert other.post(f"{BASE}/dkim/keys/{key['id']}/activate").json()["status"] == "ACTIVE"
        overlay = client.get("/api/v1/gateway-agent/rspamd-config", headers=node_headers()).json()
        assert [(s["domain"], s["selector"]) for s in overlay["signing_domains"]] == [
            ("corp.example", "s2026")
        ]
        assert "private_key_pem" not in json.dumps(overlay) and "BEGIN" not in json.dumps(overlay)
        assert other.post(f"{BASE}/dkim/keys/{key['id']}/retire").json()["status"] == "RETIRING"
        # Период перекрытия ещё не истёк: полностью вывести ключ рано.
        assert other.post(f"{BASE}/dkim/keys/{key['id']}/retire").status_code == 409

    def test_the_key_lifecycle_is_audited(self, client, people, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import AuditEvent as AuditLog
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        as_(client, people, "admin").post(
            f"{BASE}/dkim/keys", {"domain": "corp.example", "selector": "s2026"}
        )
        with sessionmaker(bind=engine)() as session:
            actions = {r.action for r in session.execute(select(AuditLog)).scalars()}
        assert "antispam.dkim_key_generated" in actions


class TestReputationAndConflicts:
    def test_reputation_has_an_explanation_and_no_hard_signal_suppression(self, client, people) -> None:  # type: ignore[no-untyped-def]
        push(client, scan_record("all_pass", "rep-1"))
        admin = as_(client, people, "admin")
        ip = admin.get(f"{BASE}/reputation/ip/10.77.0.150").json()
        assert ip["known"] and ip["explanations"] and ip["suppresses_hard_signals"] is False
        domain = admin.get(f"{BASE}/reputation/domain/example.test").json()
        assert domain["explanations"] and domain["suppresses_hard_signals"] is False
        unknown = admin.get(f"{BASE}/reputation/ip/203.0.113.9").json()
        assert unknown["known"] is False and unknown["explanations"]

    def test_the_auth_distribution_counts_results(self, client, people) -> None:  # type: ignore[no-untyped-def]
        push(client, scan_record("all_pass", "dist-1"), scan_record("dmarc_reject_fail", "dist-2"))
        distribution = as_(client, people, "analyst").get(f"{BASE}/auth/distribution").json()
        assert distribution["distributions"]["dmarc"].get("PASS", 0) >= 1
        assert distribution["distributions"]["dmarc"].get("FAIL", 0) >= 1
        assert distribution["top_failing_domains"]

    def test_a_conflict_is_reviewed_by_the_analyst_and_audited(self, client, people, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import AuditEvent as AuditLog
        from msp_api.db.models_antispam import AuthConflictRecord, SpamScan
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        push(client, scan_record("all_pass", "conf-1"))
        with sessionmaker(bind=engine, expire_on_commit=False)() as session:
            scan = session.execute(select(SpamScan)).scalars().first()
            session.add(
                AuthConflictRecord(
                    organization_id=scan.organization_id,
                    scan_id=scan.id,
                    kind="SPF_MISMATCH",
                    upstream_value="pass",
                    msp_value="fail",
                )
            )
            session.commit()
        analyst = as_(client, people, "analyst")
        items = analyst.get(f"{BASE}/auth/conflicts").json()["items"]
        assert items and items[0]["disposition"] == "OPEN"
        response = client.put(
            f"{BASE}/auth/conflicts/{items[0]['id']}",
            json={"disposition": "EXPECTED"},
            headers={"x-csrf-token": analyst.csrf},
        )
        assert response.status_code == 200 and response.json()["disposition"] == "EXPECTED"
        with sessionmaker(bind=engine)() as session:
            assert any(
                r.action == "antispam.auth_conflict_disposition"
                for r in session.execute(select(AuditLog)).scalars()
            )
        viewer = as_(client, people, "viewer")
        denied = client.put(
            f"{BASE}/auth/conflicts/{items[0]['id']}",
            json={"disposition": "FALSE_ALARM"},
            headers={"x-csrf-token": viewer.csrf},
        )
        assert denied.status_code == 403


class TestBayes:
    def test_it_starts_not_trained_and_autolearn_is_off(self, client, people) -> None:  # type: ignore[no-untyped-def]
        status_ = as_(client, people, "admin").get(f"{BASE}/spam/bayes").json()
        assert (
            status_["state"] == "NOT_TRAINED"
            and status_["autolearn"] is False
            and status_["can_enable"] is False
        )

    @pytest.mark.parametrize(
        "source", ["UNREVIEWED", "UPSTREAM_VERDICT", "USER_REPORT", "OWN_SCORE", "SYNTHETIC_TEST"]
    )
    def test_unreviewed_and_untrusted_sources_never_train(self, client, people, source: str) -> None:  # type: ignore[no-untyped-def]
        analyst = as_(client, people, "analyst")
        response = analyst.post(
            f"{BASE}/spam/bayes/samples", {"message_id": "m1", "label": "SPAM", "source": source}
        )
        assert response.status_code == 409
        assert analyst.get(f"{BASE}/spam/bayes").json()["approved_spam"] == 0

    def test_an_analyst_confirmed_sample_is_counted_and_can_be_unlearned(self, client, people) -> None:  # type: ignore[no-untyped-def]
        analyst = as_(client, people, "analyst")
        ok = analyst.post(
            f"{BASE}/spam/bayes/samples",
            {"message_id": "m2", "label": "SPAM", "source": "ANALYST_CONFIRMED_SPAM"},
        )
        assert ok.status_code == 201 and ok.json()["approved_spam"] == 1
        assert (
            client.delete(f"{BASE}/spam/bayes/samples/m2", headers={"x-csrf-token": analyst.csrf}).json()[
                "approved_spam"
            ]
            == 0
        )


class TestValidationMetrics:
    def test_reviews_feed_the_metrics_and_the_reject_gate_stays_closed(self, client, people) -> None:  # type: ignore[no-untyped-def]
        push(client, scan_record("dmarc_reject_fail", "val-1"), scan_record("all_pass", "val-2"))
        analyst = as_(client, people, "analyst")
        queue = analyst.get(f"{BASE}/spam/review-queue", params={"selection": "DMARC_REJECT_FAILURE"}).json()[
            "items"
        ]
        assert queue
        response = analyst.post(
            f"{BASE}/spam/messages/{queue[0]['id']}/review",
            {"verdict": "HAM", "selection": "DMARC_REJECT_FAILURE", "note": "ложное"},
        )
        assert response.status_code == 201
        report = analyst.get(f"{BASE}/spam/validation").json()
        assert report["metrics"]["reviewed"] == 1 and report["metrics"]["auth_fp"] == 1
        assert report["reject_safety"]["ready_for_discussion"] is False
        assert report["reject_safety"]["enforcement_enabled"] is False

    def test_an_unknown_selection_is_refused(self, client, people) -> None:  # type: ignore[no-untyped-def]
        response = as_(client, people, "analyst").get(
            f"{BASE}/spam/review-queue", params={"selection": "NOPE"}
        )
        assert response.status_code == 400
