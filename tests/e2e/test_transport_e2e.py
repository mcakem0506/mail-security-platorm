"""API транспорта почты через HTTP (ТЗ 1.1 §42, §43, §59).

Интересное живёт между частями: роль, которой нельзя применять конфигурацию; пустой справочник,
который принимают за рабочий; повторная копия письма, ставшая вторым анализом; узел без токена.
Ни одного из этих случаев модульный тест не видит, потому что в нём нет ни сессии, ни роли.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from msp_contracts import Role

TOKEN = "t" * 40
NODE = "a" * 32


@pytest.fixture
def client(engine, storage_dir, monkeypatch, organization):  # type: ignore[no-untyped-def]
    from msp_api import deps
    from msp_api.config import get_settings
    from msp_api.db.session import get_session
    from msp_api.main import create_app
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=engine, expire_on_commit=False)

    def override_session():  # type: ignore[no-untyped-def]
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    deps.reset_provider_cache()
    monkeypatch.setattr(deps, "_redis_client", lambda: None)
    deps.reset_rate_limiter()
    monkeypatch.setattr(get_settings(), "gateway_ingest_token", TOKEN)
    app = create_app(get_settings())
    app.dependency_overrides[get_session] = override_session
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    deps.reset_provider_cache()


@pytest.fixture
def people(engine, organization):  # type: ignore[no-untyped-def]
    from msp_api.db.models import User
    from msp_api.security.auth import hash_password
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    password = "Transport-Test-Password-4"
    accounts = {
        "employee": ("user@corp.example", Role.EMPLOYEE),
        "viewer": ("viewer@corp.example", Role.SECURITY_VIEWER),
        "analyst": ("analyst@corp.example", Role.SECURITY_ANALYST),
        "admin": ("admin@corp.example", Role.SECURITY_ADMIN),
        "platform": ("platform@corp.example", Role.PLATFORM_ADMIN),
    }
    created: dict[str, dict[str, str]] = {}
    with factory() as session:
        for key, (email, role) in accounts.items():
            user = User(
                organization_id=organization.id,
                email=email,
                display_name=key,
                role=role,
                password_hash=hash_password(password),
            )
            session.add(user)
            session.flush()
            created[key] = {"id": user.id, "email": email, "password": password}
        session.commit()
    return created


class Person:
    def __init__(self, client: TestClient, email: str, password: str) -> None:
        self.client = client
        response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert response.status_code == 200, response.text
        self.csrf = response.json()["csrf_token"]

    def get(self, path: str, **kwargs):  # type: ignore[no-untyped-def]
        return self.client.get(path, **kwargs)

    def post(self, path: str, json=None, **kwargs):  # type: ignore[no-untyped-def]
        return self.client.post(path, json=json, headers={"x-csrf-token": self.csrf}, **kwargs)

    def logout(self) -> None:
        self.client.post("/api/v1/auth/logout", headers={"x-csrf-token": self.csrf})
        self.client.cookies.clear()


def as_(client, people, who: str) -> Person:  # type: ignore[no-untyped-def]
    return Person(client, people[who]["email"], people[who]["password"])


def spec_dict() -> dict[str, object]:
    from gateway.harness import lab_spec

    return json.loads(lab_spec().model_dump_json())


def sync_body(count: int = 3, **extra: object) -> dict[str, object]:
    rows = ["address,kind,aliases"] + [f"user{i}@corp.example,USER," for i in range(count)]
    return {"format": "csv", "content": "\n".join(rows), "source": "e2e", **extra}


def node_headers(token: str = TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def ready(client, people) -> Person:  # type: ignore[no-untyped-def]
    """Администратор ИБ, справочник загружен: от этого состояния начинается нормальная работа."""
    admin = as_(client, people, "admin")
    assert admin.post("/api/v1/gateway/recipients/sync", sync_body()).status_code == 200
    return admin


class TestWhoMayDoWhat:
    ENDPOINTS_READ = (
        "/api/v1/gateway/nodes",
        "/api/v1/gateway/queue/summary",
        "/api/v1/gateway/messages",
        "/api/v1/gateway/recipients/status",
        "/api/v1/gateway/tls/status",
    )

    @pytest.mark.parametrize("path", ENDPOINTS_READ)
    def test_an_employee_sees_nothing(self, client, people, path: str) -> None:  # type: ignore[no-untyped-def]
        assert as_(client, people, "employee").get(path).status_code == 403

    @pytest.mark.parametrize("who", ["viewer", "analyst", "admin", "platform"])
    def test_security_and_platform_roles_may_read_the_overview(self, client, people, who: str) -> None:  # type: ignore[no-untyped-def]
        person = as_(client, people, who)
        for path in ("/api/v1/gateway/nodes", "/api/v1/gateway/queue/summary", "/api/v1/gateway/tls/status"):
            assert person.get(path).status_code == 200, (who, path)

    @pytest.mark.parametrize("who", ["viewer", "analyst"])
    def test_a_viewer_and_an_analyst_cannot_change_anything(self, client, people, who: str) -> None:  # type: ignore[no-untyped-def]
        person = as_(client, people, who)
        assert person.post("/api/v1/gateway/config/validate", {"spec": spec_dict()}).status_code == 403
        assert person.post("/api/v1/gateway/config/activate", {"version": 1}).status_code == 403
        assert person.post("/api/v1/gateway/config/1/rollback").status_code == 403
        assert person.post("/api/v1/gateway/recipients/sync", sync_body()).status_code == 403
        assert person.post("/api/v1/gateway/nodes/x/drain").status_code == 403
        assert person.get("/api/v1/gateway/config/versions").status_code == 403

    def test_the_platform_admin_runs_the_nodes_but_does_not_apply_configuration(self, client, people) -> None:  # type: ignore[no-untyped-def]
        """Эксплуатация узлов и решение, кого принимает граница организации, — разные полномочия."""
        platform = as_(client, people, "platform")
        assert platform.post("/api/v1/gateway/nodes/missing/drain").status_code == 404  # право есть
        assert platform.post("/api/v1/gateway/config/activate", {"version": 1}).status_code == 403
        assert platform.post("/api/v1/gateway/config/1/rollback").status_code == 403
        assert platform.post("/api/v1/gateway/recipients/sync", sync_body()).status_code == 403

    def test_unauthenticated_requests_are_refused(self, client) -> None:  # type: ignore[no-untyped-def]
        assert client.get("/api/v1/gateway/nodes").status_code == 401


class TestConfigurationLifecycle:
    def test_a_config_cannot_be_built_without_recipients(self, client, people) -> None:  # type: ignore[no-untyped-def]
        """Пустой справочник при настроенных доменах отверг бы всю почту: версия остаётся черновиком."""
        admin = as_(client, people, "admin")
        body = admin.post("/api/v1/gateway/config/validate", {"spec": spec_dict()}).json()
        assert body["ok"] is False
        assert body["status"] == "DRAFT"
        assert any("справочник" in error for error in body["errors"])

    def test_invalid_spec_returns_reasons_without_echoing_values(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = ready(client, people)
        bad = spec_dict()
        bad["hostname"] = "evil host; rm -rf /"
        body = admin.post("/api/v1/gateway/config/validate", {"spec": bad}).json()
        assert body["ok"] is False
        assert "rm -rf" not in json.dumps(body)

    def test_unknown_fields_are_refused(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = ready(client, people)
        bad = {**spec_dict(), "content_filter": "smtp:evil:25"}
        assert admin.post("/api/v1/gateway/config/validate", {"spec": bad}).json()["ok"] is False

    def test_full_lifecycle_validate_activate_replace_rollback(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = ready(client, people)
        first = admin.post("/api/v1/gateway/config/validate", {"spec": spec_dict(), "note": "первая"}).json()
        assert first["ok"] and first["status"] == "VALIDATED"
        assert admin.post("/api/v1/gateway/config/activate", {"version": first["version"]}).status_code == 200

        second_spec = spec_dict()
        second_spec["hostname"] = "gw2.lab.example"
        second = admin.post("/api/v1/gateway/config/validate", {"spec": second_spec}).json()
        assert second["ok"]
        assert (
            admin.post("/api/v1/gateway/config/activate", {"version": second["version"]}).status_code == 200
        )

        statuses = {
            v["version"]: v["status"] for v in admin.get("/api/v1/gateway/config/versions").json()["items"]
        }
        assert statuses[first["version"]] == "SUPERSEDED"
        assert statuses[second["version"]] == "ACTIVE"

        back = admin.post(f"/api/v1/gateway/config/{first['version']}/rollback")
        assert back.status_code == 200
        statuses = {
            v["version"]: v["status"] for v in admin.get("/api/v1/gateway/config/versions").json()["items"]
        }
        assert statuses[first["version"]] == "ACTIVE"
        assert statuses[second["version"]] == "ROLLED_BACK"

    def test_a_draft_cannot_be_activated(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        draft = admin.post("/api/v1/gateway/config/validate", {"spec": spec_dict()}).json()
        assert draft["status"] == "DRAFT"
        assert admin.post("/api/v1/gateway/config/activate", {"version": draft["version"]}).status_code == 409

    def test_an_active_version_cannot_be_rolled_back_onto_itself(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = ready(client, people)
        version = admin.post("/api/v1/gateway/config/validate", {"spec": spec_dict()}).json()["version"]
        admin.post("/api/v1/gateway/config/activate", {"version": version})
        assert admin.post(f"/api/v1/gateway/config/{version}/rollback").status_code == 409

    def test_unknown_version_is_404(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        assert admin.post("/api/v1/gateway/config/activate", {"version": 999}).status_code == 404
        assert admin.post("/api/v1/gateway/config/999/rollback").status_code == 404

    def test_the_routes_view_follows_the_active_version(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = ready(client, people)
        assert admin.get("/api/v1/gateway/routes").json()["routes"] == []
        version = admin.post("/api/v1/gateway/config/validate", {"spec": spec_dict()}).json()["version"]
        admin.post("/api/v1/gateway/config/activate", {"version": version})
        routes = admin.get("/api/v1/gateway/routes").json()
        assert routes["routes"][0]["name"] == "exchange"
        assert routes["relay_domains"][0]["domain"] == "corp.example"

    def test_every_decision_is_in_the_audit_log(self, client, people, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import AuditEvent
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        admin = ready(client, people)
        version = admin.post("/api/v1/gateway/config/validate", {"spec": spec_dict()}).json()["version"]
        admin.post("/api/v1/gateway/config/activate", {"version": version})
        admin.post("/api/v1/gateway/config/activate", {"version": version})  # повтор отвергнут, но записан
        with sessionmaker(bind=engine)() as session:
            events = list(
                session.execute(select(AuditEvent).where(AuditEvent.action.like("transport.%"))).scalars()
            )
        actions = [(e.action, e.outcome) for e in events]
        assert ("transport.recipients_sync", "success") in actions
        assert ("transport.config_validated", "success") in actions
        assert ("transport.config_activated", "success") in actions
        assert ("transport.config_activated", "rejected") in actions


class TestRecipientDirectory:
    def test_first_sync_is_accepted(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        body = admin.post("/api/v1/gateway/recipients/sync", sync_body(5)).json()
        assert body["recipient_count"] == 5
        status = admin.get("/api/v1/gateway/recipients/status").json()
        assert status["recipient_count"] == 5
        assert status["freshness"] == "FRESH"
        assert status["last_sync"]["status"] == "ACCEPTED"

    def test_an_empty_export_is_refused_and_the_working_directory_stays(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = ready(client, people)
        refused = admin.post("/api/v1/gateway/recipients/sync", {"format": "csv", "content": "address\n"})
        assert refused.status_code == 409
        status = admin.get("/api/v1/gateway/recipients/status").json()
        assert status["recipient_count"] == 3, "прежний справочник не тронут"
        assert status["last_sync"]["status"] == "REFUSED", "попытка записана"

    def test_a_sharp_shrink_needs_explicit_confirmation(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        admin.post("/api/v1/gateway/recipients/sync", sync_body(10))
        small = sync_body(3)
        assert admin.post("/api/v1/gateway/recipients/sync", small).status_code == 409
        assert admin.get("/api/v1/gateway/recipients/status").json()["recipient_count"] == 10
        assert (
            admin.post("/api/v1/gateway/recipients/sync", {**small, "confirm_shrink": True}).status_code
            == 200
        )
        assert admin.get("/api/v1/gateway/recipients/status").json()["recipient_count"] == 3

    def test_bad_rows_are_counted_and_do_not_block_good_ones(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        content = "good@corp.example\nnot-an-address\nev il@corp.example\nok@corp.example\n"
        body = admin.post("/api/v1/gateway/recipients/sync", {"format": "csv", "content": content}).json()
        assert (body["recipient_count"], body["rejected_count"]) == (2, 2)

    def test_garbage_json_is_refused_whole(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        assert (
            admin.post("/api/v1/gateway/recipients/sync", {"format": "json", "content": "{bad"}).status_code
            == 409
        )

    def test_a_stale_directory_is_reported_as_closed(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        old = (datetime.now(UTC) - timedelta(hours=10)).isoformat()
        admin.post("/api/v1/gateway/recipients/sync", sync_body(3, source_generated_at=old))
        status = admin.get("/api/v1/gateway/recipients/status").json()
        assert status["freshness"] == "STALE_HARD"
        assert status["closed"] is True

    def test_an_active_config_is_reissued_with_the_new_directory(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = ready(client, people)
        version = admin.post("/api/v1/gateway/config/validate", {"spec": spec_dict()}).json()["version"]
        admin.post("/api/v1/gateway/config/activate", {"version": version})
        body = admin.post("/api/v1/gateway/recipients/sync", sync_body(4)).json()
        assert body["activated_version"] == version + 1
        statuses = {
            v["version"]: v["status"] for v in admin.get("/api/v1/gateway/config/versions").json()["items"]
        }
        assert statuses[version] == "SUPERSEDED"
        assert statuses[version + 1] == "ACTIVE"


class TestNodeEndpoints:
    def test_endpoints_are_closed_until_a_token_is_configured(self, client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from msp_api.config import get_settings

        monkeypatch.setattr(get_settings(), "gateway_ingest_token", "")
        response = client.post("/api/v1/gateway-agent/events", json={"node_id": NODE, "events": []})
        assert response.status_code == 503

    def test_a_short_token_counts_as_not_configured(self, client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from msp_api.config import get_settings

        monkeypatch.setattr(get_settings(), "gateway_ingest_token", "short")
        assert (
            client.post("/api/v1/gateway-agent/events", json={"node_id": NODE, "events": []}).status_code
            == 503
        )

    @pytest.mark.parametrize("header", [None, "Bearer wrong", "Bearer ", TOKEN, "Basic " + TOKEN])
    def test_wrong_credentials_are_401(self, client, header: str | None) -> None:  # type: ignore[no-untyped-def]
        headers = {"Authorization": header} if header else {}
        response = client.post(
            "/api/v1/gateway-agent/events", json={"node_id": NODE, "events": []}, headers=headers
        )
        assert response.status_code == 401

    def test_a_human_session_does_not_open_the_node_endpoints(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        assert admin.post("/api/v1/gateway-agent/events", {"node_id": NODE, "events": []}).status_code == 401

    def test_heartbeat_registers_and_updates_the_node(self, client, people, organization) -> None:  # type: ignore[no-untyped-def]
        beat = {
            "type": "heartbeat",
            "at": datetime.now(UTC).isoformat(),
            "config_version": "000002-abc",
            "queue_messages": 7,
            "pressure": "PRESSURE",
            "unparsed_log_lines": 3,
        }
        response = client.post(
            "/api/v1/gateway-agent/events", json={"node_id": NODE, "events": [beat]}, headers=node_headers()
        )
        assert response.json() == {"accepted": 1, "rejected": 0}
        nodes = as_(client, people, "viewer").get("/api/v1/gateway/nodes").json()["items"]
        assert len(nodes) == 1
        assert nodes[0]["state"] == "UP"
        assert (nodes[0]["queue_messages"], nodes[0]["pressure"]) == (7, "PRESSURE")
        summary = as_(client, people, "viewer").get("/api/v1/gateway/queue/summary").json()
        assert summary["queue_messages"] == 7
        assert summary["pressure"] == "PRESSURE"
        assert "NOT APPROVED FOR PRODUCTION MX CUTOVER" in summary["deployment_note"]

    def test_a_silent_node_is_down_not_up(self, client, people, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models_transport import TransportNode
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        old = datetime.now(UTC) - timedelta(minutes=30)
        client.post(
            "/api/v1/gateway-agent/events",
            json={"node_id": NODE, "events": [{"type": "heartbeat", "at": old.isoformat()}]},
            headers=node_headers(),
        )
        nodes = as_(client, people, "viewer").get("/api/v1/gateway/nodes").json()["items"]
        assert nodes[0]["state"] == "DOWN"
        with sessionmaker(bind=engine)() as session:
            assert session.execute(select(TransportNode)).scalars().first() is not None

    def test_clock_skew_cannot_put_a_heartbeat_in_the_future(self, client, people) -> None:  # type: ignore[no-untyped-def]
        future = datetime.now(UTC) + timedelta(days=3)
        client.post(
            "/api/v1/gateway-agent/events",
            json={"node_id": NODE, "events": [{"type": "heartbeat", "at": future.isoformat()}]},
            headers=node_headers(),
        )
        node = as_(client, people, "viewer").get("/api/v1/gateway/nodes").json()["items"][0]
        assert datetime.fromisoformat(node["last_heartbeat_at"]) <= datetime.now(UTC)

    def test_unknown_and_oversized_events_are_rejected_not_stored(self, client) -> None:  # type: ignore[no-untyped-def]
        events = [
            {"type": "format_disk"},
            {"type": "heartbeat", "pad": "x" * 20000},
            {"no": "type"},
            {"type": "pressure", "state": "CRITICAL", "nested": {"a": 1}, "list": [1, 2]},
        ]
        body = client.post(
            "/api/v1/gateway-agent/events", json={"node_id": NODE, "events": events}, headers=node_headers()
        ).json()
        assert body == {"accepted": 1, "rejected": 3}

    @pytest.mark.parametrize("node_id", ["short", "Z" * 32, "../../etc/passwd", "a" * 33])
    def test_malformed_node_ids_are_422(self, client, node_id: str) -> None:  # type: ignore[no-untyped-def]
        response = client.post(
            "/api/v1/gateway-agent/events", json={"node_id": node_id, "events": []}, headers=node_headers()
        )
        assert response.status_code == 422

    def test_drain_is_a_command_the_node_collects(self, client, people) -> None:  # type: ignore[no-untyped-def]
        client.post(
            "/api/v1/gateway-agent/events",
            json={"node_id": NODE, "events": [{"type": "heartbeat", "at": datetime.now(UTC).isoformat()}]},
            headers=node_headers(),
        )
        admin = as_(client, people, "admin")
        row = admin.get("/api/v1/gateway/nodes").json()["items"][0]
        assert (
            client.get(f"/api/v1/gateway-agent/config?node_id={NODE}", headers=node_headers()).json()["drain"]
            is False
        )
        assert admin.post(f"/api/v1/gateway/nodes/{row['id']}/drain").json()["drain_requested"] is True
        assert (
            client.get(f"/api/v1/gateway-agent/config?node_id={NODE}", headers=node_headers()).json()["drain"]
            is True
        )
        assert admin.post(f"/api/v1/gateway/nodes/{row['id']}/resume").json()["drain_requested"] is False
        assert (
            client.get(f"/api/v1/gateway-agent/config?node_id={NODE}", headers=node_headers()).json()["drain"]
            is False
        )

    def test_the_node_receives_the_active_bundle(self, client, people) -> None:  # type: ignore[no-untyped-def]
        admin = ready(client, people)
        version = admin.post("/api/v1/gateway/config/validate", {"spec": spec_dict()}).json()["version"]
        admin.post("/api/v1/gateway/config/activate", {"version": version})
        config = client.get(f"/api/v1/gateway-agent/config?node_id={NODE}", headers=node_headers()).json()
        assert config["version"] == version
        assert "main.cf" in config["bundle"]["files"]
        assert config["bundle"]["manifest"]["checksum"] == config["checksum"]

    def test_the_bundle_the_panel_hands_out_passes_the_nodes_own_check(self, client, people) -> None:  # type: ignore[no-untyped-def]
        """Панель и узел обязаны соглашаться: то, что одна считает допустимым, другой не должен отвергнуть."""
        from msp_gateway.bundle import verify_bundle

        admin = ready(client, people)
        version = admin.post("/api/v1/gateway/config/validate", {"spec": spec_dict()}).json()["version"]
        admin.post("/api/v1/gateway/config/activate", {"version": version})
        bundle = client.get(f"/api/v1/gateway-agent/config?node_id={NODE}", headers=node_headers()).json()[
            "bundle"
        ]
        files = {name: text.encode() for name, text in bundle["files"].items()}
        assert verify_bundle(files, bundle["manifest"])


def shadow_headers(key: str = "b" * 64, **extra: str) -> dict[str, str]:
    return {
        **node_headers(),
        "X-MSP-Idempotency-Key": key,
        "X-MSP-Node-Id": NODE,
        "X-MSP-Direction": "INBOUND",
        "X-MSP-Message-Id": "<m1@lab.example>",
        **extra,
    }


RAW = (
    b"From: a@partner.example\r\nTo: ivan@corp.example\r\nSubject: s\r\n"
    b"Message-ID: <m1@lab.example>\r\n\r\nbody\r\n"
)


class TestShadowCopies:
    def test_a_copy_is_stored_and_listed_without_its_body(self, client, people) -> None:  # type: ignore[no-untyped-def]
        response = client.post("/api/v1/gateway-agent/shadow", content=RAW, headers=shadow_headers())
        assert response.status_code == 200, response.text
        assert response.json()["duplicate"] is False
        viewer = as_(client, people, "viewer")
        listing = viewer.get("/api/v1/gateway/messages").json()
        assert listing["total"] == 1
        item = listing["items"][0]
        assert item["internet_message_id"] == "<m1@lab.example>"
        assert "body" not in json.dumps(item).lower()
        assert "raw" not in item

    def test_the_same_copy_twice_is_one_message(self, client, people) -> None:  # type: ignore[no-untyped-def]
        first = client.post("/api/v1/gateway-agent/shadow", content=RAW, headers=shadow_headers()).json()
        second = client.post("/api/v1/gateway-agent/shadow", content=RAW, headers=shadow_headers()).json()
        assert second["duplicate"] is True
        assert second["id"] == first["id"]
        listing = as_(client, people, "viewer").get("/api/v1/gateway/messages").json()
        assert listing["total"] == 1
        assert listing["items"][0]["duplicate_count"] == 1

    def test_different_keys_are_different_messages(self, client, people) -> None:  # type: ignore[no-untyped-def]
        client.post("/api/v1/gateway-agent/shadow", content=RAW, headers=shadow_headers("c" * 64))
        client.post("/api/v1/gateway-agent/shadow", content=RAW + b"x", headers=shadow_headers("d" * 64))
        assert as_(client, people, "viewer").get("/api/v1/gateway/messages").json()["total"] == 2

    def test_the_node_token_is_required(self, client) -> None:  # type: ignore[no-untyped-def]
        headers = {k: v for k, v in shadow_headers().items() if k != "Authorization"}
        assert client.post("/api/v1/gateway-agent/shadow", content=RAW, headers=headers).status_code == 401

    @pytest.mark.parametrize("key", ["short", "G" * 64, "b" * 63, "b" * 65])
    def test_malformed_idempotency_keys_are_422(self, client, key: str) -> None:  # type: ignore[no-untyped-def]
        assert (
            client.post("/api/v1/gateway-agent/shadow", content=RAW, headers=shadow_headers(key)).status_code
            == 422
        )

    def test_empty_body_is_400(self, client) -> None:  # type: ignore[no-untyped-def]
        assert (
            client.post("/api/v1/gateway-agent/shadow", content=b"", headers=shadow_headers()).status_code
            == 400
        )

    def test_oversized_copy_is_413(self, client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from msp_api.config import get_settings

        monkeypatch.setattr(get_settings(), "limit_message_size", 20)
        assert (
            client.post("/api/v1/gateway-agent/shadow", content=RAW, headers=shadow_headers()).status_code
            == 413
        )

    def test_looking_at_one_message_is_audited(self, client, people, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import AuditEvent
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        message_id = client.post(
            "/api/v1/gateway-agent/shadow", content=RAW, headers=shadow_headers()
        ).json()["id"]
        assert as_(client, people, "viewer").get(f"/api/v1/gateway/messages/{message_id}").status_code == 200
        with sessionmaker(bind=engine)() as session:
            actions = [e.action for e in session.execute(select(AuditEvent)).scalars()]
        assert "transport.queue_viewed" in actions

    def test_unknown_message_is_404(self, client, people) -> None:  # type: ignore[no-untyped-def]
        assert as_(client, people, "viewer").get("/api/v1/gateway/messages/nope").status_code == 404

    def test_storing_the_raw_copy_uses_the_shadow_intake_source(self, client, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import IntakeRecord
        from msp_contracts import IntakeSource
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        client.post("/api/v1/gateway-agent/shadow", content=RAW, headers=shadow_headers())
        with sessionmaker(bind=engine)() as session:
            records = list(session.execute(select(IntakeRecord)).scalars())
        assert [r.source for r in records] == [IntakeSource.SHADOW]
        assert records[0].raw_storage_key


class TestTls:
    def test_certificate_states(self, client, people, engine, organization) -> None:  # type: ignore[no-untyped-def]
        from msp_api.services import transport
        from sqlalchemy.orm import sessionmaker

        now = datetime.now(UTC)
        with sessionmaker(bind=engine)() as session:
            for name, delta in (("expired", -2), ("soon", 10), ("fine", 200)):
                transport.record_certificate(
                    session,
                    organization_id=organization.id,
                    node_id=NODE,
                    usage=name,
                    subject=f"CN={name}",
                    issuer="CN=lab",
                    not_before=now - timedelta(days=300),
                    not_after=now + timedelta(days=delta),
                    fingerprint=f"fp-{name}",
                )
            session.commit()
        items = as_(client, people, "viewer").get("/api/v1/gateway/tls/status").json()["items"]
        assert {i["usage"]: i["state"] for i in items} == {
            "expired": "EXPIRED",
            "soon": "EXPIRING",
            "fine": "OK",
        }
        assert "private" not in json.dumps(items).lower()
