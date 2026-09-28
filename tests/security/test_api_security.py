"""API security tests (ТЗ 38): authorization, isolation, SSRF, XSS, traversal, RBAC."""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient
from msp_contracts import Role

from fixtures.corpus import BY_NAME


@pytest.fixture
def client(engine, storage_dir, monkeypatch):  # type: ignore[no-untyped-def]
    """A TestClient bound to an isolated in-memory database and in-process session store."""
    from sqlalchemy.orm import sessionmaker

    from msp_api import deps
    from msp_api.config import get_settings
    from msp_api.db.session import get_session
    from msp_api.main import create_app

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

    # Force the in-process session store and rate limiter: no Redis in the test environment.
    # The cached factories are rebuilt so routes that call them directly and routes that resolve
    # them through Depends share one instance — otherwise a login would land in a different store.
    deps.reset_provider_cache()
    monkeypatch.setattr(deps, "_redis_client", lambda: None)
    # The sliding-window limiter is process-wide; without a reset, earlier tests would exhaust
    # the login budget for the shared test client IP and later logins would fail with 429.
    deps.reset_rate_limiter()

    settings = get_settings()
    app = create_app(settings)
    app.dependency_overrides[get_session] = override_session
    with TestClient(app, raise_server_exceptions=False) as test_client:
        test_client.session_factory = factory  # type: ignore[attr-defined]
        yield test_client
    deps.reset_provider_cache()


@pytest.fixture
def users(engine, organization):  # type: ignore[no-untyped-def]
    from sqlalchemy.orm import sessionmaker

    from msp_api.db.models import User
    from msp_api.security.auth import hash_password

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    password = "Correct-Horse-Battery-Staple-9"
    created = {}
    with factory() as session:
        for role in Role:
            user = User(
                organization_id=organization.id,
                email=f"{role.value}@corp.example",
                display_name=role.value,
                role=role,
                password_hash=hash_password(password),
            )
            session.add(user)
            session.flush()
            created[role] = {"id": user.id, "email": user.email, "password": password}
        session.commit()
    return created


def login(client, users, role: Role):  # type: ignore[no-untyped-def]
    response = client.post(
        "/api/v1/auth/login",
        json={"email": users[role]["email"], "password": users[role]["password"]},
    )
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


class TestAuthentication:
    def test_protected_endpoints_require_auth(self, client) -> None:
        for path in (
            "/api/v1/auth/me",
            "/api/v1/dashboard",
            "/api/v1/investigations/messages",
            "/api/v1/incidents",
            "/api/v1/admin/audit",
            "/api/v1/remediation",
        ):
            assert client.get(path).status_code == 401, path

    def test_invalid_credentials_give_generic_error(self, client, users, organization) -> None:
        unknown = client.post(
            "/api/v1/auth/login", json={"email": "nobody@corp.example", "password": "x" * 16}
        )
        wrong = client.post(
            "/api/v1/auth/login",
            json={"email": users[Role.EMPLOYEE]["email"], "password": "wrong-password-value"},
        )
        assert unknown.status_code == wrong.status_code == 401
        # No account enumeration: both answers are identical.
        assert unknown.json()["detail"] == wrong.json()["detail"]

    def test_session_cookie_is_httponly_and_samesite(self, client, users, organization) -> None:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": users[Role.EMPLOYEE]["email"], "password": users[Role.EMPLOYEE]["password"]},
        )
        cookie_header = response.headers.get("set-cookie", "")
        assert "httponly" in cookie_header.lower()
        assert "samesite=strict" in cookie_header.lower()

    def test_tampered_session_cookie_rejected(self, client, users, organization) -> None:
        login(client, users, Role.EMPLOYEE)
        client.cookies.set("msp_session", "forged-session-id.invalidsignature")
        assert client.get("/api/v1/auth/me").status_code == 401

    def test_account_lockout_after_repeated_failures(self, client, users, organization) -> None:
        email = users[Role.SECURITY_VIEWER]["email"]
        codes = [
            client.post("/api/v1/auth/login", json={"email": email, "password": "bad-password-x"}).status_code
            for _ in range(8)
        ]
        assert 429 in codes, f"no lockout triggered: {codes}"

    def test_logout_revokes_session(self, client, users, organization) -> None:
        csrf = login(client, users, Role.EMPLOYEE)
        assert client.post("/api/v1/auth/logout", headers={"x-csrf-token": csrf}).status_code == 204
        assert client.get("/api/v1/auth/me").status_code == 401


class TestCsrf:
    def test_state_changing_request_without_csrf_is_rejected(self, client, users, organization) -> None:
        login(client, users, Role.EMPLOYEE)
        client.cookies.delete("msp_csrf")
        response = client.post(
            "/api/v1/analysis",
            json={"raw_eml_base64": base64.b64encode(b"From: a@b.test\r\n\r\nx").decode()},
        )
        assert response.status_code == 403

    def test_wrong_csrf_token_rejected(self, client, users, organization) -> None:
        login(client, users, Role.EMPLOYEE)
        response = client.post(
            "/api/v1/analysis",
            json={"raw_eml_base64": base64.b64encode(b"From: a@b.test\r\n\r\nx").decode()},
            headers={"x-csrf-token": "not-the-right-token"},
        )
        assert response.status_code == 403

    def test_safe_methods_do_not_need_csrf(self, client, users, organization) -> None:
        login(client, users, Role.EMPLOYEE)
        client.cookies.delete("msp_csrf")
        assert client.get("/api/v1/auth/me").status_code == 200


class TestRbac:
    @pytest.mark.parametrize(
        ("role", "path", "expected"),
        [
            (Role.EMPLOYEE, "/api/v1/investigations/messages", 403),
            (Role.EMPLOYEE, "/api/v1/incidents", 403),
            (Role.EMPLOYEE, "/api/v1/admin/audit", 403),
            (Role.EMPLOYEE, "/api/v1/admin/protected-identities", 403),
            (Role.SECURITY_VIEWER, "/api/v1/investigations/messages", 200),
            (Role.SECURITY_VIEWER, "/api/v1/admin/policies", 403),
            (Role.SECURITY_ANALYST, "/api/v1/incidents", 200),
            (Role.SECURITY_ANALYST, "/api/v1/admin/policies", 403),
            (Role.SECURITY_ADMIN, "/api/v1/admin/policies", 200),
            (Role.SECURITY_ADMIN, "/api/v1/admin/audit", 200),
            # Platform Admin runs infrastructure and does not get message access (ТЗ 23).
            (Role.PLATFORM_ADMIN, "/api/v1/investigations/messages", 403),
            (Role.PLATFORM_ADMIN, "/api/v1/admin/audit", 200),
        ],
    )
    def test_role_access_matrix(self, client, users, organization, role: Role, path: str, expected: int) -> None:
        login(client, users, role)
        assert client.get(path).status_code == expected, f"{role.value} -> {path}"

    def test_analyst_cannot_approve_remediation(self, client, users, organization) -> None:
        csrf = login(client, users, Role.SECURITY_ANALYST)
        response = client.post(
            "/api/v1/remediation/does-not-exist/approve",
            json={"decision": "approved"},
            headers={"x-csrf-token": csrf},
        )
        assert response.status_code == 403

    def test_proposer_cannot_approve_own_request(self, client, users, organization) -> None:
        """Two-person control: the same admin cannot propose and approve (ТЗ 20.1)."""
        csrf = login(client, users, Role.SECURITY_ADMIN)
        propose = client.post(
            "/api/v1/remediation",
            json={
                "action_type": "block_sender",
                "reason": "confirmed phishing sender",
                "sender": "bad@evil.test",
            },
            headers={"x-csrf-token": csrf},
        )
        assert propose.status_code == 201, propose.text
        action_id = propose.json()["action_id"]
        approve = client.post(
            f"/api/v1/remediation/{action_id}/approve",
            json={"decision": "approved"},
            headers={"x-csrf-token": csrf},
        )
        assert approve.status_code == 403
        assert "approve their own" in approve.json()["detail"]


class TestObjectLevelAuthorization:
    def test_employee_cannot_read_another_users_analysis(self, client, users, organization) -> None:
        """ТЗ 40.6: a user must not obtain another user's result."""
        csrf = login(client, users, Role.EMPLOYEE)
        raw = base64.b64encode(BY_NAME["01_normal_internal"].raw).decode()
        created = client.post(
            "/api/v1/analysis",
            json={"raw_eml_base64": raw},
            headers={"x-csrf-token": csrf},
        )
        assert created.status_code == 202, created.text
        job_id = created.json()["job_id"]
        assert client.get(f"/api/v1/analysis/{job_id}").status_code == 200

        client.post("/api/v1/auth/logout", headers={"x-csrf-token": csrf})
        login(client, users, Role.SECURITY_VIEWER)
        # A viewer has investigation rights, so they may see it; an employee must not.
        client.post("/api/v1/auth/logout", headers={"x-csrf-token": csrf})

        from msp_api.db.models import User
        from msp_api.security.auth import hash_password

        with client.session_factory() as session:  # type: ignore[attr-defined]
            other = User(
                organization_id=organization.id,
                email="other.employee@corp.example",
                role=Role.EMPLOYEE,
                password_hash=hash_password("Another-Strong-Password-1"),
            )
            session.add(other)
            session.commit()
        client.post(
            "/api/v1/auth/login",
            json={"email": "other.employee@corp.example", "password": "Another-Strong-Password-1"},
        )
        response = client.get(f"/api/v1/analysis/{job_id}")
        # 404, not 403: the existence of another user's analysis is not disclosed.
        assert response.status_code == 404

    def test_employee_cannot_submit_for_another_mailbox(self, client, users, organization) -> None:
        csrf = login(client, users, Role.EMPLOYEE)
        response = client.post(
            "/api/v1/analysis",
            json={
                "raw_eml_base64": base64.b64encode(BY_NAME["01_normal_internal"].raw).decode(),
                "mailbox": "ceo@corp.example",
            },
            headers={"x-csrf-token": csrf},
        )
        assert response.status_code == 403


class TestInputValidation:
    def test_oversized_upload_rejected(self, client, users, organization) -> None:
        csrf = login(client, users, Role.EMPLOYEE)
        payload = base64.b64encode(b"x" * (30 * 1024 * 1024)).decode()
        response = client.post(
            "/api/v1/analysis", json={"raw_eml_base64": payload}, headers={"x-csrf-token": csrf}
        )
        assert response.status_code in {413, 422}

    def test_invalid_base64_rejected(self, client, users, organization) -> None:
        csrf = login(client, users, Role.EMPLOYEE)
        response = client.post(
            "/api/v1/analysis", json={"raw_eml_base64": "!!!not-base64!!!"}, headers={"x-csrf-token": csrf}
        )
        assert response.status_code == 400

    def test_unknown_fields_rejected(self, client, users, organization) -> None:
        csrf = login(client, users, Role.EMPLOYEE)
        response = client.post(
            "/api/v1/analysis",
            json={"raw_eml_base64": base64.b64encode(b"x").decode(), "unexpected": "value"},
            headers={"x-csrf-token": csrf},
        )
        assert response.status_code == 422

    @pytest.mark.parametrize(
        "injection",
        ["' OR '1'='1", "'; DROP TABLE mail_messages; --", "%27%20OR%201=1", "../../etc/passwd"],
    )
    def test_search_filters_are_not_injectable(self, client, users, organization, injection: str) -> None:
        login(client, users, Role.SECURITY_ANALYST)
        response = client.get("/api/v1/investigations/messages", params={"sender": injection})
        assert response.status_code == 200
        assert response.json()["total"] == 0

    def test_secrets_cannot_be_set_through_provider_api(self, client, users, organization) -> None:
        csrf = login(client, users, Role.SECURITY_ADMIN)
        response = client.put(
            "/api/v1/admin/providers/virustotal",
            json={"enabled": True, "api_key": "should-be-rejected"},
            headers={"x-csrf-token": csrf},
        )
        assert response.status_code == 400


class TestSecurityHeaders:
    def test_security_headers_present(self, client) -> None:
        response = client.get("/health/live")
        for header in (
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Content-Security-Policy",
        ):
            assert header in response.headers, header
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        assert response.headers["X-Frame-Options"] == "DENY"

    def test_request_id_returned(self, client) -> None:
        assert client.get("/health/live").headers.get("X-Request-ID")

    def test_public_config_has_no_secrets(self, client) -> None:
        body = client.get("/api/v1/auth/config").json()
        serialised = str(body).lower()
        for banned in ("api_key", "password", "secret", "token"):
            assert banned not in serialised


class TestHealthAndMetrics:
    def test_liveness_needs_no_auth(self, client) -> None:
        assert client.get("/health/live").json() == {"status": "ok"}

    def test_optional_provider_outage_does_not_break_readiness(self, client) -> None:
        """ТЗ 31: readiness must not depend on VirusTotal."""
        body = client.get("/health/ready").json()
        assert "virustotal" not in body["checks"]

    def test_dependencies_separates_required_and_optional(self, client) -> None:
        body = client.get("/health/dependencies").json()
        assert "required" in body and "optional" in body
        assert all(not item.get("required", False) for item in body["optional"].values())
