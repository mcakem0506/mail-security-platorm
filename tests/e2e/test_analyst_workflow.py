"""End-to-end workflow over HTTP: report → triage → incident → remediation → audit (ТЗ 43)."""

from __future__ import annotations

import base64
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from fixtures.corpus import BY_NAME
from msp_api.db.base import utcnow
from msp_contracts import Role


@pytest.fixture
def client(engine, storage_dir, monkeypatch):  # type: ignore[no-untyped-def]
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

    app = create_app(get_settings())
    app.dependency_overrides[get_session] = override_session
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    deps.reset_provider_cache()


@pytest.fixture
def people(engine, organization):  # type: ignore[no-untyped-def]
    """An employee, an analyst and two admins — two are needed for bulk approval."""
    from msp_api.db.models import User
    from msp_api.security.auth import hash_password
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    password = "Workflow-Test-Password-7"
    accounts = {
        "employee": ("buh@corp.example", Role.EMPLOYEE),
        "analyst": ("analyst@corp.example", Role.SECURITY_ANALYST),
        "admin": ("admin@corp.example", Role.SECURITY_ADMIN),
        "admin2": ("admin2@corp.example", Role.SECURITY_ADMIN),
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


class Session:
    """A logged-in actor, carrying its own CSRF token."""

    def __init__(self, client: TestClient, email: str, password: str) -> None:
        self.client = client
        response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert response.status_code == 200, response.text
        self.csrf = response.json()["csrf_token"]
        self.email = email

    def get(self, path: str, **kwargs):  # type: ignore[no-untyped-def]
        return self.client.get(path, **kwargs)

    def post(self, path: str, json=None, **kwargs):  # type: ignore[no-untyped-def]
        return self.client.post(path, json=json, headers={"x-csrf-token": self.csrf}, **kwargs)

    def patch(self, path: str, json=None, **kwargs):  # type: ignore[no-untyped-def]
        return self.client.patch(path, json=json, headers={"x-csrf-token": self.csrf}, **kwargs)

    def logout(self) -> None:
        self.client.post("/api/v1/auth/logout", headers={"x-csrf-token": self.csrf})
        self.client.cookies.clear()


def test_full_analyst_workflow(client, people, organization) -> None:
    """The complete path a real report takes through the platform."""

    # --- 1. An employee reports a phishing message -------------------------------------------
    employee = Session(client, people["employee"]["email"], people["employee"]["password"])
    submitted = employee.post(
        "/api/v1/analysis",
        json={
            "raw_eml_base64": base64.b64encode(BY_NAME["09_bank_details_change"].raw).decode(),
            "report_as_phishing": True,
            "note": "Выглядит подозрительно, реквизиты не совпадают",
        },
    )
    assert submitted.status_code == 202, submitted.text
    reported = submitted.json()
    job_id = reported["job_id"]

    # The employee sees an explainable verdict, not a bare score.
    assert reported["classification"] in {"SUSPICIOUS", "HIGH_RISK", "MALICIOUS"}
    assert reported["reasons"], "the employee must be told why"
    assert len(reported["reasons"]) <= 5
    assert reported["recommendation"]
    assert reported["reported_to_security"] is True
    # No internal detection detail leaks into the employee projection.
    assert "rule_id" not in submitted.text
    assert "evidence" not in submitted.text

    # Submitting the same message again is idempotent, not a duplicate.
    again = employee.post(
        "/api/v1/analysis",
        json={
            "raw_eml_base64": base64.b64encode(BY_NAME["09_bank_details_change"].raw).decode(),
            "report_as_phishing": True,
            "note": "Выглядит подозрительно, реквизиты не совпадают",
        },
    )
    assert again.json()["job_id"] == job_id

    # The employee cannot reach investigation data.
    assert employee.get("/api/v1/investigations/messages").status_code == 403
    employee.logout()

    # --- 2. The analyst triages ----------------------------------------------------------------
    analyst = Session(client, people["analyst"]["email"], people["analyst"]["password"])

    found = analyst.get("/api/v1/investigations/messages", params={"verdict": reported["classification"]})
    assert found.status_code == 200
    assert found.json()["total"] >= 1
    message_id = found.json()["items"][0]["message_id"]

    detail = analyst.get(f"/api/v1/analysis/{job_id}/detail")
    assert detail.status_code == 200
    evidence = detail.json()
    assert evidence["signals"], "the analyst needs the signals behind the verdict"
    assert all(s["rule_id"] and s["rule_version"] for s in evidence["signals"])
    assert evidence["engine_version"] and evidence["risk_engine_version"]

    # Safe preview: content is available but inert.
    preview = analyst.get(f"/api/v1/investigations/messages/{message_id}/preview")
    assert preview.status_code == 200
    body = preview.json()
    html = (body.get("sanitized_html") or "").lower()
    assert "<script" not in html
    assert "href" not in html
    assert body["warning"]

    # --- 3. The analyst opens an incident ------------------------------------------------------
    created = analyst.post(
        "/api/v1/incidents",
        json={
            "title": "BEC: попытка смены платёжных реквизитов",
            "summary": "Внешний отправитель под видом сотрудника запросил смену реквизитов",
            "severity": "high",
            "message_ids": [message_id],
        },
    )
    assert created.status_code == 201, created.text
    incident = created.json()
    incident_id = incident["incident_id"]
    assert incident["message_count"] == 1
    assert incident["indicator_count"] > 0, "indicators from the message must be attached"

    assert (
        analyst.post(
            f"/api/v1/incidents/{incident_id}/notes", json={"body": "Проверил домен отправителя"}
        ).status_code
        == 201
    )

    triaged = analyst.patch(f"/api/v1/incidents/{incident_id}", json={"status": "TRIAGE"})
    assert triaged.status_code == 200
    assert triaged.json()["status"] == "TRIAGE"

    confirmed = analyst.patch(f"/api/v1/incidents/{incident_id}", json={"status": "CONFIRMED_BEC"})
    assert confirmed.status_code == 200
    timeline = confirmed.json()["timeline"]
    assert any(entry["event"] == "status_changed" for entry in timeline)

    # --- 4. The analyst proposes remediation but cannot approve or execute it -------------------
    proposed = analyst.post(
        "/api/v1/remediation",
        json={
            "action_type": "quarantine",
            "reason": "Подтверждённая попытка BEC, письмо в ящике бухгалтерии",
            "incident_id": incident_id,
            "message_ids": [message_id],
        },
    )
    assert proposed.status_code == 201, proposed.text
    action = proposed.json()
    action_id = action["action_id"]
    assert action["state"] == "PROPOSED"
    # A dry-run report exists before anything is approved (ТЗ 20.2).
    assert action["dry_run_report"]["affected_messages"] >= 1
    assert any("dry-run" in warning for warning in action["dry_run_report"]["warnings"])
    assert action["rollback_supported"] is True, "quarantine must be reversible"

    assert (
        analyst.post(f"/api/v1/remediation/{action_id}/approve", json={"decision": "approved"}).status_code
        == 403
    )
    analyst.logout()

    # --- 5. The admin approves; the proposer's own approval is impossible ----------------------
    admin = Session(client, people["admin"]["email"], people["admin"]["password"])
    approved = admin.post(f"/api/v1/remediation/{action_id}/approve", json={"decision": "approved"})
    assert approved.status_code == 200, approved.text
    assert approved.json()["state"] == "APPROVED"
    assert approved.json()["required_approvals"] == 1

    # A second decision by the same person is refused.
    assert (
        admin.post(f"/api/v1/remediation/{action_id}/approve", json={"decision": "approved"}).status_code
        == 403
    )

    # --- 6. Execution is refused while the deployment is dry-run-only -------------------------
    executed = admin.post(f"/api/v1/remediation/{action_id}/execute", params={"confirm": "true"})
    assert executed.status_code == 409
    assert "dry-run" in executed.json()["detail"]

    # Execution also requires an explicit confirmation flag.
    assert admin.post(f"/api/v1/remediation/{action_id}/execute").status_code in {400, 409}

    # --- 7. The audit trail contains the whole story ------------------------------------------
    audit = admin.get("/api/v1/admin/audit", params={"limit": 100})
    assert audit.status_code == 200
    actions = [event["action"] for event in audit.json()["items"]]
    for expected in (
        "auth.login",
        "analysis.reported",
        "message.content_view",
        "incident.created",
        "incident.status_changed",
        "remediation.proposed",
        "remediation.approved",
    ):
        assert expected in actions, f"missing audit event: {expected}"

    serialised = audit.text.lower()
    assert "password" not in serialised or "[redacted]" in serialised

    # --- 8. Reports reflect the work done -----------------------------------------------------
    summary = admin.get("/api/v1/reports/phishing_summary", params={"days": 7})
    assert summary.status_code == 200
    assert summary.json()["summary"]["employee_reports"] >= 1

    incidents_report = admin.get("/api/v1/reports/incidents", params={"days": 7})
    assert incidents_report.status_code == 200
    assert incidents_report.json()["summary"]["total"] >= 1

    export = admin.get("/api/v1/reports/incidents", params={"days": 7, "format": "csv"})
    assert export.status_code == 200
    assert export.headers["content-type"].startswith("text/csv")
    assert "attachment" in export.headers["content-disposition"]

    # The export itself is audited, because it moves data outside the platform.
    audit_after = admin.get("/api/v1/admin/audit", params={"action": "data.export"})
    assert audit_after.json()["total"] >= 1


def test_bulk_remediation_requires_two_approvers(client, people, organization, engine) -> None:
    """ТЗ 20.1: above the mailbox threshold a second approver is mandatory."""
    from msp_api.db.models import MailMessage, MailRecipient
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    message_ids: list[str] = []
    with factory() as session:
        for index in range(12):
            message = MailMessage(
                organization_id=organization.id,
                raw_sha256=f"{index:064x}",
                subject=f"Массовая рассылка {index}",
                sender_address="attacker@evil.test",
                sender_domain="evil.test",
                source="shadow",
                received_at=utcnow() - timedelta(minutes=index),
            )
            session.add(message)
            session.flush()
            session.add(MailRecipient(message_id=message.id, address=f"user{index}@corp.example", kind="to"))
            message_ids.append(message.id)
        session.commit()

    analyst = Session(client, people["analyst"]["email"], people["analyst"]["password"])
    proposed = analyst.post(
        "/api/v1/remediation",
        json={
            "action_type": "quarantine",
            "reason": "Массовая фишинговая рассылка по 12 ящикам",
            "message_ids": message_ids,
        },
    )
    assert proposed.status_code == 201, proposed.text
    action = proposed.json()
    assert action["required_approvals"] == 2, "12 mailboxes exceed the threshold of 10"
    action_id = action["action_id"]
    analyst.logout()

    admin = Session(client, people["admin"]["email"], people["admin"]["password"])
    first = admin.post(f"/api/v1/remediation/{action_id}/approve", json={"decision": "approved"})
    assert first.status_code == 200
    # One approval is not enough for a bulk action.
    assert first.json()["state"] == "PROPOSED"
    admin.logout()

    second_admin = Session(client, people["admin2"]["email"], people["admin2"]["password"])
    second = second_admin.post(f"/api/v1/remediation/{action_id}/approve", json={"decision": "approved"})
    assert second.status_code == 200
    assert second.json()["state"] == "APPROVED"
    assert len([a for a in second.json()["approvals"] if a["decision"] == "approved"]) == 2


def test_exception_lifecycle_is_audited(client, people, organization) -> None:
    """ТЗ 43.6, 15.3: an exception has an owner, a reason, an expiry and an audit trail."""
    admin = Session(client, people["admin"]["email"], people["admin"]["password"])

    expires = (utcnow() + timedelta(days=30)).isoformat()
    created = admin.post(
        "/api/v1/admin/exceptions",
        json={
            "exception_type": "trusted_domain",
            "value": "partner.example",
            "reason": "Проверенный контрагент, подтверждено службой закупок",
            "expires_at": expires,
        },
    )
    assert created.status_code == 201, created.text
    exception = created.json()
    assert exception["owner_email"] == people["admin"]["email"]
    assert exception["expires_at"]
    assert exception["active"] is True

    # An exception that expires in the past is rejected outright.
    invalid = admin.post(
        "/api/v1/admin/exceptions",
        json={
            "exception_type": "trusted_domain",
            "value": "late.example",
            "reason": "Просроченное исключение",
            "expires_at": (utcnow() - timedelta(days=1)).isoformat(),
        },
    )
    assert invalid.status_code == 422

    listed = admin.get("/api/v1/admin/exceptions")
    assert listed.status_code == 200
    assert any(item["value"] == "partner.example" for item in listed.json())

    revoked = admin.client.delete(
        f"/api/v1/admin/exceptions/{exception['exception_id']}",
        headers={"x-csrf-token": admin.csrf},
    )
    assert revoked.status_code == 204

    audit = admin.get("/api/v1/admin/audit", params={"object_type": "detection_exception"})
    actions = [event["action"] for event in audit.json()["items"]]
    assert "exception.created" in actions
    assert "exception.revoked" in actions
