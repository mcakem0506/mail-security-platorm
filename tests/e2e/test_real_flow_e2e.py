"""Реальный поток через HTTP: разбор, продвижение, подтверждение пробела (ТЗ 1.0.4 §23, §27).

Интересные отказы живут между частями, а не внутри них: право, выданное не той роли; заявка,
которую согласовал её же автор; пробел, «подтверждённый» неразобранными письмами. Ни одного из
этих случаев модульный тест не видит, потому что в нём нет ни роли, ни сессии.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
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
    from msp_api.db.models import User
    from msp_api.security.auth import hash_password
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    password = "RealFlow-Test-Password-3"
    accounts = {
        "employee": ("user@corp.example", Role.EMPLOYEE),
        "viewer": ("viewer@corp.example", Role.SECURITY_VIEWER),
        "analyst": ("analyst@corp.example", Role.SECURITY_ANALYST),
        "admin": ("admin@corp.example", Role.SECURITY_ADMIN),
        "lead": ("lead@corp.example", Role.SECURITY_ADMIN),
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


class Actor:
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

    def logout(self) -> None:
        self.client.post("/api/v1/auth/logout", headers={"x-csrf-token": self.csrf})
        self.client.cookies.clear()


def _as(client, people, who: str) -> Actor:  # type: ignore[no-untyped-def]
    return Actor(client, people[who]["email"], people[who]["password"])


def _seed(engine, organization, **overrides):  # type: ignore[no-untyped-def]
    """Письмо в наборе валидации, положенное напрямую: приём — задача конвейера, не этого теста."""
    from msp_api.db.models import ValidationMessage
    from msp_contracts import PiiStatus, RiskLevel, ValidationSource
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        record = ValidationMessage(
            organization_id=organization.id,
            source=ValidationSource.SECURITY_MAILBOX,
            message_fingerprint=overrides.pop("fingerprint", "e2e-fp-1"),
            production_verdict=overrides.pop("production_verdict", RiskLevel.HIGH_RISK),
            triggered_rules=overrides.pop("triggered_rules", ["SND-024"]),
            sampling_reasons=["HIGH_RISK"],
            anonymized=overrides.pop("anonymized", False),
            pii_status=overrides.pop("pii_status", PiiStatus.RAW),
            anonymized_object_key=overrides.pop("anonymized_object_key", ""),
            **overrides,
        )
        session.add(record)
        session.commit()
        return record.id


class TestScenario1WhoMaySeeWhat:
    def test_an_employee_cannot_read_the_validation_set(  # type: ignore[no-untyped-def]
        self, client, people, engine, organization
    ) -> None:
        """Сотруднику здесь нечего делать: это чужая почта, собранная для измерений."""
        _seed(engine, organization)
        actor = _as(client, people, "employee")
        assert actor.get("/api/v1/detection/real-flow/summary").status_code == 403

    def test_a_viewer_can_read_the_metrics(  # type: ignore[no-untyped-def]
        self, client, people, engine, organization
    ) -> None:
        """Метрики реального потока — то, из-за чего этап существует, и прятать их не от кого."""
        _seed(engine, organization)
        actor = _as(client, people, "viewer")
        response = actor.get("/api/v1/detection/real-flow/summary")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["messages_total"] == 1
        assert body["precision"] is None, "разборов нет — знаменателя нет"
        assert body["recall_is_estimate"] is True
        assert body["ground_truth_complete"] is False

    def test_a_viewer_cannot_review(  # type: ignore[no-untyped-def]
        self, client, people, engine, organization
    ) -> None:
        record_id = _seed(engine, organization)
        actor = _as(client, people, "viewer")
        response = actor.post(
            f"/api/v1/detection/real-flow/messages/{record_id}/review",
            json={"classification": "CONFIRMED_PHISHING"},
        )
        assert response.status_code == 403

    def test_the_listing_carries_no_subject_and_no_body(  # type: ignore[no-untyped-def]
        self, client, people, engine, organization
    ) -> None:
        """Содержимое для измерения не нужно, а в списке оно стало бы доступно всем, кто смотрит
        метрики."""
        _seed(engine, organization)
        actor = _as(client, people, "viewer")
        body = actor.get("/api/v1/detection/real-flow/messages").json()
        assert body, "список не должен быть пустым, иначе проверка ничего не проверяет"
        assert not {"subject", "body", "text", "raw"} & set(body[0])


class TestScenario2ReviewIsRecordedAndAudited:
    def test_a_review_changes_the_metrics_and_leaves_a_trace(  # type: ignore[no-untyped-def]
        self, client, people, engine, organization
    ) -> None:
        record_id = _seed(engine, organization)
        analyst = _as(client, people, "analyst")
        response = analyst.post(
            f"/api/v1/detection/real-flow/messages/{record_id}/review",
            json={"classification": "FALSE_POSITIVE", "comment": "рассылка своей бухгалтерии"},
        )
        assert response.status_code == 200, response.text
        assert response.json()["analyst_classification"] == "FALSE_POSITIVE"
        assert response.json()["reviewed_by"] == "analyst@corp.example"

        summary = analyst.get("/api/v1/detection/real-flow/summary").json()
        assert summary["false_positive"] == 1
        assert summary["precision"] == 0.0, "ноль честен: знаменатель появился"
        analyst.logout()

        admin = _as(client, people, "admin")
        audit = admin.get("/api/v1/admin/audit?limit=100")
        assert audit.status_code == 200, audit.text
        actions = {row["action"] for row in audit.json()["items"]}
        assert "realflow.reviewed" in actions

    def test_a_review_does_not_promote_anything(  # type: ignore[no-untyped-def]
        self, client, people, engine, organization
    ) -> None:
        record_id = _seed(engine, organization)
        analyst = _as(client, people, "analyst")
        body = analyst.post(
            f"/api/v1/detection/real-flow/messages/{record_id}/review",
            json={"classification": "CONFIRMED_PHISHING"},
        ).json()
        assert body["promotion_state"] == "NOT_REQUESTED"
        assert body["pii_status"] == "RAW"


class TestScenario3PromotionNeedsEverything:
    def _reviewed_and_anonymized(self, client, people, engine, organization):  # type: ignore[no-untyped-def]
        from msp_contracts import PiiStatus

        record_id = _seed(
            engine,
            organization,
            anonymized=True,
            pii_status=PiiStatus.REVIEWED,
            anonymized_object_key="validation/anon/e2e.eml",
        )
        analyst = _as(client, people, "analyst")
        analyst.post(
            f"/api/v1/detection/real-flow/messages/{record_id}/review",
            json={"classification": "CONFIRMED_PHISHING"},
        )
        analyst.logout()
        return record_id

    def test_an_analyst_cannot_propose_a_message_for_the_corpus(  # type: ignore[no-untyped-def]
        self, client, people, engine, organization
    ) -> None:
        """Разбор и предложение в корпус — разные решения с разной ценой ошибки (ТЗ §24)."""
        record_id = self._reviewed_and_anonymized(client, people, engine, organization)
        analyst = _as(client, people, "analyst")
        response = analyst.post(
            f"/api/v1/detection/real-flow/messages/{record_id}/promote-request",
            json={"case_id": "CASE-1"},
        )
        assert response.status_code == 403

    def test_a_raw_message_cannot_be_proposed(  # type: ignore[no-untyped-def]
        self, client, people, engine, organization
    ) -> None:
        record_id = _seed(engine, organization)
        admin = _as(client, people, "admin")
        response = admin.post(
            f"/api/v1/detection/real-flow/messages/{record_id}/promote-request",
            json={"case_id": "CASE-1"},
        )
        assert response.status_code == 400
        assert "обезличено" in response.json()["detail"]

    def test_the_requester_cannot_approve_their_own_request(  # type: ignore[no-untyped-def]
        self, client, people, engine, organization
    ) -> None:
        record_id = self._reviewed_and_anonymized(client, people, engine, organization)
        admin = _as(client, people, "admin")
        assert (
            admin.post(
                f"/api/v1/detection/real-flow/messages/{record_id}/promote-request",
                json={"case_id": "CASE-1"},
            ).status_code
            == 200
        )
        response = admin.post(
            f"/api/v1/detection/real-flow/messages/{record_id}/promote-decision",
            json={"decision": "approve"},
        )
        assert response.status_code == 400
        assert "автором заявки" in response.json()["detail"]

    def test_promotion_without_a_reproducibility_check_is_refused(  # type: ignore[no-untyped-def]
        self, client, people, engine, organization
    ) -> None:
        """Обезличенное письмо — это другое письмо, и кейс, не воспроизводящийся на нём, измерял
        бы последствия замен (ТЗ §10)."""
        record_id = self._reviewed_and_anonymized(client, people, engine, organization)
        admin = _as(client, people, "admin")
        admin.post(
            f"/api/v1/detection/real-flow/messages/{record_id}/promote-request",
            json={"case_id": "CASE-1"},
        )
        admin.logout()

        lead = _as(client, people, "lead")
        assert (
            lead.post(
                f"/api/v1/detection/real-flow/messages/{record_id}/promote-decision",
                json={"decision": "approve"},
            ).status_code
            == 200
        )
        response = lead.post(
            f"/api/v1/detection/real-flow/messages/{record_id}/promote-decision",
            json={
                "decision": "promote",
                "dataset_version": "2026.10.1",
                "current_dataset_version": "2026.09.1",
            },
        )
        assert response.status_code == 400
        assert "воспроизводимость" in response.json()["detail"]

    def test_every_promotion_step_is_audited_separately(  # type: ignore[no-untyped-def]
        self, client, people, engine, organization
    ) -> None:
        """«Кто-то поменял состояние» не отвечает на вопрос, кто что решил."""
        record_id = self._reviewed_and_anonymized(client, people, engine, organization)
        admin = _as(client, people, "admin")
        admin.post(
            f"/api/v1/detection/real-flow/messages/{record_id}/promote-request",
            json={"case_id": "CASE-1"},
        )
        admin.logout()
        lead = _as(client, people, "lead")
        lead.post(
            f"/api/v1/detection/real-flow/messages/{record_id}/promote-decision",
            json={"decision": "approve"},
        )
        actions = {row["action"] for row in lead.get("/api/v1/admin/audit?limit=100").json()["items"]}
        assert {"realflow.promotion_requested", "realflow.promotion_approved"} <= actions


class TestScenario4TheUncertainQueueIsItsOwnQueue:
    def test_an_unscannable_message_is_in_the_uncertain_queue_only(  # type: ignore[no-untyped-def]
        self, client, people, engine, organization
    ) -> None:
        from msp_contracts import RiskLevel

        _seed(
            engine,
            organization,
            fingerprint="locked",
            production_verdict=RiskLevel.LOW_RISK,
            triggered_rules=[],
            unscannable_reasons=["ENCRYPTED_ARCHIVE"],
        )
        _seed(engine, organization, fingerprint="bad")

        viewer = _as(client, people, "viewer")
        uncertain = viewer.get("/api/v1/detection/real-flow/messages?uncertain_only=true").json()
        assert [row["message_fingerprint"] for row in uncertain] == ["locked"]

        everything = viewer.get("/api/v1/detection/real-flow/messages").json()
        assert len(everything) == 2, "обычный список содержит оба: очередь — это не фильтр"


class TestScenario5AGapIsValidatedOnRealMailOrNotAtAll:
    def _gap(self, engine, organization):  # type: ignore[no-untyped-def]
        from msp_api.db.models import DetectionGapRecord
        from msp_contracts import GapStatus, Severity
        from sqlalchemy.orm import sessionmaker

        factory = sessionmaker(bind=engine, expire_on_commit=False)
        with factory() as session:
            gap = DetectionGapRecord(
                organization_id=organization.id,
                gap_id="GAP-001",
                category="sender",
                description="короткие похожие домены",
                severity=Severity.HIGH,
                status=GapStatus.VALIDATION,
            )
            session.add(gap)
            session.commit()
            return gap.gap_id

    def test_unreviewed_messages_are_not_evidence(  # type: ignore[no-untyped-def]
        self, client, people, engine, organization
    ) -> None:
        """По неразобранному письму неизвестно, что было на самом деле, — подтверждать им нечего."""
        gap_id = self._gap(engine, organization)
        record_id = _seed(engine, organization)
        admin = _as(client, people, "admin")
        response = admin.post(
            f"/api/v1/detection/gaps/{gap_id}/validation",
            json={"validation_message_ids": [record_id]},
        )
        assert response.status_code == 400
        assert "не разобраны" in response.json()["detail"]

    def test_a_message_from_another_organization_is_not_evidence(  # type: ignore[no-untyped-def]
        self, client, people, engine, organization
    ) -> None:
        gap_id = self._gap(engine, organization)
        admin = _as(client, people, "admin")
        response = admin.post(
            f"/api/v1/detection/gaps/{gap_id}/validation",
            json={"validation_message_ids": ["does-not-exist"]},
        )
        assert response.status_code == 400

    def test_validation_is_recorded_with_its_evidence(  # type: ignore[no-untyped-def]
        self, client, people, engine, organization
    ) -> None:
        """Проверка самой проверки: путь проходим, иначе отказы выше ничего не доказывают."""
        gap_id = self._gap(engine, organization)
        record_id = _seed(engine, organization)
        analyst = _as(client, people, "analyst")
        analyst.post(
            f"/api/v1/detection/real-flow/messages/{record_id}/review",
            json={"classification": "CONFIRMED_PHISHING"},
        )
        analyst.logout()

        admin = _as(client, people, "admin")
        response = admin.post(
            f"/api/v1/detection/gaps/{gap_id}/validation",
            json={"validation_message_ids": [record_id], "comment": "SND-024 сработало"},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["real_flow_evidence"]["message_count"] == 1
        assert body["real_flow_evidence"]["classifications"] == ["CONFIRMED_PHISHING"]
        assert body["real_flow_validated_by"] == "admin@corp.example"
        assert body["status"] == "VALIDATION", "подтверждение потоком не закрывает пробел само"

        actions = {row["action"] for row in admin.get("/api/v1/admin/audit?limit=100").json()["items"]}
        assert "gap.validated" in actions
