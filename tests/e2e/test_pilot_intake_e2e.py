"""Приём журнального отчёта в набор валидации через HTTP (MSP 1.3P, ТЗ 1.3P §10, §15, §16).

Проверяется путь целиком: отчёт → оригинал → надёжный приём → анализ → запись набора валидации. И то, что на этом пути
нельзя потерять письмо, посчитать его дважды, выдать непроверенное за чистое или принять реальную почту вне теневого режима.
"""

from __future__ import annotations

import pytest

from tests.unit.test_journal_report import original_message, report

from .test_transport_e2e import as_, client, people  # noqa: F401

BASE = "/api/v1/pilot"
SALT = "s" * 32


@pytest.fixture
def shadow(client, people, engine, organization, monkeypatch):  # type: ignore[no-untyped-def]
    from msp_api.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "real_flow_shadow", True)
    monkeypatch.setattr(settings, "real_flow_fingerprint_salt", SALT)
    monkeypatch.setattr(settings, "corporate_domains", "corp.example")
    return settings


def post(admin, body: bytes):  # type: ignore[no-untyped-def]
    return admin.client.post(
        f"{BASE}/intake/journal",
        content=body,
        headers={"x-csrf-token": admin.csrf, "content-type": "message/rfc822"},
    )


def sample(admin) -> dict:  # type: ignore[no-untyped-def]
    return admin.get(f"{BASE}/metrics").json()["sample"]


class TestGuards:
    def test_real_mail_is_refused_outside_shadow_mode(self, client, people, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from msp_api.config import get_settings

        monkeypatch.setattr(get_settings(), "real_flow_shadow", False)
        monkeypatch.setattr(get_settings(), "real_flow_fingerprint_salt", SALT)
        response = post(as_(client, people, "admin"), report())

        assert response.status_code == 409
        assert "REAL_FLOW_SHADOW" in response.json()["detail"]

    def test_real_mail_is_refused_without_the_fingerprint_salt(self, client, people, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from msp_api.config import get_settings

        monkeypatch.setattr(get_settings(), "real_flow_shadow", True)
        monkeypatch.setattr(get_settings(), "real_flow_fingerprint_salt", "short")
        assert post(as_(client, people, "admin"), report()).status_code == 409

    @pytest.mark.parametrize("who", ["viewer", "analyst", "employee"])
    def test_only_the_pilot_manager_may_feed_mail(self, client, people, shadow, who) -> None:  # type: ignore[no-untyped-def]
        assert post(as_(client, people, who), report()).status_code == 403

    def test_an_empty_and_an_oversized_request_are_refused(self, client, people, shadow, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        assert post(admin, b"").status_code == 422
        monkeypatch.setattr(shadow, "limit_message_size", 1000)
        assert post(admin, b"x" * 2000).status_code == 413


class TestHappyPath:
    def test_a_report_becomes_one_real_message_with_its_source(self, client, people, shadow) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")

        result = post(admin, report()).json()

        assert result["status"] == "ANALYSED" and result["created"] is True
        s = sample(admin)
        assert s["real_unique"] == 1
        assert s["real_by_source"] == {"JOURNAL_COPY": 1}

    def test_the_raw_retention_deadline_is_set(self, client, people, shadow, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import ValidationMessage
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        post(as_(client, people, "admin"), report())
        with sessionmaker(bind=engine)() as session:
            row = session.execute(select(ValidationMessage)).scalars().one()
        assert row.raw_retained_until is not None
        assert row.production_verdict is not None, "проверенное письмо осталось без вердикта"

    def test_the_same_report_twice_does_not_grow_the_sample(self, client, people, shadow) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        body = report()

        first = post(admin, body).json()
        second = post(admin, body).json()

        assert first["status"] == "ANALYSED" and second["status"] == "DUPLICATE"
        assert second["created"] is False
        assert sample(admin)["real_unique"] == 1

    def test_two_reports_about_one_message_are_one_message(self, client, people, shadow) -> None:  # type: ignore[no-untyped-def]
        """Журнал и копия из другого места дают разные отчёты об одном письме: выборка не утраивается."""
        admin = as_(client, people, "admin")

        post(admin, report(report_id="<rep-a@x>"))
        again = post(admin, report(report_id="<rep-b@x>")).json()

        assert again["status"] == "DUPLICATE"
        assert sample(admin)["real_unique"] == 1

    def test_two_letters_with_one_structure_and_different_ids_are_two_messages(
        self, client, people, shadow
    ) -> None:  # type: ignore[no-untyped-def]
        """Типовые письма одного отправителя различаются Message-ID: структурный отпечаток их бы склеил."""
        admin = as_(client, people, "admin")
        post(admin, report([original_message("первое", "<a@x>")]))
        post(admin, report([original_message("второе, другое", "<b@x>")], report_id="<r2@x>"))

        assert sample(admin)["real_unique"] == 2


class TestUnscannableIsNeverClean:
    def test_an_oversized_original_is_recorded_as_unscannable(
        self, client, people, shadow, engine, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import ValidationMessage
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        monkeypatch.setattr(shadow, "limit_message_size", 20000)
        admin = as_(client, people, "admin")

        result = post(admin, report([original_message("x" * 21000)])).json()

        assert result["status"] == "UNSCANNABLE"
        assert "ORIGINAL_OVERSIZED" in result["problems"]
        s = sample(admin)
        assert s["real_unique"] == 1
        assert s["unscannable_per_1000"] == 1000.0
        assert s["unknown_per_1000"] == 1000.0
        with sessionmaker(bind=engine)() as session:
            row = session.execute(select(ValidationMessage)).scalars().one()
        assert row.production_verdict is None, "непроверенное письмо получило вердикт"

    def test_a_non_report_is_recorded_as_unscannable(self, client, people, shadow) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        result = post(admin, report(marked=False)).json()

        assert result["status"] == "UNSCANNABLE"
        assert result["problems"] == ["NOT_A_JOURNAL_REPORT"]

    def test_a_report_without_the_original_is_recorded_as_unscannable(self, client, people, shadow) -> None:  # type: ignore[no-untyped-def]
        result = post(as_(client, people, "admin"), report(originals=[])).json()
        assert result["status"] == "UNSCANNABLE" and "NO_ORIGINAL_ATTACHMENT" in result["problems"]

    def test_garbage_is_recorded_and_does_not_break_the_service(self, client, people, shadow) -> None:  # type: ignore[no-untyped-def]
        admin = as_(client, people, "admin")
        assert post(admin, b"\x00\xff\x00 garbage").json()["status"] == "UNSCANNABLE"
        assert post(admin, report()).json()["status"] == "ANALYSED"


class TestNothingIsLost:
    def test_an_analysis_failure_keeps_the_message_for_a_retry(
        self, client, people, shadow, engine, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import IntakeRecord, ValidationMessage
        from msp_api.services import real_flow_feed
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        admin = as_(client, people, "admin")
        original = real_flow_feed.run_local_analysis

        def broken(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise RuntimeError("анализатор недоступен")

        monkeypatch.setattr(real_flow_feed, "run_local_analysis", broken)
        failed = post(admin, report()).json()
        assert failed["status"] == "FAILED"
        with sessionmaker(bind=engine)() as session:
            record = session.execute(select(IntakeRecord)).scalars().one()
            assert record.state.value == "RETRY" and record.raw_storage_key, "письмо не сохранено до анализа"
            assert session.execute(select(ValidationMessage)).first() is None

        monkeypatch.setattr(real_flow_feed, "run_local_analysis", original)
        retried = post(admin, report()).json()

        assert retried["status"] == "ANALYSED"
        assert sample(admin)["real_unique"] == 1

    def test_the_intake_is_audited_without_addresses_or_content(self, client, people, shadow, engine) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import AuditEvent
        from sqlalchemy import select
        from sqlalchemy.orm import sessionmaker

        post(as_(client, people, "admin"), report())
        with sessionmaker(bind=engine)() as session:
            rows = (
                session.execute(select(AuditEvent).where(AuditEvent.action == "pilot.journal_intake"))
                .scalars()
                .all()
            )

        assert len(rows) == 1
        text = str(rows[0].detail)
        assert "corp.example" not in text and "Счёт" not in text
        assert rows[0].detail["status"] == "ANALYSED"


class TestOutOfPilotSources:
    def test_the_security_mailbox_does_not_inflate_the_real_sample(
        self, client, people, shadow, engine, organization
    ) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import ValidationMessage
        from msp_contracts import ValidationSource
        from sqlalchemy.orm import sessionmaker

        with sessionmaker(bind=engine, expire_on_commit=False)() as session:
            for i in range(10):
                session.add(
                    ValidationMessage(
                        organization_id=organization.id,
                        source=ValidationSource.SECURITY_MAILBOX,
                        message_fingerprint=f"sm-{i}",
                    )
                )
            session.commit()
        post(as_(client, people, "admin"), report())

        s = sample(as_(client, people, "admin"))
        assert s["real_unique"] == 1 and s["biased_real_security_mailbox"] == 10
