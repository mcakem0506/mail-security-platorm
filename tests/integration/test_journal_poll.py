"""Опрос журнального ящика Exchange (MSP 1.3P, ТЗ §10, §15, §23): порядок операций и отказоустойчивость.

Свойство, ради которого существует цикл, то же, что у ящика безопасности (ТЗ 1.0.1 §4.1): письмо переносится в «Обработанные» только
после того, как запись и анализ зафиксированы. Письмо, перенесённое раньше, теряется при падении рабочего процесса; письмо,
зафиксированное раньше переноса, в худшем случае видят дважды, и дедупликация делает это безвредным. Поддельный ящик
записывает порядок вызовов, поэтому проверяется именно он, а не только исход.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field

import pytest
from msp_api.config import get_settings
from msp_api.db.models import IntakeRecord, ValidationMessage
from msp_api.services import real_flow_feed
from msp_exchange.security_mailbox import IngestedReport
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from tests.unit.test_journal_report import original_message, report

SALT = "s" * 32


class MemoryStorage:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put(self, key: str, data: bytes, content_type: str = "") -> None:
        self.objects[key] = data

    def get(self, key: str) -> bytes:
        return self.objects[key]


@dataclass
class FakeJournal:
    """Ящик, который записывает, в каком порядке к нему обращались, и показывает, что в нём осталось."""

    reports: list[IngestedReport]
    events: list[str] = field(default_factory=list)
    acked: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    def fetch_unprocessed(self, limit: int | None = None) -> list[IngestedReport]:
        self.events.append("fetch")
        return list(self.reports)

    def ack(self, uid: str) -> bool:
        self.events.append(f"ack:{uid}")
        self.acked.append(uid)
        return True

    def fail(self, uid: str) -> bool:
        self.events.append(f"fail:{uid}")
        self.failed.append(uid)
        return True


def item(uid: str, raw: bytes, *, oversized: bool = False, size: int = 0) -> IngestedReport:
    return IngestedReport(
        uid=uid, raw_mime=b"" if oversized else raw, oversized=oversized, actual_size=size or len(raw)
    )


@pytest.fixture
def shadow(db, organization, monkeypatch):  # type: ignore[no-untyped-def]
    settings = get_settings()
    monkeypatch.setattr(settings, "real_flow_shadow", True)
    monkeypatch.setattr(settings, "real_flow_fingerprint_salt", SALT)
    monkeypatch.setattr(settings, "corporate_domains", "corp.example")
    return settings


@pytest.fixture
def scope(engine):  # type: ignore[no-untyped-def]
    """Область сеанса, как у ``session_scope``: фиксация в конце блока, откат при исключении, события в журнал."""
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    log: list[str] = []

    @contextmanager
    def open_scope():  # type: ignore[no-untyped-def]
        session = factory()
        try:
            yield session
            session.commit()
            log.append("commit")
        except Exception:
            session.rollback()
            log.append("rollback")
            raise
        finally:
            session.close()

    open_scope.log = log  # type: ignore[attr-defined]
    return open_scope


def run(scope, settings, mailbox):  # type: ignore[no-untyped-def]
    return real_flow_feed.process_batch(scope, settings, mailbox, storage=MemoryStorage())


def count(engine, model) -> int:  # type: ignore[no-untyped-def]
    with sessionmaker(bind=engine)() as session:
        return len(session.execute(select(model)).scalars().all())


class TestOrder:
    def test_the_mailbox_is_told_only_after_the_record_is_committed(self, shadow, scope, engine) -> None:  # type: ignore[no-untyped-def]
        mailbox = FakeJournal([item("1", report())])
        events: list[str] = []
        original_ack = mailbox.ack

        def ack(uid: str) -> bool:
            # К моменту переноса запись уже видна из другого сеанса, то есть зафиксирована.
            events.append(f"visible={count(engine, ValidationMessage)}")
            return original_ack(uid)

        mailbox.ack = ack  # type: ignore[method-assign]
        summary = run(scope, shadow, mailbox)

        assert summary["analysed"] == 1
        assert events == ["visible=1"], "письмо перенесено до фиксации записи"
        assert mailbox.acked == ["1"]

    def test_a_crash_before_the_commit_leaves_the_message_in_the_mailbox(
        self, shadow, scope, engine, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        mailbox = FakeJournal([item("1", report())])
        monkeypatch.setattr(
            real_flow_feed,
            "ingest_journal_report",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("упал")),
        )

        summary = run(scope, shadow, mailbox)

        assert summary["errors"] == 1
        assert mailbox.acked == [] and mailbox.failed == [], "письмо перенесено, хотя запись не зафиксирована"
        assert count(engine, ValidationMessage) == 0


class TestOutcomes:
    def test_a_repeated_poll_after_a_crash_after_the_commit_adds_nothing(self, shadow, scope, engine) -> None:  # type: ignore[no-untyped-def]
        """Падение между фиксацией и переносом: письмо остаётся в ящике и берётся снова, выборка не растёт."""
        raw = report()
        first = run(scope, shadow, FakeJournal([item("1", raw)]))
        again = run(scope, shadow, FakeJournal([item("1", raw)]))

        assert first["analysed"] == 1
        assert again["duplicates"] == 1 and again["analysed"] == 0
        assert count(engine, ValidationMessage) == 1

    def test_two_reports_about_one_message_are_one_record(self, shadow, scope, engine) -> None:  # type: ignore[no-untyped-def]
        mailbox = FakeJournal([item("1", report(report_id="<a@x>")), item("2", report(report_id="<b@x>"))])
        summary = run(scope, shadow, mailbox)

        assert summary["analysed"] == 1 and summary["duplicates"] == 1
        assert count(engine, ValidationMessage) == 1
        assert sorted(mailbox.acked) == ["1", "2"], "дубликат должен быть перенесён, а не копиться в ящике"

    def test_an_unusable_report_is_recorded_as_unscannable_and_moved(self, shadow, scope, engine) -> None:  # type: ignore[no-untyped-def]
        mailbox = FakeJournal([item("1", report(originals=[])), item("2", b"\x00\xffmusor")])
        summary = run(scope, shadow, mailbox)

        assert summary["unscannable"] == 2
        assert mailbox.acked == ["1", "2"]
        with sessionmaker(bind=engine)() as session:
            rows = session.execute(select(ValidationMessage)).scalars().all()
        assert len(rows) == 2 and all(r.production_verdict is None for r in rows)

    def test_an_oversized_report_is_recorded_without_downloading_and_moved(
        self, shadow, scope, engine
    ) -> None:  # type: ignore[no-untyped-def]
        mailbox = FakeJournal(
            [item("7", b"", oversized=True, size=90_000_000), item("8", b"", oversized=True, size=95_000_000)]
        )
        summary = run(scope, shadow, mailbox)

        assert summary["unscannable"] == 2, "два больших отчёта склеились в один"
        assert mailbox.acked == ["7", "8"]
        assert count(engine, ValidationMessage) == 2

    def test_an_analysis_failure_keeps_the_message_for_a_retry(
        self, shadow, scope, engine, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        mailbox = FakeJournal([item("1", report())])

        def broken(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise RuntimeError("анализатор недоступен")

        monkeypatch.setattr(real_flow_feed, "run_local_analysis", broken)
        summary = run(scope, shadow, mailbox)

        assert summary["retry"] == 1
        assert mailbox.acked == [] and mailbox.failed == []
        assert count(engine, ValidationMessage) == 0
        with sessionmaker(bind=engine)() as session:
            record = session.execute(select(IntakeRecord)).scalars().one()
        assert record.state.value == "RETRY" and record.raw_storage_key, "письмо не сохранено до анализа"

    def test_after_the_retries_are_exhausted_the_message_goes_to_the_failed_folder(
        self, shadow, scope, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        mailbox = FakeJournal([item("1", report())])
        monkeypatch.setattr(
            real_flow_feed, "run_local_analysis", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x"))
        )

        first = run(scope, shadow, mailbox)
        assert first["retry"] == 1 and mailbox.failed == [], "письмо унесено в «неудачи» с первой попытки"
        results = [first]
        while not results[-1]["dead_lettered"] and len(results) < 5:
            results.append(run(scope, shadow, mailbox))

        assert results[-1]["dead_lettered"] == 1, "повторы не заканчиваются"
        assert mailbox.failed == ["1"] and mailbox.acked == []

    def test_a_failed_move_is_harmless_because_the_next_poll_deduplicates(
        self, shadow, scope, engine
    ) -> None:  # type: ignore[no-untyped-def]
        raw = report()

        class BrokenMove(FakeJournal):
            def ack(self, uid: str) -> bool:
                raise OSError("IMAP недоступен")

        run(scope, shadow, BrokenMove([item("1", raw)]))
        again = run(scope, shadow, FakeJournal([item("1", raw)]))

        assert again["duplicates"] == 1
        assert count(engine, ValidationMessage) == 1


class TestGuards:
    def test_the_poll_is_refused_outside_shadow_mode_and_nothing_is_fetched(
        self, db, organization, scope, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        settings = get_settings()
        monkeypatch.setattr(settings, "real_flow_shadow", False)
        monkeypatch.setattr(settings, "real_flow_fingerprint_salt", SALT)
        mailbox = FakeJournal([item("1", report())])

        with pytest.raises(real_flow_feed.FeedError):
            run(scope, settings, mailbox)

        assert mailbox.events == [], "ящик опрошен, хотя приём запрещён"

    def test_the_poll_is_refused_without_the_fingerprint_salt(
        self, db, organization, scope, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        settings = get_settings()
        monkeypatch.setattr(settings, "real_flow_shadow", True)
        monkeypatch.setattr(settings, "real_flow_fingerprint_salt", "")
        with pytest.raises(real_flow_feed.FeedError):
            run(scope, settings, FakeJournal([item("1", report())]))


class TestTask:
    def test_the_task_skips_when_the_journal_mailbox_is_not_configured(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from msp_worker import tasks

        settings = get_settings()
        monkeypatch.setattr(settings, "journal_mailbox_enabled", False)
        assert tasks.poll_journal_mailbox() == {"skipped": "journal mailbox not configured"}

    def test_the_task_skips_instead_of_polling_outside_shadow_mode(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        import msp_exchange
        from msp_worker import tasks

        settings = get_settings()
        monkeypatch.setattr(settings, "journal_mailbox_enabled", True)
        monkeypatch.setattr(settings, "journal_mailbox_host", "imap.invalid")
        monkeypatch.setattr(settings, "real_flow_shadow", False)

        class Probe:
            polled = False

            def __init__(self, config) -> None:  # type: ignore[no-untyped-def]
                self.config = config

            def fetch_unprocessed(self, limit=None):  # type: ignore[no-untyped-def]
                Probe.polled = True
                return []

        monkeypatch.setattr(msp_exchange, "SecurityMailboxProvider", Probe)

        result = tasks.poll_journal_mailbox()

        assert "skipped" in result and Probe.polled is False

    def test_the_journal_provider_is_configured_to_return_the_whole_report(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        import msp_exchange
        from msp_worker import tasks

        settings = get_settings()
        for name, value in (
            ("journal_mailbox_enabled", True),
            ("journal_mailbox_host", "imap.invalid"),
            ("real_flow_shadow", True),
            ("real_flow_fingerprint_salt", SALT),
        ):
            monkeypatch.setattr(settings, name, value)
        seen: dict[str, object] = {}

        class Probe:
            def __init__(self, config) -> None:  # type: ignore[no-untyped-def]
                seen["unwrap"] = config.unwrap_forwarded
                seen["max"] = config.max_message_size

            def fetch_unprocessed(self, limit=None):  # type: ignore[no-untyped-def]
                raise OSError("нет соединения")

        monkeypatch.setattr(msp_exchange, "SecurityMailboxProvider", Probe)

        result = tasks.poll_journal_mailbox()

        assert result == {"error": "OSError"}, "недоступный ящик уронил воркер"
        assert seen["unwrap"] is False
        assert seen["max"] > settings.limit_message_size


def test_the_unwrap_flag_returns_the_report_as_it_arrived() -> None:
    from msp_exchange.security_mailbox import SecurityMailboxConfig, SecurityMailboxProvider

    raw = report([original_message()])
    plain = SecurityMailboxProvider(SecurityMailboxConfig(host="h", unwrap_forwarded=False))._to_report(
        "1", raw
    )
    unwrapped = SecurityMailboxProvider(SecurityMailboxConfig(host="h"))._to_report("1", raw)

    assert plain.raw_mime == raw and plain.is_forwarded_original is False
    assert unwrapped.raw_mime != raw, "ящик безопасности перестал разворачивать пересылку"
