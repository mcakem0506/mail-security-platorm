"""Справочник получателей на настоящем Postfix (ТЗ 1.1 §16, §51, §68.7).

Шлюз принимает почту только известным адресатам. Здесь проверяется, что это действительно так,
что обновление справочника не ломает приём посреди работы, и что безнадёжно устаревший
справочник закрывает приём временным отказом, а не открывает его для всех.
"""

from __future__ import annotations

import json
import smtplib
import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from msp_gateway.render import Recipient

from .harness import LAB_RECIPIENTS, lab_spec, make_message


def new_id() -> str:
    return f"rcp-{uuid.uuid4().hex[:10]}"


def send(stack, rcpt: str, mid: str | None = None):  # type: ignore[no-untyped-def]
    sender = "a@partner.example"
    return stack.send_external(sender, [rcpt], make_message(mid or new_id(), sender, rcpt))


def refusal(stack, rcpt: str) -> int | None:  # type: ignore[no-untyped-def]
    """Код отказа по адресату или ``None``, если письмо принято."""
    try:
        refused = send(stack, rcpt)
    except smtplib.SMTPRecipientsRefused as error:
        return next(iter(error.recipients.values()))[0]
    return next(iter(refused.values()))[0] if refused else None


def meta(age: timedelta, count: int = 3) -> dict[str, object]:
    return {
        "generated_at": (datetime.now(UTC) - age).isoformat(),
        "recipient_count": count,
        "checksum": "lab",
        "source": "lab",
    }


def gate(stack) -> dict[str, object]:  # type: ignore[no-untyped-def]
    out = stack.exec("python3 -m msp_gateway.node gate-refresh").stdout
    return dict(json.loads(out.strip().splitlines()[-1]))


@pytest.fixture(autouse=True)
def restore(lab):  # type: ignore[no-untyped-def]
    yield
    lab.apply(lab_spec(), LAB_RECIPIENTS, recipients_meta=meta(timedelta(0)))
    gate(lab)
    lab.flush()


class TestWhoIsAccepted:
    def test_primary_alias_and_shared_addresses_are_accepted(self, clean) -> None:  # type: ignore[no-untyped-def]
        for rcpt in ("ivan@corp.example", "i.petrov@corp.example", "shared@corp.example"):
            assert refusal(clean, rcpt) is None, rcpt

    def test_address_case_does_not_matter(self, clean) -> None:  # type: ignore[no-untyped-def]
        assert refusal(clean, "IVAN@Corp.Example") is None

    @pytest.mark.parametrize("rcpt", ["nobody@corp.example", "ivan2@corp.example", "ivan@sub.corp.example"])
    def test_unknown_addresses_get_a_permanent_refusal_at_rcpt(self, clean, rcpt: str) -> None:  # type: ignore[no-untyped-def]
        assert refusal(clean, rcpt) == 550

    def test_refused_recipients_never_enter_the_queue(self, clean) -> None:  # type: ignore[no-untyped-def]
        before = clean.queue_size()
        refusal(clean, "ghost@corp.example")
        assert clean.queue_size() == before, "обратного рассеяния быть не может: отказ до приёма письма"


class TestUpdates:
    def test_a_new_address_appears_and_a_removed_one_disappears(self, clean) -> None:  # type: ignore[no-untyped-def]
        assert refusal(clean, "newbie@corp.example") == 550
        updated = [Recipient("ivan@corp.example"), Recipient("newbie@corp.example")]
        assert clean.apply(lab_spec(), updated, recipients_meta=meta(timedelta(0)))["outcome"] == "ACTIVE"
        assert refusal(clean, "newbie@corp.example") is None
        assert refusal(clean, "shared@corp.example") == 550, "удалённый адрес больше не принимается"

    def test_existing_recipients_are_not_disturbed_during_an_update(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Обновление атомарно: известный адресат не получает отказ посреди применения."""
        failures: list[object] = []
        stop = threading.Event()

        def hammer() -> None:
            while not stop.is_set():
                try:
                    code = refusal(clean, "ivan@corp.example")
                except (OSError, smtplib.SMTPException) as error:
                    failures.append(type(error).__name__)
                    continue
                if code is not None:
                    failures.append(code)
                # Лимит шлюза — 60 соединений в минуту на клиента (это его защита, а не сбой
                # обновления); идём заметно ниже лимита.
                stop.wait(1.5)

        worker = threading.Thread(target=hammer)
        worker.start()
        try:
            for i in range(3):
                extra = [*LAB_RECIPIENTS, Recipient(f"extra{i}@corp.example")]
                assert (
                    clean.apply(lab_spec(), extra, recipients_meta=meta(timedelta(0)))["outcome"] == "ACTIVE"
                )
        finally:
            stop.set()
            worker.join()
        assert failures == [], f"известный адресат получил отказ во время обновления: {failures[:5]}"

    def test_a_node_refuses_to_activate_an_empty_directory(self, clean) -> None:  # type: ignore[no-untyped-def]
        result = clean.apply(lab_spec(), [], recipients_meta=meta(timedelta(0), 0))
        assert result["outcome"] != "ACTIVE"
        assert refusal(clean, "ivan@corp.example") is None, "прежний справочник продолжает работать"


class TestFreshness:
    def test_fresh_directory_keeps_the_gate_open(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.apply(lab_spec(), LAB_RECIPIENTS, recipients_meta=meta(timedelta(minutes=5)))
        state = gate(clean)
        assert state["freshness"] == "FRESH"
        assert state["gate_closed"] is False

    def test_stale_within_grace_still_accepts_mail(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.apply(lab_spec(), LAB_RECIPIENTS, recipients_meta=meta(timedelta(minutes=90)))
        state = gate(clean)
        assert state["freshness"] == "STALE_GRACE"
        assert refusal(clean, "ivan@corp.example") is None

    def test_hopelessly_stale_directory_defers_instead_of_accepting_everyone(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.apply(lab_spec(), LAB_RECIPIENTS, recipients_meta=meta(timedelta(hours=10)))
        state = gate(clean)
        assert state["freshness"] == "STALE_HARD"
        assert state["gate_closed"] is True
        # Временный отказ: отправитель повторит позже, письмо не потеряно и нигде не отскочило.
        assert refusal(clean, "ivan@corp.example") == 451
        assert refusal(clean, "stranger@corp.example") == 451

    def test_gate_reopens_after_a_fresh_directory_arrives(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.apply(lab_spec(), LAB_RECIPIENTS, recipients_meta=meta(timedelta(hours=10)))
        gate(clean)
        assert refusal(clean, "ivan@corp.example") == 451
        clean.apply(lab_spec(), LAB_RECIPIENTS, recipients_meta=meta(timedelta(0)))
        assert gate(clean)["gate_closed"] is False
        assert refusal(clean, "ivan@corp.example") is None

    def test_no_meta_at_all_is_treated_as_the_worst_state(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.exec("rm -f /var/lib/msp/state/recipients.meta.json")
        assert gate(clean)["freshness"] == "STALE_HARD"

    def test_a_failed_apply_does_not_refresh_the_age(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Пустой справочник отклонён: возраст прежнего не должен помолодеть от неудачной попытки."""
        clean.apply(lab_spec(), LAB_RECIPIENTS, recipients_meta=meta(timedelta(minutes=90)))
        before = clean.exec("cat /var/lib/msp/state/recipients.meta.json").stdout
        clean.apply(lab_spec(), [], recipients_meta=meta(timedelta(0), 0))
        assert clean.exec("cat /var/lib/msp/state/recipients.meta.json").stdout == before
