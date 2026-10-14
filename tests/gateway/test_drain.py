"""Режим слива перед обслуживанием (ТЗ 1.1 §26, §68.10).

Слив останавливает *приём* новой почты временным отказом (4xx), не трогая то, что уже
принято: очередь доставляется, как обычно. Отправитель повторит позже, письмо не теряется и
не возвращается ему как недоставленное.
"""

from __future__ import annotations

import json
import smtplib
import uuid

import pytest

from .harness import make_message


def new_id() -> str:
    return f"drn-{uuid.uuid4().hex[:10]}"


def full_id(mid: str) -> str:
    return f"<{mid}@lab.example>"


def drain(stack, mode: str) -> dict[str, object]:  # type: ignore[no-untyped-def]
    out = stack.exec(f"python3 -m msp_gateway.node drain {mode}").stdout
    return dict(json.loads(out.strip().splitlines()[-1]))


def refusal_code(stack, mid: str) -> int | None:  # type: ignore[no-untyped-def]
    sender, rcpt = "a@partner.example", "ivan@corp.example"
    try:
        refused = stack.send_external(sender, [rcpt], make_message(mid, sender, rcpt))
    except smtplib.SMTPRecipientsRefused as error:
        return next(iter(error.recipients.values()))[0]
    except smtplib.SMTPResponseException as error:
        return error.smtp_code
    except smtplib.SMTPConnectError as error:
        return error.smtp_code
    return next(iter(refused.values()))[0] if refused else None


@pytest.fixture(autouse=True)
def restore(lab):  # type: ignore[no-untyped-def]
    yield
    drain(lab, "off")
    for control in (lab.exchange1, lab.exchange2):
        control.mode("accept")
    lab.flush()
    lab.wait_until(lambda: lab.queue_size() == 0, timeout=120, what="очередь опустела")


class TestDrain:
    def test_a_draining_node_defers_new_mail_with_a_temporary_code(self, clean) -> None:  # type: ignore[no-untyped-def]
        assert drain(clean, "on")["draining"] is True
        code = refusal_code(clean, new_id())
        assert code is not None and 400 <= code < 500, f"ожидался временный отказ, получено {code}"

    def test_a_deferred_message_is_not_in_the_queue_and_nothing_bounces(self, clean) -> None:  # type: ignore[no-untyped-def]
        drain(clean, "on")
        before = clean.queue_size()
        refusal_code(clean, new_id())
        assert clean.queue_size() == before
        assert clean.sink.received() == [], "отправителю не уходит уведомление о недоставке"

    def test_mail_accepted_before_the_drain_is_still_delivered(self, clean) -> None:  # type: ignore[no-untyped-def]
        mid = new_id()
        for control in (clean.exchange1, clean.exchange2):
            control.mode("tempfail")
        assert refusal_code(clean, mid) is None
        clean.wait_until(lambda: clean.queue_size() >= 1, what="письмо в очереди")
        drain(clean, "on")
        for control in (clean.exchange1, clean.exchange2):
            control.mode("accept")
        clean.flush()
        assert clean.exchange1.wait_for(full_id(mid), timeout=90) is not None, (
            "слив не останавливает доставку"
        )

    def test_normal_service_returns_when_the_drain_is_lifted(self, clean) -> None:  # type: ignore[no-untyped-def]
        drain(clean, "on")
        assert refusal_code(clean, new_id()) is not None
        assert drain(clean, "off")["draining"] is False
        mid = new_id()
        assert refusal_code(clean, mid) is None
        assert clean.exchange1.wait_for(full_id(mid), timeout=60) is not None

    def test_the_drain_survives_a_restart_of_the_node(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Оператор включил слив перед обслуживанием; перезапуск не должен тихо вернуть приём."""
        drain(clean, "on")
        clean.restart()
        assert drain(clean, "status")["draining"] is True
        code = refusal_code(clean, new_id())
        assert code is not None and 400 <= code < 500

    def test_the_drain_is_visible_in_the_metrics(self, clean) -> None:  # type: ignore[no-untyped-def]
        import urllib.request

        drain(clean, "on")
        url = f"http://127.0.0.1:{clean.ports['GW_PORT_METRICS']}/metrics"

        def draining() -> bool:
            try:
                with urllib.request.urlopen(url, timeout=5) as response:
                    return 'msp_gateway_pressure_state{state="DRAINING"} 1' in response.read().decode()
            except OSError:
                return False

        clean.wait_until(draining, timeout=40, what="слив виден в метриках")
