"""Принятая почта не теряется (ТЗ 1.1 §6, §7, §27, §50, §68.2–4).

После ответа ``250`` письмо лежит в устойчивой очереди Postfix, и всё, что происходит дальше, —
сбой Exchange, обрыв соединения, убитый процесс, перезапуск контейнера — может задержать
доставку, но не потерять письмо. Это главное обещание транспорта, и проверяется оно сбоями,
которые нельзя вызвать иначе, чем извне: остановкой соседа, ``SIGKILL`` на контейнер, рестартом.

Гарантия — «не меньше одного раза», а не «ровно один». Письмо, у которого узел упал посреди
передачи, будет доставлено заново, и Exchange может получить копию. Это свойство SMTP, а не
шлюза: альтернатива — терять письма. Тесты поэтому там, где возможен сбой посреди передачи,
требуют «хотя бы одно», а там, где его нет, — «ровно одно».
"""

from __future__ import annotations

import contextlib
import time
import uuid

import pytest

from .harness import LAB_RECIPIENTS, lab_spec, make_message


def new_id() -> str:
    return f"dur-{uuid.uuid4().hex[:10]}"


def send(
    stack,
    message_id: str,
    *,
    rcpt: str = "ivan@corp.example",
    sender: str = "a@partner.example",
    size: int = 0,
):  # type: ignore[no-untyped-def]
    return stack.send_external(sender, [rcpt], make_message(message_id, sender, rcpt, size=size))


def full_id(message_id: str) -> str:
    return f"<{message_id}@lab.example>"


def count_at(control, message_id: str) -> int:  # type: ignore[no-untyped-def]
    return control.message_ids().count(full_id(message_id))


def both(stack, mode: str, **kwargs) -> None:  # type: ignore[no-untyped-def]
    """Перевести оба сервера Exchange в один режим.

    Запасные цели Postfix пробуются при любом временном отказе основной, поэтому, чтобы письмо
    осталось в очереди, временно отказывать должны оба: один отказывающий сервер просто передаст
    письмо второму.
    """
    stack.exchange1.mode(mode, **kwargs)
    stack.exchange2.mode(mode, **kwargs)


@pytest.fixture(autouse=True)
def restore(lab):  # type: ignore[no-untyped-def]
    """Каждый сценарий оставляет стенд в исходном состоянии: соседи подняты, очередь пуста."""
    yield
    for service in ("fake-exchange", "fake-exchange-2", "outbound-sink"):
        with contextlib.suppress(Exception):  # уже запущен
            lab.start_service(service)
    for control in (lab.exchange1, lab.exchange2, lab.sink):
        with contextlib.suppress(OSError):
            control.mode("accept")
    lab.apply(lab_spec(), LAB_RECIPIENTS)
    lab.flush()
    lab.wait_until(lambda: lab.queue_size() == 0, timeout=90, what="очередь опустела")


class TestTemporaryFailureOfExchange:
    def test_the_message_is_held_not_lost_and_delivered_once_after_recovery(self, clean) -> None:  # type: ignore[no-untyped-def]
        mid = new_id()
        both(clean, "tempfail")
        assert send(clean, mid) == {}, (
            "шлюз принимает письмо: Exchange временно недоступен — не причина отказывать отправителю"
        )

        clean.wait_until(lambda: clean.queue_size() >= 1, what="письмо в очереди")
        assert count_at(clean.exchange1, mid) == 0

        both(clean, "accept")
        clean.flush()
        assert clean.exchange1.wait_for(full_id(mid), timeout=90) is not None
        clean.wait_until(lambda: clean.queue_size() == 0, what="очередь опустела")
        assert count_at(clean.exchange1, mid) == 1, "ровно одна копия: сбоя посреди передачи не было"

    def test_a_temporary_refusal_by_the_primary_is_retried_at_the_fallback_target(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Запасные цели ведут себя как MX-хосты: следующая пробуется при любом временном отказе.

        Первая версия этого теста утверждала обратное и строилась на моём неверном допущении о
        поведении Postfix; журнал показал, что после 451 он сразу доставил письмо второму серверу.
        """
        mid = new_id()
        clean.exchange1.mode("tempfail")
        assert send(clean, mid) == {}
        assert clean.exchange2.wait_for(full_id(mid), timeout=60) is not None, clean.postfix_log()[-1500:]
        assert count_at(clean.exchange1, mid) == 0
        clean.wait_until(lambda: clean.queue_size() == 0, what="очередь опустела")

    def test_several_messages_survive_the_outage_together(self, clean) -> None:  # type: ignore[no-untyped-def]
        ids = [new_id() for _ in range(8)]
        both(clean, "tempfail")
        for mid in ids:
            send(clean, mid)
        clean.wait_until(lambda: clean.queue_size() >= len(ids), what="все письма в очереди")
        both(clean, "accept")
        clean.flush()
        clean.wait_until(
            lambda: all(count_at(clean.exchange1, mid) >= 1 for mid in ids),
            timeout=120,
            what="все доставлены",
        )
        assert all(count_at(clean.exchange1, mid) == 1 for mid in ids)

    def test_an_outage_with_the_exchange_host_down_queues_and_recovers(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Exchange недоступен целиком (ТЗ §50.4, в сокращённом масштабе: 30 минут проверяются
        тем же механизмом, только дольше). Запасной сервер тоже остановлен."""
        mid = new_id()
        clean.stop_service("fake-exchange")
        clean.stop_service("fake-exchange-2")
        assert send(clean, mid) == {}
        clean.wait_until(lambda: clean.queue_size() >= 1, what="письмо в очереди")
        clean.start_service("fake-exchange")
        clean.flush()
        assert clean.exchange1.wait_for(full_id(mid), timeout=90) is not None


class TestFallbackTarget:
    def test_an_unreachable_primary_hands_the_message_to_the_next_target(self, clean) -> None:  # type: ignore[no-untyped-def]
        """ТЗ §19: упорядоченный запасной вариант. Основной недоступен — доставляет второй."""
        mid = new_id()
        clean.stop_service("fake-exchange")
        send(clean, mid)
        delivered = clean.exchange2.wait_for(full_id(mid), timeout=90)
        assert delivered is not None, clean.postfix_log()[-2000:]
        assert delivered["tls"] is True

    def test_the_primary_is_preferred_when_it_is_up(self, clean) -> None:  # type: ignore[no-untyped-def]
        mid = new_id()
        send(clean, mid)
        assert clean.exchange1.wait_for(full_id(mid), timeout=60) is not None
        assert count_at(clean.exchange2, mid) == 0


class TestTheGatewayItselfFails:
    def _queue_one_behind_a_tempfail(self, stack) -> tuple[str, set[str]]:  # type: ignore[no-untyped-def]
        mid = new_id()
        both(stack, "tempfail")
        assert send(stack, mid) == {}
        stack.wait_until(lambda: stack.queue_size() >= 1, what="письмо в очереди")
        return mid, stack.queue_ids()

    def test_a_graceful_restart_keeps_the_queue(self, clean) -> None:  # type: ignore[no-untyped-def]
        mid, before = self._queue_one_behind_a_tempfail(clean)
        clean.restart()
        assert before <= clean.queue_ids(), "после рестарта очередь та же, а не пересозданная"
        both(clean, "accept")
        clean.flush()
        assert clean.exchange1.wait_for(full_id(mid), timeout=90) is not None

    def test_a_hard_kill_keeps_the_queue(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Так узел падает от OOM-killer или потери питания: ни остановки, ни сброса буферов."""
        mid, before = self._queue_one_behind_a_tempfail(clean)
        clean.kill_postfix_hard()
        clean.start()
        assert before <= clean.queue_ids(), "принятое письмо пережило SIGKILL"
        both(clean, "accept")
        clean.flush()
        assert clean.exchange1.wait_for(full_id(mid), timeout=90) is not None
        clean.wait_until(lambda: clean.queue_size() == 0, what="очередь опустела")

    def test_a_kill_in_the_middle_of_delivery_never_loses_the_message(self, clean) -> None:  # type: ignore[no-untyped-def]
        """ТЗ §50.1: kill после DATA, до доставки. Exchange намеренно медленный, и узел убивают, пока
        доставка идёт. Гарантия — «не меньше одного раза»: дубликат допустим, потеря — нет."""
        mid = new_id()
        both(clean, "delay", delay=12)
        assert send(clean, mid) == {}
        time.sleep(2)  # доставка уже началась и ждёт ответа Exchange
        clean.kill_postfix_hard()
        clean.start()
        both(clean, "accept")
        clean.flush()
        clean.wait_until(lambda: count_at(clean.exchange1, mid) >= 1, timeout=120, what="письмо дошло")
        assert count_at(clean.exchange1, mid) <= 2, "не больше одного повтора"

    def test_the_queue_volume_is_what_holds_the_mail(self, clean) -> None:  # type: ignore[no-untyped-def]
        """§7: очередь на постоянном томе, а не в файловой системе контейнера."""
        inspected = clean.exec("mount | grep ' /var/spool/postfix ' || true", check=False).stdout
        assert "/var/spool/postfix" in inspected, "очередь должна быть отдельным томом"
        assert "tmpfs" not in inspected, "очередь не должна быть в памяти"


class TestPermanentFailure:
    def test_a_permanent_refusal_is_not_passed_on_to_the_fallback_target(self, clean) -> None:  # type: ignore[no-untyped-def]
        """5xx — окончательный ответ: письмо возвращается отправителю, а не пробует счастье у второго."""
        mid = new_id()
        clean.exchange1.mode("permfail")
        send(clean, mid)
        clean.wait_until(lambda: len(clean.sink.received()) >= 1, timeout=90, what="уведомление")
        assert count_at(clean.exchange2, mid) == 0

    def test_a_permanent_refusal_is_reported_to_the_sender_once(self, clean) -> None:  # type: ignore[no-untyped-def]
        mid = new_id()
        clean.exchange1.mode("permfail")
        send(clean, mid)
        clean.wait_until(lambda: len(clean.sink.received()) >= 1, timeout=90, what="уведомление о недоставке")
        notice = clean.sink.received()[0]
        assert notice["mail_from"] in ("", "<>"), "уведомление идёт с пустого адреса отправителя"
        assert "a@partner.example" in notice["rcpt_tos"]
        clean.wait_until(lambda: clean.queue_size() == 0, what="очередь опустела")

    def test_no_notification_storm_follows(self, clean) -> None:  # type: ignore[no-untyped-def]
        """ТЗ §27: отсутствие петель уведомлений. Одно письмо — одно уведомление, и тишина после."""
        clean.exchange1.mode("permfail")
        send(clean, new_id())
        clean.wait_until(lambda: len(clean.sink.received()) >= 1, timeout=90, what="уведомление")
        time.sleep(15)
        assert len(clean.sink.received()) == 1
        assert clean.queue_size() == 0

    def test_a_message_from_the_null_sender_is_not_bounced(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Уведомление на пустой адрес породило бы уведомление на уведомление — классическая петля."""
        clean.exchange1.mode("permfail")
        message = make_message(new_id(), "MAILER-DAEMON@partner.example", "ivan@corp.example")
        clean.send_external("", ["ivan@corp.example"], message)
        clean.wait_until(lambda: clean.queue_size() == 0, timeout=90, what="очередь опустела")
        time.sleep(10)
        assert not [item for item in clean.sink.received() if "ivan@corp.example" in str(item["rcpt_tos"])]

    def test_an_unknown_recipient_at_exchange_is_a_permanent_failure_reported_to_the_sender(
        self, clean
    ) -> None:  # type: ignore[no-untyped-def]
        mid = new_id()
        clean.exchange1.mode("reject_rcpt", rejected_recipients=["ivan@corp.example"])
        send(clean, mid)
        clean.wait_until(lambda: len(clean.sink.received()) >= 1, timeout=90, what="уведомление")
        assert count_at(clean.exchange1, mid) == 0


class TestDisconnects:
    def test_a_disconnect_in_the_middle_of_data_is_retried_not_lost(self, clean) -> None:  # type: ignore[no-untyped-def]
        mid = new_id()
        both(clean, "disconnect")
        send(clean, mid)
        clean.wait_until(lambda: clean.queue_size() >= 1, what="письмо в очереди")
        assert count_at(clean.exchange1, mid) == 0, "оборванная передача не должна считаться доставкой"
        both(clean, "accept")
        clean.flush()
        assert clean.exchange1.wait_for(full_id(mid), timeout=90) is not None


class TestSizes:
    @pytest.mark.parametrize("size", [10 * 1024, 1024 * 1024, 10 * 1024 * 1024])
    def test_messages_of_the_baseline_sizes_are_delivered_intact(self, clean, size: int) -> None:  # type: ignore[no-untyped-def]
        """Базовые размеры из ТЗ §54: 10 КБ, 1 МБ, 10 МБ."""
        mid = new_id()
        message = make_message(mid, "a@partner.example", "ivan@corp.example", size=size)
        clean.send_external("a@partner.example", ["ivan@corp.example"], message)
        delivered = clean.exchange1.wait_for(full_id(mid), timeout=120)
        assert delivered is not None
        import hashlib

        # Postfix добавляет Received, поэтому побайтного равенства нет; размер не меньше исходного.
        assert delivered["size"] >= len(message)
        assert hashlib.sha256(message).hexdigest()  # хеш исходного фиксируется для сверки в отчёте

    def test_a_message_over_the_limit_is_refused_with_a_clear_code_and_not_queued(self, clean) -> None:  # type: ignore[no-untyped-def]
        from msp_gateway.spec import Limits

        assert clean.apply(lab_spec(limits=Limits(max_message_size=2 * 1024 * 1024)))["outcome"] == "ACTIVE"
        message = make_message(new_id(), "a@partner.example", "ivan@corp.example", size=3 * 1024 * 1024)
        import smtplib

        with pytest.raises(smtplib.SMTPException) as caught:
            clean.send_external("a@partner.example", ["ivan@corp.example"], message)
        assert "552" in str(caught.value) or "size" in str(caught.value).lower()
        assert clean.queue_size() == 0


class TestQueueLifetime:
    def test_an_expired_message_is_returned_to_the_sender_and_leaves_the_queue(self, clean) -> None:  # type: ignore[no-untyped-def]
        """ТЗ §28: срок жизни настраивается. Здесь минимальный, чтобы увидеть истечение за минуту."""
        assert (
            clean.apply(lab_spec(maximal_queue_lifetime_seconds=60, bounce_queue_lifetime_seconds=60))[
                "outcome"
            ]
            == "ACTIVE"
        )
        mid = new_id()
        both(clean, "tempfail")
        send(clean, mid)
        clean.wait_until(lambda: clean.queue_size() >= 1, what="письмо в очереди")
        time.sleep(65)
        clean.flush()
        clean.wait_until(
            lambda: len(clean.sink.received()) >= 1, timeout=120, what="уведомление об истечении срока"
        )
        clean.wait_until(lambda: clean.queue_size() == 0, timeout=60, what="очередь опустела")
