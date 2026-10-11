"""Шлюз не должен быть открытым релеем (ТЗ 1.1 §12, §53).

Обязательная проверка приёмки. Каждая строка таблицы §53 — отдельный тест, и к ним добавлены
обходы, которых в таблице нет: подмена HELO и адреса отправителя, процентный хак, маршрут в адресе.
Проверяется настоящий Postfix: открытый релей — свойство поведения MTA, и на модели его не увидеть.

Источник определяется адресом, с которого пришло соединение:

* ``send_external`` идёт через опубликованный порт, и шлюз видит адрес моста сети Docker;
* ``send_trusted`` запускается в контейнере из доверенной подсети (роль Exchange);
* ``send_trusted(ip=UNTRUSTED_CLIENT_IP)`` — из той же сети, но вне доверенной подсети.
"""

from __future__ import annotations

import smtplib
import uuid

import pytest
from msp_gateway import probes

from .harness import UNTRUSTED_CLIENT_IP, make_message


def unique() -> str:
    return f"or-{uuid.uuid4().hex[:10]}"


def rcpt_reply(
    stack, rcpt: str, *, mail_from: str = "attacker@external-sender.invalid", helo: str = "probe.example"
) -> probes.ProbeResult:  # type: ignore[no-untyped-def]
    return probes.smtp_probe(
        "127.0.0.1", stack.ports["GW_PORT_IN"], mail_from=mail_from, rcpt_to=rcpt, helo=helo, timeout=15
    )


class TestMatrixFromTheSpecification:
    """Таблица §53 построчно."""

    def test_internet_to_an_owned_domain_with_a_valid_recipient_is_accepted(self, clean) -> None:  # type: ignore[no-untyped-def]
        mid = unique()
        assert (
            clean.send_external(
                "a@partner.example",
                ["ivan@corp.example"],
                make_message(mid, "a@partner.example", "ivan@corp.example"),
            )
            == {}
        )
        assert clean.exchange1.wait_for(f"<{mid}@lab.example>", timeout=60) is not None

    def test_internet_to_an_external_domain_is_rejected(self, clean) -> None:  # type: ignore[no-untyped-def]
        result = rcpt_reply(clean, "victim@another-external.example")
        assert result.state is probes.ProbeState.REJECTED, result
        assert result.code == 554
        assert clean.queue_size() == 0

    def test_a_trusted_exchange_may_relay_to_an_external_domain_on_the_internal_listener(self, clean) -> None:  # type: ignore[no-untyped-def]
        mid = unique()
        result = clean.send_trusted(
            "boss@corp.example",
            ["partner@external.example"],
            make_message(mid, "boss@corp.example", "partner@external.example"),
        )
        assert result["ok"] is True, result
        assert clean.sink.wait_for(f"<{mid}@lab.example>", timeout=60) is not None, (
            "письмо должно дойти до приёмника исходящей почты"
        )

    def test_an_untrusted_internal_client_is_rejected_for_an_external_domain(self, clean) -> None:  # type: ignore[no-untyped-def]
        result = clean.send_trusted(
            "attacker@corp.example",
            ["victim@external.example"],
            make_message(unique(), "attacker@corp.example", "victim@external.example"),
            ip=UNTRUSTED_CLIENT_IP,
        )
        assert result["ok"] is False, result
        assert clean.queue_size() == 0

    def test_a_trusted_exchange_sending_to_an_owned_domain_is_refused_as_a_loop(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Явная политика (§53): единственная причина, по которой Exchange отдаёт шлюзу наш же домен,
        — неверная маршрутизация, и возврат такого письма замкнул бы петлю."""
        result = clean.send_trusted(
            "a@corp.example",
            ["ivan@corp.example"],
            make_message(unique(), "a@corp.example", "ivan@corp.example"),
        )
        assert result["ok"] is False, result
        flat = str(result)
        assert "5.4.6" in flat or "loop" in flat.lower(), result

    def test_internet_to_an_unknown_owned_recipient_is_rejected_when_the_directory_is_fresh(
        self, clean
    ) -> None:  # type: ignore[no-untyped-def]
        result = rcpt_reply(clean, "nobody@corp.example")
        assert result.state is probes.ProbeState.REJECTED, result
        assert result.code == 550


class TestWaysAroundTheMatrix:
    """Обходы, которых в таблице нет, но которыми открытый релей находят на практике."""

    @pytest.mark.parametrize(
        "claimed_helo", ["exchange.corp.example", "gw.lab.example", "localhost", "mail.corp.example"]
    )
    def test_a_claimed_helo_grants_nothing(self, clean, claimed_helo: str) -> None:  # type: ignore[no-untyped-def]
        """ТЗ §12: запрещён implicit trust по HELO. HELO пишет клиент, а значит, любой клиент."""
        result = rcpt_reply(clean, "victim@another-external.example", helo=claimed_helo)
        assert result.state is probes.ProbeState.REJECTED, result

    @pytest.mark.parametrize(
        "claimed_sender",
        ["ceo@corp.example", "postmaster@corp.example", "ivan@corp.example", "admin@gw.lab.example"],
    )
    def test_a_sender_in_an_owned_domain_grants_nothing(self, clean, claimed_sender: str) -> None:  # type: ignore[no-untyped-def]
        """Адрес отправителя — тоже заявление клиента."""
        result = rcpt_reply(clean, "victim@another-external.example", mail_from=claimed_sender)
        assert result.state is probes.ProbeState.REJECTED, result

    @pytest.mark.parametrize(
        "recipient",
        [
            "victim%another-external.example@corp.example",
            "victim%another-external.example@corp.example.",
            "another-external.example!victim@corp.example",
            "@another-external.example:victim@corp.example",
            "victim@another-external.example@corp.example",
        ],
    )
    def test_routing_tricks_inside_the_address_do_not_relay(self, clean, recipient: str) -> None:  # type: ignore[no-untyped-def]
        """Процентный хак: проверка видит наш домен, а доставка идёт на чужой."""
        result = rcpt_reply(clean, recipient)
        assert result.state is not probes.ProbeState.ACCEPTED, result
        assert clean.queue_size() == 0

    @pytest.mark.parametrize(
        "recipient",
        [
            "victim@Another-External.EXAMPLE",
            "victim@another-external.example.",
            "victim@[203.0.113.5]",
            "victim@203.0.113.5",
        ],
    )
    def test_case_trailing_dot_and_address_literals_do_not_relay(self, clean, recipient: str) -> None:  # type: ignore[no-untyped-def]
        result = rcpt_reply(clean, recipient)
        assert result.state is not probes.ProbeState.ACCEPTED, result

    def test_mixed_recipients_reject_the_foreign_one_without_dropping_the_owned_one(self, clean) -> None:  # type: ignore[no-untyped-def]
        mid = unique()
        # sendmail бросает исключение, только если отказали ВСЕМ; при частичном отказе
        # возвращает словарь отказавших — а именно частичный случай здесь и проверяется.
        refused = clean.send_external(
            "a@partner.example",
            ["ivan@corp.example", "victim@another-external.example"],
            make_message(mid, "a@partner.example", "ivan@corp.example"),
        )
        assert set(refused) == {"victim@another-external.example"}
        assert refused["victim@another-external.example"][0] == 554
        assert clean.exchange1.wait_for(f"<{mid}@lab.example>", timeout=60) is not None, (
            "свой получатель должен получить письмо"
        )

    def test_the_internal_listener_does_not_welcome_the_internet(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Интернет-клиенты не должны иметь доступа к исходящему релею (§11). Сетевая изоляция — забота
        развёртывания, но даже без неё MTA не пропускает чужих."""
        result = probes.smtp_probe(
            "127.0.0.1",
            clean.ports["GW_PORT_INTERNAL"],
            mail_from="a@corp.example",
            rcpt_to="victim@another-external.example",
            starttls=True,
            timeout=15,
        )
        assert result.state is not probes.ProbeState.ACCEPTED, result


class TestTheSyntheticProbesAgree:
    """Те же пробы, что запускает активация конфигурации и постоянный самоконтроль (§39, §47)."""

    def test_the_public_listener_passes_the_open_relay_probe(self, clean) -> None:  # type: ignore[no-untyped-def]
        assert probes.open_relay_probe(
            "127.0.0.1", clean.ports["GW_PORT_IN"], timeout=15
        ).is_safe_for_relay_test

    def test_the_internal_listener_passes_the_open_relay_probe_from_an_untrusted_address(self, clean) -> None:  # type: ignore[no-untyped-def]
        assert probes.open_relay_probe(
            "127.0.0.1", clean.ports["GW_PORT_INTERNAL"], timeout=15
        ).is_safe_for_relay_test

    def test_the_probe_leaves_no_message_in_the_queue(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Проба доходит до RCPT и закрывается: проверки безопасны на узле с живым трафиком."""
        probes.open_relay_probe("127.0.0.1", clean.ports["GW_PORT_IN"], timeout=15)
        assert clean.queue_size() == 0

    def test_a_listener_that_does_not_answer_is_not_reported_safe(self, clean) -> None:  # type: ignore[no-untyped-def]
        result = probes.open_relay_probe("127.0.0.1", 1, timeout=1.0)
        assert not result.is_safe_for_relay_test


class TestProtocolEdges:
    def test_the_null_sender_is_accepted_for_a_valid_recipient(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Уведомления о недоставке приходят с пустым отправителем; отвергать его — терять их."""
        result = rcpt_reply(clean, "ivan@corp.example", mail_from="")
        assert result.state is probes.ProbeState.ACCEPTED, result

    def test_the_null_sender_does_not_unlock_relaying(self, clean) -> None:  # type: ignore[no-untyped-def]
        result = rcpt_reply(clean, "victim@another-external.example", mail_from="")
        assert result.state is probes.ProbeState.REJECTED, result

    def test_the_internal_listener_requires_starttls(self, clean) -> None:  # type: ignore[no-untyped-def]
        script = """
        import smtplib, json
        c = smtplib.SMTP("gateway-postfix", 2525, timeout=20)
        c.ehlo("exchange.lab.example")
        code, msg = c.docmd("MAIL FROM:<boss@corp.example>")
        print(json.dumps({"code": code, "msg": msg.decode()}))
        """
        out = clean.run_client(script)
        assert '"code": 530' in out.stdout or '"code": 5' in out.stdout, out.stdout + out.stderr

    def test_helo_is_required(self, clean) -> None:  # type: ignore[no-untyped-def]
        client = smtplib.SMTP("127.0.0.1", clean.ports["GW_PORT_IN"], timeout=15)
        try:
            code, _ = client.docmd("MAIL FROM:<a@partner.example>")
            assert code == 503
        finally:
            client.close()
