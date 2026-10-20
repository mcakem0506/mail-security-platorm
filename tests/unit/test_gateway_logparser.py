"""Разбор журнала Postfix (ТЗ 1.1 §31, §33, §62).

Образцы строк — настоящие, из журнала стенда на Postfix 3.10, а не придуманные: разбор,
проверенный на выдуманных строках, проверяет выдумку. Вторая половина тестов — враждебный ввод:
HELO, адреса и тексты ответов задаёт клиент, это канал для внедрения в журнал (§62).
"""

# ruff: noqa: E501 - строки журнала приведены целиком, как их пишет Postfix

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from msp_gateway.logparser import Direction, EventType, LogParser

# Настоящие строки журнала стенда.
CONNECT = "Oct 11 12:28:51 gw postfix-in/smtpd[354]: connect from unknown[10.77.0.1]"
CLIENT = "Oct 11 12:28:51 gw postfix-in/smtpd[354]: 83B3418819D: client=unknown[10.77.0.1]"
MESSAGE_ID = "Oct 11 12:28:51 gw postfix/cleanup[358]: 83B3418819D: message-id=<dur-ac392455ed@lab.example>"
QUEUED = "Oct 11 12:28:51 gw postfix/qmgr[338]: 83B3418819D: from=<a@partner.example>, size=440, nrcpt=2 (queue active)"
DISCONNECT = "Oct 11 12:28:51 gw postfix-in/smtpd[354]: disconnect from unknown[10.77.0.1] ehlo=1 mail=1 rcpt=1 data=1 quit=1 commands=5"
TLS = (
    "Oct 11 12:28:51 gw postfix/smtp[360]: Verified TLS connection established to fake-exchange[10.77.0.20]:2526: "
    "TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits) key-exchange x25519 server-signature RSA-PSS "
    "(2048 bits) server-digest SHA256"
)
SAID = (
    "Oct 11 12:28:51 gw postfix/smtp[360]: 83B3418819D: host fake-exchange[10.77.0.20] said: "
    "451 4.3.0 Temporary failure, try again later (in reply to end of DATA command)"
)
SENT = (
    "Oct 11 12:28:51 gw postfix/smtp[360]: 83B3418819D: to=<ivan@corp.example>, relay=fake-exchange-2[10.77.0.21]:2526, "
    "delay=0.04, delays=0.02/0.01/0.01/0, dsn=2.0.0, status=sent (250 2.0.0 Message accepted for delivery)"
)
JOURNAL = (
    "Oct 11 12:28:51 gw postfix/pipe[359]: 83B3418819D: to=<journal-in@journal.msp.invalid>, relay=msp-journal, "
    "delay=0.05, delays=0.02/0/0/0.03, dsn=2.0.0, status=sent (delivered via msp-journal service)"
)
DEFERRED = (
    "Oct 11 12:30:00 gw postfix/smtp[361]: 83B3418819D: to=<ivan@corp.example>, relay=none, delay=20, "
    "delays=0/0.01/20/0, dsn=4.4.1, status=deferred (connect to fake-exchange[10.77.0.20]:2526: Connection refused)"
)
BOUNCED = (
    "Oct 11 12:30:00 gw postfix/smtp[361]: 83B3418819D: to=<ivan@corp.example>, relay=fake-exchange[10.77.0.20]:2526, "
    "delay=0.2, delays=0.1/0/0.05/0.05, dsn=5.7.1, status=bounced (host fake-exchange[10.77.0.20] said: 554 5.7.1 Message rejected "
    "(in reply to end of DATA command))"
)
REMOVED = "Oct 11 12:28:51 gw postfix/qmgr[338]: 83B3418819D: removed"
REJECT_RCPT = (
    "Oct 11 12:30:01 gw postfix-in/smtpd[400]: NOQUEUE: reject: RCPT from unknown[10.77.0.1]: 554 5.7.1 "
    "<victim@another-external.example>: Relay access denied; from=<attacker@external-sender.invalid> "
    "to=<victim@another-external.example> proto=ESMTP helo=<probe.example>"
)
REJECT_CONNECT = (
    "Oct 11 12:30:02 gw postfix-out/smtpd[401]: NOQUEUE: reject: CONNECT from unknown[127.0.0.1]: 554 5.7.1 "
    "<unknown[127.0.0.1]>: Client host rejected: Access denied; proto=SMTP"
)
BOUNCE_NOTICE = (
    "Oct 11 12:30:03 gw postfix/bounce[402]: 83B3418819D: sender non-delivery notification: 9A8B7C6D5E4"
)
NOISE = [
    "Oct 11 12:29:05 gw postfix/postfix-script[517]: the Postfix mail system is running: PID: 1",
    "Oct 11 12:10:04 gw postfix/master[1]: reload -- version 3.10.13, configuration /var/lib/msp/config/active",
    "Oct 11 12:10:04 gw postfix/anvil[357]: statistics: max connection rate 1/60s for (25:10.77.0.1) at Oct 11 12:10:02",
    "Oct 11 12:28:51 gw postfix-in/smtpd[354]: NOQUEUE: lost connection after CONNECT from unknown[10.77.0.1]",
    "Oct 11 12:28:47 gw postfix/master[1]: daemon started -- version 3.10.13, configuration /var/lib/msp/config/active",
]


def parse(*lines: str) -> list:
    return LogParser(year=2026).parse_lines(lines)


class TestRealLines:
    def test_a_connection_is_attributed_to_the_listener(self) -> None:
        (event,) = parse(CONNECT)
        assert event.event_type is EventType.CONNECT
        assert event.direction is Direction.INBOUND
        assert event.client_address == "10.77.0.1"

    def test_the_internal_listener_is_outbound(self) -> None:
        (event,) = parse(REJECT_CONNECT)
        assert event.direction is Direction.OUTBOUND

    def test_direction_follows_the_listener_not_the_sender_domain(self) -> None:
        """ТЗ §30. Отправитель в нашем домене на публичном порту — всё равно входящее."""
        events = parse(CLIENT, QUEUED.replace("a@partner.example", "ceo@corp.example"))
        assert [e.direction for e in events] == [Direction.INBOUND, Direction.INBOUND]

    def test_the_queue_id_ties_the_stages_of_one_message_together(self) -> None:
        events = parse(CLIENT, MESSAGE_ID, QUEUED, SENT, REMOVED)
        assert {e.queue_id for e in events} == {"83B3418819D"}

    def test_delivery_inherits_the_direction_learned_from_the_listener(self) -> None:
        """Строка доставки приходит от smtp, а слушатель известен только из строки smtpd."""
        events = parse(CLIENT, MESSAGE_ID, QUEUED, SENT)
        assert events[-1].event_type is EventType.DELIVERY
        assert events[-1].direction is Direction.INBOUND

    def test_a_queued_event_carries_sender_size_and_recipient_count(self) -> None:
        events = parse(CLIENT, MESSAGE_ID, QUEUED)
        queued = events[-1]
        assert queued.envelope_from == "a@partner.example"
        assert queued.recipients_count == 2
        assert queued.extras["size"] == "440"
        assert queued.message_id == "dur-ac392455ed@lab.example"

    def test_a_delivery_carries_relay_delay_dsn_and_code(self) -> None:
        (event,) = parse(SENT)
        assert event.event_type is EventType.DELIVERY
        assert event.status == "sent"
        assert event.relay == "fake-exchange-2[10.77.0.21]:2526"
        assert event.delay == pytest.approx(0.04)
        assert event.dsn == "2.0.0"
        assert event.smtp_code == 250

    def test_a_deferral_is_a_deferral(self) -> None:
        (event,) = parse(DEFERRED)
        assert event.status == "deferred"
        assert event.dsn == "4.4.1"

    def test_a_bounce_reports_the_remote_code(self) -> None:
        (event,) = parse(BOUNCED)
        assert event.status == "bounced"
        assert event.smtp_code == 554

    def test_a_refusal_before_the_fallback_is_visible(self) -> None:
        """В настоящем журнале отказ основного сервера нигде больше не отражается: итоговая строка
        доставки относится уже ко второму. Без этого события основной выглядел бы здоровым."""
        (event,) = parse(SAID)
        assert event.event_type is EventType.REMOTE_REPLY
        assert event.smtp_code == 451
        assert event.status == "deferred"
        assert event.relay.startswith("fake-exchange[")
        assert event.extras["stage"] == "end of DATA command"

    def test_a_permanent_remote_reply_is_marked_refused(self) -> None:
        said = SAID.replace("451 4.3.0 Temporary", "554 5.7.1 Permanent")
        (event,) = parse(said)
        assert event.status == "refused"

    def test_the_shadow_copy_is_counted_apart_from_delivery(self) -> None:
        """Копия для анализа — не доставка письма: смешать их значило бы завысить доставленное вдвое."""
        (event,) = parse(JOURNAL)
        assert event.event_type is EventType.SHADOW

    def test_a_rejection_carries_the_code_and_the_stage(self) -> None:
        (event,) = parse(REJECT_RCPT)
        assert event.event_type is EventType.REJECTED
        assert event.smtp_code == 554
        assert event.dsn == "5.7.1"
        assert event.extras["stage"] == "RCPT"
        assert event.client_address == "10.77.0.1"

    def test_tls_events_distinguish_verified_from_unverified(self) -> None:
        (event,) = parse(TLS)
        assert event.event_type is EventType.TLS
        assert event.status == "verified"
        assert "TLSv1.3" in event.detail

    def test_an_untrusted_tls_connection_is_not_reported_as_verified(self) -> None:
        (event,) = parse(TLS.replace("Verified TLS", "Untrusted TLS"))
        assert event.status == "untrusted"

    def test_removal_closes_the_message_and_frees_the_memory(self) -> None:
        parser = LogParser(year=2026)
        parser.parse_lines([CLIENT, MESSAGE_ID, QUEUED])
        assert "83B3418819D" in parser._direction
        (removed,) = list(parser.parse_lines([REMOVED]))
        assert removed.event_type is EventType.REMOVED
        assert removed.envelope_from == "a@partner.example"
        assert "83B3418819D" not in parser._direction

    def test_a_bounce_notice_links_to_the_notice_queue_id(self) -> None:
        (event,) = parse(BOUNCE_NOTICE)
        assert event.event_type is EventType.BOUNCE_NOTICE
        assert event.extras["notice_queue_id"] == "9A8B7C6D5E4"


class TestNoiseIsCountedNotConfused:
    @pytest.mark.parametrize("line", NOISE)
    def test_known_periodic_noise_is_ignored_not_unparsed(self, line: str) -> None:
        parser = LogParser(year=2026)
        assert parser.parse_line(line) is None
        assert parser.stats.ignored == 1
        assert parser.stats.unparsed == 0

    @pytest.mark.parametrize(
        "line",
        [
            "",
            "garbage",
            "Oct 11 12:00:00",
            "Foo 11 12:00:00 gw postfix/smtp[1]: x",
            "Oct 99 12:00:00 gw postfix/smtp[1]: x",
        ],
    )
    def test_an_unknown_line_is_counted_as_unparsed_and_does_not_crash(self, line: str) -> None:
        parser = LogParser(year=2026)
        assert parser.parse_line(line) is None
        assert parser.stats.unparsed == 1

    def test_an_unparsed_line_does_not_stop_the_stream(self) -> None:
        parser = LogParser(year=2026)
        events = parser.parse_lines([CONNECT, "полная абракадабра", SENT])
        assert len(events) == 2
        assert parser.stats.unparsed == 1

    def test_a_warning_is_an_event_not_noise(self) -> None:
        line = "Oct 11 12:00:00 gw postfix/qmgr[1]: warning: queue file write error: No space left on device"
        (event,) = parse(line)
        assert event.event_type is EventType.WARNING


class TestHostileLogContent:
    """HELO, адреса и тексты ответов задаёт клиент: это канал внедрения в журнал (ТЗ §62)."""

    def test_control_characters_are_replaced_in_every_extracted_field(self) -> None:
        line = SAID.replace("Temporary failure", "Temp\x1b[31mora\x00ry\x07")
        (event,) = parse(line)
        assert not any(ord(c) < 32 for c in event.detail)

    def test_an_oversized_field_is_truncated(self) -> None:
        line = SENT.replace("Message accepted for delivery", "x" * 100_000)
        (event,) = parse(line)
        assert len(event.detail) <= 200

    def test_a_sender_address_stuffed_with_markup_stays_data(self) -> None:
        sender = "<script>alert(1)</script>%s%n$(id)`id`"
        (event,) = parse(QUEUED.replace("a@partner.example", sender))
        assert event.envelope_from  # сохранено как данные...
        assert "\n" not in event.envelope_from  # ...и не более того

    def test_format_string_directives_are_not_interpreted(self) -> None:
        (event,) = parse(SENT.replace("Message accepted", "%s%s%s%n%n {0} {{x}}"))
        assert "%s" in event.detail

    def test_a_forged_second_log_line_inside_a_value_is_not_a_second_event(self) -> None:
        """Postfix не допускает перевода строки в значении, но разбор не должен на это полагаться."""
        forged = SENT.replace("Message accepted", "x\\nOct 11 12:00:00 gw postfix/smtp[1]: AAAA: removed")
        events = parse(forged)
        assert len(events) == 1

    def test_the_tracked_state_is_bounded(self) -> None:
        """Без строк «removed» память росла бы без предела: узел с огромной очередью не должен
        съедать память разбора."""
        parser = LogParser(year=2026)
        parser.MAX_TRACKED = 1000
        for index in range(5000):
            parser.parse_line(
                f"Oct 11 12:00:00 gw postfix-in/smtpd[1]: {index:011X}: client=unknown[10.0.0.1]"
            )
        assert len(parser._direction) <= 1100


class TestNeverCrashes:
    @given(st.text(max_size=600))
    @settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    def test_any_text_is_survivable(self, text: str) -> None:
        parser = LogParser(year=2026)
        event = parser.parse_line(text)
        assert event is None or event.event_type in EventType

    @given(st.binary(max_size=400))
    @settings(max_examples=300, deadline=None)
    def test_any_bytes_decoded_loosely_are_survivable(self, raw: bytes) -> None:
        LogParser(year=2026).parse_line(raw.decode("utf-8", errors="replace"))

    @given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=200))
    @settings(max_examples=300, deadline=None)
    def test_a_known_prefix_with_arbitrary_tail_is_survivable(self, tail: str) -> None:
        parser = LogParser(year=2026)
        parser.parse_line("Oct 11 12:00:00 gw postfix/smtp[1]: 83B3418819D: " + tail)

    def test_the_accounting_adds_up(self) -> None:
        parser = LogParser(year=2026)
        lines = [CONNECT, CLIENT, MESSAGE_ID, QUEUED, SENT, JOURNAL, REMOVED, *NOISE, "мусор", ""]
        parser.parse_lines(lines)
        stats = parser.stats
        assert stats.parsed + stats.ignored + stats.unparsed == len(lines)
