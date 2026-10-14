"""Метрики и агент на настоящем Postfix (ТЗ 1.1 §38, §45, §68.12).

Юнит-тесты проверяют разбор строк, но не то, что агент в контейнере вообще видит журнал,
имеет право читать его и отдаёт метрики наружу. Это проверяется здесь.
"""

from __future__ import annotations

import re
import smtplib
import urllib.request
import uuid

import pytest

from .harness import make_message

REQUIRED = [
    "msp_gateway_smtp_connections_total",
    "msp_gateway_messages_received_total",
    "msp_gateway_messages_rejected_total",
    "msp_gateway_messages_delivered_total",
    "msp_gateway_queue_messages",
    "msp_gateway_queue_bytes",
    "msp_gateway_oldest_message_seconds",
    "msp_gateway_delivery_delay_seconds",
    "msp_gateway_disk_free_bytes",
    "msp_gateway_pressure_state",
    "msp_gateway_config_info",
    "msp_gateway_node_up",
]


def scrape(stack) -> str:  # type: ignore[no-untyped-def]
    url = f"http://127.0.0.1:{stack.ports['GW_PORT_METRICS']}/metrics"
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.read().decode("utf-8")


def value(text: str, series: str) -> float:
    match = re.search(rf"^{re.escape(series)} (\S+)$", text, re.MULTILINE)
    return float(match.group(1)) if match else 0.0


def new_id() -> str:
    return f"met-{uuid.uuid4().hex[:10]}"


def send(stack, mid: str, rcpt: str = "ivan@corp.example"):  # type: ignore[no-untyped-def]
    sender = "a@partner.example"
    return stack.send_external(sender, [rcpt], make_message(mid, sender, rcpt))


class TestAgentInTheContainer:
    def test_metrics_are_served_and_complete(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.wait_until(lambda: "msp_gateway_node_up 1" in scrape(clean), what="агент отдаёт метрики")
        text = scrape(clean)
        for name in REQUIRED:
            assert f"# TYPE {name} " in text, name

    def test_agent_does_not_run_as_root(self, clean) -> None:  # type: ignore[no-untyped-def]
        out = clean.exec("ps -eo user,args | grep '[m]sp_gateway.node agent' | grep -v grep").stdout
        assert out.strip(), "агент не запущен"
        assert out.split()[0] == "mspagent", out

    def test_one_message_is_counted_exactly_once(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Счётчик, который считает дважды, хуже отсутствующего: по нему считают нагрузку и потери."""
        series_in = 'msp_gateway_messages_received_total{direction="INBOUND"}'
        series_ok = 'msp_gateway_messages_delivered_total{direction="INBOUND"}'
        before = scrape(clean)
        assert send(clean, new_id()) == {}
        clean.wait_until(
            lambda: value(scrape(clean), series_ok) > value(before, series_ok),
            timeout=60,
            what="доставка учтена",
        )
        after = scrape(clean)
        assert value(after, series_in) - value(before, series_in) == 1
        assert value(after, series_ok) - value(before, series_ok) == 1

    def test_a_refused_recipient_is_counted_as_a_rejection(self, clean) -> None:  # type: ignore[no-untyped-def]
        before = scrape(clean)
        total_before = sum(
            float(m)
            for m in re.findall(r"^msp_gateway_messages_rejected_total\{[^}]*\} (\S+)$", before, re.M)
        )
        with pytest.raises(smtplib.SMTPRecipientsRefused):
            send(clean, new_id(), rcpt="nobody-here@corp.example")

        def total() -> float:
            return sum(
                float(m)
                for m in re.findall(
                    r"^msp_gateway_messages_rejected_total\{[^}]*\} (\S+)$", scrape(clean), re.M
                )
            )

        clean.wait_until(lambda: total() > total_before, timeout=60, what="отказ учтён")

    def test_queued_mail_shows_up_as_queue_size_and_age(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.exchange1.mode("tempfail")
        clean.exchange2.mode("tempfail")
        try:
            assert send(clean, new_id()) == {}
            clean.wait_until(
                lambda: (
                    value(scrape(clean), 'msp_gateway_queue_messages{queue="deferred"}') >= 1
                    or value(scrape(clean), 'msp_gateway_queue_messages{queue="active"}') >= 1
                ),
                timeout=60,
                what="очередь видна в метриках",
            )
            clean.wait_until(
                lambda: value(scrape(clean), "msp_gateway_oldest_message_seconds") > 0,
                timeout=60,
                what="возраст письма отличен от нуля",
            )
            assert value(scrape(clean), "msp_gateway_queue_bytes") > 0
        finally:
            clean.exchange1.mode("accept")
            clean.exchange2.mode("accept")
            clean.flush()
            clean.wait_until(lambda: clean.queue_size() == 0, timeout=90, what="очередь опустела")

    def test_the_log_is_understood_without_leftovers(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Доля нераспознанных строк журнала — прямой признак того, что разбор отстал от Postfix."""
        send(clean, new_id())
        clean.wait_until(lambda: "msp_gateway_node_up 1" in scrape(clean), what="агент жив")
        # Нераспознанное попадает в heartbeat, но не в метрики; смотрим журнал агента напрямую
        out = clean.exec(
            "python3 -c \"import sys; sys.path.insert(0,'/opt/msp'); "
            "from msp_gateway.logparser import LogParser; p=LogParser(year=2026); "
            "[p.parse_line(l) for l in open('/var/log/msp/postfix.log')]; "
            'print(p.stats.parsed, p.stats.unparsed)"'
        ).stdout.split()
        parsed, unparsed = int(out[0]), int(out[1])
        assert parsed > 0
        assert unparsed <= max(2, parsed // 20), f"разбор не понимает {unparsed} из {parsed + unparsed} строк"

    def test_mail_flows_when_the_agent_is_dead(self, clean) -> None:  # type: ignore[no-untyped-def]
        """Наблюдатель не стоит на пути письма: без агента почта идёт, как шла."""
        clean.exec("pkill -f '[m]sp_gateway.node agent'", check=False)
        clean.wait_until(
            lambda: clean.exec("pgrep -f '[m]sp_gateway.node agent'", check=False).returncode != 0,
            what="агент остановлен",
        )
        mid = new_id()
        assert send(clean, mid) == {}
        assert clean.exchange1.wait_for(f"<{mid}@lab.example>", timeout=60) is not None
