"""Метрики узла (ТЗ 1.1 §45): состав, формат, ограниченная кардинальность."""

# ruff: noqa: E501 - строки журнала приведены целиком, как их пишет Postfix

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta

import pytest
from msp_gateway.logparser import Direction, EventType, LogEvent
from msp_gateway.metrics import Metrics, age_seconds, escape_label, parse_postqueue_json
from msp_gateway.state import PressureState

NOW = datetime(2026, 10, 11, 12, 0, 0, tzinfo=UTC)

REQUIRED = [
    "msp_gateway_smtp_connections_total",
    "msp_gateway_messages_received_total",
    "msp_gateway_messages_rejected_total",
    "msp_gateway_messages_deferred_total",
    "msp_gateway_messages_delivered_total",
    "msp_gateway_queue_messages",
    "msp_gateway_queue_bytes",
    "msp_gateway_oldest_message_seconds",
    "msp_gateway_delivery_delay_seconds",
    "msp_gateway_delivery_failures_total",
    "msp_gateway_disk_free_bytes",
    "msp_gateway_pressure_state",
    "msp_gateway_shadow_delivery_total",
    "msp_gateway_shadow_failures_total",
    "msp_gateway_recipient_map_age_seconds",
    "msp_gateway_config_info",
    "msp_gateway_node_up",
]

SAMPLE = re.compile(
    r'^([a-z_:][a-z0-9_:]*)(\{(?:[a-z_]+="(?:[^"\\\n]|\\.)*"(?:,|(?=\})))*\})? (-?[0-9.e+]+|\+Inf)$'
)


def ev(kind: EventType, **kw) -> LogEvent:  # type: ignore[no-untyped-def]
    kw.setdefault("direction", Direction.INBOUND)
    return LogEvent(kind, NOW, "postfix/test", **kw)


def full_metrics() -> Metrics:
    m = Metrics()
    m.disk_free_bytes = 10**10
    m.recipient_map_age = 120.0
    m.config_version = "v1"
    m.config_checksum = "abc"
    m.node_role = "LAB"
    return m


def samples(text: str) -> dict[str, float]:
    result: dict[str, float] = {}
    for line in text.splitlines():
        if line and not line.startswith("#"):
            key, value = line.rsplit(" ", 1)
            result[key] = float("inf") if value == "+Inf" else float(value)
    return result


class TestExposition:
    def test_every_required_metric_is_present(self) -> None:
        text = full_metrics().render()
        for name in REQUIRED:
            assert f"# TYPE {name} " in text, name

    def test_every_line_is_valid_exposition_format(self) -> None:
        m = full_metrics()
        m.observe(ev(EventType.CONNECT))
        m.observe(ev(EventType.REJECTED, smtp_code=554))
        m.observe(ev(EventType.DELIVERY, status="sent", delay=1.5))
        text = m.render()
        assert text.endswith("\n")
        for line in text.splitlines():
            assert line.startswith("#") or SAMPLE.match(line), line

    def test_help_and_type_come_before_samples(self) -> None:
        lines = full_metrics().render().splitlines()
        seen: set[str] = set()
        for line in lines:
            if line.startswith("# TYPE "):
                seen.add(line.split()[2])
            elif not line.startswith("#"):
                name = re.split(r"[{ ]", line)[0]
                base = re.sub(r"_(bucket|sum|count)$", "", name)
                assert name in seen or base in seen, line

    def test_unknown_values_do_not_appear_as_gaps(self) -> None:
        text = chr(10).join(x for x in Metrics().render().splitlines() if not x.startswith("#"))
        # Диск и справочник не измерены — метрики нет, а не «0» (ноль выглядел бы как беда или как норма)
        assert "msp_gateway_disk_free_bytes " not in text
        assert "msp_gateway_recipient_map_age_seconds " not in text

    def test_pressure_state_is_one_hot(self) -> None:
        m = full_metrics()
        m.pressure = PressureState.CRITICAL
        values = {k: v for k, v in samples(m.render()).items() if k.startswith("msp_gateway_pressure_state")}
        assert sum(values.values()) == 1
        assert values['msp_gateway_pressure_state{state="CRITICAL"}'] == 1


class TestCounting:
    def test_events_are_counted_by_direction(self) -> None:
        m = full_metrics()
        m.observe(ev(EventType.CONNECT))
        m.observe(ev(EventType.CONNECT, direction=Direction.OUTBOUND))
        m.observe(ev(EventType.QUEUED, status="queued"))
        s = samples(m.render())
        assert s['msp_gateway_smtp_connections_total{direction="INBOUND"}'] == 1
        assert s['msp_gateway_smtp_connections_total{direction="OUTBOUND"}'] == 1
        assert s['msp_gateway_messages_received_total{direction="INBOUND"}'] == 1

    @pytest.mark.parametrize(("code", "klass"), [(554, "5xx"), (450, "4xx"), (None, "other"), (250, "other")])
    def test_rejections_are_classified_by_code(self, code: int | None, klass: str) -> None:
        m = full_metrics()
        m.observe(ev(EventType.REJECTED, smtp_code=code))
        key = f'msp_gateway_messages_rejected_total{{class="{klass}",direction="INBOUND"}}'
        assert samples(m.render())[key] == 1

    def test_delivery_outcomes(self) -> None:
        m = full_metrics()
        m.observe(ev(EventType.DELIVERY, status="sent", delay=0.2))
        m.observe(ev(EventType.DELIVERY, status="deferred"))
        m.observe(ev(EventType.DELIVERY, status="bounced"))
        s = samples(m.render())
        assert s['msp_gateway_messages_delivered_total{direction="INBOUND"}'] == 1
        assert s['msp_gateway_messages_deferred_total{direction="INBOUND"}'] == 1
        assert s['msp_gateway_delivery_failures_total{class="5xx",direction="INBOUND"}'] == 1

    def test_remote_refusal_is_visible_even_when_the_fallback_delivers(self) -> None:
        m = full_metrics()
        m.observe(ev(EventType.REMOTE_REPLY, smtp_code=451))
        m.observe(ev(EventType.DELIVERY, status="sent", delay=1))
        s = samples(m.render())
        assert s['msp_gateway_delivery_failures_total{class="4xx",direction="INBOUND"}'] == 1

    def test_delay_histogram_is_cumulative(self) -> None:
        m = full_metrics()
        for delay in (0.1, 3, 100):
            m.observe(ev(EventType.DELIVERY, status="sent", delay=delay))
        s = samples(m.render())
        assert s['msp_gateway_delivery_delay_seconds_bucket{le="0.5"}'] == 1
        assert s['msp_gateway_delivery_delay_seconds_bucket{le="5"}'] == 2
        assert s['msp_gateway_delivery_delay_seconds_bucket{le="300"}'] == 3
        assert s['msp_gateway_delivery_delay_seconds_bucket{le="+Inf"}'] == 3
        assert s["msp_gateway_delivery_delay_seconds_count"] == 3
        assert s["msp_gateway_delivery_delay_seconds_sum"] == pytest.approx(103.1)

    def test_negative_delay_is_not_counted(self) -> None:
        m = full_metrics()
        m.observe(ev(EventType.DELIVERY, status="sent", delay=-5))
        assert samples(m.render())["msp_gateway_delivery_delay_seconds_count"] == 0

    def test_shadow_success_and_failure(self) -> None:
        m = full_metrics()
        m.observe(ev(EventType.SHADOW, status="sent"))
        m.observe(ev(EventType.SHADOW, status="deferred"))
        s = samples(m.render())
        assert s["msp_gateway_shadow_delivery_total"] == 1
        assert s["msp_gateway_shadow_failures_total"] == 1


class TestCardinality:
    def test_hostile_values_never_become_label_values(self) -> None:
        m = full_metrics()
        for i in range(500):
            m.observe(
                ev(
                    EventType.DELIVERY,
                    status=f'evil"{i}\n',
                    relay=f"host{i}.attacker.example",
                    client_address=f"10.0.{i % 250}.{i % 200}",
                    envelope_from=f"x{i}@attacker.example",
                )
            )
            m.observe(ev(EventType.REJECTED, smtp_code=400 + i))
        text = m.render()
        assert "attacker" not in text
        assert "evil" not in text
        assert len(text.splitlines()) < 120

    def test_exposition_stays_valid_with_hostile_config_labels(self) -> None:
        m = full_metrics()
        m.config_version = 'v"1\\\n{x="y"}'
        for line in m.render().splitlines():
            assert line.startswith("#") or SAMPLE.match(line), line

    def test_escape_label(self) -> None:
        assert escape_label('a"b\\c\nd') == 'a\\"b\\\\c\\nd'


def pq(**kw) -> str:  # type: ignore[no-untyped-def]
    return json.dumps(kw)


class TestPostqueue:
    NOW = 1_000_000.0

    def test_counts_bytes_and_oldest(self) -> None:
        lines = [
            pq(queue_name="deferred", arrival_time=self.NOW - 600, message_size=1000),
            pq(queue_name="active", arrival_time=self.NOW - 30, message_size=500),
        ]
        snap = parse_postqueue_json(lines, now=self.NOW)
        assert (snap.messages, snap.bytes, snap.oldest_seconds) == (2, 1500, 600)
        assert snap.by_queue == {"deferred": 1, "active": 1}

    def test_empty_queue(self) -> None:
        snap = parse_postqueue_json([], now=self.NOW)
        assert (snap.messages, snap.bytes, snap.oldest_seconds) == (0, 0, 0)

    def test_broken_lines_are_skipped_not_fatal(self) -> None:
        lines = [
            "not json",
            "",
            "[1,2]",
            "42",
            pq(queue_name="deferred", arrival_time=self.NOW - 5, message_size=7),
        ]
        snap = parse_postqueue_json(lines, now=self.NOW)
        assert snap.messages == 1
        assert snap.bytes == 7

    def test_hostile_field_types_do_not_crash_or_poison_sums(self) -> None:
        lines = [
            pq(queue_name="x" * 1000, arrival_time="yesterday", message_size=-5),
            pq(queue_name=["a"], arrival_time=True, message_size=True),
            pq(queue_name="hold", arrival_time=self.NOW + 9999, message_size=3),
        ]
        snap = parse_postqueue_json(lines, now=self.NOW)
        assert snap.messages == 3
        assert snap.bytes == 3
        assert snap.oldest_seconds == 0
        assert set(snap.by_queue) <= {"other", "hold"}

    def test_future_arrival_does_not_give_negative_age(self) -> None:
        snap = parse_postqueue_json(
            [pq(queue_name="active", arrival_time=self.NOW + 100, message_size=1)], now=self.NOW
        )
        assert snap.oldest_seconds == 0


class TestAge:
    def test_none_stays_none(self) -> None:
        assert age_seconds(None, NOW) is None

    def test_age(self) -> None:
        assert age_seconds(NOW - timedelta(seconds=90), NOW) == 90

    def test_clock_skew_gives_zero_not_negative(self) -> None:
        assert age_seconds(NOW + timedelta(seconds=90), NOW) == 0


class TestRealLogLines:
    """Счёт по настоящим строкам, а не по событиям, собранным вручную."""

    LINES = (
        "Oct 11 19:16:16 gw postfix-in/smtpd[364]: connect from unknown[10.77.0.1]",
        "Oct 11 19:16:16 gw postfix-in/smtpd[364]: 2A004187F09: client=unknown[10.77.0.1]",
        "Oct 11 19:16:16 gw postfix/cleanup[380]: 2A004187F09: message-id=<m@lab.example>",
        "Oct 11 19:16:16 gw postfix/qmgr[348]: 2A004187F09: from=<a@partner.example>, size=440, nrcpt=2 (queue active)",
        "Oct 11 19:16:16 gw postfix/smtp[382]: 2A004187F09: to=<ivan@corp.example>, relay=fake-exchange[10.77.0.20]:2526, delay=0.03, delays=0.01/0/0.01/0, dsn=2.0.0, status=sent (250 2.0.0 ok)",
        "Oct 11 19:16:16 gw postfix/pipe[381]: 2A004187F09: to=<journal-in@journal.msp.invalid>, relay=msp-journal, delay=0.04, delays=0.01/0/0/0.03, dsn=2.0.0, status=sent (delivered via msp-journal service)",
    )

    def test_one_message_is_one_received_and_one_delivered(self) -> None:
        from msp_gateway.logparser import LogParser

        m = full_metrics()
        m.observe_all(LogParser(year=2026).parse_lines(self.LINES))
        s = samples(m.render())
        assert s['msp_gateway_messages_received_total{direction="INBOUND"}'] == 1
        assert s['msp_gateway_messages_delivered_total{direction="INBOUND"}'] == 1
        assert s['msp_gateway_smtp_connections_total{direction="INBOUND"}'] == 1
        assert s["msp_gateway_shadow_delivery_total"] == 1, "копия журнала не должна считаться доставкой"
