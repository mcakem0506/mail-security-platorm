"""Агент: пробы Exchange, самопроверка открытого релея, сборщик, сертификаты, дрейф (ТЗ 1.1 §46–§48)."""

from __future__ import annotations

import json
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from gateway.harness import Authority
from msp_gateway.agent import Agent, LogTailer, ProbeConfig
from msp_gateway.apply import CommandResult

from .test_gateway_exchange_probe import Server, free_port

NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=UTC)
GB = 1024**3


class NoQueue:
    def __call__(self, argv, *, env=None, timeout: float = 60.0) -> CommandResult:  # type: ignore[no-untyped-def]
        return CommandResult(0, "")


def make_agent(tmp_path: Path, **kw) -> Agent:  # type: ignore[no-untyped-def]
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    log = tmp_path / "mail.log"
    log.write_text("", encoding="utf-8")
    agent = Agent(
        state_dir=state,
        log_path=log,
        role="LAB",
        runner=NoQueue(),
        disk_reader=lambda: 50 * GB,
        **kw,
    )
    agent.tailer = LogTailer(log, from_start=True)
    return agent


def events(agent: Agent, kind: str) -> list[dict[str, object]]:
    return [e for e in agent.outbox.pending() if e["type"] == kind]


def samples(agent: Agent) -> dict[str, float]:
    result: dict[str, float] = {}
    for line in agent.metrics.render().splitlines():
        if line and not line.startswith("#"):
            key, value = line.rsplit(" ", 1)
            result[key] = float(value)
    return result


@pytest.fixture
def authority(tmp_path: Path) -> Authority:
    auth = Authority.create()
    auth.write_ca(tmp_path / "ca.crt")
    return auth


class TestExchangeProbe:
    def config(self, server: Server, tmp_path: Path, **kw) -> ProbeConfig:  # type: ignore[no-untyped-def]
        return ProbeConfig(
            exchange_targets=(("127.0.0.1", server.port, "exchange.lab.example"),),
            ca_file=str(tmp_path / "ca.crt"),
            interval=0.0,
            timeout=5.0,
            **kw,
        )

    def test_a_healthy_exchange_gives_ones_and_no_event(self, tmp_path: Path, authority: Authority) -> None:
        with Server(tmp_path, authority=authority) as server:
            agent = make_agent(
                tmp_path, probes=self.config(server, tmp_path, probe_recipient="p@corp.example")
            )
            agent.collect_once(NOW)
        values = {k: v for k, v in samples(agent).items() if k.startswith("msp_gateway_exchange_probe_ok")}
        assert len(values) == 4 and set(values.values()) == {1.0}
        assert events(agent, "probe") == [], "норма с первого раза — не событие"

    def test_a_broken_tls_is_named_and_the_layers_after_it_are_absent_not_green(
        self, tmp_path: Path, authority: Authority
    ) -> None:
        with Server(tmp_path, authority=authority, days=-2) as server:
            agent = make_agent(tmp_path, probes=self.config(server, tmp_path))
            agent.collect_once(NOW)
        keys = {
            re.search(r'layer="(\w+)"', k)[1]: v  # type: ignore[index]
            for k, v in samples(agent).items()
            if "exchange_probe_ok" in k
        }
        assert keys["NETWORK"] == 1.0
        assert keys["TLS"] == 0.0
        assert "SMTP" not in keys and "DELIVERY" not in keys, "непроверенное не изображается зелёным"
        (event,) = events(agent, "probe")
        assert (event["probe"], event["ok"], event["failed_layer"]) == ("exchange", False, "TLS")
        assert "expired" in str(event["detail"])

    def test_recovery_is_an_event_too(self, tmp_path: Path, authority: Authority) -> None:
        with Server(tmp_path, authority=authority, days=-2) as bad:
            agent = make_agent(tmp_path, probes=self.config(bad, tmp_path))
            agent.collect_once(NOW)
        with Server(tmp_path, authority=authority, port=bad.port) as good:
            agent.probes = self.config(good, tmp_path)
            agent._last_probe = 0.0
            agent.collect_once(NOW)
        flags = [e["ok"] for e in events(agent, "probe")]
        assert flags == [False, True]

    def test_a_steady_failure_is_reported_once_not_every_minute(self, tmp_path: Path) -> None:
        agent = make_agent(
            tmp_path,
            probes=ProbeConfig(
                exchange_targets=(("127.0.0.1", free_port(), "x"),), interval=0.0, timeout=1.0
            ),
        )
        for _ in range(4):
            agent._last_probe = 0.0
            agent.collect_once(NOW)
        assert len(events(agent, "probe")) == 1

    def test_probes_wait_for_their_interval(self, tmp_path: Path) -> None:
        agent = make_agent(
            tmp_path,
            probes=ProbeConfig(
                exchange_targets=(("127.0.0.1", free_port(), "x"),), interval=3600.0, timeout=1.0
            ),
        )
        agent.collect_once(NOW)
        first = dict(agent.metrics.exchange_layers)
        agent.metrics.exchange_layers.clear()
        agent.collect_once(NOW)
        assert first and agent.metrics.exchange_layers == {}, (
            "вторая проба до истечения интервала не запускалась"
        )

    def test_no_probe_config_means_no_probes_and_no_invented_metrics(self, tmp_path: Path) -> None:
        agent = make_agent(tmp_path)
        agent.collect_once(NOW)
        assert not [k for k in samples(agent) if "exchange_probe_ok" in k or "open_relay" in k]

    def test_heartbeat_summarises_exchange_health(self, tmp_path: Path) -> None:
        agent = make_agent(
            tmp_path,
            probes=ProbeConfig(
                exchange_targets=(("127.0.0.1", free_port(), "x"),), interval=0.0, timeout=1.0
            ),
        )
        agent.collect_once(NOW)
        agent.heartbeat()
        (beat,) = events(agent, "heartbeat")
        assert beat["exchange_ok"] is False
        (tmp_path / "other").mkdir()
        quiet = make_agent(tmp_path / "other")
        quiet.collect_once(NOW)
        quiet.heartbeat()
        assert events(quiet, "heartbeat")[0]["exchange_ok"] is None


class TestOpenRelaySelfTest:
    def agent_for(self, server: Server, tmp_path: Path) -> Agent:
        return make_agent(
            tmp_path,
            probes=ProbeConfig(relay_host="127.0.0.1", relay_port=server.port, interval=0.0, timeout=5.0),
        )

    def test_a_refusing_listener_is_safe(self, tmp_path: Path, authority: Authority) -> None:
        with Server(tmp_path, authority=authority, tls=False, reject=True) as server:
            agent = self.agent_for(server, tmp_path)
            agent.collect_once(NOW)
        assert samples(agent)["msp_gateway_open_relay_selftest_ok"] == 1.0
        assert events(agent, "probe") == []

    def test_a_listener_that_accepts_a_stranger_is_a_critical_event(
        self, tmp_path: Path, authority: Authority
    ) -> None:
        with Server(tmp_path, authority=authority, tls=False, reject=False) as server:
            agent = self.agent_for(server, tmp_path)
            agent.collect_once(NOW)
        assert samples(agent)["msp_gateway_open_relay_selftest_ok"] == 0.0
        (event,) = events(agent, "probe")
        assert (event["probe"], event["ok"], event["state"]) == ("open_relay", False, "OPEN_RELAY")

    def test_an_unreachable_listener_is_unknown_not_safe(self, tmp_path: Path) -> None:
        agent = make_agent(tmp_path, probes=ProbeConfig(relay_port=free_port(), interval=0.0, timeout=1.0))
        agent.collect_once(NOW)
        assert "msp_gateway_open_relay_selftest_ok" not in samples(agent)
        (event,) = events(agent, "probe")
        assert event["state"] == "UNREACHABLE"
        assert event["ok"] is None, "недоступность — не провал: тревоги о релее быть не должно"


class TestDrift:
    def test_drift_is_a_gauge_and_an_event_on_change(self, tmp_path: Path) -> None:
        state = {"drift": False}
        agent = make_agent(tmp_path, drift_reader=lambda: state["drift"])
        agent.collect_once(NOW)
        assert samples(agent)["msp_gateway_config_drift"] == 0.0
        assert events(agent, "drift") == []
        state["drift"] = True
        agent.collect_once(NOW)
        assert samples(agent)["msp_gateway_config_drift"] == 1.0
        state["drift"] = False
        agent.collect_once(NOW)
        assert [e["drifting"] for e in events(agent, "drift")] == [True, False]

    def test_unknown_drift_state_is_not_zero(self, tmp_path: Path) -> None:
        agent = make_agent(tmp_path, drift_reader=lambda: None)
        agent.collect_once(NOW)
        assert "msp_gateway_config_drift" not in samples(agent)

    def test_an_unreadable_config_does_not_crash_the_agent(self, tmp_path: Path) -> None:
        def boom() -> bool:
            raise OSError("нет доступа")

        agent = make_agent(tmp_path, drift_reader=boom)
        agent.collect_once(NOW)
        assert "msp_gateway_config_drift" not in samples(agent)


class TestCollectorReport:
    def write(self, path: Path, **values: object) -> None:
        path.write_text(json.dumps(values), encoding="utf-8")

    def test_report_age_and_pending_are_exposed(self, tmp_path: Path) -> None:
        status = tmp_path / "collector.json"
        self.write(status, updated_at=NOW.timestamp() - 30, oldest_pending_seconds=120.0)
        agent = make_agent(tmp_path, collector_status=status)
        agent.collect_once(NOW)
        values = samples(agent)
        assert values["msp_gateway_shadow_collector_report_age_seconds"] == 30
        assert values["msp_gateway_shadow_pending_seconds"] == 120

    @pytest.mark.parametrize("content", [None, "{bad", "[]", '{"updated_at": "вчера"}', "{}"])
    def test_a_missing_or_broken_report_is_unknown_not_healthy(
        self, tmp_path: Path, content: str | None
    ) -> None:
        status = tmp_path / "collector.json"
        if content is not None:
            status.write_text(content, encoding="utf-8")
        agent = make_agent(tmp_path, collector_status=status)
        agent.collect_once(NOW)
        assert "msp_gateway_shadow_collector_report_age_seconds" not in samples(agent)

    def test_the_collector_report_may_live_outside_the_journal(self, tmp_path: Path) -> None:
        from msp_gateway.collector import Collector

        class Sink:
            def deliver(self, record, raw) -> None:  # type: ignore[no-untyped-def]
                pass

        status = tmp_path / "status" / "collector.json"
        status.parent.mkdir()
        Collector(tmp_path / "journal", Sink(), status_file=status).run_once()
        assert json.loads(status.read_text(encoding="utf-8"))["collected"] == 0
        assert not (tmp_path / "journal" / "collector.status.json").exists()


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl не установлен")
class TestCertificates:
    def issue(self, tmp_path: Path, days: int) -> Path:
        auth = Authority.create()
        auth.issue(
            tmp_path / "certs",
            "tls",
            ["gw.lab.example"],
            days=days,
            valid_from_days_ago=max(1, 5 - days) if days < 0 else 1,
        )
        return tmp_path / "certs" / "tls.crt"

    def test_expiry_is_exposed_and_the_certificate_is_announced_once(self, tmp_path: Path) -> None:
        cert = self.issue(tmp_path, 10)
        agent = make_agent(
            tmp_path, probes=ProbeConfig(certificates=(("smtp-public", str(cert)),), interval=0.0)
        )
        now = datetime.now(UTC)
        agent.collect_once(now)
        agent._last_probe = 0.0
        agent.collect_once(now)
        left = samples(agent)['msp_gateway_certificate_expiry_seconds{usage="smtp-public"}']
        assert 9 * 86400 < left < 11 * 86400
        announced = events(agent, "certificate")
        assert len(announced) == 1
        assert announced[0]["usage"] == "smtp-public"
        assert len(str(announced[0]["fingerprint"])) == 64

    def test_an_expired_certificate_gives_a_negative_value(self, tmp_path: Path) -> None:
        cert = self.issue(tmp_path, -2)
        agent = make_agent(
            tmp_path, probes=ProbeConfig(certificates=(("smtp-public", str(cert)),), interval=0.0)
        )
        agent.collect_once(datetime.now(UTC))
        assert samples(agent)['msp_gateway_certificate_expiry_seconds{usage="smtp-public"}'] < 0

    def test_an_unreadable_file_is_not_a_crash_and_not_a_value(self, tmp_path: Path) -> None:
        broken = tmp_path / "broken.crt"
        broken.write_text("not a certificate", encoding="utf-8")
        agent = make_agent(tmp_path, probes=ProbeConfig(certificates=(("x", str(broken)),), interval=0.0))
        agent.collect_once(datetime.now(UTC))
        assert not [k for k in samples(agent) if "certificate_expiry" in k]

    def test_the_private_key_is_never_read(self, tmp_path: Path) -> None:
        cert = self.issue(tmp_path, 10)
        key = cert.with_suffix(".key")
        key.chmod(0)
        agent = make_agent(
            tmp_path, probes=ProbeConfig(certificates=(("smtp-public", str(cert)),), interval=0.0)
        )
        agent.collect_once(datetime.now(UTC))
        text = json.dumps(agent.outbox.pending())
        assert "PRIVATE" not in text
        key.chmod(0o600)


class TestProbeEnvironment:
    def test_full_configuration(self) -> None:
        from msp_gateway.agent import parse_probe_env

        cfg = parse_probe_env(
            {
                "MSP_PROBE_EXCHANGE": "ex1.lab:2526:ex1.corp.example, ex2.lab:25",
                "MSP_PROBE_CA": "/ca.crt",
                "MSP_PROBE_RECIPIENT": "probe@corp.example",
                "MSP_PROBE_SELFTEST": "1",
                "MSP_PROBE_RELAY_PORT": "2525",
                "MSP_CERT_FILES": "smtp-public=/c/tls.crt,internal=/c/in.crt",
                "MSP_PROBE_INTERVAL": "15",
            }
        )
        assert cfg.exchange_targets == (("ex1.lab", 2526, "ex1.corp.example"), ("ex2.lab", 25, "ex2.lab"))
        assert cfg.relay_port == 2525
        assert cfg.certificates == (("smtp-public", "/c/tls.crt"), ("internal", "/c/in.crt"))
        assert cfg.interval == 15.0
        assert cfg.require_tls is True

    def test_nothing_configured_means_no_probes(self) -> None:
        from msp_gateway.agent import parse_probe_env

        cfg = parse_probe_env({})
        assert (cfg.exchange_targets, cfg.relay_port, cfg.certificates) == ((), None, ())

    def test_tls_can_be_made_optional_explicitly(self) -> None:
        from msp_gateway.agent import parse_probe_env

        assert parse_probe_env({"MSP_PROBE_REQUIRE_TLS": "0"}).require_tls is False

    @pytest.mark.parametrize(
        "env",
        [
            {"MSP_PROBE_EXCHANGE": "host-without-port"},
            {"MSP_PROBE_EXCHANGE": "host:notaport"},
            {"MSP_PROBE_EXCHANGE": "host:0"},
            {"MSP_PROBE_EXCHANGE": "host:70000"},
            {"MSP_PROBE_EXCHANGE": ":25"},
            {"MSP_PROBE_EXCHANGE": "a:1:b:c"},
            {"MSP_CERT_FILES": "no-equals"},
            {"MSP_CERT_FILES": "=path"},
            {"MSP_CERT_FILES": "bad usage=/p"},
            {"MSP_PROBE_SELFTEST": "1", "MSP_PROBE_RELAY_PORT": "abc"},
        ],
    )
    def test_a_misconfiguration_is_loud(self, env: dict[str, str]) -> None:
        from msp_gateway.agent import parse_probe_env

        with pytest.raises(ValueError):
            parse_probe_env(env)
