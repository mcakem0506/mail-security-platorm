"""Узловая часть сканера: метрики, сведение конфигурации, приёмник (ТЗ 1.2 §22, §27, §31, §36)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from msp_antispam import node
from msp_antispam.metrics import ScanMetrics
from msp_antispam.overlay import merge
from msp_antispam.rspamd_config import ConfigError, DkimSigning, RspamdNodeConfig

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "rspamd"
REQUIRED_METRICS = (
    "msp_rspamd_up",
    "msp_rspamd_scan_total",
    "msp_rspamd_scan_duration_seconds",
    "msp_rspamd_scan_errors_total",
    "msp_rspamd_suggested_actions_total",
    "msp_spf_results_total",
    "msp_dkim_results_total",
    "msp_dmarc_results_total",
    "msp_arc_results_total",
    "msp_rbl_queries_total",
    "msp_rbl_listed_total",
    "msp_rbl_errors_total",
    "msp_spam_fp_total",
    "msp_spam_fn_total",
    "msp_dkim_sign_total",
    "msp_dkim_sign_failures_total",
)


def record(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def sample_value(text: str, metric: str, labels: str = "") -> float:
    pattern = re.compile(rf"^{re.escape(metric)}{re.escape(labels)} (\S+)$", re.MULTILINE)
    match = pattern.search(text)
    assert match, f"{metric}{labels} нет в выдаче"
    return float(match.group(1))


class TestMetrics:
    def test_every_required_metric_is_exposed(self) -> None:
        text = ScanMetrics().render()
        for name in REQUIRED_METRICS:
            assert f"# TYPE {name} " in text, name

    def test_results_are_counted_by_normalised_value(self) -> None:
        metrics = ScanMetrics()
        metrics.observe(record("all_pass"))
        metrics.observe(record("dmarc_reject_fail"))
        text = metrics.render()
        assert sample_value(text, "msp_spf_results_total", '{result="PASS"}') == 1
        assert sample_value(text, "msp_spf_results_total", '{result="FAIL"}') == 1
        assert sample_value(text, "msp_dmarc_results_total", '{result="PASS"}') == 1
        assert sample_value(text, "msp_dmarc_results_total", '{result="FAIL"}') == 1

    def test_suggested_actions_are_counted_and_nothing_is_applied(self) -> None:
        metrics = ScanMetrics()
        metrics.observe(record("dmarc_reject_fail"))
        text = metrics.render()
        assert "msp_rspamd_suggested_actions_total{" in text
        assert "applied" not in text.lower()

    def test_symbol_names_from_the_message_cannot_inflate_labels(self) -> None:
        metrics = ScanMetrics()
        hostile = record("all_pass")
        hostile["symbols"] = [{"name": f"MSP_RBL_EVIL{i}_CLIENT_IP", "score": 0} for i in range(500)]
        hostile["action"] = "x" * 500
        metrics.observe(hostile)
        text = metrics.render()
        assert text.count("\n") < 200
        assert "x" * 100 not in text

    def test_direction_comes_from_the_listener_symbol(self) -> None:
        metrics = ScanMetrics()
        outbound = record("all_pass")
        outbound["symbols"] = [{"name": "MSP_DIRECTION_OUTBOUND", "score": 0}]
        metrics.observe(outbound)
        assert sample_value(metrics.render(), "msp_rspamd_scan_total", '{direction="OUTBOUND"}') == 1

    def test_dkim_signing_is_counted_and_a_missing_signature_for_an_active_domain_is_a_failure(self) -> None:
        metrics = ScanMetrics()
        metrics.configure(signing_domains=frozenset({"corp.example"}), active_providers=frozenset())
        signed = {
            "symbols": [{"name": "MSP_DIRECTION_OUTBOUND"}, {"name": "DKIM_SIGNED"}],
            "from": "i@corp.example",
        }
        unsigned = {
            "symbols": [{"name": "MSP_DIRECTION_OUTBOUND"}],
            "from": "i@corp.example",
            "header_from": ["i@corp.example"],
        }
        foreign = {
            "symbols": [{"name": "MSP_DIRECTION_OUTBOUND"}],
            "from": "x@other.example",
            "header_from": ["x@other.example"],
        }
        for item in (signed, unsigned, foreign):
            metrics.observe(item)
        text = metrics.render()
        assert sample_value(text, "msp_dkim_sign_total") == 1
        assert sample_value(text, "msp_dkim_sign_failures_total") == 1

    def test_rbl_errors_are_not_claimed_to_be_zero(self) -> None:
        text = ScanMetrics().render()
        assert 'msp_rbl_errors_total{source="not_collected"}' in text

    def test_health_gauges(self) -> None:
        metrics = ScanMetrics()
        metrics.set_health(up=True, redis_up=False)
        text = metrics.render()
        assert sample_value(text, "msp_rspamd_up") == 1 and sample_value(text, "msp_rspamd_redis_up") == 0


def base_config(**overrides: object) -> RspamdNodeConfig:
    data: dict[str, object] = {
        "authserv_id": "gw.lab.example",
        "nameservers": ("10.77.0.51",),
        "redis": {"host": "10.77.0.52"},
        "dkim_signing": DkimSigning(enabled=True, sign_networks=("10.77.0.64/26",), domains=()),
    }
    data.update(overrides)
    return RspamdNodeConfig(**data)  # type: ignore[arg-type]


class TestOverlay:
    def test_thresholds_providers_and_signing_domains_are_taken_from_the_panel(self) -> None:
        overlay = {
            "thresholds": {"greylist": 3, "add_header": 5, "reject": 12},
            "providers": [
                {
                    "id": "labzone",
                    "provider_name": "Лаб",
                    "enabled": True,
                    "license_mode": "LAB_ZONE",
                    "query_types": ["CLIENT_IP"],
                    "privacy_class": "INTERNAL",
                    "zone": "rbl.lab.test",
                }
            ],
            "signing_domains": [
                {"domain": "corp.example", "selector": "s1", "private_key_file": "/run/secrets/k.key"}
            ],
        }
        result = merge(base_config(), overlay, key_exists=lambda path: True)
        assert result.config.thresholds.reject == 12
        assert [p.id for p in result.config.providers] == ["labzone"]
        assert [(d.domain, d.selector) for d in result.config.dkim_signing.domains] == [
            ("corp.example", "s1")
        ]

    def test_the_panel_cannot_widen_who_gets_signed(self) -> None:
        overlay = {
            "signing_domains": [
                {"domain": "corp.example", "selector": "s1", "private_key_file": "/run/secrets/k.key"}
            ],
            "sign_networks": ["0.0.0.0/0"],
        }
        result = merge(base_config(), overlay, key_exists=lambda path: True)
        assert result.config.dkim_signing.sign_networks == ("10.77.0.64/26",)

    def test_signing_is_not_enabled_on_a_node_without_trusted_networks(self) -> None:
        overlay = {
            "signing_domains": [
                {"domain": "corp.example", "selector": "s1", "private_key_file": "/run/secrets/k.key"}
            ]
        }
        node_without = base_config(dkim_signing=DkimSigning(enabled=False))
        result = merge(node_without, overlay, key_exists=lambda path: True)
        assert result.config.dkim_signing.enabled is False
        assert any("доверенные сети" in item for item in result.ignored)

    def test_a_domain_without_a_key_file_is_reported_and_left_out(self) -> None:
        overlay = {
            "signing_domains": [
                {"domain": "corp.example", "selector": "s1", "private_key_file": "/run/secrets/k.key"}
            ]
        }
        result = merge(base_config(), overlay, key_exists=lambda path: False)
        assert result.missing_keys == ["corp.example:s1"]
        assert result.config.dkim_signing.enabled is False

    @pytest.mark.parametrize(
        "overlay",
        [
            {"thresholds": {"greylist": 9, "add_header": 5, "reject": 12}},
            {"providers": [{"id": "Bad Id", "provider_name": "x", "zone": "a.example"}]},
            {"providers": [{"id": "ok", "provider_name": "x", "zone": 'a".example'}]},
            {"signing_domains": [{"domain": "corp.example", "selector": "s 1", "private_key_file": "/k"}]},
            {
                "signing_domains": [
                    {"domain": "corp.example", "selector": "s1", "private_key_file": "/etc/../shadow"}
                ]
            },
        ],
    )
    def test_hostile_assignments_do_not_pass_the_model(self, overlay: dict) -> None:
        with pytest.raises((ConfigError, ValueError)):
            merge(base_config(), overlay, key_exists=lambda path: True)

    def test_bayes_and_greylisting_need_redis_on_the_node(self) -> None:
        no_redis = base_config(redis=None)
        result = merge(no_redis, {"bayes_enabled": True, "greylisting": True}, key_exists=lambda path: True)
        assert result.config.bayes.enabled is False and result.config.greylisting is False
        assert len(result.ignored) == 2

    def test_bayes_follows_the_panel_when_redis_exists(self) -> None:
        result = merge(base_config(), {"bayes_enabled": True}, key_exists=lambda path: True)
        assert result.config.bayes.enabled is True and result.config.bayes.autolearn is False


class TestReceiver:
    def test_a_record_is_stored_with_its_origin_and_counted(self, tmp_path: Path) -> None:
        receiver = node.Receiver(tmp_path / "outbox", None, None, "a" * 32)
        assert receiver.accept(json.dumps(record("all_pass")).encode())
        stored = json.loads(next((tmp_path / "outbox").glob("*.json")).read_text(encoding="utf-8"))
        assert "received_at" in stored["_msp"] and "rspamd_version" in stored["_msp"]
        assert "msp_rspamd_scan_total" in receiver.metrics.render()

    @pytest.mark.parametrize("payload", [b"", b"not json", b"[1,2]", b"\xff\xfe", b"{"])
    def test_garbage_is_refused_and_counted(self, tmp_path: Path, payload: bytes) -> None:
        receiver = node.Receiver(tmp_path / "outbox", None, None, "a" * 32)
        assert receiver.accept(payload) is False
        assert not list((tmp_path / "outbox").glob("*.json"))

    def test_the_outbox_is_bounded(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(node, "OUTBOX_LIMIT", 5)
        receiver = node.Receiver(tmp_path / "outbox", None, None, "a" * 32)
        for _ in range(12):
            receiver.accept(json.dumps(record("all_pass")).encode())
        assert len(list((tmp_path / "outbox").glob("*.json"))) == 5
        assert receiver.dropped == 7

    def test_without_a_panel_nothing_is_sent_and_nothing_is_lost(self, tmp_path: Path) -> None:
        receiver = node.Receiver(tmp_path / "outbox", None, None, "a" * 32)
        receiver.accept(json.dumps(record("all_pass")).encode())
        assert receiver.flush() == 0
        assert len(list((tmp_path / "outbox").glob("*.json"))) == 1

    def test_a_failing_panel_keeps_the_records(self, tmp_path: Path) -> None:
        receiver = node.Receiver(tmp_path / "outbox", "http://127.0.0.1:9/spam-scans", "t" * 40, "a" * 32)
        receiver.accept(json.dumps(record("all_pass")).encode())
        assert receiver.flush() == 0
        assert len(list((tmp_path / "outbox").glob("*.json"))) == 1


class TestKeygen:
    def test_the_private_key_stays_on_the_node_and_cannot_be_overwritten(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import argparse

        args = argparse.Namespace(domain="corp.example", selector="s1", secret_dir=str(tmp_path))
        assert node.cmd_keygen(args) == 0
        printed = json.loads(capsys.readouterr().out)
        assert "PRIVATE" not in json.dumps(printed) and printed["public_record"].startswith("v=DKIM1")
        key_file = tmp_path / "corp.example.s1.key"
        assert key_file.read_bytes().startswith(b"-----BEGIN")
        with pytest.raises(FileExistsError):
            node.cmd_keygen(args)
