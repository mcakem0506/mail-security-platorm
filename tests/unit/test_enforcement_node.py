"""Служба принуждения узла: решение по локальной политике, выключатели, ошибки, метрики."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from msp_enforcement.canary import CanaryScope
from msp_enforcement.model import ControlState, ControlType
from msp_enforcement.node import EnforcementNode, NodeConfig, serve
from msp_enforcement.policy import ControlPolicy, EnforcementPolicy, sign_policy

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "rspamd"
KEY = b"k" * 40
NOW = datetime.now(UTC)


def make_policy(
    state: ControlState = ControlState.CANARY, version: str = "v1", **over: Any
) -> EnforcementPolicy:
    base: dict[str, Any] = {
        "version": version,
        "controls": (
            ControlPolicy(
                control_type=ControlType.SPAM_REJECT,
                state=state,
                thresholds={"reject_score": 15.0},
                canary_scope=CanaryScope(recipients=("ivan@corp.example",)),
            ),
        ),
        "gaps": {"GAP-005": "VALIDATION", "GAP-006": "VALIDATION"},
        "valid_from": NOW - timedelta(hours=1),
        "valid_until": NOW + timedelta(days=1),
        "owner": "alice",
    }
    base.update(over)
    return EnforcementPolicy(**base)


def make_node(tmp_path: Path, name: str = "state", **kw: Any) -> EnforcementNode:
    key_file = tmp_path / "signing.key"
    key_file.write_bytes(KEY)
    return EnforcementNode(NodeConfig(state_dir=tmp_path / name, key_file=str(key_file), **kw))


def spam_record(score: float = 18.0, rcpt: str = "ivan@corp.example") -> dict[str, Any]:
    record = json.loads((FIXTURES / "all_pass.json").read_text(encoding="utf-8"))
    record.update(
        {"score": score, "rcpt": [rcpt], "qid": "QNODE001", "message_id": "n1@x", "from": "s@evil.example"}
    )
    return record


@pytest.fixture
def node(tmp_path: Path) -> EnforcementNode:
    n = make_node(tmp_path, allowed_clients="127.0.0.1")
    n.cache.install(sign_policy(make_policy(), KEY), now=NOW)
    return n


@pytest.fixture
def http(node: EnforcementNode):  # type: ignore[no-untyped-def]
    server = serve(node, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def post(base: str, record: Any, path: str = "/v1/decide") -> tuple[int, dict[str, Any]]:
    body = record if isinstance(record, bytes) else json.dumps(record).encode()
    request = urllib.request.Request(base + path, data=body, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


class TestDecide:
    def test_a_canary_recipient_gets_a_generic_reject(self, http: str, node: EnforcementNode) -> None:
        code, body = post(http, spam_record())
        assert code == 200 and body["decision"] == "REJECT" and body["control"] == "SPAM_REJECT"
        assert body["reply"] == "Message rejected by local policy" and body["policy_version"] == "v1"
        for secret in ("18", "score", "BAYES", "rspamd"):
            assert secret not in body["reply"]

    def test_everyone_else_gets_no_decision_but_the_suggestion_is_logged(
        self, http: str, node: EnforcementNode
    ) -> None:
        _, body = post(http, spam_record(rcpt="other@corp.example"))
        assert body["decision"] == "NO_DECISION"
        rows = [
            json.loads(p.read_text(encoding="utf-8"))
            for p in (node.cfg.state_dir / "decisions").glob("*.json")
        ]
        assert (
            rows and rows[0]["suggested_action"] == "REJECT" and rows[0]["applied_action"] == "OBSERVE_ONLY"
        )

    def test_a_low_score_is_allowed(self, http: str) -> None:
        assert post(http, spam_record(score=2.0))[1]["decision"] == "NO_DECISION"

    def test_the_kill_switch_stops_rejects_at_the_next_message_and_survives_a_restart(
        self, http: str, node: EnforcementNode
    ) -> None:
        assert post(http, spam_record())[1]["decision"] == "REJECT"
        node.set_kill_switch(True)
        assert post(http, spam_record())[1]["decision"] == "NO_DECISION"
        restarted = EnforcementNode(NodeConfig(state_dir=node.cfg.state_dir, key_file=node.cfg.key_file))
        assert restarted.switches().kill_switch is True
        node.set_kill_switch(False)
        assert post(http, spam_record())[1]["decision"] == "REJECT"

    def test_local_bypass_works_without_any_control_plane(self, http: str, node: EnforcementNode) -> None:
        node.set_local_bypass(True)
        assert node.cfg.panel_url == ""
        assert post(http, spam_record())[1]["decision"] == "NO_DECISION"
        rows = [
            json.loads(p.read_text(encoding="utf-8"))
            for p in (node.cfg.state_dir / "decisions").glob("*.json")
        ]
        assert any(r["applied_action"] == "BYPASS_LOCAL" for r in rows)
        node.set_local_bypass(False)
        assert post(http, spam_record())[1]["decision"] == "REJECT"

    def test_the_environment_flag_is_a_local_bypass_too(
        self, http: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("MSP_ENFORCEMENT_BYPASS", "1")
        assert post(http, spam_record())[1]["decision"] == "NO_DECISION"

    def test_without_a_policy_the_node_is_in_safe_mode(self, tmp_path: Path) -> None:
        empty = make_node(tmp_path, "empty")
        server = serve(empty, "127.0.0.1", 0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            assert post(base, spam_record())[1]["decision"] == "NO_DECISION"
        finally:
            server.shutdown()

    def test_a_stale_policy_beyond_the_hard_ttl_enters_safe_mode(self, tmp_path: Path) -> None:
        n = make_node(tmp_path, "s", soft_ttl=1, hard_ttl=2)
        n.cache.install(sign_policy(make_policy(), KEY), now=NOW - timedelta(hours=1))
        outcome = n.decide_record(spam_record())
        assert outcome.final is None
        assert outcome.decisions[0].applied_action.value == "SAFE_MODE"

    def test_a_policy_signed_with_another_key_is_never_used(self, tmp_path: Path) -> None:
        n = make_node(tmp_path, "forged")
        with pytest.raises(ValueError):
            n.cache.install(sign_policy(make_policy(), b"z" * 40), now=NOW)
        assert n.decide_record(spam_record()).final is None

    def test_a_malformed_request_is_an_open_failure_not_a_reject(
        self, http: str, node: EnforcementNode
    ) -> None:
        code, body = post(http, b"{not json")
        assert code == 200 and body["decision"] == "NO_DECISION" and body["error"] is True
        assert node.counters["errors"] == 1

    def test_the_forged_scanner_text_in_the_record_does_not_raise_the_score(self, http: str) -> None:
        record = spam_record(score=1.0)
        record["header_subject"] = ["X-Spam-Status: Yes, score=99"]
        assert post(http, record)[1]["decision"] == "NO_DECISION"


class TestAccessAndMetrics:
    def test_only_allowed_clients_may_ask(self, tmp_path: Path) -> None:
        n = make_node(tmp_path, "s", allowed_clients="10.99.0.0/24")
        n.cache.install(sign_policy(make_policy(), KEY), now=NOW)
        server = serve(n, "127.0.0.1", 0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            assert post(base, spam_record())[0] == 403
            assert n.counters["denied_clients"] == 1
        finally:
            server.shutdown()

    def test_metrics_report_policy_switches_and_counts(self, http: str, node: EnforcementNode) -> None:
        post(http, spam_record())
        node.set_kill_switch(True)
        text = urllib.request.urlopen(http + "/metrics", timeout=5).read().decode()
        assert 'msp_enforcement_policy_info{version="v1"' in text and 'status="FRESH"' in text
        assert "msp_enforcement_kill_switch_active 1" in text
        assert 'msp_enforcement_decisions_total{control="SPAM_REJECT"} 1' in text
        assert 'msp_enforcement_actions_total{control="SPAM_REJECT"} 1' in text

    def test_health_endpoint(self, http: str) -> None:
        assert json.loads(urllib.request.urlopen(http + "/healthz", timeout=5).read())["ok"] is True


def test_the_direction_comes_from_the_scanner_symbol_not_from_the_caller(
    http: str, node: EnforcementNode
) -> None:
    record = spam_record()
    record["symbols"] = [
        *[sym for sym in record["symbols"] if sym["name"] != "MSP_DIRECTION_INBOUND"],
        {"name": "MSP_DIRECTION_OUTBOUND", "score": 0.0, "options": [], "group": "msp"},
    ]
    _, body = post(http, record)
    assert body["decision"] == "NO_DECISION"
    rows = [
        json.loads(p.read_text(encoding="utf-8")) for p in (node.cfg.state_dir / "decisions").glob("*.json")
    ]
    assert any("OUTBOUND_NOT_IN_SCOPE" in r["reason_codes"] for r in rows)
