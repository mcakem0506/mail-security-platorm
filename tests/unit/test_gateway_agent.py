"""Агент узла: чтение журнала, очередь событий, состояние (ТЗ 1.1 §38, §45)."""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.request
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from msp_gateway.agent import (
    MAX_READ_BYTES,
    Agent,
    LogTailer,
    Outbox,
    Thresholds,
    http_sender,
    node_identity,
    read_recipient_generated_at,
    serve_metrics,
)
from msp_gateway.apply import CommandResult
from msp_gateway.state import is_draining, set_drain

NOW = datetime(2026, 10, 11, 12, 0, 0, tzinfo=UTC)
GB = 1024**3


class TestNodeIdentity:
    def test_is_created_once_and_stable(self, tmp_path: Path) -> None:
        first = node_identity(tmp_path)
        assert len(first) == 32
        assert node_identity(tmp_path) == first

    @pytest.mark.parametrize("garbage", ["", "short", "../../etc/passwd", "Z" * 32, "a" * 33])
    def test_corrupt_identity_is_replaced_by_a_valid_one(self, tmp_path: Path, garbage: str) -> None:
        (tmp_path / "node_id").write_text(garbage, encoding="ascii")
        value = node_identity(tmp_path)
        assert len(value) == 32
        assert value != garbage
        assert node_identity(tmp_path) == value

    def test_different_state_dirs_give_different_nodes(self, tmp_path: Path) -> None:
        assert node_identity(tmp_path / "a") != node_identity(tmp_path / "b")


class TestTailer:
    def make(
        self, tmp_path: Path, content: bytes = b"", *, from_start: bool = False
    ) -> tuple[LogTailer, Path]:
        path = tmp_path / "mail.log"
        path.write_bytes(content)
        return LogTailer(path, from_start=from_start), path

    def append(self, path: Path, data: bytes) -> None:
        with path.open("ab") as handle:
            handle.write(data)

    def test_missing_file_is_not_an_error(self, tmp_path: Path) -> None:
        assert LogTailer(tmp_path / "nope.log").read_new() == []

    def test_starts_at_the_end_by_default(self, tmp_path: Path) -> None:
        tailer, path = self.make(tmp_path, b"old\n")
        assert tailer.read_new() == []
        self.append(path, b"new\n")
        assert tailer.read_new() == ["new"]

    def test_from_start_reads_everything(self, tmp_path: Path) -> None:
        tailer, _ = self.make(tmp_path, b"a\nb\n", from_start=True)
        assert tailer.read_new() == ["a", "b"]

    def test_incomplete_last_line_waits_for_its_end(self, tmp_path: Path) -> None:
        tailer, path = self.make(tmp_path, from_start=True)
        self.append(path, b"first\nsec")
        assert tailer.read_new() == ["first"]
        self.append(path, b"ond\n")
        assert tailer.read_new() == ["second"]

    def test_truncation_restarts_from_the_beginning(self, tmp_path: Path) -> None:
        tailer, path = self.make(tmp_path, b"aaaa\nbbbb\n", from_start=True)
        tailer.read_new()
        path.write_bytes(b"c\n")
        assert tailer.read_new() == ["c"]

    def test_rotation_by_rename_is_followed(self, tmp_path: Path) -> None:
        tailer, path = self.make(tmp_path, b"one\n", from_start=True)
        assert tailer.read_new() == ["one"]
        os.replace(path, tmp_path / "mail.log.1")
        path.write_bytes(b"two\n")
        assert tailer.read_new() == ["two"]

    def test_invalid_utf8_is_replaced_not_fatal(self, tmp_path: Path) -> None:
        tailer, _ = self.make(tmp_path, b"bad \xff\xfe bytes\n", from_start=True)
        (line,) = tailer.read_new()
        assert "bad" in line

    def test_giant_backlog_is_bounded_and_accounted(self, tmp_path: Path) -> None:
        line = b"x" * 99 + b"\n"
        count = (MAX_READ_BYTES // 100) * 2
        tailer, _ = self.make(tmp_path, line * count, from_start=True)
        lines = tailer.read_new()
        assert len(lines) * 100 <= MAX_READ_BYTES + 200
        assert tailer.overflow_bytes > 0

    def test_endless_line_does_not_grow_memory(self, tmp_path: Path) -> None:
        tailer, path = self.make(tmp_path, from_start=True)
        for _ in range(5):
            self.append(path, b"y" * 10000)
            tailer.read_new()
        assert len(tailer._partial) <= 8192


class TestOutbox:
    def test_roundtrip_and_survives_a_new_instance(self, tmp_path: Path) -> None:
        box = Outbox(tmp_path / "o.jsonl")
        box.append({"type": "a"})
        assert Outbox(tmp_path / "o.jsonl").pending() == [{"type": "a"}]

    def test_is_bounded_and_drops_the_oldest(self, tmp_path: Path) -> None:
        box = Outbox(tmp_path / "o.jsonl", max_events=3)
        for i in range(10):
            box.append({"i": i})
        assert [e["i"] for e in box.pending()] == [7, 8, 9]
        assert box.dropped == 7

    def test_failed_send_keeps_everything(self, tmp_path: Path) -> None:
        box = Outbox(tmp_path / "o.jsonl")
        box.append({"i": 1})

        def broken(_events: list[dict[str, object]]) -> None:
            raise OSError("панель недоступна")

        assert box.flush(broken) == 0
        assert box.pending() == [{"i": 1}]

    def test_successful_send_empties_it(self, tmp_path: Path) -> None:
        box = Outbox(tmp_path / "o.jsonl")
        for i in range(250):
            box.append({"i": i})
        received: list[dict[str, object]] = []
        assert box.flush(received.extend, batch=100) == 250
        assert len(received) == 250
        assert box.pending() == []

    def test_failure_midway_keeps_only_the_unsent(self, tmp_path: Path) -> None:
        box = Outbox(tmp_path / "o.jsonl")
        for i in range(150):
            box.append({"i": i})
        calls: list[int] = []

        def flaky(events: list[dict[str, object]]) -> None:
            calls.append(len(events))
            if len(calls) == 2:
                raise OSError("обрыв")

        assert box.flush(flaky, batch=100) == 100
        assert len(box.pending()) == 50

    def test_corrupt_lines_do_not_block_the_queue(self, tmp_path: Path) -> None:
        path = tmp_path / "o.jsonl"
        path.write_text('not json\n{"i": 1}\n[1]\n', encoding="utf-8")
        box = Outbox(path)
        assert box.pending() == [{"i": 1}]
        received: list[dict[str, object]] = []
        box.flush(received.extend)
        assert received == [{"i": 1}]
        assert box.pending() == []


class FakeQueue:
    def __init__(self, lines: list[str] | None = None, *, fail: bool = False) -> None:
        self.lines = lines or []
        self.fail = fail
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], *, env=None, timeout: float = 60.0) -> CommandResult:  # type: ignore[no-untyped-def]
        self.calls.append(argv)
        if self.fail:
            raise OSError("postqueue нет")
        return CommandResult(0, "\n".join(self.lines))


def make_agent(tmp_path: Path, runner=None, **kw) -> Agent:  # type: ignore[no-untyped-def]
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    log = tmp_path / "mail.log"
    log.write_text("", encoding="utf-8")
    agent = Agent(state_dir=state, log_path=log, role="LAB", runner=runner or FakeQueue(), **kw)
    agent.tailer = LogTailer(log, from_start=True)
    return agent


def queue_line(arrival: float, size: int = 100, queue: str = "deferred") -> str:
    return json.dumps({"queue_name": queue, "arrival_time": arrival, "message_size": size})


class TestAgent:
    def test_log_lines_become_metrics(self, tmp_path: Path) -> None:
        agent = make_agent(tmp_path, disk_reader=lambda: 50 * GB)
        with (tmp_path / "mail.log").open("a", encoding="utf-8") as f:
            f.write("Oct 11 12:00:00 gw postfix-in/smtpd[10]: connect from unknown[10.77.0.1]\n")
        agent.collect_once(NOW)
        assert 'msp_gateway_smtp_connections_total{direction="INBOUND"} 1' in agent.metrics.render()

    def test_queue_is_asked_of_postfix_not_read_from_the_spool(self, tmp_path: Path) -> None:
        queue = FakeQueue([queue_line(NOW.timestamp() - 300, 2048)])
        agent = make_agent(tmp_path, queue, disk_reader=lambda: 50 * GB)
        agent.collect_once(NOW)
        assert queue.calls == [["postqueue", "-j"]]
        assert agent.metrics.queue.messages == 1
        assert agent.metrics.queue.oldest_seconds == 300

    def test_postqueue_failure_keeps_the_previous_snapshot(self, tmp_path: Path) -> None:
        queue = FakeQueue([queue_line(NOW.timestamp() - 10)])
        agent = make_agent(tmp_path, queue, disk_reader=lambda: 50 * GB)
        agent.collect_once(NOW)
        queue.fail = True
        agent.collect_once(NOW)
        assert agent.metrics.queue.messages == 1

    def test_pressure_transition_is_an_event(self, tmp_path: Path) -> None:
        free = {"v": 50 * GB}
        agent = make_agent(tmp_path, disk_reader=lambda: free["v"])
        agent.collect_once(NOW)
        free["v"] = GB // 2
        agent.collect_once(NOW)
        events = [e for e in agent.outbox.pending() if e["type"] == "pressure"]
        assert [(e["previous"], e["state"]) for e in events] == [("NORMAL", "CRITICAL")]

    def test_unmeasurable_disk_is_not_reported_as_normal(self, tmp_path: Path) -> None:
        def broken() -> int:
            raise OSError

        agent = make_agent(tmp_path, disk_reader=broken)
        agent.collect_once(NOW)
        assert agent.metrics.disk_free_bytes is None
        assert "msp_gateway_disk_free_bytes " not in "\n".join(
            x for x in agent.metrics.render().splitlines() if not x.startswith("#")
        )

    def test_drain_shows_as_draining(self, tmp_path: Path) -> None:
        agent = make_agent(tmp_path, disk_reader=lambda: 50 * GB)
        set_drain(True, state_dir=agent.state_dir, reload=False)
        agent.collect_once(NOW)
        assert 'msp_gateway_pressure_state{state="DRAINING"} 1' in agent.metrics.render()

    def test_queue_growth_alone_raises_pressure(self, tmp_path: Path) -> None:
        lines = [queue_line(NOW.timestamp()) for _ in range(1200)]
        agent = make_agent(tmp_path, FakeQueue(lines), disk_reader=lambda: 50 * GB, thresholds=Thresholds())
        agent.collect_once(NOW)
        assert 'msp_gateway_pressure_state{state="PRESSURE"} 1' in agent.metrics.render()

    def test_recipient_age_and_gate(self, tmp_path: Path) -> None:
        agent = make_agent(tmp_path, disk_reader=lambda: 50 * GB, manage_gate=True)
        (agent.state_dir / "recipients.meta.json").write_text(
            json.dumps({"generated_at": (NOW - timedelta(hours=5)).isoformat()}), encoding="utf-8"
        )
        # reload=False нельзя передать через агента: проверяем на уровне состояния через подмену
        import msp_gateway.agent as module

        calls: list[str] = []
        original = module.set_recipient_gate
        module.set_recipient_gate = lambda fresh, **kw: calls.append(fresh.value)  # type: ignore[assignment]
        try:
            agent.collect_once(NOW)
        finally:
            module.set_recipient_gate = original
        assert calls == ["STALE_HARD"]
        assert agent.metrics.recipient_map_age == 5 * 3600

    def test_gate_is_not_touched_unless_enabled(self, tmp_path: Path) -> None:
        agent = make_agent(tmp_path, disk_reader=lambda: 50 * GB)
        agent.collect_once(NOW)
        assert not (agent.state_dir / "recipient_gate.pcre").exists()
        assert not is_draining(agent.state_dir)

    def test_heartbeat_has_no_message_content(self, tmp_path: Path) -> None:
        agent = make_agent(tmp_path, disk_reader=lambda: 50 * GB)
        agent.collect_once(NOW)
        agent.heartbeat()
        (beat,) = [e for e in agent.outbox.pending() if e["type"] == "heartbeat"]
        assert set(beat) == {
            "type",
            "at",
            "node_id",
            "config_version",
            "queue_messages",
            "pressure",
            "unparsed_log_lines",
            "log_overflow_bytes",
        }


class TestRecipientMeta:
    def test_missing_or_broken_is_none(self, tmp_path: Path) -> None:
        assert read_recipient_generated_at(tmp_path) is None
        (tmp_path / "recipients.meta.json").write_text("{bad", encoding="utf-8")
        assert read_recipient_generated_at(tmp_path) is None
        (tmp_path / "recipients.meta.json").write_text('{"generated_at": "вчера"}', encoding="utf-8")
        assert read_recipient_generated_at(tmp_path) is None

    def test_naive_time_is_treated_as_utc(self, tmp_path: Path) -> None:
        (tmp_path / "recipients.meta.json").write_text(
            '{"generated_at": "2026-10-11T10:00:00"}', encoding="utf-8"
        )
        assert read_recipient_generated_at(tmp_path) == datetime(2026, 10, 11, 10, tzinfo=UTC)


class TestHttp:
    def test_metrics_and_health_endpoints(self, tmp_path: Path) -> None:
        agent = make_agent(tmp_path, disk_reader=lambda: 50 * GB)
        server = serve_metrics(agent, "127.0.0.1", 0)
        port = server.server_address[1]
        try:
            with pytest.raises(urllib.error.HTTPError) as stale:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5)
            assert stale.value.code == 503
            agent.collect_once(NOW)
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5) as r:
                assert r.status == 200
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as r:
                assert "msp_gateway_node_up 1" in r.read().decode()
            with pytest.raises(urllib.error.HTTPError) as missing:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/etc/passwd", timeout=5)
            assert missing.value.code == 404
        finally:
            server.shutdown()
            server.server_close()


class TestSender:
    def test_rejects_non_http_urls(self) -> None:
        for bad in ("file:///etc/passwd", "ftp://x", "javascript:1", ""):
            with pytest.raises(ValueError, match="http"):
                http_sender(bad, "t", "n")

    def test_posts_events_with_bearer_token_and_never_in_url(self) -> None:
        seen: dict[str, object] = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                seen["auth"] = self.headers.get("Authorization")
                seen["path"] = self.path
                seen["body"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                self.send_response(204)
                self.end_headers()

            def log_message(self, *_a: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            send = http_sender(
                f"http://127.0.0.1:{server.server_address[1]}/ingest", "secret-token", "n" * 32
            )
            send([{"type": "x"}])
        finally:
            server.shutdown()
            server.server_close()
        assert seen["auth"] == "Bearer secret-token"
        assert "secret-token" not in str(seen["path"])
        assert seen["body"] == {"node_id": "n" * 32, "events": [{"type": "x"}]}

    def test_unreachable_panel_raises_without_leaking_the_token(self) -> None:
        send = http_sender("http://127.0.0.1:9/ingest", "secret-token", "n" * 32, timeout=1)
        with pytest.raises(OSError) as info:
            send([{"type": "x"}])
        assert "secret-token" not in str(info.value)


class TestQueueSnapshot:
    """Снимок очереди, который кладёт root-цикл контейнера (агент сам к postqueue не ходит)."""

    def agent(self, tmp_path: Path, snapshot: Path):  # type: ignore[no-untyped-def]
        queue = FakeQueue([queue_line(NOW.timestamp(), 1)], fail=True)  # прямой вызов не должен понадобиться
        return make_agent(tmp_path, queue, disk_reader=lambda: 50 * GB, queue_snapshot=snapshot), queue

    def test_fresh_snapshot_is_used_and_postqueue_is_not_called(self, tmp_path: Path) -> None:
        snapshot = tmp_path / "queue.json"
        snapshot.write_text(queue_line(NOW.timestamp() - 40, 500) + "\n", encoding="utf-8")
        agent, queue = self.agent(tmp_path, snapshot)
        agent.collect_once(NOW)
        assert agent.metrics.queue.messages == 1
        assert agent.metrics.queue.bytes == 500
        assert queue.calls == []

    def test_stale_snapshot_is_ignored(self, tmp_path: Path) -> None:
        """Цикл остановился — старое число писем нельзя выдавать за текущее."""
        snapshot = tmp_path / "queue.json"
        snapshot.write_text(queue_line(NOW.timestamp(), 500) + "\n", encoding="utf-8")
        old = time.time() - 600
        os.utime(snapshot, (old, old))
        agent, _ = self.agent(tmp_path, snapshot)
        agent.collect_once(NOW)
        assert agent.metrics.queue.messages == 0

    def test_missing_snapshot_is_not_an_error(self, tmp_path: Path) -> None:
        agent, _ = self.agent(tmp_path, tmp_path / "absent.json")
        agent.collect_once(NOW)
        assert agent.metrics.queue.messages == 0

    def test_empty_snapshot_means_an_empty_queue(self, tmp_path: Path) -> None:
        snapshot = tmp_path / "queue.json"
        snapshot.write_text("", encoding="utf-8")
        agent, _ = self.agent(tmp_path, snapshot)
        agent.metrics.queue.messages = 7
        agent.collect_once(NOW)
        assert agent.metrics.queue.messages == 0
