"""Сборщик теневых копий (ТЗ 1.1 §34, §58, §68.16): не меньше одного раза, идемпотентно."""

from __future__ import annotations

import base64
import io
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from msp_gateway import journal_writer
from msp_gateway.collector import (
    Collector,
    CopyError,
    CopyRecord,
    DirectorySink,
    HttpSink,
    extract_message_id,
    make_key,
    parse_meta,
    read_copy,
)

MAGIC = journal_writer.MAGIC


def mime(message_id: str | None = "<a1@lab.example>", body: str = "hello") -> bytes:
    lines = ["From: a@partner.example", "To: ivan@corp.example", "Subject: t"]
    if message_id is not None:
        lines.append(f"Message-ID: {message_id}")
    return ("\r\n".join(lines) + f"\r\n\r\n{body}\r\n").encode()


def journal_copy(
    root: Path,
    raw: bytes,
    *,
    recipient: str = "journal-in@journal.msp.invalid",
    sender: str = "a@partner.example",
) -> str:
    name = journal_writer.write_copy(
        io.BytesIO(raw),
        queue_id="ABCDEF12345",
        recipient=recipient,
        sender=sender,
        client_address="10.0.0.1",
        client_helo="helo.example",
        size=str(len(raw)),
        directory=str(root),
    )
    assert name
    return name


def raw_file(root: Path, content: bytes, name: str = "0001-x-aaaaaaaa.msj") -> Path:
    (root / "new").mkdir(parents=True, exist_ok=True)
    path = root / "new" / name
    path.write_bytes(content)
    return path


def header(meta: object) -> bytes:
    return MAGIC + base64.b64encode(json.dumps(meta).encode()) + b"\n"


GOOD_META = {
    "direction": "INBOUND",
    "queue_id": "ABC123",
    "envelope_from": "a@b.example",
    "journaled_at": 1.0,
}


class RecordingSink:
    def __init__(self) -> None:
        self.records: list[CopyRecord] = []
        self.bodies: list[bytes] = []
        self.fail = False

    def deliver(self, record: CopyRecord, raw: bytes) -> None:
        if self.fail:
            raise OSError("приёмник недоступен")
        self.records.append(record)
        self.bodies.append(raw)


class TestReading:
    def test_real_journal_file_is_read(self, tmp_path: Path) -> None:
        raw = mime()
        name = journal_copy(tmp_path, raw)
        record = read_copy(tmp_path / "new" / name)
        assert record.direction == "INBOUND"
        assert record.message_id == "<a1@lab.example>"
        assert record.size == len(raw)
        assert len(record.sha256) == 64
        assert record.queue_id == "ABCDEF12345"

    def test_outbound_direction_is_preserved(self, tmp_path: Path) -> None:
        name = journal_copy(tmp_path, mime(), recipient="journal-out@journal.msp.invalid")
        assert read_copy(tmp_path / "new" / name).direction == "OUTBOUND"

    def test_key_is_stable_for_identical_copies(self, tmp_path: Path) -> None:
        a = read_copy(tmp_path / "new" / journal_copy(tmp_path, mime()))
        b = read_copy(tmp_path / "new" / journal_copy(tmp_path, mime()))
        assert a.key == b.key

    @pytest.mark.parametrize(
        "other",
        [
            {"raw": mime(body="другое")},
            {"raw": mime(message_id="<zz@lab.example>")},
            {"raw": mime(), "recipient": "journal-out@journal.msp.invalid"},
            {"raw": mime(), "sender": "b@partner.example"},
        ],
    )
    def test_key_changes_with_every_component(self, tmp_path: Path, other: dict[str, object]) -> None:
        base = read_copy(tmp_path / "new" / journal_copy(tmp_path, mime()))
        kwargs = {k: v for k, v in other.items() if k != "raw"}
        changed = read_copy(tmp_path / "new" / journal_copy(tmp_path, other["raw"], **kwargs))  # type: ignore[arg-type]
        assert changed.key != base.key

    def test_key_fields_cannot_be_shifted_between_each_other(self) -> None:
        assert make_key("INBOUND", "ab", "c", "d") != make_key("INBOUND", "a", "bc", "d")

    def test_message_without_message_id_still_has_a_key(self, tmp_path: Path) -> None:
        record = read_copy(tmp_path / "new" / journal_copy(tmp_path, mime(message_id=None)))
        assert record.message_id == ""
        assert len(record.key) == 64


class TestMessageId:
    def test_folded_header(self) -> None:
        head = b"Subject: x\r\nMessage-ID:\r\n <folded@lab.example>\r\n\r\nbody"
        assert extract_message_id(head) == "<folded@lab.example>"

    def test_header_name_is_case_insensitive(self) -> None:
        assert extract_message_id(b"message-id: <x@y>\r\n\r\n") == "<x@y>"

    def test_message_id_in_the_body_is_ignored(self) -> None:
        """Тело письма — данные отправителя; подделать «Message-ID» в нём ничего не должно давать."""
        assert extract_message_id(b"Subject: x\r\n\r\nMessage-ID: <fake@evil>\r\n") == ""

    def test_control_characters_are_neutralised(self) -> None:
        value = extract_message_id(b"Message-ID: <a\x01b\x1b[31m@x>\r\n\r\n")
        assert not any(ord(c) < 32 for c in value)

    def test_length_is_bounded(self) -> None:
        assert len(extract_message_id(b"Message-ID: <" + b"a" * 5000 + b"@x>\r\n\r\n")) <= 998


class TestBadFiles:
    @pytest.mark.parametrize(
        "content",
        [
            b"",
            b"no magic here\nbody",
            MAGIC + b"!!!not base64!!!\nbody",
            header([1, 2]) + b"body",
            header({**GOOD_META, "direction": "SIDEWAYS"}) + b"body",
            header({**GOOD_META, "queue_id": "../../etc"}) + b"body",
            header({**GOOD_META, "queue_id": 5}) + b"body",
            header(GOOD_META),  # заголовок есть, письма нет
            MAGIC + b"A" * 20000 + b"\nbody",
            MAGIC + base64.b64encode(json.dumps(GOOD_META).encode()),  # без перевода строки
        ],
    )
    def test_unparseable_files_are_rejected(self, tmp_path: Path, content: bytes) -> None:
        with pytest.raises(CopyError):
            read_copy(raw_file(tmp_path, content))

    def test_missing_file_is_a_copy_error(self, tmp_path: Path) -> None:
        with pytest.raises(CopyError):
            read_copy(tmp_path / "absent.msj")

    def test_hostile_meta_values_are_sanitised_not_trusted(self) -> None:
        meta = parse_meta(
            header(
                {
                    **GOOD_META,
                    "envelope_from": "a\nb\x00" + "x" * 1000,
                    "client_helo": ["список"],
                    "journaled_at": "вчера",
                    "declared_size": True,
                }
            )
        )
        assert "\n" not in meta["envelope_from"] and len(meta["envelope_from"]) <= 320  # type: ignore[arg-type]
        assert meta["client_helo"] == ""
        assert meta["journaled_at"] == 0.0
        assert meta["declared_size"] is None


class TestCollecting:
    def make(self, tmp_path: Path, sink=None, **kw) -> tuple[Collector, RecordingSink]:  # type: ignore[no-untyped-def]
        sink = sink or RecordingSink()
        return Collector(tmp_path, sink, **kw), sink

    def test_collected_copy_moves_to_done_and_is_delivered_once(self, tmp_path: Path) -> None:
        raw = mime()
        name = journal_copy(tmp_path, raw)
        collector, sink = self.make(tmp_path)
        stats = collector.run_once()
        assert stats.collected == 1
        assert sink.bodies == [raw], "приёмник получает письмо как есть, без служебной строки"
        assert not (tmp_path / "new" / name).exists()
        assert len(list((tmp_path / "done").iterdir())) == 1
        collector.run_once()
        assert len(sink.records) == 1, "второй проход ничего не находит"

    def test_failed_delivery_keeps_the_file_and_retries(self, tmp_path: Path) -> None:
        name = journal_copy(tmp_path, mime())
        collector, sink = self.make(tmp_path)
        sink.fail = True
        stats = collector.run_once()
        assert stats.failed == 1
        assert (tmp_path / "new" / name).exists(), "копия не теряется, пока приёмник её не принял"
        sink.fail = False
        collector.run_once()
        assert len(sink.records) == 1
        assert not (tmp_path / "new" / name).exists()

    def test_one_failure_does_not_block_the_others(self, tmp_path: Path) -> None:
        for i in range(3):
            journal_copy(tmp_path, mime(message_id=f"<m{i}@x>"))
        calls: list[str] = []

        class Flaky:
            def deliver(self, record: CopyRecord, raw: bytes) -> None:
                calls.append(record.message_id)
                if record.message_id == "<m1@x>":
                    raise OSError

        collector = Collector(tmp_path, Flaky())
        stats = collector.run_once()
        assert (stats.collected, stats.failed) == (2, 1)

    def test_bad_file_goes_to_quarantine_and_does_not_block(self, tmp_path: Path) -> None:
        raw_file(tmp_path, b"garbage", name="0000-bad-aaaaaaaa.msj")
        journal_copy(tmp_path, mime())
        collector, _sink = self.make(tmp_path)
        stats = collector.run_once()
        assert (stats.quarantined, stats.collected) == (1, 1)
        assert [p.name for p in (tmp_path / "bad").iterdir()] == ["0000-bad-aaaaaaaa.msj"]

    def test_crash_after_delivery_before_move_gives_a_duplicate_not_a_loss(self, tmp_path: Path) -> None:
        """Файл остался в new, хотя приёмник уже получил копию: при повторе это один и тот же ключ."""
        raw = mime()
        name = journal_copy(tmp_path, raw)
        collector, sink = self.make(tmp_path)
        collector.run_once()
        again = journal_copy(tmp_path, raw)  # как будто файл вернулся
        assert again != name
        stats = collector.run_once()
        assert stats.duplicates == 1
        assert sink.records[0].key == sink.records[1].key
        assert len(list((tmp_path / "done").iterdir())) == 1

    def test_foreign_files_are_left_alone(self, tmp_path: Path) -> None:
        (tmp_path / "new").mkdir()
        (tmp_path / "new" / "notes.txt").write_text("не наше", encoding="utf-8")
        collector, sink = self.make(tmp_path)
        collector.run_once()
        assert (tmp_path / "new" / "notes.txt").exists()
        assert sink.records == []

    def test_batch_limit(self, tmp_path: Path) -> None:
        for i in range(5):
            journal_copy(tmp_path, mime(message_id=f"<b{i}@x>"))
        collector, _ = self.make(tmp_path, batch=2)
        assert collector.run_once().collected == 2
        assert len(list((tmp_path / "new").iterdir())) == 3

    def test_oldest_pending_age_is_reported(self, tmp_path: Path) -> None:
        name = journal_copy(tmp_path, mime())
        path = tmp_path / "new" / name
        os.utime(path, (1000, 1000))
        collector, sink = self.make(tmp_path, clock=lambda: 1600.0)
        sink.fail = True
        assert collector.run_once().oldest_pending_seconds == 600

    def test_a_delivered_copy_is_not_pending_any_more(self, tmp_path: Path) -> None:
        """Возраст «ожидающей» копии — это то, что осталось после прохода, а не то, что только что ушло."""
        name = journal_copy(tmp_path, mime())
        os.utime(tmp_path / "new" / name, (1000, 1000))
        collector, _ = self.make(tmp_path, clock=lambda: 1600.0)
        assert collector.run_once().oldest_pending_seconds == 0

    def test_retention_prunes_old_done_and_bad(self, tmp_path: Path) -> None:
        journal_copy(tmp_path, mime())
        raw_file(tmp_path, b"junk", name="0000-bad-aaaaaaaa.msj")
        collector, _ = self.make(tmp_path, retention_days=1, clock=lambda: 1_000_000.0)
        for directory in ("done", "bad"):
            (tmp_path / directory).mkdir(exist_ok=True)
        collector.clock = lambda: 1_000_000.0
        collector.run_once()
        collector.clock = lambda: 1_000_000.0 + 3 * 86400
        # mtime файлов — реальное «сейчас» (~1.7e9), поэтому сдвигаем часы за него
        collector.clock = lambda: 4_000_000_000.0
        stats = collector.run_once()
        assert stats.pruned == 2
        assert list((tmp_path / "done").iterdir()) == []
        assert list((tmp_path / "bad").iterdir()) == []

    def test_status_file_reports_failures_for_the_agent(self, tmp_path: Path) -> None:
        journal_copy(tmp_path, mime())
        collector, sink = self.make(tmp_path)
        sink.fail = True
        collector.run_once()
        status = json.loads((tmp_path / "collector.status.json").read_text(encoding="utf-8"))
        assert status["failed"] == 1
        assert status["last_failure_reason"] == "OSError"

    def test_missing_journal_directory_is_not_fatal(self, tmp_path: Path) -> None:
        collector, _ = self.make(tmp_path / "nowhere")
        assert collector.run_once().collected == 0


class TestSinks:
    def test_directory_sink_is_idempotent(self, tmp_path: Path) -> None:
        record = read_copy(tmp_path / "new" / journal_copy(tmp_path, mime()))
        sink = DirectorySink(tmp_path / "out")
        sink.deliver(record, mime())
        sink.deliver(record, mime())
        assert sorted(p.suffix for p in (tmp_path / "out").iterdir()) == [".eml", ".json"]

    def test_http_sink_rejects_other_schemes(self) -> None:
        for bad in ("file:///etc/passwd", "ftp://x", ""):
            with pytest.raises(ValueError, match="http"):
                HttpSink(bad, "t")

    def test_http_sink_sends_key_meta_and_token(self, tmp_path: Path) -> None:
        seen: dict[str, object] = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                seen["headers"] = {k.lower(): v for k, v in self.headers.items()}
                seen["path"] = self.path
                seen["body"] = self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(202)
                self.end_headers()

            def log_message(self, *_a: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            raw = mime()
            record = read_copy(tmp_path / "new" / journal_copy(tmp_path, raw))
            HttpSink(
                f"http://127.0.0.1:{server.server_address[1]}/ingest", "secret-token", node_id="n" * 32
            ).deliver(record, raw)
        finally:
            server.shutdown()
            server.server_close()
        headers = seen["headers"]
        assert headers["x-msp-idempotency-key"] == record.key  # type: ignore[index]
        assert headers["authorization"] == "Bearer secret-token"  # type: ignore[index]
        assert "secret-token" not in str(seen["path"])
        assert seen["body"] == raw
        assert headers["x-msp-direction"] == "INBOUND"  # type: ignore[index]
        assert headers["x-msp-node-id"] == "n" * 32  # type: ignore[index]
        assert headers["x-msp-message-id"] == "<a1@lab.example>"  # type: ignore[index]

    def test_server_error_is_a_failure_and_does_not_leak_the_token(self, tmp_path: Path) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.send_response(503)
                self.end_headers()

            def log_message(self, *_a: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            record = read_copy(tmp_path / "new" / journal_copy(tmp_path, mime()))
            sink = HttpSink(f"http://127.0.0.1:{server.server_address[1]}/ingest", "secret-token")
            with pytest.raises(OSError) as info:
                sink.deliver(record, mime())
            assert "secret-token" not in str(info.value)
        finally:
            server.shutdown()
            server.server_close()

    def test_failing_http_sink_keeps_the_copy(self, tmp_path: Path) -> None:
        name = journal_copy(tmp_path, mime())
        collector = Collector(tmp_path, HttpSink("http://127.0.0.1:9/x", "t", timeout=1))
        assert collector.run_once().failed == 1
        assert (tmp_path / "new" / name).exists()
