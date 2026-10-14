"""Синхронизация узла с панелью (ТЗ 1.1 §37–§40): недоступная панель ничего не ломает."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from msp_gateway.apply import ApplyResult, Outcome, Stage
from msp_gateway.panelsync import PanelError, detect_drift, http_fetch, sync_once
from msp_gateway.state import is_draining

NODE = "a" * 32


class Store:
    def __init__(self, active: str | None = None, disk: str | None = None) -> None:
        self._active, self._disk = active, disk

    def active_checksum(self) -> str | None:
        return self._active

    def drift_checksum(self) -> str | None:
        return self._disk


def reply(
    version: int = 2, checksum: str = "c2", *, drain: bool = False, recipients: object = None
) -> dict[str, Any]:
    manifest: dict[str, Any] = {"version": version, "checksum": checksum, "files": ["main.cf"]}
    if recipients is not None:
        manifest["recipients"] = recipients
    return {"version": version, "drain": drain, "bundle": {"files": {"main.cf": "x\n"}, "manifest": manifest}}


class Recorder:
    def __init__(self, outcome: Outcome = Outcome.ACTIVE) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []
        self.applied: list[dict[str, Any]] = []
        self.outcome = outcome

    def report(self, kind: str, data: dict[str, object]) -> None:
        self.events.append((kind, data))

    def apply(self, files: dict[str, bytes], manifest: dict[str, Any]) -> ApplyResult:
        self.applied.append(manifest)
        return ApplyResult(self.outcome, Stage.DONE, "сообщение", steps=[])


def run(
    tmp_path: Path, data: dict[str, Any] | Exception, store: Store | None = None, rec: Recorder | None = None
):  # type: ignore[no-untyped-def]
    rec = rec or Recorder()
    drains: list[bool] = []

    def fetch() -> dict[str, Any]:
        if isinstance(data, Exception):
            raise data
        return data

    result = sync_once(
        fetch, store or Store("c1"), tmp_path, rec.apply, rec.report, drain_setter=drains.append
    )  # type: ignore[arg-type]
    return result, rec, drains


class TestConfiguration:
    def test_a_new_checksum_is_applied_and_reported(self, tmp_path: Path) -> None:
        result, rec, _ = run(tmp_path, reply(2, "c2"))
        assert result.applied is True
        assert [m["checksum"] for m in rec.applied] == ["c2"]
        assert rec.events[-1][0] == "config_applied"
        assert rec.events[-1][1]["outcome"] == "ACTIVE"

    def test_the_same_checksum_is_not_applied_again(self, tmp_path: Path) -> None:
        """Иначе каждый опрос перезагружал бы Postfix."""
        result, rec, _ = run(tmp_path, reply(1, "c1"), Store("c1"))
        assert result.applied is False
        assert rec.applied == []
        assert rec.events == []

    def test_a_failed_apply_is_reported_with_its_outcome(self, tmp_path: Path) -> None:
        result, rec, _ = run(tmp_path, reply(3, "c3"), rec=Recorder(Outcome.ROLLED_BACK))
        assert result.applied is False
        assert result.outcome == "ROLLED_BACK"
        assert rec.events[-1][1]["outcome"] == "ROLLED_BACK"

    def test_recipient_age_metadata_follows_a_successful_apply(self, tmp_path: Path) -> None:
        meta = {"generated_at": "2026-10-14T10:00:00+00:00", "recipient_count": 5}
        run(tmp_path, reply(2, "c2", recipients=meta))
        assert (
            json.loads((tmp_path / "recipients.meta.json").read_text(encoding="utf-8"))["recipient_count"]
            == 5
        )

    def test_recipient_age_is_not_refreshed_by_a_failed_apply(self, tmp_path: Path) -> None:
        meta = {"generated_at": "2026-10-14T10:00:00+00:00", "recipient_count": 5}
        run(tmp_path, reply(2, "c2", recipients=meta), rec=Recorder(Outcome.FAILED))
        assert not (tmp_path / "recipients.meta.json").exists()

    def test_no_bundle_means_nothing_to_do(self, tmp_path: Path) -> None:
        result, rec, _ = run(tmp_path, {"version": None, "bundle": None, "drain": False})
        assert (result.applied, rec.applied) == (False, [])

    @pytest.mark.parametrize(
        "bad",
        [
            {"bundle": {"files": "x", "manifest": {}}},
            {"bundle": {"files": {"main.cf": 5}, "manifest": {"checksum": "z"}}},
            {"bundle": {"files": {5: "x"}, "manifest": {"checksum": "z"}}},
            {"bundle": {"files": {}, "manifest": []}},
            {"bundle": {"files": {}}},
        ],
    )
    def test_a_malformed_bundle_is_rejected_without_touching_the_node(
        self, tmp_path: Path, bad: dict[str, Any]
    ) -> None:
        result, rec, _ = run(tmp_path, bad)
        assert result.applied is False
        assert rec.applied == []
        assert rec.events[-1][1]["outcome"] == "REJECTED"


class TestPanelUnavailable:
    def test_nothing_changes_and_nothing_is_reported_as_an_error_of_the_node(self, tmp_path: Path) -> None:
        result, rec, drains = run(tmp_path, PanelError("панель недоступна"))
        assert result.panel_reachable is False
        assert (rec.applied, rec.events, drains) == ([], [], [])

    def test_drain_state_is_kept_as_it_was(self, tmp_path: Path) -> None:
        from msp_gateway.state import set_drain

        set_drain(True, state_dir=tmp_path, reload=False)
        run(tmp_path, PanelError("x"))
        assert is_draining(tmp_path) is True, "связь пропала — слив не отменяется сам"


class TestDrain:
    def test_drain_command_is_executed_and_reported(self, tmp_path: Path) -> None:
        _, rec, drains = run(tmp_path, {**reply(1, "c1"), "drain": True}, Store("c1"))
        assert drains == [True]
        assert rec.events == [("drain", {"draining": True})]

    def test_a_repeated_command_does_nothing(self, tmp_path: Path) -> None:
        from msp_gateway.state import set_drain

        set_drain(True, state_dir=tmp_path, reload=False)
        _, _, drains = run(tmp_path, {**reply(1, "c1"), "drain": True}, Store("c1"))
        assert drains == []

    def test_drain_does_not_wait_for_the_configuration(self, tmp_path: Path) -> None:
        """Слив исполняется, даже если пакет в том же ответе повреждён."""
        _, _, drains = run(tmp_path, {"drain": True, "bundle": {"files": "broken", "manifest": {}}})
        assert drains == [True]

    @pytest.mark.parametrize("value", ["yes", 1, None, [True]])
    def test_non_boolean_drain_values_are_ignored(self, tmp_path: Path, value: object) -> None:
        _, _, drains = run(tmp_path, {**reply(1, "c1"), "drain": value}, Store("c1"))
        assert drains == []


class TestDrift:
    def test_equal_checksums_mean_no_drift(self) -> None:
        assert detect_drift(Store("abc", "abc")) is None  # type: ignore[arg-type]

    def test_different_checksums_are_reported(self) -> None:
        assert detect_drift(Store("abc", "xyz")) == {"expected": "abc", "found": "xyz"}  # type: ignore[arg-type]

    def test_unknown_state_is_not_drift(self) -> None:
        assert detect_drift(Store(None, None)) is None  # type: ignore[arg-type]


class TestHttpFetch:
    def serve(self, handler_body: bytes, status: int = 200):  # type: ignore[no-untyped-def]
        seen: dict[str, str] = {}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                seen["path"] = self.path
                seen["auth"] = self.headers.get("Authorization", "")
                self.send_response(status)
                self.end_headers()
                self.wfile.write(handler_body)

            def log_message(self, *_a: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, seen

    def test_token_goes_in_the_header_not_the_url(self) -> None:
        server, seen = self.serve(b'{"drain": false}')
        try:
            data = http_fetch(f"http://127.0.0.1:{server.server_address[1]}/api", "secret-token", NODE)()
        finally:
            server.shutdown()
            server.server_close()
        assert data == {"drain": False}
        assert seen["auth"] == "Bearer secret-token"
        assert "secret-token" not in seen["path"]
        assert f"node_id={NODE}" in seen["path"]

    @pytest.mark.parametrize("body", [b"not json", b"[1, 2]", b'"text"'])
    def test_unusable_answers_are_panel_errors(self, body: bytes) -> None:
        server, _ = self.serve(body)
        try:
            with pytest.raises(PanelError):
                http_fetch(f"http://127.0.0.1:{server.server_address[1]}/api", "t", NODE)()
        finally:
            server.shutdown()
            server.server_close()

    def test_http_errors_and_dead_ports_are_panel_errors_without_the_token(self) -> None:
        server, _ = self.serve(b"", status=503)
        try:
            with pytest.raises(PanelError) as info:
                http_fetch(f"http://127.0.0.1:{server.server_address[1]}/api", "secret-token", NODE)()
        finally:
            server.shutdown()
            server.server_close()
        assert "secret-token" not in str(info.value)
        with pytest.raises(PanelError):
            http_fetch("http://127.0.0.1:9/api", "secret-token", NODE, timeout=1)()

    def test_only_http_urls_are_allowed(self) -> None:
        for bad in ("file:///etc/passwd", "ftp://x", ""):
            with pytest.raises(ValueError, match="http"):
                http_fetch(bad, "t", NODE)
