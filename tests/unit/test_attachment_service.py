"""Сервис песочницы через каталог-очередь (ТЗ 1.1 §55): задания, результаты, очистка."""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path

import pytest
from fixtures import attachments as make
from msp_attachment_sandbox import runner, service


@pytest.fixture
def spool(tmp_path: Path) -> Path:
    for directory in service.spool_dirs(tmp_path):
        directory.mkdir(parents=True)
    return tmp_path


class Serving:
    """Сервис в фоновом потоке — как контейнер, который крутит ``run_once`` в цикле."""

    def __init__(self, spool: Path) -> None:
        self.spool = spool
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self) -> None:
        while not self.stop.is_set():
            if service.run_once(self.spool) == 0:
                time.sleep(0.05)

    def __enter__(self) -> Serving:
        self.thread.start()
        return self

    def __exit__(self, *_a: object) -> None:
        self.stop.set()
        self.thread.join(timeout=5)


def submit(spool: Path, module: str, job: dict) -> runner.SandboxResult:  # type: ignore[type-arg]
    return runner.run_remote(spool, module, job, timeout=30)


class TestRoundtrip:
    def test_an_archive_listing_goes_through_the_spool(self, spool: Path) -> None:
        import base64

        data = make.make_7z({"a.txt": b"hello", "run.exe": b"MZ"})
        with Serving(spool):
            result = submit(
                spool, runner.ARCHIVE_WORKER, {"kind": "7z", "data": base64.b64encode(data).decode("ascii")}
            )
        assert result.status == "OK"
        assert {e["name"] for e in result.payload["entries"]} == {"a.txt", "run.exe"}

    def test_a_pdf_goes_through_the_spool(self, spool: Path) -> None:
        import base64

        data = make.pdf_with_embedded_qr("https://evil.example/x")
        with Serving(spool):
            result = submit(spool, runner.PDF_WORKER, {"data": base64.b64encode(data).decode("ascii")})
        assert result.status == "OK"
        assert result.payload["pages_rendered"] == 1

    def test_the_dispatcher_uses_the_spool_when_it_is_configured(self, spool: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setenv("MSP_SANDBOX_SPOOL", str(spool))
        with Serving(spool):
            result = runner.list_archive(make.make_7z({"a.txt": b"x"}), "7z")
        assert result.status == "OK"

    def test_nothing_is_left_behind(self, spool: Path) -> None:
        import base64

        with Serving(spool):
            submit(spool, runner.ARCHIVE_WORKER, {"kind": "7z", "data": base64.b64encode(b"junk").decode()})
        time.sleep(0.3)
        in_dir, out_dir, _ = service.spool_dirs(spool)
        assert list(in_dir.iterdir()) == []
        assert list(out_dir.iterdir()) == []


class TestTheServiceDoesNotTrustJobs:
    def run(self, spool: Path, job_id: str, content: str | bytes) -> dict:  # type: ignore[type-arg]
        in_dir, out_dir, _ = service.spool_dirs(spool)
        path = in_dir / f"{job_id}.job"
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
        assert service.process_job(path, out_dir) is True
        return json.loads((out_dir / f"{job_id}.res").read_text(encoding="utf-8"))

    def test_an_unknown_worker_is_not_started(self, spool: Path) -> None:
        for module in ("os", "subprocess", "msp_attachment_sandbox.service", "../../etc/passwd", ""):
            result = self.run(spool, uuid.uuid4().hex, json.dumps({"module": module, "job": {}}))
            assert result["status"] == "PROTOCOL_ERROR", module

    @pytest.mark.parametrize(
        "body", ["not json", "[]", "null", '{"module": 1}', '{"job": {}}', b"\xff\xfe\x00"]
    )
    def test_malformed_jobs_get_an_answer_not_a_crash(self, spool: Path, body) -> None:  # type: ignore[no-untyped-def]
        assert self.run(spool, uuid.uuid4().hex, body)["status"] == "PROTOCOL_ERROR"

    def test_an_oversized_job_is_a_named_limit(self, spool: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr(service, "MAX_JOB_BYTES", 100)
        result = self.run(
            spool, uuid.uuid4().hex, json.dumps({"module": runner.PDF_WORKER, "job": {"data": "A" * 500}})
        )
        assert result["status"] == "LIMIT_EXCEEDED"

    @pytest.mark.parametrize(
        "name", ["../x.job", "x.job", "a" * 31 + ".job", "A" * 32 + ".job", "z" * 32 + ".job", "id.txt"]
    )
    def test_files_that_are_not_valid_job_names_are_ignored(self, spool: Path, name: str) -> None:
        in_dir, out_dir, _ = service.spool_dirs(spool)
        safe = in_dir / name.replace("/", "_")
        safe.write_text("{}", encoding="utf-8")
        assert service.process_job(safe, out_dir) is False
        assert list(out_dir.iterdir()) == []

    def test_a_crashing_worker_does_not_stop_the_service(self, spool: Path) -> None:
        import base64

        in_dir, out_dir, _ = service.spool_dirs(spool)
        for _ in range(3):
            job_id = uuid.uuid4().hex
            (in_dir / f"{job_id}.job").write_text(
                json.dumps(
                    {"module": runner.PDF_WORKER, "job": {"data": base64.b64encode(b"%PDF-1.4 x").decode()}}
                ),
                encoding="utf-8",
            )
        assert service.run_once(spool) == 3
        assert len(list(out_dir.iterdir())) == 3


class TestFailures:
    def test_a_dead_service_is_a_timeout_not_a_silent_local_run(self, spool: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setenv("MSP_SANDBOX_SPOOL", str(spool))
        started = time.monotonic()
        result = runner.run_worker(runner.ARCHIVE_WORKER, {"kind": "7z", "data": ""}, timeout=0.2)
        assert result.status == "TIMEOUT"
        assert time.monotonic() - started < 15
        in_dir, _, _ = service.spool_dirs(spool)
        assert list(in_dir.iterdir()) == [], "невзятое задание убирается"

    def test_a_missing_spool_is_unavailable(self, tmp_path: Path) -> None:
        result = runner.run_remote(tmp_path / "nowhere", runner.PDF_WORKER, {}, timeout=1)
        assert result.status == "UNAVAILABLE"

    def test_unclaimed_results_and_foreign_files_are_swept(self, spool: Path) -> None:
        in_dir, out_dir, _ = service.spool_dirs(spool)
        stale_result = out_dir / f"{uuid.uuid4().hex}.res"
        stale_result.write_text("{}", encoding="utf-8")
        foreign = in_dir / "junk.bin"
        foreign.write_text("x", encoding="utf-8")
        old = time.time() - service.RESULT_TTL - 10
        for path in (stale_result, foreign):
            os.utime(path, (old, old))
        fresh = out_dir / f"{uuid.uuid4().hex}.res"
        fresh.write_text("{}", encoding="utf-8")
        service.run_once(spool)
        assert not stale_result.exists()
        assert not foreign.exists()
        assert fresh.exists()

    def test_a_job_survives_a_service_restart(self, spool: Path) -> None:
        import base64

        data = make.make_7z({"a.txt": b"x"})
        results: list[runner.SandboxResult] = []
        client = threading.Thread(
            target=lambda: results.append(
                submit(spool, runner.ARCHIVE_WORKER, {"kind": "7z", "data": base64.b64encode(data).decode()})
            )
        )
        client.start()
        time.sleep(1.0)  # сервис ещё не запущен: задание лежит в очереди
        in_dir, _, _ = service.spool_dirs(spool)
        assert len(list(in_dir.iterdir())) == 1
        with Serving(spool):
            client.join(timeout=30)
        assert results and results[0].status == "OK"
