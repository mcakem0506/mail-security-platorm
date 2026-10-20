"""Контейнер песочницы вложений на живом Docker (ТЗ 1.1 §55, §68.19–§68.22).

Юнит-тесты проверяют воркеры, а не то, что из них собрано. Здесь проверяется сам контейнер с теми
же параметрами изоляции, что в ``compose.yml``: без сети, не от root, с файловой системой только
для чтения, — и что через него действительно проходят задания, в том числе враждебные.
"""

from __future__ import annotations

import base64
import json
import stat
import time
import uuid
from pathlib import Path

import pytest

from .harness import docker

IMAGE = "msp-attachment-sandbox:test"
REPO = Path(__file__).resolve().parents[2]

pytest.importorskip("msp_attachment_sandbox")


@pytest.fixture(scope="module")
def sandbox(tmp_path_factory):  # type: ignore[no-untyped-def]
    docker(
        "build",
        "-f",
        str(REPO / "infrastructure/compose/Dockerfile.sandbox"),
        "-t",
        IMAGE,
        str(REPO),
        timeout=1800,
    )
    spool = tmp_path_factory.mktemp("sandbox-spool")
    for name in ("", "in", "out", "work"):
        directory = spool / name if name else spool
        directory.mkdir(exist_ok=True)
        directory.chmod(0o777)
    name = f"sbx{uuid.uuid4().hex[:8]}"
    docker(
        "run",
        "-d",
        "--name",
        name,
        "--network",
        "none",
        "--read-only",
        "--user",
        "10004:10004",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "64",
        "--memory",
        "3g",
        "--tmpfs",
        "/tmp:size=64m,noexec,nosuid",
        "-v",
        f"{spool}:/spool",
        IMAGE,
        timeout=120,
    )
    deadline = time.time() + 60
    while time.time() < deadline and not (spool / "work" / "alive").exists():
        time.sleep(0.5)
    try:
        yield name, spool
    finally:
        logs = docker("logs", name, check=False).stdout[-2000:]
        docker("rm", "-f", name, check=False)
        if logs.strip():
            print("--- журнал песочницы ---\n" + logs)


def submit(spool: Path, module: str, job: dict, timeout: float = 60):  # type: ignore[no-untyped-def,type-arg]
    from msp_attachment_sandbox import runner

    return runner.run_remote(spool, module, job, timeout=timeout)


def archive_job(data: bytes, kind: str = "7z") -> dict:  # type: ignore[type-arg]
    return {"kind": kind, "data": base64.b64encode(data).decode("ascii")}


def run_in(name: str, *command: str):  # type: ignore[no-untyped-def]
    return docker("exec", name, *command, check=False, timeout=60)


class TestTheContainerIsIsolated:
    def test_it_runs_as_an_unprivileged_user(self, sandbox) -> None:  # type: ignore[no-untyped-def]
        name, _ = sandbox
        assert run_in(name, "id", "-u").stdout.strip() == "10004"

    def test_it_has_no_network_at_all(self, sandbox) -> None:  # type: ignore[no-untyped-def]
        name, _ = sandbox
        info = json.loads(docker("inspect", name).stdout)[0]
        assert info["HostConfig"]["NetworkMode"] == "none"
        interfaces = run_in(name, "python", "-c", "print(open('/proc/net/dev').read())").stdout
        names = [line.split(":")[0].strip() for line in interfaces.splitlines() if ":" in line]
        assert [n for n in names if n and n != "lo"] == []
        probe = run_in(
            name,
            "python",
            "-c",
            "import socket\n"
            "try:\n"
            "    socket.create_connection(('1.1.1.1', 53), timeout=3)\n"
            "    print('CONNECTED')\n"
            "except OSError as e:\n"
            "    print('BLOCKED', type(e).__name__)\n",
        )
        assert "BLOCKED" in probe.stdout, probe.stdout + probe.stderr

    def test_the_root_filesystem_is_read_only(self, sandbox) -> None:  # type: ignore[no-untyped-def]
        name, _ = sandbox
        info = json.loads(docker("inspect", name).stdout)[0]
        assert info["HostConfig"]["ReadonlyRootfs"] is True
        probe = run_in(name, "python", "-c", "open('/etc/evil', 'w')")
        assert probe.returncode != 0
        assert "Read-only file system" in probe.stderr

    def test_the_workspace_in_memory_does_not_allow_execution(self, sandbox) -> None:  # type: ignore[no-untyped-def]
        name, _ = sandbox
        script = (
            "import os\n"
            "p = '/tmp/x.sh'\n"
            "open(p, 'w').write('#!/bin/sh\\necho hi\\n'); os.chmod(p, 0o755)\n"
            "os.execv(p, [p])\n"
        )
        probe = run_in(name, "python", "-c", script)
        assert probe.returncode != 0, "из рабочего каталога ничего не запускается"

    def test_no_capabilities(self, sandbox) -> None:  # type: ignore[no-untyped-def]
        name, _ = sandbox
        status = run_in(name, "python", "-c", "print(open('/proc/self/status').read())").stdout
        effective = next(line for line in status.splitlines() if line.startswith("CapEff"))
        assert effective.split()[-1].strip("0") == ""

    def test_the_container_is_healthy(self, sandbox) -> None:  # type: ignore[no-untyped-def]
        name, _ = sandbox
        deadline = time.time() + 90
        state = ""
        while time.time() < deadline:
            state = docker("inspect", "-f", "{{.State.Health.Status}}", name).stdout.strip()
            if state == "healthy":
                break
            time.sleep(3)
        assert state == "healthy"


class TestJobsThroughTheContainer:
    def test_an_archive_listing(self, sandbox) -> None:  # type: ignore[no-untyped-def]
        from fixtures import attachments as make
        from msp_attachment_sandbox import runner

        _, spool = sandbox
        result = submit(
            spool, runner.ARCHIVE_WORKER, archive_job(make.make_7z({"a.txt": b"hi", "x.exe": b"MZ"}))
        )
        assert result.status == "OK"
        assert {e["name"] for e in result.payload["entries"]} == {"a.txt", "x.exe"}

    def test_a_pdf_with_a_qr_code(self, sandbox) -> None:  # type: ignore[no-untyped-def]
        from fixtures import attachments as make
        from msp_attachment_sandbox import page_images, runner
        from msp_mail_parser.images import decode_images

        _, spool = sandbox
        data = make.pdf_with_vector_qr("https://evil.example/in-container")
        result = submit(spool, runner.PDF_WORKER, {"data": base64.b64encode(data).decode("ascii")})
        assert result.status == "OK", result.detail
        decoded, _ = decode_images(page_images(result, "x.pdf"))
        assert "https://evil.example/in-container" in [p for ps in decoded.values() for p in ps]

    def test_the_worker_limits_hold_inside_the_container(self, sandbox) -> None:  # type: ignore[no-untyped-def]
        from msp_attachment_sandbox import runner

        _, spool = sandbox
        result = submit(spool, runner.ARCHIVE_WORKER, archive_job(b"junk", "7z"))
        limits = result.payload.get("limits", {})
        assert limits.get("applied") is True
        assert limits.get("non_root") is True, "воркер в контейнере обязан быть непривилегированным"
        assert limits.get("RLIMIT_FSIZE") == 0
        assert limits.get("RLIMIT_NPROC") == 0

    def test_hostile_inputs_do_not_stop_the_service(self, sandbox) -> None:  # type: ignore[no-untyped-def]
        from fixtures import attachments as make
        from msp_attachment_sandbox import runner

        _, spool = sandbox
        pdf_bomb = make._pdf(  # type: ignore[attr-defined]
            [
                b"<< /Type /Catalog /Pages 2 0 R >>",
                b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 600 800] /Contents 4 0 R "
                b"/Resources << /XObject << /Im0 5 0 R >> >> >>",
                make._stream(b"", b"q 600 0 0 800 0 0 cm /Im0 Do Q"),  # type: ignore[attr-defined]
                make._stream(  # type: ignore[attr-defined]
                    b"/Type /XObject /Subtype /Image /Width 60000 /Height 60000 /ColorSpace /DeviceGray "
                    b"/BitsPerComponent 8 /Filter /FlateDecode",
                    __import__("zlib").compress(b"\0" * 1024 * 1024),
                ),
            ]
        )
        hostile = [
            (runner.PDF_WORKER, {"data": base64.b64encode(pdf_bomb).decode()}),
            (runner.PDF_WORKER, {"data": base64.b64encode(b"%PDF-1.4" + b"\xff" * 5000).decode()}),
            (runner.ARCHIVE_WORKER, archive_job(make.make_7z({"z": b"\0" * (52 * 1024 * 1024)}))),
            (runner.ARCHIVE_WORKER, archive_job(b"Rar!\x1a\x07\x01\x00" + b"\xff" * 4000, "rar")),
            (runner.ARCHIVE_WORKER, archive_job(make.random_bytes(200_000), "7z")),
        ]
        for module, job in hostile:
            result = submit(spool, module, job, timeout=90)
            assert result.status in {"OK", "PARTIAL", "MALFORMED", "LIMIT_EXCEEDED", "CRASHED", "TIMEOUT"}
            assert result.status != "UNAVAILABLE"
        # после всего этого сервис отвечает на обычное задание
        after = submit(spool, runner.ARCHIVE_WORKER, archive_job(make.make_7z({"ok.txt": b"x"})))
        assert after.status == "OK"

    def test_nothing_is_left_in_the_queue(self, sandbox) -> None:  # type: ignore[no-untyped-def]
        _, spool = sandbox
        time.sleep(1.0)
        assert list((spool / "in").iterdir()) == []
        assert list((spool / "out").iterdir()) == []

    def test_the_spool_is_the_only_writable_place(self, sandbox) -> None:  # type: ignore[no-untyped-def]
        name, spool = sandbox
        mounts = json.loads(docker("inspect", name).stdout)[0]["Mounts"]
        writable = [m["Destination"] for m in mounts if m.get("RW")]
        assert writable == ["/spool"]
        assert stat.S_ISDIR((spool / "in").stat().st_mode)
