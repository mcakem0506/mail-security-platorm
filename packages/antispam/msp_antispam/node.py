"""Узловой инструмент сканера Rspamd: выпуск конфигурации, состояние, приёмник результатов.

Запускается внутри контейнера ``rspamd`` (``python3 -m msp_antispam.node``). Использует только
стандартную библиотеку и пакет ``msp_antispam``, у которого есть одна внешняя зависимость —
pydantic; она ставится в образ вместе с пакетом.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import socket
import subprocess  # nosec B404 - вызывается только rspamadm по фиксированному пути
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from .rspamd_config import (
    ReleaseStore,
    RspamdNodeConfig,
    apply_release,
)

ROOT = Path(os.environ.get("MSP_RSPAMD_ROOT", "/var/lib/msp-rspamd"))
ENTRY_CONFIG = os.environ.get("MSP_RSPAMD_ENTRY", "/opt/msp-rspamd/rspamd.conf")
RSPAMADM = os.environ.get("MSP_RSPAMADM", "/usr/bin/rspamadm")
CONTROLLER = os.environ.get("MSP_RSPAMD_CONTROLLER", "http://127.0.0.1:11334")
PID_FILE = os.environ.get("MSP_RSPAMD_PID", "/run/rspamd/rspamd.pid")


_FATAL_LINE = re.compile(
    r"init of .* failed|cannot register|No such (formatter|selector)|has no backend|invalid backend|"
    r"failed to load|ucl parser error",
    re.IGNORECASE,
)


def configtest(staged: Path) -> tuple[bool, str]:
    result = subprocess.run(  # noqa: S603  # nosec B603
        [RSPAMADM, f"--var=LOCAL_CONFDIR={staged}", "configtest", "-c", ENTRY_CONFIG],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    output = (result.stdout + result.stderr).strip().splitlines()
    ok = result.returncode == 0 and any(line.strip() == "syntax OK" for line in output)
    # «syntax OK» не означает, что модули загрузились: сканер отдельно пишет об отказе инициализации
    # модуля, о неизвестном форматтере и о невозможной зависимости. Для выпуска это тоже отказ.
    for line in output:
        if _FATAL_LINE.search(line):
            return False, line.strip()
    return ok, output[-1] if output else ""


def reload_rspamd() -> None:
    try:
        pid = int(Path(PID_FILE).read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return  # сканер ещё не запущен: он прочитает выпуск при старте
    os.kill(pid, 1)  # SIGHUP


def tcp_alive(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3):
            return True
    except OSError:
        return False


def healthcheck() -> bool:
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if tcp_alive(11332) and tcp_alive(11333):
            try:
                with urllib.request.urlopen(f"{CONTROLLER}/ping", timeout=3) as response:  # noqa: S310  # nosec B310
                    if response.read().strip() == b"pong":
                        return True
            except (OSError, urllib.error.URLError):
                pass
        time.sleep(1)
    return False


def cmd_apply(args: argparse.Namespace) -> int:
    cfg = RspamdNodeConfig.model_validate_json(Path(args.config).read_text(encoding="utf-8"))
    store = ReleaseStore(ROOT)
    started = tcp_alive(11332)
    outcome = apply_release(
        store,
        cfg,
        configtest=configtest,
        reload=reload_rspamd,
        # До первого запуска сканера проверять нечего: проверка здоровья имеет смысл после reload.
        healthcheck=healthcheck if started else (lambda: True),
    )
    print(
        json.dumps(
            {"outcome": outcome.outcome, "config_version": outcome.config_version, "detail": outcome.detail}
        )
    )
    return 0 if outcome.outcome == "ACTIVE" else 2


def cmd_status(_: argparse.Namespace) -> int:
    store = ReleaseStore(ROOT)
    version = store.active_version()
    manifest = {}
    if version:
        with contextlib.suppress(OSError, ValueError):
            manifest = json.loads(
                (store.releases / version / store.manifest_name).read_text(encoding="utf-8")
            )
    print(
        json.dumps(
            {
                "active": version,
                "checksum": manifest.get("checksum"),
                "intact": bool(version and store.verify(version)),
                "proxy_inbound": tcp_alive(11332),
                "proxy_outbound": tcp_alive(11333),
            }
        )
    )
    return 0


# ---------------------------------------------------------------------------------------------
# Приёмник результатов сканирования
# ---------------------------------------------------------------------------------------------
MAX_RECORD = 1024 * 1024
OUTBOX_LIMIT = 5000


class Receiver:
    """TCP-приёмник результатов Rspamd (json_raw_tcp). Хранит их в папке и пересылает панели.

    Сбой панели не касается сканирования и доставки: записи ждут в папке (не больше предела,
    самые старые отбрасываются и считаются).
    """

    def __init__(self, directory: Path, panel_url: str | None, token: str | None) -> None:
        self.directory = directory
        self.panel_url = panel_url
        self.token = token
        self.dropped = 0
        self.received = 0
        self.sent = 0
        self.directory.mkdir(parents=True, exist_ok=True)

    def accept(self, payload: bytes) -> bool:
        try:
            record = json.loads(payload)
        except ValueError:
            return False
        if not isinstance(record, dict):
            return False
        self.received += 1
        name = f"{time.time_ns()}.json"
        (self.directory / name).write_text(json.dumps(record), encoding="utf-8")
        files = sorted(self.directory.glob("*.json"))
        for stale in files[: max(0, len(files) - OUTBOX_LIMIT)]:
            stale.unlink(missing_ok=True)
            self.dropped += 1
        return True

    def flush(self) -> int:
        if not self.panel_url:
            return 0
        sent = 0
        for path in sorted(self.directory.glob("*.json"))[:100]:
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                path.unlink(missing_ok=True)
                continue
            body = json.dumps({"scans": [record]}).encode()
            request = urllib.request.Request(  # noqa: S310
                self.panel_url,
                data=body,
                method="POST",
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"},
            )
            try:
                with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310  # nosec B310
                    if response.status >= 300:
                        break
            except (OSError, urllib.error.URLError):
                break
            path.unlink(missing_ok=True)
            sent += 1
            self.sent += 1
        return sent


def serve_receiver(receiver: Receiver, host: str, port: int) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(32)

    def handle(conn: socket.socket) -> None:
        with conn:
            conn.settimeout(5)
            chunks: list[bytes] = []
            size = 0
            try:
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    size += len(data)
                    if size > MAX_RECORD:
                        return
                    chunks.append(data)
            except OSError:
                pass
            receiver.accept(b"".join(chunks))

    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def cmd_collector(args: argparse.Namespace) -> int:
    token = None
    if args.token_file:
        with contextlib.suppress(OSError):
            token = Path(args.token_file).read_text(encoding="utf-8").strip()
    receiver = Receiver(Path(args.outbox), args.panel_url or None, token)
    threading.Thread(target=serve_receiver, args=(receiver, args.listen, args.port), daemon=True).start()
    while True:
        receiver.flush()
        time.sleep(args.interval)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="msp_antispam.node")
    sub = parser.add_subparsers(dest="command", required=True)
    apply = sub.add_parser("apply")
    apply.add_argument("--config", required=True)
    apply.set_defaults(func=cmd_apply)
    status = sub.add_parser("status")
    status.set_defaults(func=cmd_status)
    collector = sub.add_parser("collector")
    collector.add_argument("--listen", default="127.0.0.1")  # nosec B104 - приёмник слушает только loopback
    collector.add_argument("--port", type=int, default=11380)
    collector.add_argument("--outbox", default="/var/lib/msp-rspamd/outbox")
    collector.add_argument("--panel-url", default=os.environ.get("MSP_PANEL_SPAM_URL", ""))
    collector.add_argument("--token-file", default=os.environ.get("MSP_PANEL_TOKEN_FILE", ""))
    collector.add_argument("--interval", type=float, default=2.0)
    collector.set_defaults(func=cmd_collector)
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
