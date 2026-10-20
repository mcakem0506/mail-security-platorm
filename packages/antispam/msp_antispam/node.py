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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .metrics import ScanMetrics
from .overlay import merge
from .rspamd_config import (
    ConfigError,
    ReleaseStore,
    RspamdNodeConfig,
    apply_release,
    drift_state,
    render,
)

ROOT = Path(os.environ.get("MSP_RSPAMD_ROOT", "/var/lib/msp-rspamd"))
ENTRY_CONFIG = os.environ.get("MSP_RSPAMD_ENTRY", "/opt/msp-rspamd/rspamd.conf")
BASE_CONFIG = os.environ.get("MSP_RSPAMD_BASE", "/bootstrap/rspamd.json")
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


def rspamd_pid() -> int | None:
    """PID главного процесса. В режиме без форка файла PID нет, поэтому процесс ищется по названию."""
    try:
        return int(Path(PID_FILE).read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        pass
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            title = (entry / "cmdline").read_bytes().split(b"\x00")[0].decode("utf-8", "replace")
        except OSError:
            continue
        if title.startswith("rspamd: main process"):
            return int(entry.name)
    return None


def reload_rspamd() -> None:
    pid = rspamd_pid()
    if pid is None:
        return  # сканер ещё не запущен: он прочитает выпуск при старте
    os.kill(pid, 1)  # SIGHUP


def config_id() -> str:
    """Признак загруженной конфигурации: набор PID прокси-воркеров.

    При SIGHUP сканер запускает новых воркеров с новой конфигурацией, поэтому смена набора PID —
    надёжный признак перезагрузки. ``config_id`` из статистики контроллера для этого не годится:
    он не обновляется при горячей перезагрузке.
    """
    pids: list[str] = []
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                title = (entry / "cmdline").read_bytes().split(b"\x00")[0].decode("utf-8", "replace")
            except OSError:
                continue
            if title.startswith("rspamd: rspamd_proxy process"):
                pids.append(entry.name)
    except OSError:
        return ""
    return ",".join(sorted(pids))


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


def _rspamd_version() -> str:
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603
            [os.environ.get("MSP_RSPAMD_BIN", "/usr/bin/rspamd"), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    match = re.search(r"version\s+([0-9][0-9.]*)", result.stdout)
    return match.group(1) if match else ""


def cmd_apply(args: argparse.Namespace) -> int:
    cfg = RspamdNodeConfig.model_validate_json(Path(args.config).read_text(encoding="utf-8"))
    store = ReleaseStore(ROOT)
    started = tcp_alive(11332)
    before = config_id() if started else ""
    unchanged = ReleaseStore(ROOT).active_version() == render(cfg).config_version

    def verified() -> bool:
        # Перезагрузка считается выполненной, когда сканер отвечает И загрузил другую конфигурацию.
        if not healthcheck():
            return False
        if not before or unchanged:
            return True
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            current = config_id()
            # Все прежние воркеры ушли: пока хоть один живёт, он может принять письмо по старой конфигурации
            # (на медленной машине первые письма после перезагрузки иначе обрабатывает прежняя).
            if current and not (set(current.split(",")) & set(before.split(","))):
                return True
            time.sleep(1)
        return False

    outcome = apply_release(
        store,
        cfg,
        configtest=configtest,
        reload=reload_rspamd,
        # До первого запуска сканера проверять нечего: проверка здоровья имеет смысл после reload.
        healthcheck=verified if started else (lambda: True),
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

    def __init__(self, directory: Path, panel_url: str | None, token: str | None, node_id: str = "") -> None:
        self.directory = directory
        self.panel_url = panel_url
        self.token = token
        self.node_id = node_id
        self.metrics = ScanMetrics()
        self.dropped = 0
        self.received = 0
        self.sent = 0
        self.rspamd_version = _rspamd_version()
        self.directory.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def config_version() -> str:
        try:
            return ReleaseStore(ROOT).active_version() or ""
        except OSError:
            return ""

    @staticmethod
    def advisory_thresholds() -> dict[str, float]:
        """Пороги предложения действия из активного выпуска (в Rspamd они недостижимы)."""
        try:
            raw = json.loads(
                (ReleaseStore(ROOT).active_link / "msp-advisory.json").read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            return {}
        if not isinstance(raw, dict):
            return {}
        return {
            k: float(v)
            for k, v in raw.items()
            if k in ("greylist", "add_header", "reject") and isinstance(v, (int, float))
        }

    def accept(self, payload: bytes) -> bool:
        try:
            record = json.loads(payload)
        except ValueError:
            return False
        if not isinstance(record, dict):
            self.metrics.error()
            return False
        self.received += 1
        self.metrics.observe(record)
        # Происхождение записи: версия выпуска и сканера, под которыми она получена (ТЗ 1.2 §27).
        record["_msp"] = {
            "received_at": time.time(),
            "config_version": self.config_version(),
            "rspamd_version": self.rspamd_version,
            "advisory_thresholds": self.advisory_thresholds(),
        }
        name = f"{time.time_ns()}-{self.received:08d}.json"
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
            body = json.dumps({"node_id": self.node_id, "scans": [record]}).encode()
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


class _MetricsHandler(BaseHTTPRequestHandler):
    receiver: Receiver

    def do_GET(self) -> None:
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return
        self.receiver.metrics.set_health(up=tcp_alive(11332) and tcp_alive(11333), redis_up=_redis_alive())
        body = self.receiver.metrics.render().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


def _redis_alive() -> bool:
    try:
        base = RspamdNodeConfig.model_validate_json(Path(BASE_CONFIG).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if base.redis is None:
        return False
    try:
        with socket.create_connection((base.redis.host, base.redis.port), timeout=2):
            return True
    except OSError:
        return False


def serve_metrics(receiver: Receiver, host: str, port: int) -> None:
    handler = type("Handler", (_MetricsHandler,), {"receiver": receiver})
    ThreadingHTTPServer((host, port), handler).serve_forever()


def cmd_collector(args: argparse.Namespace) -> int:
    token = None
    if args.token_file:
        with contextlib.suppress(OSError):
            token = Path(args.token_file).read_text(encoding="utf-8").strip()
    receiver = Receiver(Path(args.outbox), args.panel_url or None, token, args.node_id)
    threading.Thread(target=serve_receiver, args=(receiver, args.listen, args.port), daemon=True).start()
    threading.Thread(
        target=serve_metrics, args=(receiver, args.metrics_host, args.metrics_port), daemon=True
    ).start()
    while True:
        receiver.flush()
        time.sleep(args.interval)


def _panel_request(url: str, token: str, *, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(  # noqa: S310
        url,
        data=data,
        method="POST" if body is not None else "GET",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310  # nosec B310
        return json.loads(response.read())


def sync_once(panel_url: str, token: str, node_id: str, last: dict) -> dict:
    """Забрать назначение панели, свести с локальной конфигурацией, применить, сообщить итог."""
    base = RspamdNodeConfig.model_validate_json(Path(BASE_CONFIG).read_text(encoding="utf-8"))
    state: dict = {
        "up": tcp_alive(11332) and tcp_alive(11333),
        "redis_up": _redis_alive(),
        "version": _rspamd_version(),
    }
    try:
        overlay = _panel_request(f"{panel_url}/rspamd-config", token)
        merged = merge(base, overlay)
        cfg = merged.config
        state["dkim_missing_keys"] = merged.missing_keys
        store = ReleaseStore(ROOT)
        version = render(cfg).config_version
        if store.active_version() != version:
            outcome = apply_release(
                store,
                cfg,
                configtest=configtest,
                reload=reload_rspamd,
                healthcheck=healthcheck,
            )
            state["last_apply"] = {
                "outcome": outcome.outcome,
                "config_version": outcome.config_version,
                "detail": outcome.detail,
            }
        else:
            state["last_apply"] = last.get("last_apply") or {"outcome": "ACTIVE", "config_version": version}
        state["expected_checksum"] = render(cfg).checksum
    except (OSError, ValueError, ConfigError, urllib.error.URLError) as exc:
        # Панель недоступна или назначение не прошло проверку: узел остаётся на прежней версии и работает.
        state["last_apply"] = {"outcome": "SYNC_FAILED", "detail": type(exc).__name__}
    active = ReleaseStore(ROOT).active_version() or ""
    state["config_version"] = active
    state["config_checksum"] = _checksum(active)
    # Дрейф: действующий выпуск повреждён после применения либо отличается от ожидаемого (ТЗ 1.2 §27).
    intact = bool(active) and ReleaseStore(ROOT).verify(active)
    state["drift"] = drift_state(
        state["config_checksum"] if intact else "tampered", state.get("expected_checksum")
    )
    with contextlib.suppress(OSError, ValueError, urllib.error.URLError):
        _panel_request(f"{panel_url}/rspamd-status", token, body={"node_id": node_id, "state": state})
    return state


def _checksum(version: str) -> str:
    if not version:
        return ""
    try:
        manifest = json.loads((ROOT / "releases" / version / "MANIFEST.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    return str(manifest.get("checksum", ""))


def cmd_sync(args: argparse.Namespace) -> int:
    token = Path(args.token_file).read_text(encoding="utf-8").strip()
    last: dict = {}
    while True:
        last = sync_once(args.panel_url, token, args.node_id, last)
        if args.once:
            print(json.dumps(last))
            return 0
        time.sleep(args.interval)


def cmd_keygen(args: argparse.Namespace) -> int:
    """Сгенерировать ключ подписи на узле: закрытая часть остаётся в хранилище секретов узла, наружу
    выдаётся только запись для DNS. Рекомендуемый способ для рабочей установки."""
    from .dkim_keys import generate

    key, pem = generate(args.domain, args.selector, generated_by="node", secret_dir=args.secret_dir)
    target = Path(key.private_key_ref)
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(target, flags, 0o640)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    print(
        json.dumps(
            {
                "domain": key.domain,
                "selector": key.selector,
                "dns_name": key.dns_name,
                "public_record": key.public_record,
                "private_key_ref": key.private_key_ref,
            }
        )
    )
    return 0


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
    collector.add_argument(
        "--panel-url", default=os.environ.get("MSP_PANEL_SPAM_URL", "")
    )  # .../gateway-agent/spam-scans
    collector.add_argument("--token-file", default=os.environ.get("MSP_PANEL_TOKEN_FILE", ""))
    collector.add_argument("--interval", type=float, default=2.0)
    collector.add_argument("--node-id", default=os.environ.get("MSP_NODE_ID", ""))
    collector.add_argument("--metrics-host", default="0.0.0.0")  # nosec B104 - порт доступен сети мониторинга узла  # noqa: S104
    collector.add_argument("--metrics-port", type=int, default=9101)
    collector.set_defaults(func=cmd_collector)
    sync = sub.add_parser("sync")
    sync.add_argument("--panel-url", default=os.environ.get("MSP_PANEL_URL", ""))
    sync.add_argument("--token-file", default=os.environ.get("MSP_PANEL_TOKEN_FILE", ""))
    sync.add_argument("--node-id", default=os.environ.get("MSP_NODE_ID", ""))
    sync.add_argument("--interval", type=float, default=30.0)
    sync.add_argument("--once", action="store_true")
    sync.set_defaults(func=cmd_sync)
    keygen = sub.add_parser("keygen")
    keygen.add_argument("--domain", required=True)
    keygen.add_argument("--selector", required=True)
    keygen.add_argument("--secret-dir", default="/run/secrets/rspamd/dkim")
    keygen.set_defaults(func=cmd_keygen)
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
