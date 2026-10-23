"""Служба принуждения узла: ``gateway-enforcement`` (ТЗ 1.3 §13, §19–§22, §47–§49).

Служба принимает от Rspamd (по закрытому каналу, только с разрешённых адресов) запись сканирования и отвечает
решением. Анализа она не делает: разбор записи — код этапа 1.2, правила — подписанная политика. Решение
принимается по **локальной проверенной копии политики**, поэтому недоступность панели, базы данных,
внешних сервисов и консоли аналитика синхронные ответы не меняет (§48, §49).

Состояние на диске (каталог состояния):

* ``policy/`` — последняя проверенная политика и копия до неё;
* ``kill_switch.json`` — общий выключатель, как его в последний раз сообщила панель;
* ``bypass.json`` — локальный обход ``enforcement_bypass``; включается на узле и работает без панели (§20);
* ``decisions/`` — журнал решений, ожидающих отправки панели.

Любая ошибка внутри обработчика решения даёт ответ «решения нет» (открытый сбой) и учитывается в метриках: служба
не вправе отклонить письмо из-за собственной ошибки (§15).
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .engine import Outcome, Runtime, Switches, decide
from .evidence import Stopwatch, input_from_record
from .model import AppliedAction
from .policy import PolicyBundle, PolicyCache, PolicyError, PolicyStatus

ENGINE_VERSION = "msp-enforcement/1.3"
MAX_BODY = 1024 * 1024
DECISION_OUTBOX_LIMIT = 5000


def _now() -> datetime:
    return datetime.now(UTC)


class NodeConfig:
    def __init__(self, **kw: Any) -> None:
        self.state_dir = Path(
            kw.get("state_dir") or os.environ.get("MSP_ENFORCEMENT_STATE", "/var/lib/msp-enforcement")
        )
        self.panel_url = (kw.get("panel_url") or os.environ.get("MSP_PANEL_URL", "")).rstrip("/")
        self.token_file = kw.get("token_file") or os.environ.get("MSP_ENFORCEMENT_TOKEN_FILE", "")
        self.key_file = kw.get("key_file") or os.environ.get("MSP_ENFORCEMENT_KEY_FILE", "")
        self.node_id = kw.get("node_id") or os.environ.get("MSP_NODE_ID", "0" * 32)
        self.allowed_clients = tuple(
            c.strip()
            for c in (
                kw.get("allowed_clients") or os.environ.get("MSP_ENFORCEMENT_ALLOWED", "127.0.0.1")
            ).split(",")
            if c.strip()
        )
        self.soft_ttl = timedelta(
            seconds=int(kw.get("soft_ttl") or os.environ.get("MSP_POLICY_SOFT_TTL", 600))
        )
        self.hard_ttl = timedelta(
            seconds=int(kw.get("hard_ttl") or os.environ.get("MSP_POLICY_HARD_TTL", 21600))
        )


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip() if path else ""
    except OSError:
        return ""


class EnforcementNode:
    def __init__(self, cfg: NodeConfig) -> None:
        self.cfg = cfg
        self.cfg.state_dir.mkdir(parents=True, exist_ok=True)
        (cfg.state_dir / "decisions").mkdir(exist_ok=True)
        key = _read(cfg.key_file).encode()
        self.cache = PolicyCache(cfg.state_dir / "policy", key, soft_ttl=cfg.soft_ttl, hard_ttl=cfg.hard_ttl)
        self.counters: Counter[str] = Counter()
        self.lock = threading.Lock()
        self._seq = 0

    # --- состояние на диске ----------------------------------------------------------------
    def _flag(self, name: str, field: str) -> bool:
        try:
            return bool(json.loads((self.cfg.state_dir / name).read_text(encoding="utf-8")).get(field))
        except (OSError, ValueError):
            return False

    def set_kill_switch(self, active: bool) -> None:
        self._write("kill_switch.json", {"active": active, "at": _now().isoformat()})

    def set_local_bypass(self, enabled: bool) -> None:
        self._write("bypass.json", {"enabled": enabled, "at": _now().isoformat()})

    def _write(self, name: str, body: dict[str, Any]) -> None:
        tmp = self.cfg.state_dir / f".{name}.tmp"
        tmp.write_text(json.dumps(body), encoding="utf-8")
        os.replace(tmp, self.cfg.state_dir / name)

    def switches(self) -> Switches:
        bypass = self._flag("bypass.json", "enabled") or os.environ.get("MSP_ENFORCEMENT_BYPASS") == "1"
        return Switches(kill_switch=self._flag("kill_switch.json", "active"), local_bypass=bypass)

    def runtime(self) -> Runtime:
        policy, status = self.cache.load(_now())
        return Runtime(
            policy=policy,
            status=status,
            switches=self.switches(),
            now=_now(),
            engine_versions={"enforcement": ENGINE_VERSION},
        )

    # --- решение ---------------------------------------------------------------------------
    def decide_record(self, record: dict[str, Any], *, direction: str = "INBOUND", **extra: Any) -> Outcome:
        watch = Stopwatch()
        inp = input_from_record(record, direction=direction, **extra)
        inp = inp.model_copy(update={"elapsed_ms": max(inp.elapsed_ms, watch.ms())})
        outcome = decide(inp, self.runtime())
        self._log(outcome, inp)
        return outcome

    def decide_inp(self, inp: Any) -> Outcome:
        """Решение по уже собранным свидетельствам (послеочередной шлюз)."""
        outcome = decide(inp, self.runtime())
        self._log(outcome, inp)
        return outcome

    def _log(self, outcome: Outcome, inp: Any) -> None:
        domain = inp.sender.rsplit("@", 1)[-1] if "@" in inp.sender else ""
        rows: list[dict[str, Any]] = []
        for d in outcome.decisions:
            # Подробный журнал нужен для решений, меняющих судьбу письма, обходов и предложений; «ничего не было» не пишем.
            noteworthy = (
                d.suggested_action
                or d.applied_action is not AppliedAction.OBSERVE_ONLY
                or d.fail_mode_applied
            )
            self.counters[f"evaluated:{d.control_type.value}"] += 1
            if d.applied_action in (
                AppliedAction.SMTP_REJECT,
                AppliedAction.SMTP_TEMPFAIL,
                AppliedAction.QUARANTINED,
                AppliedAction.HELD,
            ):
                self.counters[f"applied:{d.control_type.value}"] += 1
            if d.fail_mode_applied:
                self.counters["timeouts"] += 1
            if not noteworthy:
                continue
            row = d.model_dump(mode="json")
            row["internet_message_id"] = inp.message_id
            row["sender_domain"] = domain
            row["client_ip"] = inp.source_ip
            rows.append(row)
        for row in rows:
            self._seq += 1
            name = f"{time.time_ns()}-{self._seq:08d}.json"
            with contextlib.suppress(OSError):
                (self.cfg.state_dir / "decisions" / name).write_text(json.dumps(row), encoding="utf-8")
        files = sorted((self.cfg.state_dir / "decisions").glob("*.json"))
        for stale in files[: max(0, len(files) - DECISION_OUTBOX_LIMIT)]:
            stale.unlink(missing_ok=True)
            self.counters["decisions_dropped"] += 1

    # --- обмен с панелью -------------------------------------------------------------------
    def _request(
        self, path: str, *, body: dict[str, Any] | None = None, timeout: float = 8.0
    ) -> dict[str, Any]:
        token = _read(self.cfg.token_file)
        request = urllib.request.Request(  # noqa: S310
            f"{self.cfg.panel_url}{path}",
            method="POST" if body is not None else "GET",
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310  # nosec B310
            return dict(json.loads(response.read()))

    def poll_state(self) -> None:
        """Быстрый опрос: общий выключатель. Сбой панели оставляет прежнее значение (файл)."""
        if not self.cfg.panel_url:
            return
        try:
            state = self._request("/gateway-agent/enforcement/state", timeout=3.0)
        except (OSError, urllib.error.URLError, ValueError):
            self.counters["panel_errors"] += 1
            return
        active = bool(state.get("kill_switch"))
        if active != self._flag("kill_switch.json", "active"):
            self.set_kill_switch(active)
        self.counters["state_polls"] += 1

    def sync_policy(self) -> bool:
        if not self.cfg.panel_url:
            return False
        try:
            payload = self._request("/gateway-agent/enforcement/policy")
            bundle = payload.get("bundle")
            if not bundle:
                return False
            self.cache.install(PolicyBundle.model_validate(bundle), now=_now())
            if bool(payload.get("kill_switch")) != self._flag("kill_switch.json", "active"):
                self.set_kill_switch(bool(payload.get("kill_switch")))
        except (OSError, urllib.error.URLError, ValueError, PolicyError):
            self.counters["policy_errors"] += 1
            return False
        self.counters["policy_syncs"] += 1
        return True

    def flush_decisions(self) -> int:
        if not self.cfg.panel_url:
            return 0
        files = sorted((self.cfg.state_dir / "decisions").glob("*.json"))[:200]
        rows: list[dict[str, Any]] = []
        for path in files:
            try:
                rows.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                path.unlink(missing_ok=True)
        if not rows:
            return 0
        try:
            self._request(
                "/gateway-agent/enforcement/decisions", body={"node_id": self.cfg.node_id, "decisions": rows}
            )
        except (OSError, urllib.error.URLError, ValueError):
            self.counters["panel_errors"] += 1
            return 0
        for path in files:
            path.unlink(missing_ok=True)
        return len(rows)

    def report_state(self) -> None:
        if not self.cfg.panel_url:
            return
        policy, status = self.cache.load(_now())
        state = {
            "policy_checksum": policy.checksum() if policy else "",
            "policy_version": policy.version if policy else "",
            "policy_status": status.value,
            "local_bypass": self.switches().local_bypass,
            "kill_switch_seen": self.switches().kill_switch,
            "decisions_total": sum(v for k, v in self.counters.items() if k.startswith("evaluated:")),
            "errors_total": self.counters["errors"],
            "timeouts_total": self.counters["timeouts"],
        }
        with contextlib.suppress(OSError, urllib.error.URLError, ValueError):
            self._request(
                "/gateway-agent/enforcement/state", body={"node_id": self.cfg.node_id, "state": state}
            )

    def metrics_text(self) -> str:
        policy, status = self.cache.load(_now())
        lines = [
            "# TYPE msp_enforcement_policy_info gauge",
            f'msp_enforcement_policy_info{{version="{policy.version if policy else ""}",'
            f'checksum="{policy.checksum()[:12] if policy else ""}",status="{status.value}"}} 1',
            f"msp_enforcement_kill_switch_active {int(self.switches().kill_switch)}",
            f"msp_enforcement_local_bypass_active {int(self.switches().local_bypass)}",
            f"msp_enforcement_errors_total {self.counters['errors']}",
            f"msp_enforcement_timeouts_total {self.counters['timeouts']}",
            f"msp_enforcement_decisions_dropped_total {self.counters['decisions_dropped']}",
            f"msp_enforcement_panel_errors_total {self.counters['panel_errors']}",
            f"msp_enforcement_policy_stale {int(status in (PolicyStatus.STALE, PolicyStatus.SAFE_MODE))}",
        ]
        for key, value in sorted(self.counters.items()):
            if key.startswith("evaluated:"):
                lines.append(f'msp_enforcement_decisions_total{{control="{key.split(":", 1)[1]}"}} {value}')
            if key.startswith("applied:"):
                lines.append(f'msp_enforcement_actions_total{{control="{key.split(":", 1)[1]}"}} {value}')
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------------------------
# HTTP для Rspamd
# ---------------------------------------------------------------------------------------------
def _client_allowed(allowed: tuple[str, ...], address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(net, strict=False) for net in allowed)


def make_handler(node: EnforcementNode) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "msp-enforcement"

        def log_message(self, *_: Any) -> None:
            return

        def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/healthz":
                self._send(200, b'{"ok":true}')
            elif self.path == "/metrics":
                self._send(200, node.metrics_text().encode(), "text/plain; version=0.0.4")
            else:
                self._send(404, b'{"error":"not found"}')

        def do_POST(self) -> None:
            if self.path != "/v1/decide":
                return self._send(404, b'{"error":"not found"}')
            if not _client_allowed(node.cfg.allowed_clients, self.client_address[0]):
                node.counters["denied_clients"] += 1
                return self._send(403, b'{"error":"forbidden"}')
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_BODY:
                    return self._send(413, b'{"error":"size"}')
                record = json.loads(self.rfile.read(length))
                if not isinstance(record, dict):
                    raise ValueError("record")
                direction = str(record.pop("_direction", "INBOUND"))
                outcome = node.decide_record(record, direction=direction)
            except Exception:  # noqa: BLE001 - любая ошибка = «решения нет»: открытый сбой (ТЗ §15)
                node.counters["errors"] += 1
                return self._send(200, json.dumps({"decision": "NO_DECISION", "error": True}).encode())
            final = outcome.final
            body = {
                "decision": final.decision.value if final else "NO_DECISION",
                "reply": _reply_text(final.smtp_action) if final else "",
                "control": final.control_type.value if final else "",
                "policy_version": final.policy_version if final else "",
            }
            self._send(200, json.dumps(body).encode())

    return Handler


def _reply_text(smtp: str) -> str:
    """Текст ответа без кода: Milter сам добавляет ``5.7.1``/``4.7.1`` и код."""
    parts = smtp.split(" ", 2)
    return parts[2] if len(parts) == 3 else smtp


def serve(node: EnforcementNode, host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(node))
    server.daemon_threads = True
    return server


def background_loop(
    node: EnforcementNode, *, policy_interval: float = 30.0, state_interval: float = 2.0
) -> None:
    last_policy = last_report = 0.0
    while True:
        moment = time.monotonic()
        node.poll_state()
        if moment - last_policy >= policy_interval:
            node.sync_policy()
            last_policy = moment
        node.flush_decisions()
        if moment - last_report >= 10.0:
            node.report_state()
            last_report = moment
        time.sleep(state_interval)


# ---------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="msp_enforcement.node")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("serve")
    run.add_argument("--host", default="127.0.0.1")
    run.add_argument("--port", type=int, default=11390)
    bypass = sub.add_parser("bypass")
    bypass.add_argument("state", choices=("on", "off"))
    sub.add_parser("status")
    args = parser.parse_args(argv)
    node = EnforcementNode(NodeConfig())
    if args.command == "bypass":
        node.set_local_bypass(args.state == "on")
        print(json.dumps({"local_bypass": args.state == "on"}))
        return 0
    if args.command == "status":
        policy, status = node.cache.load(_now())
        print(
            json.dumps(
                {
                    "policy_version": policy.version if policy else "",
                    "checksum": policy.checksum() if policy else "",
                    "status": status.value,
                    "kill_switch": node.switches().kill_switch,
                    "local_bypass": node.switches().local_bypass,
                }
            )
        )
        return 0
    node.sync_policy()
    threading.Thread(target=background_loop, args=(node,), daemon=True).start()
    server = serve(node, args.host, args.port)
    print(f"gateway-enforcement слушает {args.host}:{args.port}", file=sys.stderr)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
