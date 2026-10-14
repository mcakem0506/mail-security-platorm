"""Командная строка узла шлюза: применить пакет, показать состояние (ТЗ 1.1 §39–§40).

    python -m msp_gateway.node apply  /path/to/bundle
    python -m msp_gateway.node status

Пакет — каталог с файлами конфигурации и ``manifest.json``. Одна и та же логика применения
используется при первой загрузке контейнера, агентом и вручную оператором: расхождение между
этими тремя путями было бы путём, которым узел оказывается в состоянии, которое никто не
проверял.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from .apply import ConfigStore, Outcome, apply_bundle
from .probes import ProbeResult, ProbeState, banner_probe, open_relay_probe
from .state import (
    RecipientFreshness,
    classify_freshness,
    gate_is_closed,
    set_recipient_gate,
    write_recipient_meta,
)

CONFIG_ROOT = os.environ.get("MSP_CONFIG_ROOT", "/var/lib/msp/config")
STATE_DIR = os.environ.get("MSP_STATE_DIR", "/var/lib/msp/state")


def load_bundle(directory: Path) -> tuple[dict[str, bytes], dict[str, object]]:
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    names = manifest.get("files", [])
    files = {str(name): (directory / str(name)).read_bytes() for name in names}
    return files, manifest


def _wait_for_greeting(host: str, port: int, deadline_seconds: float) -> ProbeResult:
    """Опрашивать слушатель до срока. Возвращает первый ответ или последнюю неудачу."""
    deadline = time.monotonic() + deadline_seconds
    result = banner_probe(host, port)
    while result.state is ProbeState.UNREACHABLE and time.monotonic() < deadline:
        time.sleep(0.5)
        result = banner_probe(host, port)
    return result


def make_healthcheck(
    inbound_port: int | None,
    internal_port: int | None,
    host: str = "127.0.0.1",
    deadline_seconds: float = 20.0,
):  # type: ignore[no-untyped-def]
    """Проверка после перезагрузки: слушатели отвечают, а шлюз по-прежнему не открытый релей.

    Проверка открытого релея входит в проверку здоровья, а не только в тесты, потому что
    конфигурация может быть синтаксически безупречной и при этом открытой: ровно так
    выглядит ошибка в списке доверенных сетей.
    """

    def check() -> list[str]:
        problems: list[str] = []
        for name, port in (("inbound", inbound_port), ("internal", internal_port)):
            if port is None:
                continue
            # `postfix reload` асинхронен: мастер перечитывает конфигурацию и перезапускает
            # службы, на что под нагрузкой уходит заметное время. Первая версия ждала
            # фиксированную секунду и принимала запоздавший слушатель за неисправный — ровно та
            # гонка, из-за которой исправная конфигурация откатывалась. Слушатель опрашивается
            # до срока, и неисправным он считается только если не ответил за весь срок.
            greeting = _wait_for_greeting(host, port, deadline_seconds)
            # Жив — значит ответил ЛЮБЫМ приветствием SMTP. Внутренний слушатель отвечает чужим
            # отказом при подключении (554), а проверка идёт с 127.0.0.1, то есть как чужая:
            # отказ здесь — правильный ответ закрытого порта, а не признак неисправности.
            # Неисправность — это когда ответа нет вовсе.
            if greeting.state is ProbeState.UNREACHABLE:
                problems.append(f"слушатель {name} не отвечает приветствием ({greeting.stage})")
                continue
            relay = open_relay_probe(host, port)
            if relay.state is ProbeState.UNREACHABLE:
                problems.append(f"слушатель {name} не удалось проверить на открытый релей")
            elif not relay.is_safe_for_relay_test:
                problems.append(f"слушатель {name} принял внешнего получателя с недоверенного адреса")
        return problems

    return check


def cmd_apply(args: argparse.Namespace) -> int:
    files, manifest = load_bundle(Path(args.bundle))
    store = ConfigStore(CONFIG_ROOT, state_dir=STATE_DIR)
    health = None
    if not args.no_health:
        health = make_healthcheck(args.inbound_port, args.internal_port)
    result = apply_bundle(files, manifest, store, healthcheck=health, reload_wait=args.reload_wait)
    if result.outcome is Outcome.ACTIVE:
        write_recipient_meta(manifest.get("recipients"), Path(STATE_DIR))
    print(
        json.dumps(
            {
                "outcome": result.outcome.value,
                "stage": result.stage.value,
                "message": result.message,
                "steps": result.steps,
                "rolled_back_to": result.rolled_back_to,
            },
            ensure_ascii=False,
        )
    )
    return 0 if result.outcome is Outcome.ACTIVE else 1


def cmd_status(_args: argparse.Namespace) -> int:
    store = ConfigStore(CONFIG_ROOT, state_dir=STATE_DIR)
    print(
        json.dumps(
            {
                "active_version": store.active_version(),
                "active_checksum": store.active_checksum(),
                "disk_checksum": store.drift_checksum(),
            },
            ensure_ascii=False,
        )
    )
    return 0


def cmd_agent(args: argparse.Namespace) -> int:
    """Наблюдающий агент: работает без прав на изменение Postfix (только чтение журнала и очереди)."""
    from .agent import Agent, Thresholds, http_sender, parse_probe_env, run_forever, serve_metrics
    from .panelsync import drift_state

    state = Path(STATE_DIR)
    store = ConfigStore(CONFIG_ROOT, state_dir=STATE_DIR)

    def config() -> tuple[str, str]:
        return (store.active_version() or "", store.active_checksum() or "")

    agent = Agent(
        state_dir=state,
        data_dir=Path(args.data_dir),
        identity_dir=Path(args.identity_dir),
        queue_snapshot=Path(args.queue_snapshot) if args.queue_snapshot else None,
        log_path=Path(args.log),
        role=args.role,
        thresholds=Thresholds(),
        config_reader=config,
        probes=parse_probe_env(dict(os.environ)),
        collector_status=Path(os.environ["MSP_COLLECTOR_STATUS"])
        if os.environ.get("MSP_COLLECTOR_STATUS")
        else None,
        drift_reader=lambda: drift_state(store),
    )
    serve_metrics(agent, args.listen, args.port)
    sender = None
    url = os.environ.get("MSP_CONTROL_URL", "")
    token_file = os.environ.get("MSP_CONTROL_TOKEN_FILE", "")
    if url and token_file:
        sender = http_sender(url, Path(token_file).read_text(encoding="utf-8").strip(), agent.node_id)
    run_forever(agent, interval=args.interval, sender=sender)
    return 0


def cmd_collector(args: argparse.Namespace) -> int:
    """Сборщик теневых копий. Запускается от владельца журнала, не от root и не от агента."""
    from .collector import Collector, DirectorySink, HttpSink, run_forever

    if args.sink_dir:
        sink = DirectorySink(Path(args.sink_dir))
    else:
        url = args.url or os.environ.get("MSP_INGEST_URL", "")
        token_file = args.token_file or os.environ.get("MSP_INGEST_TOKEN_FILE", "")
        if not url or not token_file:
            print("collector: нужен --sink-dir либо --url и --token-file", file=sys.stderr)
            return 2
        from .agent import node_identity

        sink = HttpSink(
            url,
            Path(token_file).read_text(encoding="utf-8").strip(),
            node_id=node_identity(Path(args.identity_dir)),
        )
    status = os.environ.get("MSP_COLLECTOR_STATUS")
    collector = Collector(
        Path(args.journal),
        sink,
        retention_days=args.retention_days,
        status_file=Path(status) if status else None,
    )
    if args.once:
        stats = collector.run_once()
        print(
            json.dumps(
                {"collected": stats.collected, "failed": stats.failed, "quarantined": stats.quarantined}
            )
        )
        return 0
    run_forever(collector, interval=args.interval)
    return 0


def cmd_gate_refresh(_args: argparse.Namespace) -> int:
    """Пересчитать свежесть справочника и при необходимости закрыть или открыть приём получателей.

    Запускается от root периодически: смена состояния требует ``postfix reload``.
    """
    from .agent import read_recipient_generated_at
    from .metrics import age_seconds

    state = Path(STATE_DIR)
    age = age_seconds(read_recipient_generated_at(state), datetime.now(UTC))
    freshness = classify_freshness(
        age_seconds=age,
        fresh_seconds=float(os.environ.get("MSP_RECIPIENTS_FRESH_SECONDS", "3600")),
        grace_seconds=float(os.environ.get("MSP_RECIPIENTS_GRACE_SECONDS", "7200")),
    )
    want_closed = freshness is RecipientFreshness.STALE_HARD
    if want_closed != gate_is_closed(state):
        set_recipient_gate(freshness, state_dir=state)
    print(
        json.dumps({"freshness": freshness.value, "age_seconds": age, "gate_closed": gate_is_closed(state)})
    )
    return 0


def cmd_sync(args: argparse.Namespace) -> int:
    """Забрать у панели назначенную конфигурацию и команду слива. Запускается от root."""
    import time as _time

    from .agent import http_sender, node_identity
    from .panelsync import PanelError, default_apply, detect_drift, http_fetch, postfix_flush, sync_once

    url = args.panel_url or os.environ.get("MSP_PANEL_URL", "")
    token_file = args.token_file or os.environ.get("MSP_PANEL_TOKEN_FILE", "")
    if not url or not token_file:
        print("sync: нужны --panel-url и --token-file", file=sys.stderr)
        return 2
    token = Path(token_file).read_text(encoding="utf-8").strip()
    node_id = node_identity(Path(args.identity_dir))
    send = http_sender(f"{url.rstrip('/')}/events", token, node_id)

    def report(kind: str, data: dict[str, object]) -> None:
        event = {"type": kind, "at": datetime.now(UTC).isoformat(), "node_id": node_id, **data}
        try:
            send([event])
        except Exception as error:  # noqa: BLE001 - отчёт не обязан удаваться: итог виден и в журнале узла
            print(f"sync: отчёт не доставлен: {type(error).__name__}", file=sys.stderr)

    store = ConfigStore(CONFIG_ROOT, state_dir=STATE_DIR)
    fetch = http_fetch(url, token, node_id)
    apply = default_apply(store, healthcheck=make_healthcheck(25, None), reload_wait=1.0)
    while True:
        try:
            result = sync_once(fetch, store, Path(STATE_DIR), apply, report, flusher=postfix_flush)
            drift = detect_drift(store)
            if drift:
                report("drift", drift)
            print(json.dumps({"applied": result.applied, "outcome": result.outcome, "detail": result.detail}))
        except PanelError as error:
            print(f"sync: {error}", file=sys.stderr)
        if args.once:
            return 0
        _time.sleep(args.interval)


def cmd_drain(args: argparse.Namespace) -> int:
    """Включить или выключить слив. Запускается от root: нужен ``postfix reload``."""
    from .state import is_draining, set_drain

    if args.mode in ("on", "off"):
        set_drain(args.mode == "on", state_dir=Path(STATE_DIR))
    print(json.dumps({"draining": is_draining(Path(STATE_DIR))}))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="msp-gateway-node")
    sub = parser.add_subparsers(dest="command", required=True)
    apply = sub.add_parser("apply")
    apply.add_argument("bundle")
    apply.add_argument("--inbound-port", type=int, default=25)
    apply.add_argument("--internal-port", type=int, default=None)
    apply.add_argument("--no-health", action="store_true")
    apply.add_argument("--reload-wait", type=float, default=1.0)
    apply.set_defaults(func=cmd_apply)
    status = sub.add_parser("status")
    status.set_defaults(func=cmd_status)
    agent = sub.add_parser("agent")
    agent.add_argument("--log", default="/var/log/msp/postfix.log")
    agent.add_argument("--role", default="LAB")
    agent.add_argument("--identity-dir", default=os.environ.get("MSP_IDENTITY_DIR", "/var/lib/msp"))
    agent.add_argument("--queue-snapshot", default="")
    agent.add_argument("--data-dir", default=os.environ.get("MSP_AGENT_DIR", "/var/lib/msp/agent"))
    agent.add_argument("--listen", default="0.0.0.0")  # noqa: S104 - порт доступен только во внутренней сети узла
    agent.add_argument("--port", type=int, default=9100)
    agent.add_argument("--interval", type=float, default=5.0)
    agent.set_defaults(func=cmd_agent)
    collector = sub.add_parser("collector")
    collector.add_argument("--journal", default=os.environ.get("MSP_JOURNAL_DIR", "/var/lib/msp/journal"))
    collector.add_argument("--sink-dir", default="")
    collector.add_argument("--identity-dir", default=os.environ.get("MSP_IDENTITY_DIR", "/var/lib/msp"))
    collector.add_argument("--url", default="")
    collector.add_argument("--token-file", default="")
    collector.add_argument("--retention-days", type=float, default=7.0)
    collector.add_argument("--interval", type=float, default=5.0)
    collector.add_argument("--once", action="store_true")
    collector.set_defaults(func=cmd_collector)
    gate = sub.add_parser("gate-refresh")
    gate.set_defaults(func=cmd_gate_refresh)
    sync = sub.add_parser("sync")
    sync.add_argument("--panel-url", default="")
    sync.add_argument("--token-file", default="")
    sync.add_argument("--identity-dir", default=os.environ.get("MSP_IDENTITY_DIR", "/var/lib/msp"))
    sync.add_argument("--interval", type=float, default=30.0)
    sync.add_argument("--once", action="store_true")
    sync.set_defaults(func=cmd_sync)
    drain = sub.add_parser("drain")
    drain.add_argument("mode", choices=["on", "off", "status"])
    drain.set_defaults(func=cmd_drain)
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
