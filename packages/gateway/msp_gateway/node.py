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
from pathlib import Path

from .apply import ConfigStore, Outcome, apply_bundle
from .probes import ProbeState, banner_probe, open_relay_probe

CONFIG_ROOT = os.environ.get("MSP_CONFIG_ROOT", "/var/lib/msp/config")
STATE_DIR = os.environ.get("MSP_STATE_DIR", "/var/lib/msp/state")


def load_bundle(directory: Path) -> tuple[dict[str, bytes], dict[str, object]]:
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    names = manifest.get("files", [])
    files = {str(name): (directory / str(name)).read_bytes() for name in names}
    return files, manifest


def make_healthcheck(inbound_port: int | None, internal_port: int | None, host: str = "127.0.0.1"):  # type: ignore[no-untyped-def]
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
            greeting = banner_probe(host, port)
            if greeting.state is not ProbeState.ACCEPTED:
                problems.append(f"слушатель {name} не отвечает приветствием ({greeting.stage})")
                continue
            relay = open_relay_probe(host, port)
            if not relay.is_safe_for_relay_test:
                problems.append(
                    f"слушатель {name} принял внешнего получателя с недоверенного адреса или недоступен"
                )
        return problems

    return check


def cmd_apply(args: argparse.Namespace) -> int:
    files, manifest = load_bundle(Path(args.bundle))
    store = ConfigStore(CONFIG_ROOT, state_dir=STATE_DIR)
    health = None
    if not args.no_health:
        health = make_healthcheck(args.inbound_port, args.internal_port)
    result = apply_bundle(files, manifest, store, healthcheck=health, reload_wait=args.reload_wait)
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
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
