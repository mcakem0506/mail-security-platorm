"""Пилот ничего не включает (MSP 1.3P, ТЗ §30 — Definition of Done: ни одно действие в бою не включается автоматически).

Проверяется устройство кода, а не поведение: модули пилота не вызывают ни одной функции, которая включает, выключает, публикует или
откатывает контроль принуждения, и не обращаются к DNS, Exchange и SMTP-узлам. Переключение контролей остаётся на защищённых точках
этапа 1.3 с их четырьмя глазами.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
PILOT_MODULES = (
    "apps/api/msp_api/services/pilot.py",
    "apps/api/msp_api/routers/pilot.py",
    "apps/api/msp_api/services/real_flow_feed.py",
    "packages/enforcement/msp_enforcement/pilot_stats.py",
    "packages/mail-parser/msp_mail_parser/journal.py",
)

#: Функции, меняющие состояние принуждения или почтового потока.
FORBIDDEN_CALLS = frozenset(
    {
        "request_activation",
        "approve_activation",
        "cancel_request",
        "pause",
        "rollback",
        "return_to_shadow",
        "activate_kill_switch",
        "clear_kill_switch",
        "publish",
        "publish_policy",
        "ensure_baseline",
        "create_exception",
        "approve_exception",
        "release",
        "confirm_release",
        "delete_item",
        "attest",
    }
)
FORBIDDEN_IMPORTS = (
    "smtplib",
    "socket",
    "dns",
    "dnspython",
    "requests",
    "httpx",
    "urllib.request",
    "subprocess",
    "winrm",
)


def _tree(path: str) -> ast.AST:
    return ast.parse((ROOT / path).read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", PILOT_MODULES)
def test_the_pilot_does_not_call_functions_that_change_enforcement(path: str) -> None:
    called: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name in FORBIDDEN_CALLS:
                called.add(name)
    assert not called, f"{path} вызывает {sorted(called)}: пилот не должен менять принуждение"


@pytest.mark.parametrize("path", PILOT_MODULES)
def test_the_pilot_does_not_reach_the_network_or_the_mail_system(path: str) -> None:
    imported: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    found = {m for m in imported if any(m == f or m.startswith(f + ".") for f in FORBIDDEN_IMPORTS)}
    assert not found, f"{path} подключает {sorted(found)}: пилот не обращается к сети и системе почты"


def test_the_pilot_router_exposes_no_control_toggle() -> None:
    """Все маршруты пилота — чтение, запись подтверждений/решений/остановок и приём журнала; переключателей контролей нет."""
    from msp_api.routers import pilot

    paths = {
        (sorted(route.methods)[0], route.path) for route in pilot.router.routes if hasattr(route, "methods")
    }
    names = " ".join(path for _, path in paths)
    for forbidden in ("kill-switch", "canary", "pause", "rollback", "activate", "publish", "mx", "dns"):
        assert forbidden not in names, f"в маршрутах пилота есть {forbidden!r}"


def test_the_pilot_assigns_state_only_to_its_own_records() -> None:
    """Присваивание ``.state`` в модуле пилота допустимо только для решений и остановок пилота (переменные ``row`` и ``old``).

    Состояние контроля принуждения (``EnforcementControlRecord.state``) пилот не присваивает: решение по P4 только разрешает
    входить в фазу, а включение остаётся за защищёнными точками этапа 1.3.
    """
    bases: set[str] = set()
    for node in ast.walk(_tree("apps/api/msp_api/services/pilot.py")):
        targets = (
            node.targets
            if isinstance(node, ast.Assign)
            else [node.target]
            if isinstance(node, ast.AugAssign)
            else []
        )
        for target in targets:
            if (
                isinstance(target, ast.Attribute)
                and target.attr == "state"
                and isinstance(target.value, ast.Name)
            ):
                bases.add(target.value.id)
    assert bases, "проверка пуста: присваиваний состояния не найдено"
    assert bases <= {"row", "old"}, f"пилот присваивает состояние объектам {sorted(bases - {'row', 'old'})}"
