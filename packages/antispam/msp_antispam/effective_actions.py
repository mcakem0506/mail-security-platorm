"""Аудит действий сканера, которые видит Milter (ТЗ MSP 1.3 §50).

Milter исполняет родное действие Rspamd независимо от того, что написано в панели: пороги — лишь один из
источников. Действие может навязать модуль (``force_actions``, ``greylist``, ``ratelimit``, ``antivirus``,
``multimap``, ``dmarc``), правило настроек и шаблон GTUBE. Поэтому проверяется не ``actions.conf``, а
итоговая конфигурация (``rspamadm configdump``) выпуска: неизвестный источник reject или soft reject
блокирует активацию.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict

#: Ниже этого порога родное действие достижимо: оценка писем реально бывает такой.
REACHABLE_BELOW = 1000.0
NATIVE_ACTIONS = ("reject", "soft reject", "add_header", "rewrite subject", "greylist")


class ActionSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    module: str
    kind: str
    detail: str
    approved: bool = False


class EffectiveActionsReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    clean: bool
    sources: tuple[ActionSource, ...] = ()
    checked: tuple[str, ...] = ()

    @property
    def unknown(self) -> tuple[ActionSource, ...]:
        return tuple(s for s in self.sources if not s.approved)


def _walk_actions(node: Any, path: str) -> Iterable[tuple[str, Any]]:
    if isinstance(node, Mapping):
        for key, value in node.items():
            here = f"{path}.{key}"
            if str(key) in ("action", "actions", "force_action") and value not in (None, {}, [], "", False):
                yield here, value
            yield from _walk_actions(value, here)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _walk_actions(value, f"{path}[{i}]")


def audit(dump: Mapping[str, Any], approved: Iterable[str] = ()) -> EffectiveActionsReport:
    """``dump`` — результат ``rspamadm configdump -j`` выпуска; ``approved`` — виды источников
    (``GREYLIST`` и т. п.), принятые осознанно."""
    ok_sources = frozenset(approved)
    found: list[ActionSource] = []

    def add(module: str, kind: str, detail: str) -> None:
        found.append(ActionSource(module=module, kind=kind, detail=detail, approved=kind in ok_sources))

    checked = [
        "actions",
        "force_actions",
        "greylist",
        "ratelimit",
        "antivirus",
        "multimap",
        "settings",
        "dmarc",
        "spamtrap",
        "options",
        "*",
    ]

    actions = dump.get("actions") or {}
    for name, value in actions.items():
        if value is None:
            continue
        try:
            reachable = float(value) < REACHABLE_BELOW
        except (TypeError, ValueError):
            reachable = True
        if reachable:
            add("actions", "REACHABLE_THRESHOLD", f"{name}={value}")
    for name in NATIVE_ACTIONS:
        if name not in actions and name in ("reject",):
            # Порог не задан: действует значение по умолчанию сканера, то есть достижимое.
            add("actions", "THRESHOLD_NOT_OVERRIDDEN", f"{name} не переопределён")

    if dump.get("force_actions"):
        add("force_actions", "FORCE_ACTION", "правила force_actions заданы")

    grey = dump.get("greylist")
    if isinstance(grey, Mapping) and grey.get("enabled", True) is not False:
        add("greylist", "GREYLIST", f"включён, действие {grey.get('action', 'soft reject')}")

    rate = dump.get("ratelimit")
    if (
        isinstance(rate, Mapping)
        and rate.get("enabled", True) is not False
        and (rate.get("rates") or rate.get("limit"))
    ):
        add("ratelimit", "RATELIMIT", "заданы лимиты скорости (soft reject)")

    av = dump.get("antivirus")
    if isinstance(av, Mapping) and av.get("enabled", True) is not False and len(av) > 1:
        add("antivirus", "ANTIVIRUS", "антивирус включён")

    mm = dump.get("multimap")
    if isinstance(mm, Mapping):
        for path, value in _walk_actions(mm, "multimap"):
            add("multimap", "MULTIMAP_ACTION", f"{path}={value}")

    st = dump.get("settings")
    if isinstance(st, Mapping):
        for path, value in _walk_actions(st, "settings"):
            add("settings", "SETTINGS_ACTIONS", f"{path}={value}")

    dm = dump.get("dmarc")
    if isinstance(dm, Mapping) and dm.get("actions"):
        add("dmarc", "DMARC_ACTIONS", f"родные действия DMARC заданы: {dm.get('actions')}")

    trap = dump.get("spamtrap")
    if isinstance(trap, Mapping) and trap.get("enabled", False) is True:
        add("spamtrap", "SPAMTRAP", "spamtrap включён")

    options = dump.get("options") or {}
    if options.get("gtube_patterns") != "disabled":
        add("options", "GTUBE", f"gtube_patterns={options.get('gtube_patterns')!r}: шаблон GTUBE даёт reject")

    # Любой другой модуль, несущий непустое поле «action(s)», — неизвестный источник действия.
    handled = {
        "actions",
        "force_actions",
        "greylist",
        "ratelimit",
        "antivirus",
        "multimap",
        "settings",
        "dmarc",
        "spamtrap",
        "options",
    }
    for module, section in dump.items():
        if module in handled:
            continue
        for path, value in _walk_actions(section, module):
            if isinstance(section, Mapping) and section.get("enabled", True) is False:
                continue
            add(module, "UNKNOWN_ACTION_FIELD", f"{path}={str(value)[:80]}")

    return EffectiveActionsReport(
        clean=all(s.approved for s in found), sources=tuple(found), checked=tuple(checked)
    )
