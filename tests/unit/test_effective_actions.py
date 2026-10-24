"""Аудит итоговых действий сканера (ТЗ 1.3 §50): неизвестный источник reject блокирует активацию."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from msp_antispam.effective_actions import audit
from msp_antispam.rspamd_config import (
    ReleaseStore,
    RspamdNodeConfig,
    apply_release,
)

DUMP = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "rspamd" / "configdump_effective.json").read_text(
        encoding="utf-8"
    )
)


def mutated(**changes: Any) -> dict[str, Any]:
    dump = copy.deepcopy(DUMP)
    for dotted, value in changes.items():
        node = dump
        *parents, last = dotted.split("__")
        for part in parents:
            node = node.setdefault(part, {})
        node[last] = value
    return dump


def kinds(dump: dict[str, Any]) -> set[str]:
    return {s.kind for s in audit(dump).unknown}


def test_the_msp_release_has_no_hidden_action_source() -> None:
    report = audit(DUMP)
    assert report.clean, [s.model_dump() for s in report.sources]


@pytest.mark.parametrize(
    ("change", "kind"),
    [
        ({"actions__reject": 15}, "REACHABLE_THRESHOLD"),
        ({"actions__add_header": 6.0}, "REACHABLE_THRESHOLD"),
        ({"greylist__enabled": True}, "GREYLIST"),
        ({"force_actions": {"X": {"action": "reject"}}}, "FORCE_ACTION"),
        ({"ratelimit__rates": {"to": "100 / 1m"}}, "RATELIMIT"),
        ({"antivirus": {"enabled": True, "clamav": {"servers": "x"}}}, "ANTIVIRUS"),
        ({"multimap__BAD": {"type": "ip", "map": "x", "action": "reject"}}, "MULTIMAP_ACTION"),
        ({"settings__bad": {"id": "bad", "apply": {"actions": {"reject": 1}}}}, "SETTINGS_ACTIONS"),
        ({"dmarc__actions": {"reject": "reject"}}, "DMARC_ACTIONS"),
        ({"spamtrap__enabled": True}, "SPAMTRAP"),
        ({"options__gtube_patterns": "all"}, "GTUBE"),
        ({"newmodule": {"enabled": True, "action": "reject"}}, "UNKNOWN_ACTION_FIELD"),
    ],
)
def test_every_hidden_source_is_found(change: dict[str, Any], kind: str) -> None:
    assert kind in kinds(mutated(**change))


def test_a_missing_gtube_option_is_not_assumed_safe() -> None:
    dump = copy.deepcopy(DUMP)
    del dump["options"]["gtube_patterns"]
    assert "GTUBE" in kinds(dump)


def test_a_disabled_module_action_field_is_ignored() -> None:
    assert audit(mutated(newmodule={"enabled": False, "action": "reject"})).clean


def test_an_approved_kind_is_reported_but_does_not_block() -> None:
    report = audit(mutated(greylist__enabled=True), approved=["GREYLIST"])
    assert report.clean and any(s.kind == "GREYLIST" and s.approved for s in report.sources)


def test_activation_is_refused_when_the_audit_finds_an_unknown_source(tmp_path: Path) -> None:
    cfg = RspamdNodeConfig(
        authserv_id="gw.example.test",
        nameservers=("192.0.2.53",),
        redis={"host": "192.0.2.52", "port": 6379},  # type: ignore[arg-type]
        local_networks=("192.0.2.0/26",),
    )
    store = ReleaseStore(tmp_path)
    reloaded: list[bool] = []
    outcome = apply_release(
        store,
        cfg,
        configtest=lambda _: (True, "syntax OK"),
        reload=lambda: reloaded.append(True),
        healthcheck=lambda: True,
        audit=lambda _: (False, "GREYLIST: включён"),
    )
    assert outcome.outcome == "REJECTED" and "effective actions" in outcome.detail
    assert store.active_version() is None and not reloaded
