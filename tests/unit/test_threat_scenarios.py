"""The threat scenario catalog must stay true (ТЗ 1.0.3 §28, §29, §37).

A catalog is a claim about what the platform protects against. The claim is only worth
something if every part of it is checkable: the rules it names must exist, the fixtures it
names must exist, and the playbook it points at must be written. A scenario that names a
deleted rule asserts coverage that is gone — worse than saying nothing, because the coverage
map reads as green.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml
from msp_contracts import RuleStatus
from msp_detection import default_ruleset
from msp_detection_eval.corpus import build_golden_dataset

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CATALOG = _ROOT / "datasets" / "threat_scenarios.yaml"
_PLAYBOOKS = _ROOT / "docs" / "ANALYST_PLAYBOOKS.md"


@pytest.fixture(scope="module")
def catalog() -> dict:
    return yaml.safe_load(_CATALOG.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def scenarios(catalog: dict) -> list[dict]:
    return catalog["scenarios"]


@pytest.fixture(scope="module")
def case_ids() -> set[str]:
    dataset, _ = build_golden_dataset()
    return {case.id for case in dataset.cases}


def test_scenario_ids_are_unique(scenarios: list[dict]) -> None:
    ids = [s["id"] for s in scenarios]
    assert len(ids) == len(set(ids))


def test_every_named_rule_exists(scenarios: list[dict]) -> None:
    known = {rule.id for rule in default_ruleset().rules}
    missing = {s["id"]: sorted(set(s["rules"]) - known) for s in scenarios}
    assert not {k: v for k, v in missing.items() if v}, (
        f"сценарии ссылаются на несуществующие правила: {missing}"
    )


def test_every_named_fixture_exists(scenarios: list[dict], case_ids: set[str]) -> None:
    """A scenario without real fixtures is an unverifiable claim of coverage."""
    missing = {s["id"]: sorted(set(s["fixtures"]) - case_ids) for s in scenarios}
    assert not {k: v for k, v in missing.items() if v}, (
        f"сценарии ссылаются на несуществующие кейсы корпуса: {missing}"
    )


def test_every_scenario_has_fixtures_and_a_playbook(scenarios: list[dict]) -> None:
    text = _PLAYBOOKS.read_text(encoding="utf-8")
    for scenario in scenarios:
        assert scenario["fixtures"], f"{scenario['id']}: нет кейсов, покрытие непроверяемо"
        assert scenario["rules"], f"{scenario['id']}: нет правил"
        assert scenario["description"].strip(), f"{scenario['id']}: нет описания"
        playbook = scenario["playbook"]
        assert playbook, f"{scenario['id']}: не указан плейбук"
        assert f"## {playbook}" in text, f"{scenario['id']}: плейбук {playbook} не написан"


def test_every_scenario_is_covered_by_at_least_one_active_rule(scenarios: list[dict]) -> None:
    """Coverage is computed, never stored — this is the computation the console shows."""
    rules = {rule.id: rule for rule in default_ruleset().rules}
    uncovered = [
        scenario["id"]
        for scenario in scenarios
        if not any(
            rule_id in rules and rules[rule_id].status is RuleStatus.ACTIVE for rule_id in scenario["rules"]
        )
    ]
    assert not uncovered, f"сценарии без единого активного правила: {uncovered}"


def test_playbooks_do_not_tell_an_analyst_to_open_the_link(scenarios: list[dict]) -> None:
    """A playbook is operational text; the dangerous advice must not be in it by accident."""
    # Collapsed, because the source is wrapped at the line width and a phrase may span lines.
    text = " ".join(_PLAYBOOKS.read_text(encoding="utf-8").lower().split())
    assert "не открывайте целевой адрес из корпоративной сети" in text
    assert "ничего не открывайте" in text
    # The one instruction that must never appear as advice.
    assert "откройте ссылку, чтобы проверить" not in text
