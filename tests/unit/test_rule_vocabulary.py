"""Every rule condition must name a fact the engine can actually produce (ТЗ 1.0.3 §12, §60).

A rule whose condition contains a typo loads cleanly, validates cleanly, and never fires. It
looks like coverage on every dashboard and provides none — a worse failure than a missing rule,
because something appears to be watching.
"""

from __future__ import annotations

from typing import ClassVar

from msp_detection import default_ruleset
from msp_detection.vocabulary import known_facts, unknown_condition_keys


def test_vocabulary_is_not_empty() -> None:
    vocabulary = known_facts()
    assert len(vocabulary) > 150, "словарь фактов не извлёкся — проверка потеряла бы смысл"
    # Spot-check the three mechanisms that produce facts, so a change to any one of them is
    # caught here rather than by a rule that quietly stops firing.
    assert "attachment_executable" in vocabulary  # literal fs.flag call
    assert "intent_bank_details_change" in vocabulary  # declared intent pattern
    assert "dmarc_fail" in vocabulary  # generated from the auth method tuples


def test_every_condition_names_a_known_fact() -> None:
    unknown = unknown_condition_keys(default_ruleset())
    assert not unknown, (
        "правила ссылаются на факты, которых движок не выставляет "
        f"(такое правило никогда не сработает): {unknown}"
    )


def test_every_evidence_key_is_known() -> None:
    """Evidence keys reach the analyst's view, so a typo there shows an empty field."""
    vocabulary = known_facts()
    unknown = {
        rule.id: missing
        for rule in default_ruleset().rules
        if (missing := {key for key in rule.evidence_keys if key not in vocabulary})
    }
    assert not unknown, f"правила ссылаются на неизвестные ключи доказательств: {unknown}"


def test_a_typo_would_be_caught() -> None:
    """The check has to fail on a bad rule, or it proves nothing."""

    class _Term:
        kind = "term"
        key = "intent_bank_detais_change"  # deliberate typo
        children: ClassVar[list[object]] = []

    class _Rule:
        id = "TEST-001"
        conditions = _Term()

    class _Pack:
        rules: ClassVar[list[object]] = [_Rule()]

    assert unknown_condition_keys(_Pack()) == {"TEST-001": {"intent_bank_detais_change"}}
