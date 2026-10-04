"""Every rule condition must name a fact the engine can actually produce (ТЗ 1.0.3 §12, §60).

A rule whose condition contains a typo loads cleanly, validates cleanly, and never fires. It
looks like coverage on every dashboard and provides none — a worse failure than a missing rule,
because something appears to be watching.
"""

from __future__ import annotations

from typing import ClassVar

from msp_detection import default_ruleset
from msp_detection.vocabulary import (
    facts_reachable_by_default,
    known_facts,
    optional_only_facts,
    unknown_condition_keys,
    unreachable_condition_keys,
)


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


#: Rules allowed to depend on a fact only an optional component can produce. A rule belongs here
#: only if it is meant to be inert until that component is enabled, and the reason is written
#: next to it — the list is reviewable in a diff for exactly that reason. Empty is the normal
#: state.
SEMANTIC_DEPENDENT_RULES: frozenset[str] = frozenset()


def test_no_rule_depends_on_a_fact_only_an_optional_component_can_produce() -> None:
    """A correctly spelled fact that nothing in a default deployment sets (ТЗ 1.0.4).

    This is the vocabulary check one level down. ``known_facts`` is satisfied because the engine
    really does contain code that sets the name — in the semantic provider, which is disabled by
    default. A condition on such a fact loads cleanly, validates cleanly and never fires, which
    is the failure the vocabulary check exists to prevent.

    Written after walking into it: SND-024 was first authored against ``intent_payment_request``,
    a name the regex intent analysis never emits and only the semantic provider does.
    """
    unreachable = {
        rule_id: keys
        for rule_id, keys in unreachable_condition_keys(default_ruleset()).items()
        if rule_id not in SEMANTIC_DEPENDENT_RULES
    }
    assert not unreachable, (
        f"правила опираются на факты, недостижимые в конфигурации по умолчанию: {unreachable}"
    )


def test_the_two_vocabularies_differ_and_name_the_optional_facts() -> None:
    """Guards the guard: if the two sets were equal the test above would pass vacuously."""
    optional = optional_only_facts()
    assert optional, "необязательных фактов не найдено — проверка выше ничего не проверяет"
    assert optional <= known_facts()
    assert not (optional & facts_reachable_by_default())
    # The semantic provider shares its intent vocabulary with the regex analysis on purpose, so
    # a name both can produce must stay reachable.
    assert "intent_credential_request" in facts_reachable_by_default()
    assert "intent_payment_request" in optional


def test_a_rule_on_an_optional_fact_would_be_caught() -> None:
    class _Term:
        kind = "term"
        key = "intent_payment_request"
        children: ClassVar[list[object]] = []

    class _Rule:
        id = "TEST-002"
        conditions = _Term()

    class _Pack:
        rules: ClassVar[list[object]] = [_Rule()]

    assert unreachable_condition_keys(_Pack()) == {"TEST-002": {"intent_payment_request"}}
