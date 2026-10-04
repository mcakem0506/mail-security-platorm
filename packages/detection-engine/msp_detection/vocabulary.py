"""The fact vocabulary a rule may refer to (ТЗ 1.0.3 §12, §60).

Rules are data, and the facts they name are the interface between the engine and that data. A
rule naming a fact the engine never sets loads cleanly, validates cleanly and never fires — it
occupies a line in the coverage map and protects nothing. That is a worse failure than a
missing rule, because something appears to be watching.

The vocabulary is derived from the engine's own source rather than hand-maintained. A list
somebody has to remember to update is a list that silently stops being true; reading the
literals the code actually uses cannot drift from the code.

This is a development- and CI-time check. Nothing in the hot path calls it.
"""

from __future__ import annotations

import ast
import functools
import pathlib
import re

from .auth import auth_fact_names

#: A fact name: lowercase, snake_case, no dots, slashes or spaces. Narrow enough that ordinary
#: strings in the source (messages, regexes, header names) are not mistaken for facts.
_FACT_NAME_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")

#: Short snake_case strings that exist in the source for other reasons and are not facts.
_NOT_FACTS = frozenset(
    {
        "utf_8",
        "no_cover",
        "type_ignore",
    }
)

_PACKAGE_DIR = pathlib.Path(__file__).resolve().parent


#: Modules that implement components which are optional and **off by default**. A fact only
#: these can produce is not reachable in a default deployment, so a rule conditioned on it does
#: nothing while looking like coverage.
_OPTIONAL_MODULES = frozenset({"semantic.py"})


def _fact_names_in(path: pathlib.Path) -> set[str]:
    """Fact-shaped string literals in one module."""
    names: set[str] = set()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError):  # pragma: no cover - the package always parses
        return names
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
            if len(value) <= 64 and _FACT_NAME_RE.match(value) and value not in _NOT_FACTS:
                names.add(value)
    return names


def _module_paths(*, include_optional: bool) -> list[pathlib.Path]:
    return [
        path
        for path in sorted(_PACKAGE_DIR.glob("*.py"))
        if path.name != "vocabulary.py" and (include_optional or path.name not in _OPTIONAL_MODULES)
    ]


@functools.lru_cache(maxsize=1)
def known_facts() -> frozenset[str]:
    """Every fact name the engine can produce, including through optional components."""
    names: set[str] = set(auth_fact_names())
    for path in _module_paths(include_optional=True):
        names |= _fact_names_in(path)
    return frozenset(names)


@functools.lru_cache(maxsize=1)
def facts_reachable_by_default() -> frozenset[str]:
    """Facts a default deployment can produce — optional components left out.

    A fact produced by both an optional module and a core one stays reachable: the semantic
    provider shares its intent vocabulary with the regex intent analysis on purpose, so
    ``intent_credential_request`` is reachable while ``intent_payment_request`` is not.
    """
    names: set[str] = set(auth_fact_names())
    for path in _module_paths(include_optional=False):
        names |= _fact_names_in(path)
    return frozenset(names)


@functools.lru_cache(maxsize=1)
def optional_only_facts() -> frozenset[str]:
    """Facts no default deployment can produce."""
    return frozenset(known_facts() - facts_reachable_by_default())


def unknown_condition_keys(rules: object) -> dict[str, set[str]]:
    """Rules whose conditions name something the engine never sets.

    Accepts anything with a ``rules`` attribute holding rule objects, which keeps this module
    free of an import cycle with :mod:`msp_detection.rules`.
    """
    vocabulary = known_facts()
    out: dict[str, set[str]] = {}
    for rule in getattr(rules, "rules", []):
        missing = {key for key in _keys(rule.conditions) if key not in vocabulary}
        if missing:
            out[rule.id] = missing
    return out


def unreachable_condition_keys(rules: object) -> dict[str, set[str]]:
    """Rules naming a fact only an optional, disabled-by-default component can set.

    Separate from :func:`unknown_condition_keys` because the failure is different: the name is
    spelled correctly and the engine really does have code that sets it, but not code that runs
    unless somebody turns an optional component on. A branch of an ``any:`` conditioned on such
    a fact never contributes, and a rule conditioned solely on one never fires at all.
    """
    optional = optional_only_facts()
    out: dict[str, set[str]] = {}
    for rule in getattr(rules, "rules", []):
        unreachable = {key for key in _keys(rule.conditions) if key in optional}
        if unreachable:
            out[rule.id] = unreachable
    return out


def _keys(condition: object) -> set[str]:
    keys: set[str] = set()
    key = getattr(condition, "key", "")
    if getattr(condition, "kind", "") == "term" and key:
        keys.add(str(key))
    for child in getattr(condition, "children", []) or []:
        keys |= _keys(child)
    return keys
