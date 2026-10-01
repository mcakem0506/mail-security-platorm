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


@functools.lru_cache(maxsize=1)
def known_facts() -> frozenset[str]:
    """Every fact name the engine can produce."""
    names: set[str] = set(auth_fact_names())
    for path in sorted(_PACKAGE_DIR.glob("*.py")):
        if path.name == "vocabulary.py":
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError):  # pragma: no cover - the package always parses
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                if len(value) <= 64 and _FACT_NAME_RE.match(value) and value not in _NOT_FACTS:
                    names.add(value)
    return frozenset(names)


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


def _keys(condition: object) -> set[str]:
    keys: set[str] = set()
    key = getattr(condition, "key", "")
    if getattr(condition, "kind", "") == "term" and key:
        keys.add(str(key))
    for child in getattr(condition, "children", []) or []:
        keys |= _keys(child)
    return keys
