"""Versioned YAML rule engine (ТЗ 15.2).

Conditions are evaluated by a small, explicit interpreter — never ``eval``. A rule turns facts
into a Signal carrying its own explanation, evidence and recommendation, so every verdict can be
traced back to the rule version that produced it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from msp_contracts import SEVERITY_BASE_WEIGHT, Severity, Signal

from .context import AnalysisContext
from .facts import FactSet

_TERM_RE = re.compile(
    r"""^\s*(?P<key>[a-z_][a-z0-9_.]*)\s*
        (?:(?P<op>==|!=|>=|<=|>|<|\bin\b|\bnot\s+in\b|\bmatches\b)\s*(?P<value>.+?))?\s*$""",
    re.VERBOSE | re.IGNORECASE,
)


class RuleError(ValueError):
    pass


def _coerce(raw: str) -> Any:
    raw = raw.strip()
    if raw.startswith("[") and raw.endswith("]"):
        return [_coerce(p) for p in raw[1:-1].split(",") if p.strip()]
    if (raw.startswith("'") and raw.endswith("'")) or (raw.startswith('"') and raw.endswith('"')):
        return raw[1:-1]
    low = raw.lower()
    if low in {"true", "false"}:
        return low == "true"
    if low in {"null", "none"}:
        return None
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        return raw


def _compare(actual: Any, op: str, expected: Any) -> bool:
    op = re.sub(r"\s+", " ", op.strip().lower())
    try:
        match op:
            case "==":
                return actual == expected
            case "!=":
                return actual != expected
            case ">":
                return actual is not None and float(actual) > float(expected)
            case ">=":
                return actual is not None and float(actual) >= float(expected)
            case "<":
                return actual is not None and float(actual) < float(expected)
            case "<=":
                return actual is not None and float(actual) <= float(expected)
            case "in":
                if isinstance(expected, list):
                    return actual in expected
                return bool(actual) and str(actual) in str(expected)
            case "not in":
                if isinstance(expected, list):
                    return actual not in expected
                return not (bool(actual) and str(actual) in str(expected))
            case "matches":
                return bool(actual) and re.search(str(expected), str(actual), re.IGNORECASE) is not None
    except (TypeError, ValueError, re.error):
        return False
    raise RuleError(f"unsupported operator: {op}")


@dataclass
class Condition:
    """A condition tree node: either a term or a boolean combinator."""

    kind: str  # term|all|any|not|count
    key: str = ""
    op: str = ""
    value: Any = None
    children: list[Condition] = field(default_factory=list)

    def evaluate(self, facts: dict[str, Any]) -> bool:
        match self.kind:
            case "term":
                actual = facts.get(self.key)
                if not self.op:
                    return bool(actual)
                return _compare(actual, self.op, self.value)
            case "all":
                return all(c.evaluate(facts) for c in self.children)
            case "any":
                return any(c.evaluate(facts) for c in self.children)
            case "not":
                return not any(c.evaluate(facts) for c in self.children)
            case "count":
                hits = sum(1 for c in self.children if c.evaluate(facts))
                return _compare(hits, self.op or ">=", self.value if self.value is not None else 1)
        raise RuleError(f"unsupported condition kind: {self.kind}")

    def matched_keys(self, facts: dict[str, Any]) -> list[str]:
        if self.kind == "term":
            return [self.key] if self.evaluate(facts) and self.key in facts else []
        out: list[str] = []
        for c in self.children:
            out.extend(c.matched_keys(facts))
        return out


def parse_condition(node: Any) -> Condition:
    if isinstance(node, str):
        m = _TERM_RE.match(node)
        if not m:
            raise RuleError(f"cannot parse condition term: {node!r}")
        op = (m.group("op") or "").strip()
        value = _coerce(m.group("value")) if m.group("value") is not None else None
        return Condition("term", key=m.group("key").lower(), op=op, value=value)
    if isinstance(node, list):
        return Condition("all", children=[parse_condition(n) for n in node])
    if isinstance(node, dict):
        if len(node) > 1:
            # Sibling combinators are an implicit AND: {all: [...], not: [...]}.
            return Condition("all", children=[parse_condition({k: v}) for k, v in node.items()])
        if not node:
            raise RuleError("empty condition object")
        (key, body), = node.items()
        key = key.lower()
        if key in {"all", "and"}:
            return Condition("all", children=[parse_condition(n) for n in body])
        if key in {"any", "or"}:
            return Condition("any", children=[parse_condition(n) for n in body])
        if key in {"not", "none_of"}:
            items = body if isinstance(body, list) else [body]
            return Condition("not", children=[parse_condition(n) for n in items])
        if key == "count":
            terms = body.get("of") or []
            return Condition(
                "count",
                op=str(body.get("op", ">=")),
                value=body.get("value", 1),
                children=[parse_condition(n) for n in terms],
            )
        raise RuleError(f"unsupported condition combinator: {key}")
    raise RuleError(f"unsupported condition node type: {type(node).__name__}")


@dataclass
class Rule:
    id: str
    version: int
    name: str
    category: str
    severity: Severity
    confidence: float
    conditions: Condition
    evidence_keys: list[str] = field(default_factory=list)
    recommendation: str = ""
    explanation: str = ""
    exclusions: Condition | None = None
    enabled: bool = True
    hard: bool = False
    internal: bool = False
    weight: float | None = None
    tags: list[str] = field(default_factory=list)

    @property
    def effective_weight(self) -> float:
        return self.weight if self.weight is not None else float(SEVERITY_BASE_WEIGHT[self.severity])


def load_rule(data: dict[str, Any]) -> Rule:
    required = ("id", "version", "name", "category", "severity", "confidence", "conditions")
    missing = [k for k in required if k not in data]
    if missing:
        raise RuleError(f"rule {data.get('id', '<no id>')} missing fields: {', '.join(missing)}")
    severity = Severity(str(data["severity"]).lower())
    confidence = float(data["confidence"])
    if not 0.0 <= confidence <= 1.0:
        raise RuleError(f"rule {data['id']}: confidence must be within 0..1")
    return Rule(
        id=str(data["id"]),
        version=int(data["version"]),
        name=str(data["name"]),
        category=str(data["category"]),
        severity=severity,
        confidence=confidence,
        conditions=parse_condition(data["conditions"]),
        exclusions=parse_condition(data["exclusions"]) if data.get("exclusions") else None,
        evidence_keys=list(data.get("evidence", []) or []),
        recommendation=str(data.get("recommendation", "") or ""),
        explanation=str(data.get("explanation", "") or ""),
        enabled=bool(data.get("enabled", True)),
        hard=bool(data.get("hard", False)),
        internal=bool(data.get("internal", False)),
        weight=float(data["weight"]) if data.get("weight") is not None else None,
        tags=list(data.get("tags", []) or []),
    )


class RuleSet:
    def __init__(self, rules: list[Rule]) -> None:
        seen: dict[str, Rule] = {}
        for r in rules:
            if r.id in seen:
                raise RuleError(f"duplicate rule id: {r.id}")
            seen[r.id] = r
        self.rules = rules

    @property
    def version_fingerprint(self) -> str:
        return ",".join(f"{r.id}:{r.version}" for r in sorted(self.rules, key=lambda r: r.id))

    @classmethod
    def from_directory(cls, directory: str | Path) -> RuleSet:
        path = Path(directory)
        rules: list[Rule] = []
        for file in sorted(path.glob("*.yaml")):
            payload = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
            for item in payload.get("rules", []) or []:
                try:
                    rules.append(load_rule(item))
                except RuleError as exc:
                    raise RuleError(f"{file.name}: {exc}") from exc
        if not rules:
            raise RuleError(f"no rules found in {path}")
        return cls(rules)

    def evaluate(self, fs: FactSet, ctx: AnalysisContext) -> list[Signal]:
        facts = fs.facts
        sender = str(facts.get("from_address") or "")
        domain = str(facts.get("from_domain") or "")
        signals: list[Signal] = []
        for rule in self.rules:
            if not rule.enabled or not rule.conditions.evaluate(facts):
                continue
            if rule.exclusions is not None and rule.exclusions.evaluate(facts):
                continue
            evidence: dict[str, Any] = {}
            keys = rule.evidence_keys or rule.conditions.matched_keys(facts)
            for key in keys[:12]:
                if key in fs.evidence:
                    evidence[key] = fs.evidence[key]
                elif key in facts and facts[key] is not True:
                    evidence[key] = facts[key]
                elif key in facts:
                    evidence[key] = True
            exc = ctx.matching_exception(sender=sender, domain=domain, rule_id=rule.id)
            signal = Signal(
                id=f"{rule.id}.v{rule.version}",
                category=rule.category,
                title=rule.name,
                explanation=rule.explanation or rule.name,
                severity=rule.severity,
                confidence=rule.confidence,
                weight=rule.effective_weight,
                source="rule_engine",
                evidence=evidence,
                rule_id=rule.id,
                rule_version=rule.version,
                hard=rule.hard,
                internal=rule.internal,
                recommendation=rule.recommendation or None,
                suppressed=exc is not None,
                suppressed_by=(
                    f"{exc.exception_type.value}:{exc.exception_id}" if exc is not None else None
                ),
            )
            signals.append(signal)
        return signals


def default_ruleset() -> RuleSet:
    return RuleSet.from_directory(Path(__file__).parent / "rules")
