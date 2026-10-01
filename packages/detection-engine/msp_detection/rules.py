"""Versioned YAML rule engine (ТЗ 15.2).

Conditions are evaluated by a small, explicit interpreter — never ``eval``. A rule turns facts
into a Signal carrying its own explanation, evidence and recommendation, so every verdict can be
traced back to the rule version that produced it.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from msp_contracts import (
    RULE_EVALUATED,
    RULE_SCORING,
    SEVERITY_BASE_WEIGHT,
    RuleStatus,
    Severity,
    Signal,
)

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

    def render(self) -> str:
        """The condition in readable source form, for the analyst view (ТЗ 1.0.3 §15).

        An analyst asking "why did this fire" is better served by the condition than by a list
        of matched keys: the keys say what was true, the condition says what the rule asked.
        """
        match self.kind:
            case "term":
                return f"{self.key} {self.op} {self.value}".strip() if self.op else self.key
            case "all":
                return " AND ".join(c.render() for c in self.children)
            case "any":
                return " OR ".join(c.render() for c in self.children)
            case "not":
                return "NOT (" + " OR ".join(c.render() for c in self.children) + ")"
            case "count":
                inner = ", ".join(c.render() for c in self.children)
                return f"count({inner}) {self.op or '>='} {self.value if self.value is not None else 1}"
        return self.kind

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
        ((key, body),) = node.items()
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
    # -- lifecycle (ТЗ 1.0.3 §8, §11) ---------------------------------------------------------
    status: RuleStatus = RuleStatus.ACTIVE
    #: Who answers for this rule's quality. An ACTIVE rule without an owner is a rule nobody
    #: will tune when it starts misfiring, which is why §60 makes ownership an exit criterion.
    owner: str = ""
    author: str = ""
    reviewer: str = ""
    change_reason: str = ""
    #: Threat scenarios this rule is meant to cover (ТЗ 1.0.3 §28).
    scenarios: list[str] = field(default_factory=list)
    #: Upper bound on evaluation time, in milliseconds (ТЗ 1.0.3 §44).
    budget_ms: float = 5.0

    @property
    def effective_weight(self) -> float:
        """Weight this rule contributes to the score.

        A SHADOW rule contributes nothing by construction, not by configuration: returning zero
        here means no amount of tuning elsewhere can let an unvalidated rule move a verdict.
        """
        if self.status not in RULE_SCORING:
            return 0.0
        return self.weight if self.weight is not None else float(SEVERITY_BASE_WEIGHT[self.severity])

    @property
    def condition_source(self) -> str:
        return self.conditions.render()[:500]

    @property
    def evaluated(self) -> bool:
        return self.enabled and self.status in RULE_EVALUATED

    @property
    def scores(self) -> bool:
        return self.enabled and self.status in RULE_SCORING


#: Fields a rule file may contain. An unknown key is an error rather than something ignored:
#: a typo in ``severity`` that silently defaults would change detection without anyone noticing.
_ALLOWED_FIELDS = frozenset(
    {
        "id",
        "version",
        "name",
        "category",
        "severity",
        "confidence",
        "conditions",
        "exclusions",
        "evidence",
        "recommendation",
        "explanation",
        "enabled",
        "hard",
        "internal",
        "weight",
        "tags",
        "status",
        "owner",
        "author",
        "reviewer",
        "change_reason",
        "scenarios",
        "budget_ms",
    }
)
_RULE_ID_RE = re.compile(r"^[A-Z]{2,6}-\d{3,4}$")


def validate_rule_schema(data: dict[str, Any]) -> list[str]:
    """Check a rule definition against the schema, returning every problem found.

    Returns all problems rather than raising on the first, so an author fixing a rule file sees
    the whole list in one pass.
    """
    problems: list[str] = []
    rule_id = str(data.get("id", "<no id>"))

    for key in ("id", "version", "name", "category", "severity", "confidence", "conditions"):
        if key not in data:
            problems.append(f"{rule_id}: missing required field '{key}'")
    for key in sorted(set(data) - _ALLOWED_FIELDS):
        problems.append(f"{rule_id}: unknown field '{key}'")

    if "id" in data and not _RULE_ID_RE.match(str(data["id"])):
        problems.append(f"{rule_id}: id must look like 'SND-001' (2-6 letters, dash, 3-4 digits)")
    if "severity" in data:
        try:
            Severity(str(data["severity"]).lower())
        except ValueError:
            problems.append(f"{rule_id}: severity must be one of {[s.value for s in Severity]}")
    if "status" in data:
        try:
            RuleStatus(str(data["status"]).upper())
        except ValueError:
            problems.append(f"{rule_id}: status must be one of {[s.value for s in RuleStatus]}")
    if "confidence" in data:
        try:
            confidence = float(data["confidence"])
            if not 0.0 <= confidence <= 1.0:
                problems.append(f"{rule_id}: confidence must be within 0..1")
        except (TypeError, ValueError):
            problems.append(f"{rule_id}: confidence must be a number")
    if "version" in data:
        try:
            if int(data["version"]) < 1:
                problems.append(f"{rule_id}: version must be >= 1")
        except (TypeError, ValueError):
            problems.append(f"{rule_id}: version must be an integer")
    if "weight" in data and data["weight"] is not None:
        try:
            weight = float(data["weight"])
            if not 0.0 <= weight <= 100.0:
                problems.append(f"{rule_id}: weight must be within 0..100")
        except (TypeError, ValueError):
            problems.append(f"{rule_id}: weight must be a number")

    # An ACTIVE rule without an owner has nobody to tune it when it starts misfiring, which is
    # the exit criterion of ТЗ 1.0.3 §60.
    status = str(data.get("status", "ACTIVE")).upper()
    if status in {"ACTIVE", "DEGRADED"} and not str(data.get("owner", "")).strip():
        problems.append(f"{rule_id}: an ACTIVE rule must name an owner")

    if "conditions" in data:
        try:
            parse_condition(data["conditions"])
        except RuleError as exc:
            problems.append(f"{rule_id}: {exc}")
    if data.get("exclusions"):
        try:
            parse_condition(data["exclusions"])
        except RuleError as exc:
            problems.append(f"{rule_id}: exclusions: {exc}")
    return problems


def load_rule(data: dict[str, Any]) -> Rule:
    problems = validate_rule_schema(data)
    if problems:
        raise RuleError("; ".join(problems))
    severity = Severity(str(data["severity"]).lower())
    confidence = float(data["confidence"])
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
        status=RuleStatus(str(data.get("status", "ACTIVE")).upper()),
        owner=str(data.get("owner", "") or ""),
        author=str(data.get("author", "") or ""),
        reviewer=str(data.get("reviewer", "") or ""),
        change_reason=str(data.get("change_reason", "") or ""),
        scenarios=[str(s) for s in (data.get("scenarios", []) or [])],
        budget_ms=float(data.get("budget_ms", 5.0)),
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
        """Load every rule file under ``directory``, including subdirectories.

        The pack is organised by area (``sender/``, ``bec/``, ``url/`` …), so the search is
        recursive. Files are read in sorted order so the rule set is byte-for-byte reproducible,
        which is what makes ``version_fingerprint`` meaningful.
        """
        path = Path(directory)
        rules: list[Rule] = []
        for file in sorted(path.rglob("*.yaml")):
            payload = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
            for item in payload.get("rules", []) or []:
                try:
                    rules.append(load_rule(item))
                except RuleError as exc:
                    raise RuleError(f"{file.name}: {exc}") from exc
        if not rules:
            raise RuleError(f"no rules found in {path}")
        return cls(rules)

    # -- lifecycle views (ТЗ 1.0.3 §8, §10) ----------------------------------------------------
    def by_status(self, status: RuleStatus) -> list[Rule]:
        return [rule for rule in self.rules if rule.status is status]

    @property
    def active(self) -> list[Rule]:
        return [rule for rule in self.rules if rule.scores]

    @property
    def shadow(self) -> list[Rule]:
        return [rule for rule in self.rules if rule.status is RuleStatus.SHADOW]

    def get(self, rule_id: str) -> Rule | None:
        return next((rule for rule in self.rules if rule.id == rule_id), None)

    def status_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for rule in self.rules:
            counts[rule.status.value] = counts.get(rule.status.value, 0) + 1
        return counts

    def evaluate(self, fs: FactSet, ctx: AnalysisContext) -> list[Signal]:
        facts = fs.facts
        sender = str(facts.get("from_address") or "")
        domain = str(facts.get("from_domain") or "")
        signals: list[Signal] = []
        for rule in self.rules:
            if not rule.evaluated or not rule.conditions.evaluate(facts):
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
                # A SHADOW rule never produces a hard signal: a hard signal sets a floor on
                # the classification, which is exactly the influence shadow mode withholds.
                hard=rule.hard and rule.scores,
                internal=rule.internal or not rule.scores,
                shadow=not rule.scores,
                rule_status=rule.status.value,
                rule_condition=rule.condition_source,
                recommendation=rule.recommendation or None,
                suppressed=exc is not None,
                suppressed_by=(f"{exc.exception_type.value}:{exc.exception_id}" if exc is not None else None),
            )
            signals.append(signal)
        return signals


#: Where the rule pack lives, in search order. Rules are data, not code (ТЗ 1.0.3 §12), so
#: they sit outside the Python package and can be updated without redeploying the application.
def rule_pack_paths() -> list[Path]:
    """Candidate locations for the rule pack, most specific first."""
    candidates: list[Path] = []
    configured = os.environ.get("MSP_RULE_PACK_PATH")
    if configured:
        candidates.append(Path(configured))
    # Installed layout: /app/rules next to the application.
    candidates.append(Path("/app/rules"))
    # Development layout: the repository root, four levels up from this file.
    candidates.append(Path(__file__).resolve().parents[3] / "rules")
    return candidates


def find_rule_pack() -> Path:
    """The first existing rule pack, or a clear error naming where it was looked for.

    Failing loudly matters here: a missing rule pack would otherwise mean a platform that
    analyses every message and detects nothing, which looks exactly like a quiet week.
    """
    for candidate in rule_pack_paths():
        if candidate.is_dir() and any(candidate.rglob("*.yaml")):
            return candidate
    searched = ", ".join(str(c) for c in rule_pack_paths())
    raise RuleError(
        "detection rule pack not found. Rules are shipped as data, not inside the Python "
        f"package. Searched: {searched}. Set MSP_RULE_PACK_PATH to override."
    )


def default_ruleset() -> RuleSet:
    return RuleSet.from_directory(find_rule_pack())
