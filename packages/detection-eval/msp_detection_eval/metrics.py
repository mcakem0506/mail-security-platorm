"""Detection quality metrics (ТЗ 1.0.3 §7, §8).

Every number here is defined so that it cannot flatter the system by accident.

**Precision has a denominator that can be zero, and stays undefined when it is.** A rule that has
never fired has no precision — not a perfect one. ``None`` propagates instead of becoming 1.0.

**Recall is measured only over cases the platform had a chance to catch.** A case that needs
Threat Intelligence enrichment is excluded from a local-analysis run rather than counted as a
miss, because judging a stage for information it does not yet have measures the wrong thing.

**Spam is scored separately.** Calling spam "suspicious" is neither a true positive nor a false
one; folding it into either would make the headline numbers depend on how much marketing mail
happened to be in the sample.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from msp_contracts import RISK_ORDER, RiskLevel

#: The verdict at or above which a message counts as "flagged".
FLAGGED_AT = RiskLevel.SUSPICIOUS


def is_flagged(level: RiskLevel) -> bool:
    return RISK_ORDER[level] >= RISK_ORDER[FLAGGED_AT]


def ratio(numerator: int, denominator: int) -> float | None:
    """A rate, or ``None`` when there is nothing to divide by.

    Returning ``None`` rather than 0.0 or 1.0 is the whole point: "no data" and "perfect" must
    not look the same on a dashboard.
    """
    if denominator <= 0:
        return None
    return round(numerator / denominator, 4)


@dataclass
class ConfusionMatrix:
    """Counts over a set of cases, plus the derived rates."""

    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0
    #: Returned UNKNOWN where a verdict was expected: neither a catch nor a clean miss.
    unknown: int = 0
    #: Returned UNKNOWN where UNKNOWN *was* the right answer — a message the platform correctly
    #: refused to judge. Counted apart from ``unknown`` because folding the two together makes
    #: honesty about a malformed message look like a failure to detect one.
    correctly_uncertain: int = 0
    #: Could not be examined at all (limits, encryption).
    unscannable: int = 0
    #: Excluded because the case needs a stage that did not run.
    skipped: int = 0

    @property
    def total(self) -> int:
        return (
            self.true_positive
            + self.false_positive
            + self.true_negative
            + self.false_negative
            + self.unknown
            + self.correctly_uncertain
        )

    @property
    def precision(self) -> float | None:
        return ratio(self.true_positive, self.true_positive + self.false_positive)

    @property
    def recall(self) -> float | None:
        # UNKNOWN counts against recall: the message was not caught, whatever the reason.
        return ratio(self.true_positive, self.true_positive + self.false_negative + self.unknown)

    @property
    def false_positive_rate(self) -> float | None:
        return ratio(self.false_positive, self.false_positive + self.true_negative)

    @property
    def false_negative_rate(self) -> float | None:
        caught = self.true_positive + self.false_negative + self.unknown
        return ratio(self.false_negative + self.unknown, caught)

    @property
    def f1(self) -> float | None:
        precision, recall = self.precision, self.recall
        if precision is None or recall is None or (precision + recall) == 0:
            return None
        return round(2 * precision * recall / (precision + recall), 4)

    @property
    def unknown_rate(self) -> float | None:
        return ratio(self.unknown, self.total)

    @property
    def unscannable_rate(self) -> float | None:
        return ratio(self.unscannable, self.total + self.unscannable)

    def as_dict(self) -> dict[str, Any]:
        return {
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "unknown": self.unknown,
            "correctly_uncertain": self.correctly_uncertain,
            "unscannable": self.unscannable,
            "skipped": self.skipped,
            "total": self.total,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "unknown_rate": self.unknown_rate,
            "unscannable_rate": self.unscannable_rate,
        }


@dataclass
class RuleMetrics:
    """Per-rule quality over an evaluation run (ТЗ 1.0.3 §8)."""

    rule_id: str
    version: int = 1
    status: str = "ACTIVE"
    owner: str = ""
    total_triggers: int = 0
    #: Fired on a case whose expected answer was a threat.
    true_positive: int = 0
    #: Fired on a case that should not have been flagged.
    false_positive: int = 0
    #: Fired on a case whose expected answer is genuinely uncertain (spam).
    confirmed_unknown: int = 0
    suppressed: int = 0
    #: Fired where a case explicitly forbade it.
    forbidden_hits: int = 0
    #: Expected by a case but did not fire.
    missed_expectations: int = 0
    latency_ms_total: float = 0.0

    @property
    def precision(self) -> float | None:
        return ratio(self.true_positive, self.true_positive + self.false_positive)

    @property
    def trigger_rate(self) -> float | None:
        return None  # meaningful only against a corpus size; supplied by the report

    @property
    def suppression_rate(self) -> float | None:
        return ratio(self.suppressed, self.total_triggers)

    @property
    def mean_latency_ms(self) -> float | None:
        return round(self.latency_ms_total / self.total_triggers, 3) if self.total_triggers else None

    def as_dict(self, corpus_size: int = 0) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "status": self.status,
            "owner": self.owner,
            "total_triggers": self.total_triggers,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "confirmed_unknown": self.confirmed_unknown,
            "suppressed": self.suppressed,
            "forbidden_hits": self.forbidden_hits,
            "missed_expectations": self.missed_expectations,
            "precision": self.precision,
            "trigger_rate": ratio(self.total_triggers, corpus_size),
            "suppression_rate": self.suppression_rate,
            "mean_latency_ms": self.mean_latency_ms,
        }


@dataclass
class CategoryMetrics:
    """Quality within one threat category (ТЗ 1.0.3 §7)."""

    category: str
    matrix: ConfusionMatrix = field(default_factory=ConfusionMatrix)

    def as_dict(self) -> dict[str, Any]:
        return {"category": self.category, **self.matrix.as_dict()}


@dataclass
class EvaluationMetrics:
    """The whole picture for one evaluation run."""

    overall: ConfusionMatrix = field(default_factory=ConfusionMatrix)
    by_category: dict[str, CategoryMetrics] = field(default_factory=dict)
    rules: dict[str, RuleMetrics] = field(default_factory=dict)
    #: Spam handled on its own terms: escalating it to an attack verdict is the failure mode.
    spam_escalated: int = 0
    spam_total: int = 0
    latency_ms: list[float] = field(default_factory=list)

    def category(self, name: str) -> CategoryMetrics:
        if name not in self.by_category:
            self.by_category[name] = CategoryMetrics(category=name)
        return self.by_category[name]

    def rule(self, rule_id: str) -> RuleMetrics:
        if rule_id not in self.rules:
            self.rules[rule_id] = RuleMetrics(rule_id=rule_id)
        return self.rules[rule_id]

    # -- derived views -----------------------------------------------------------------------
    def coverage(self) -> float | None:
        """Share of cases the run could actually judge."""
        judged = self.overall.total
        return ratio(judged, judged + self.overall.skipped + self.overall.unscannable)

    def percentile(self, fraction: float) -> float | None:
        if not self.latency_ms:
            return None
        ordered = sorted(self.latency_ms)
        index = max(0, min(len(ordered) - 1, round(fraction * len(ordered)) - 1))
        return round(ordered[index], 2)

    def noisy_rules(self, limit: int = 10, min_triggers: int = 3) -> list[dict[str, Any]]:
        """Rules that fire often and are wrong more than half the time."""
        candidates = [
            metric
            for metric in self.rules.values()
            if metric.total_triggers >= min_triggers
            and metric.precision is not None
            and metric.precision < 0.5
        ]
        candidates.sort(key=lambda m: (m.precision or 0.0, -m.total_triggers))
        return [m.as_dict(self.overall.total) for m in candidates[:limit]]

    def effective_rules(self, limit: int = 10) -> list[dict[str, Any]]:
        candidates = [
            metric
            for metric in self.rules.values()
            if metric.true_positive >= 2 and (metric.precision or 0.0) >= 0.7
        ]
        candidates.sort(key=lambda m: (-(m.precision or 0.0), -m.true_positive))
        return [m.as_dict(self.overall.total) for m in candidates[:limit]]

    def unowned_active_rules(self) -> list[str]:
        """ACTIVE rules with no owner — an exit criterion of ТЗ 1.0.3 §60."""
        return sorted(
            metric.rule_id
            for metric in self.rules.values()
            if metric.status in {"ACTIVE", "DEGRADED"} and not metric.owner
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "overall": self.overall.as_dict(),
            "coverage": self.coverage(),
            "by_category": {name: metric.as_dict() for name, metric in sorted(self.by_category.items())},
            "spam": {
                "total": self.spam_total,
                "escalated_to_attack": self.spam_escalated,
                "escalation_rate": ratio(self.spam_escalated, self.spam_total),
            },
            "latency_ms": {
                "median": self.percentile(0.5),
                "p95": self.percentile(0.95),
                "p99": self.percentile(0.99),
                "samples": len(self.latency_ms),
            },
            "rules": {
                rule_id: metric.as_dict(self.overall.total) for rule_id, metric in sorted(self.rules.items())
            },
            "top_noisy_rules": self.noisy_rules(),
            "top_effective_rules": self.effective_rules(),
            "unowned_active_rules": self.unowned_active_rules(),
        }


def merge(matrices: Iterable[ConfusionMatrix]) -> ConfusionMatrix:
    total = ConfusionMatrix()
    for matrix in matrices:
        total.true_positive += matrix.true_positive
        total.false_positive += matrix.false_positive
        total.true_negative += matrix.true_negative
        total.false_negative += matrix.false_negative
        total.unknown += matrix.unknown
        total.unscannable += matrix.unscannable
        total.skipped += matrix.skipped
    return total
