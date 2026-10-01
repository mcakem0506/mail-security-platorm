"""Detection regression gate (ТЗ 1.0.3 §9).

A rule change that raises recall on one category while quietly destroying precision on another
is the normal way detection quality decays. Nobody does it deliberately; it happens because the
person changing the rule only looked at the case in front of them.

The gate exists to make that visible before a release, and it blocks on four things:

* overall precision below the floor;
* per-category recall below its floor;
* **new high-severity false negatives** — a threat category that used to be caught and now is
  not. This is checked against a stored baseline rather than an absolute number, because "we
  never caught it" and "we just stopped catching it" call for different responses;
* critical acceptance scenarios that stopped firing.

The thresholds are configuration, and the defaults are explicitly starting values: ТЗ §9 says
they must be corrected after the pilot, on real numbers rather than guesses.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .metrics import EvaluationMetrics
from .runner import EvaluationResult


@dataclass
class GateThresholds:
    """Release thresholds. Starting values per ТЗ 1.0.3 §9; tune after the pilot."""

    overall_precision_min: float = 0.90
    bec_recall_min: float = 0.85
    impersonation_recall_min: float = 0.90
    phishing_recall_min: float = 0.85
    #: How far any metric may fall relative to the baseline, in percent.
    max_regression_percent: float = 3.0
    #: Categories where losing a previously-caught case blocks the release.
    high_severity_categories: list[str] = field(
        default_factory=lambda: [
            "bec",
            "phishing",
            "impersonation",
            "credential_theft",
            "malicious_attachment",
        ]
    )
    #: Cases that must always pass, whatever the aggregate numbers say.
    critical_case_ids: list[str] = field(default_factory=list)
    #: A rule firing on more than this share of a benign corpus is noise by definition.
    max_benign_trigger_rate: float = 0.25

    @classmethod
    def load(cls, path: str | Path) -> GateThresholds:
        payload = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        gate = payload.get("detection_gate", payload) or {}
        known = set(cls.__dataclass_fields__)
        unknown = sorted(set(gate) - known)
        if unknown:
            # A misspelled threshold would silently keep the default, which is the one failure
            # mode a release gate must not have.
            raise ValueError(f"unknown detection_gate settings: {', '.join(unknown)}")
        return cls(**{k: v for k, v in gate.items() if k in known})

    def as_dict(self) -> dict[str, Any]:
        return {
            "overall_precision_min": self.overall_precision_min,
            "bec_recall_min": self.bec_recall_min,
            "impersonation_recall_min": self.impersonation_recall_min,
            "phishing_recall_min": self.phishing_recall_min,
            "max_regression_percent": self.max_regression_percent,
            "high_severity_categories": list(self.high_severity_categories),
            "critical_case_ids": list(self.critical_case_ids),
            "max_benign_trigger_rate": self.max_benign_trigger_rate,
        }


@dataclass
class GateViolation:
    kind: str
    detail: str
    observed: Any = None
    required: Any = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "observed": self.observed,
            "required": self.required,
        }


@dataclass
class GateResult:
    passed: bool
    violations: list[GateViolation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    thresholds: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "violations": [v.as_dict() for v in self.violations],
            "warnings": self.warnings,
            "thresholds": self.thresholds,
        }

    def render(self) -> str:
        lines = ["Detection regression gate: " + ("ПРОЙДЕН" if self.passed else "ЗАБЛОКИРОВАН")]
        for violation in self.violations:
            lines.append(f"  [БЛОКЕР] {violation.kind}: {violation.detail}")
        for warning in self.warnings:
            lines.append(f"  [ПРЕДУПРЕЖДЕНИЕ] {warning}")
        return "\n".join(lines)


@dataclass
class Baseline:
    """A previous run, used to tell a new failure from a long-standing one."""

    ruleset_fingerprint: str = ""
    dataset_checksum: str = ""
    overall: dict[str, Any] = field(default_factory=dict)
    by_category: dict[str, dict[str, Any]] = field(default_factory=dict)
    passing_case_ids: list[str] = field(default_factory=list)

    @classmethod
    def from_result(cls, result: EvaluationResult) -> Baseline:
        return cls(
            ruleset_fingerprint=result.ruleset_fingerprint,
            dataset_checksum=result.dataset_checksum,
            overall=result.metrics.overall.as_dict(),
            by_category={name: metric.as_dict() for name, metric in result.metrics.by_category.items()},
            passing_case_ids=sorted(o.case.id for o in result.outcomes if o.passed and not o.skipped),
        )

    @classmethod
    def load(cls, path: str | Path) -> Baseline | None:
        file = Path(path)
        if not file.is_file():
            return None
        payload = json.loads(file.read_text(encoding="utf-8"))
        return cls(
            ruleset_fingerprint=str(payload.get("ruleset_fingerprint", "")),
            dataset_checksum=str(payload.get("dataset_checksum", "")),
            overall=dict(payload.get("overall", {})),
            by_category=dict(payload.get("by_category", {})),
            passing_case_ids=[str(c) for c in payload.get("passing_case_ids", [])],
        )

    def write(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(
                {
                    "ruleset_fingerprint": self.ruleset_fingerprint,
                    "dataset_checksum": self.dataset_checksum,
                    "overall": self.overall,
                    "by_category": self.by_category,
                    "passing_case_ids": self.passing_case_ids,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        return target


def _below(observed: float | None, required: float) -> bool:
    """A metric fails only when it exists and is below the floor.

    ``None`` means "no data", which is a warning rather than a failure: blocking a release
    because a category had no samples would just teach people to delete the check.
    """
    return observed is not None and observed < required


def check(
    result: EvaluationResult,
    thresholds: GateThresholds | None = None,
    baseline: Baseline | None = None,
    zero_weight_rules: frozenset[str] | None = None,
) -> GateResult:
    """Decide whether this evaluation may be released."""
    thresholds = thresholds or GateThresholds()
    zero_weight_rules = zero_weight_rules or frozenset()
    gate = GateResult(passed=True, thresholds=thresholds.as_dict())
    metrics: EvaluationMetrics = result.metrics

    # -- 1. absolute floors --------------------------------------------------------------------
    precision = metrics.overall.precision
    if precision is None:
        gate.warnings.append("общая precision не определена: ни одного сработавшего правила на корпусе")
    elif _below(precision, thresholds.overall_precision_min):
        gate.violations.append(
            GateViolation(
                "precision",
                f"общая precision {precision} ниже порога",
                precision,
                thresholds.overall_precision_min,
            )
        )

    for category, minimum in (
        ("bec", thresholds.bec_recall_min),
        ("impersonation", thresholds.impersonation_recall_min),
        ("phishing", thresholds.phishing_recall_min),
    ):
        metric = metrics.by_category.get(category)
        if metric is None:
            gate.warnings.append(f"категория {category} отсутствует в корпусе: recall не измерен")
            continue
        recall = metric.matrix.recall
        if recall is None:
            gate.warnings.append(f"recall категории {category} не определён")
        elif _below(recall, minimum):
            gate.violations.append(
                GateViolation("recall", f"recall {category} = {recall} ниже порога", recall, minimum)
            )

    # -- 2. new high-severity false negatives --------------------------------------------------
    if baseline is not None:
        previously_passing = set(baseline.passing_case_ids)
        now_failing = {o.case.id for o in result.failures}
        regressed = sorted(previously_passing & now_failing)
        high_severity = [
            o
            for o in result.failures
            if o.case.id in regressed
            and o.case.category.value in thresholds.high_severity_categories
            and not o.case.known_gap
        ]
        if high_severity:
            gate.violations.append(
                GateViolation(
                    "new_false_negative",
                    "перестали обнаруживаться ранее обнаруживаемые угрозы: "
                    + ", ".join(f"{o.case.id} ({o.failure_reason()})" for o in high_severity[:5]),
                    [o.case.id for o in high_severity],
                    "0",
                )
            )
        elif regressed:
            gate.warnings.append(
                f"перестали проходить {len(regressed)} кейсов вне высокоприоритетных категорий: "
                + ", ".join(regressed[:5])
            )

        # -- 3. relative regression ------------------------------------------------------------
        for name, current in metrics.by_category.items():
            before = baseline.by_category.get(name, {})
            for key in ("precision", "recall"):
                old_value, new_value = before.get(key), current.as_dict().get(key)
                if old_value is None or new_value is None or old_value == 0:
                    continue
                drop_percent = (old_value - new_value) / old_value * 100
                if drop_percent > thresholds.max_regression_percent:
                    gate.violations.append(
                        GateViolation(
                            "regression",
                            f"{name}: {key} упал с {old_value} до {new_value} ({drop_percent:.1f}%)",
                            new_value,
                            f">= {old_value * (1 - thresholds.max_regression_percent / 100):.4f}",
                        )
                    )
    else:
        gate.warnings.append(
            "базовая линия отсутствует: проверяются только абсолютные пороги, регрессия — нет"
        )

    # -- 3b. known gaps ---------------------------------------------------------------------------
    # A miss that falls into a registered DetectionGap is an accepted limitation with an owner
    # and a target release; a miss without one is a regression. This is the distinction ТЗ
    # 1.0.3 §60 makes an exit criterion, and it is the only thing separating "we know about it"
    # from "we did not notice".
    gap_failures = [o for o in result.failures if o.case.known_gap]
    for outcome in gap_failures:
        gate.warnings.append(
            f"известный пробел {outcome.case.known_gap}: {outcome.case.id} — {outcome.failure_reason()}"
        )

    # -- 4. critical cases ----------------------------------------------------------------------
    failing = {o.case.id: o for o in result.failures}
    for case_id in thresholds.critical_case_ids:
        if case_id in failing:
            gate.violations.append(
                GateViolation(
                    "critical_case",
                    f"критический сценарий {case_id} не проходит: {failing[case_id].failure_reason()}",
                    case_id,
                    "passed",
                )
            )

    # -- 5. rules that fire on everything -------------------------------------------------------
    benign_total = sum(
        m.matrix.false_positive + m.matrix.true_negative
        for name, m in metrics.by_category.items()
        if name == "legitimate"
    )
    if benign_total:
        for rule_id, rule_metric in metrics.rules.items():
            if rule_metric.status not in {"ACTIVE", "DEGRADED"}:
                continue
            # Zero-weight rules are context, not detection: "sender not seen before" fires on
            # most legitimate mail and is supposed to. Counting it as noise would measure the
            # wrong thing and train people to ignore the warning.
            if rule_id in zero_weight_rules:
                continue
            rate = rule_metric.false_positive / benign_total
            if rate > thresholds.max_benign_trigger_rate:
                gate.warnings.append(f"правило {rule_id} срабатывает на {rate:.0%} легитимной почты")

    # -- 6. ownership (ТЗ 1.0.3 §60) --------------------------------------------------------------
    unowned = metrics.unowned_active_rules()
    if unowned:
        gate.violations.append(
            GateViolation(
                "unowned_rule",
                "у активных правил нет владельца: " + ", ".join(unowned[:10]),
                unowned,
                "каждое ACTIVE правило имеет owner",
            )
        )

    gate.passed = not gate.violations
    return gate
