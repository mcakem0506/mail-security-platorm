"""Run the golden corpus from inside the API (ТЗ 1.0.3B §10, §11, §24).

The same evaluation CI runs, exposed so a candidate pack can be benchmarked before anyone is
asked to review it. Reviewing a rule change by reading it is exactly what the corpus exists to
avoid.

The run is deliberately in-process and synchronous. It takes under a second on 340 cases, and a
background job would add a state machine, a queue and a progress API for no gain — complexity
worth avoiding in a path that gates releases.
"""

from __future__ import annotations

import functools
import logging
from typing import Any

from msp_contracts import Severity
from msp_detection.rules import RuleSet, find_rule_pack
from msp_detection_eval import (
    Baseline,
    EvaluationRunner,
    GateThresholds,
    check,
    evaluation_context,
    findings_factory,
    gateway_registry,
)
from msp_detection_eval.corpus import build_golden_dataset, corpus_checksum

from ..db.models import RuleCandidate
from .releases import ReleaseError, load_pack

logger = logging.getLogger(__name__)


def _baseline_path() -> str:
    from .detection_ops import _dataset_file

    return str(_dataset_file("baseline.json"))


def _gate_path() -> str:
    from .detection_ops import _dataset_file

    return str(_dataset_file("detection_gate.yaml"))


@functools.lru_cache(maxsize=1)
def _dataset():  # type: ignore[no-untyped-def]
    return build_golden_dataset()


def run_evaluation(ruleset: RuleSet) -> dict[str, Any]:
    """Evaluate one rule pack against the golden corpus."""
    dataset, messages = _dataset()
    findings_for = findings_factory(gateway_registry())

    runner = EvaluationRunner(
        ruleset=ruleset,
        context=evaluation_context(),
        resolver=lambda reference: messages[reference],
        findings_factory=findings_for,
    )
    result = runner.run(dataset)
    metrics = result.metrics
    overall = metrics.overall

    zero_weight = frozenset(
        rule.id for rule in ruleset.rules if rule.effective_weight == 0 or rule.severity is Severity.INFO
    )
    try:
        thresholds = GateThresholds.load(_gate_path())
        gate = check(result, thresholds, Baseline.load(_baseline_path()), zero_weight_rules=zero_weight)
        gate_payload = {
            "passed": gate.passed,
            "violations": [
                {"kind": v.kind, "detail": v.detail, "observed": v.observed, "required": v.required}
                for v in gate.violations
            ],
            "warnings": list(gate.warnings),
        }
    except (OSError, ValueError) as exc:  # pragma: no cover - misconfigured deployment
        logger.warning("evaluation.gate_unavailable", extra={"error": type(exc).__name__})
        gate_payload = {"passed": None, "violations": [], "warnings": ["гейт недоступен"]}

    return {
        "dataset_version": dataset.version,
        "dataset_checksum": corpus_checksum(),
        "cases": len(result.outcomes),
        "failures": [outcome.case.id for outcome in result.failures],
        "metrics": {
            "precision": overall.precision,
            "recall": overall.recall,
            "f1": overall.f1,
            "false_positive_rate": overall.false_positive_rate,
            "coverage": metrics.coverage(),
            "true_positive": overall.true_positive,
            "false_positive": overall.false_positive,
            "false_negative": overall.false_negative,
            "unknown": overall.unknown,
            "latency_ms": {
                "p50": metrics.percentile(0.5),
                "p95": metrics.percentile(0.95),
                "p99": metrics.percentile(0.99),
            },
        },
        "gate": gate_payload,
    }


def current_metrics() -> dict[str, Any]:
    """Evaluate the pack that is actually deployed."""
    return run_evaluation(RuleSet.from_directory(find_rule_pack()))


def benchmark_candidate(candidate: RuleCandidate) -> dict[str, Any]:
    """Benchmark a candidate and compare it with production (ТЗ 1.0.3B §10, §11)."""
    try:
        pack = load_pack(candidate.source, candidate.source_kind)
    except ReleaseError:
        raise
    production = run_evaluation(RuleSet.from_directory(find_rule_pack()))
    proposed = run_evaluation(pack)

    before = set(production["failures"])
    after = set(proposed["failures"])
    return {
        "dataset_version": proposed["dataset_version"],
        "cases": proposed["cases"],
        "precision": proposed["metrics"]["precision"],
        "recall": proposed["metrics"]["recall"],
        "f1": proposed["metrics"]["f1"],
        "gate_passed": proposed["gate"]["passed"],
        "gate_violations": proposed["gate"]["violations"],
        "production": production["metrics"],
        "candidate": proposed["metrics"],
        # Cases the candidate fixes and cases it breaks, by id. The second list is the one that
        # decides a review: a change that fixes four cases and breaks one is a conversation, not
        # an improvement.
        "resolved_cases": sorted(before - after),
        "broken_cases": sorted(after - before),
        "deltas": {
            key: _delta(production["metrics"].get(key), proposed["metrics"].get(key))
            for key in ("precision", "recall", "f1", "false_positive_rate", "coverage")
        },
    }


def _delta(before: Any, after: Any) -> float | None:
    """Difference, or ``None`` when either side is undefined.

    A metric that could not be computed on one side has no delta: reporting one against zero
    would turn "nothing to measure" into "it fell".
    """
    if isinstance(before, (int, float)) and isinstance(after, (int, float)):
        return round(after - before, 4)
    return None
