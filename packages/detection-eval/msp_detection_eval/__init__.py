"""Detection evaluation framework (ТЗ 1.0.3 §4).

Measuring a detection engine needs three things that are easy to get wrong and expensive to get
wrong quietly: a dataset whose labels are trustworthy, metrics that cannot flatter the system by
accident, and a gate that blocks a release when quality drops.

The package is deliberately free of database and API dependencies, so an evaluation can be run
from a checkout — which is what lets CI block a regression without a deployment.
"""

from .corpus import GoldenCorpusBuilder, build_golden_dataset, resolve_message
from .dataset import (
    AMBIGUOUS_CATEGORIES,
    BENIGN_CATEGORIES,
    ApprovalStatus,
    CaseSource,
    Dataset,
    DatasetCategory,
    EvaluationCase,
    PiiStatus,
)
from .gate import Baseline, GateResult, GateThresholds, GateViolation, check
from .metrics import (
    CategoryMetrics,
    ConfusionMatrix,
    EvaluationMetrics,
    RuleMetrics,
    is_flagged,
    ratio,
)
from .report import render_markdown, render_text
from .runner import CaseOutcome, EvaluationResult, EvaluationRunner, score

__all__ = [
    "AMBIGUOUS_CATEGORIES",
    "BENIGN_CATEGORIES",
    "ApprovalStatus",
    "Baseline",
    "CaseOutcome",
    "CaseSource",
    "CategoryMetrics",
    "ConfusionMatrix",
    "Dataset",
    "DatasetCategory",
    "EvaluationCase",
    "EvaluationMetrics",
    "EvaluationResult",
    "EvaluationRunner",
    "GateResult",
    "GateThresholds",
    "GateViolation",
    "GoldenCorpusBuilder",
    "PiiStatus",
    "RuleMetrics",
    "build_golden_dataset",
    "check",
    "is_flagged",
    "ratio",
    "render_markdown",
    "render_text",
    "resolve_message",
    "score",
]
