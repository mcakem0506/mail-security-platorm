"""Running a dataset through the detection engine (ТЗ 1.0.3 §4).

The runner is deliberately independent of the API and the database: it takes messages, rules and
a context, and produces outcomes. That makes an evaluation reproducible from a checkout alone,
which is what lets CI block a regression without needing a deployment.

Two judging decisions are worth stating, because they are where an evaluation harness usually
starts lying to itself:

* a case that needs enrichment is **skipped** in a local-analysis run, not counted as a miss;
* ``UNKNOWN`` on a threat case is counted separately from a clean miss. Both are failures to
  catch, but they have different causes — one is "we looked and were unsure", the other is
  "we looked and said it was fine" — and fixing them takes different work.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from typing import Any

from msp_contracts import RISK_ORDER, RiskLevel, ScanCompleteness, Signal
from msp_detection import AnalysisContext, analyze
from msp_detection.rules import RuleSet
from msp_mail_parser import ParserLimits, parse_message
from msp_risk import RiskThresholds, evaluate

from .dataset import Dataset, EvaluationCase
from .metrics import EvaluationMetrics, is_flagged

#: Resolves ``message_reference`` to raw bytes.
MessageResolver = Callable[[str], bytes]
#: Produces gateway findings for one parsed message. Supplied by the caller so this package
#: stays independent of any gateway provider implementation.
FindingsFactory = Callable[[Any], Any]


@dataclass
class CaseOutcome:
    """What happened to one case."""

    case: EvaluationCase
    classification: RiskLevel = RiskLevel.UNKNOWN
    score: int = 0
    fired_rules: list[str] = field(default_factory=list)
    shadow_rules: list[str] = field(default_factory=list)
    suppressed_rules: list[str] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    completeness: str = ScanCompleteness.COMPLETE.value
    missing_evidence: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    skipped: bool = False
    error: str = ""

    # -- judgement ---------------------------------------------------------------------------
    @property
    def flagged(self) -> bool:
        return is_flagged(self.classification)

    @property
    def meets_expected_level(self) -> bool:
        return RISK_ORDER[self.classification] >= RISK_ORDER[self.case.expected_classification]

    @property
    def missing_expected_rules(self) -> list[str]:
        return sorted(set(self.case.expected_rules) - set(self.fired_rules))

    @property
    def forbidden_rules_fired(self) -> list[str]:
        return sorted(set(self.case.forbidden_rules) & set(self.fired_rules))

    @property
    def passed(self) -> bool:
        if self.skipped:
            return True
        if self.error:
            return False
        if self.forbidden_rules_fired or self.missing_expected_rules:
            return False
        if self.case.is_benign:
            return not self.flagged
        if self.case.is_ambiguous:
            # Spam may be flagged, but escalating it to an attack verdict is a failure.
            return RISK_ORDER[self.classification] < RISK_ORDER[RiskLevel.HIGH_RISK]
        return self.meets_expected_level

    def failure_reason(self) -> str:
        if self.skipped:
            return ""
        if self.error:
            return f"ошибка анализа: {self.error}"
        if self.forbidden_rules_fired:
            return f"сработали запрещённые правила: {', '.join(self.forbidden_rules_fired)}"
        if self.missing_expected_rules:
            return f"не сработали ожидаемые правила: {', '.join(self.missing_expected_rules)}"
        if self.case.is_benign and self.flagged:
            return f"легитимное письмо помечено как {self.classification.value}"
        if self.case.is_ambiguous and RISK_ORDER[self.classification] >= RISK_ORDER[RiskLevel.HIGH_RISK]:
            return f"спам поднят до {self.classification.value}"
        if not self.meets_expected_level:
            return (
                f"получено {self.classification.value}, "
                f"ожидалось не ниже {self.case.expected_classification.value}"
            )
        return ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case.id,
            "category": self.case.category.value,
            "expected": self.case.expected_classification.value,
            "actual": self.classification.value,
            "score": self.score,
            "passed": self.passed,
            "skipped": self.skipped,
            "reason": self.failure_reason(),
            "fired_rules": self.fired_rules,
            "shadow_rules": self.shadow_rules,
            "completeness": self.completeness,
            "latency_ms": round(self.latency_ms, 2),
        }


@dataclass
class EvaluationResult:
    dataset_id: str
    dataset_version: str
    dataset_checksum: str
    ruleset_fingerprint: str
    outcomes: list[CaseOutcome] = field(default_factory=list)
    metrics: EvaluationMetrics = field(default_factory=EvaluationMetrics)

    @property
    def failures(self) -> list[CaseOutcome]:
        return [o for o in self.outcomes if not o.passed]

    @property
    def passed(self) -> bool:
        return not self.failures

    def as_dict(self) -> dict[str, Any]:
        return {
            "dataset": {
                "id": self.dataset_id,
                "version": self.dataset_version,
                "checksum": self.dataset_checksum,
            },
            "ruleset_fingerprint": self.ruleset_fingerprint,
            "passed": self.passed,
            "cases": len(self.outcomes),
            "failures": [o.as_dict() for o in self.failures],
            "metrics": self.metrics.as_dict(),
        }


class EvaluationRunner:
    """Runs a dataset against a rule set and scores the result."""

    def __init__(
        self,
        ruleset: RuleSet,
        context: AnalysisContext,
        resolver: MessageResolver,
        *,
        thresholds: RiskThresholds | None = None,
        limits: ParserLimits | None = None,
        analysis_complete: bool = False,
        findings_factory: FindingsFactory | None = None,
    ) -> None:
        self.ruleset = ruleset
        self.context = context
        self.resolver = resolver
        # Gateway trust is decided per message — a forged header is only forged relative to
        # that message's own delivery chain — so findings are computed per case, not once.
        self.findings_factory = findings_factory
        self.thresholds = thresholds or RiskThresholds()
        self.limits = limits or ParserLimits()
        # Local analysis by default: that is the stage the add-in shows first and the one a
        # regression gate should protect, because it runs on every message.
        self.analysis_complete = analysis_complete

    def run_case(self, case: EvaluationCase) -> CaseOutcome:
        outcome = CaseOutcome(case=case)
        if case.requires_enrichment and not self.analysis_complete:
            outcome.skipped = True
            return outcome

        try:
            raw = self.resolver(case.message_reference)
        except Exception as exc:  # noqa: BLE001 - a missing sample is a dataset problem
            outcome.error = f"не удалось получить сообщение: {type(exc).__name__}"
            return outcome

        started = time.perf_counter()
        try:
            parsed = parse_message(raw, self.limits)
            context = self.context
            if self.findings_factory is not None:
                context = replace(context, gateway_findings=self.findings_factory(parsed))
            detection = analyze(parsed, context, ruleset=self.ruleset)
            verdict = evaluate(
                detection.signals,
                missing_evidence=detection.facts.missing_evidence,
                thresholds=self.thresholds,
                analysis_complete=self.analysis_complete,
                content_encrypted=parsed.encrypted,
                unparseable=not parsed.parse_ok,
            )
        except Exception as exc:  # noqa: BLE001 - one bad case must not stop the run
            outcome.error = f"{type(exc).__name__}: {exc}"
            return outcome
        outcome.latency_ms = (time.perf_counter() - started) * 1000

        outcome.classification = verdict.classification
        outcome.score = verdict.score
        outcome.signals = detection.signals
        outcome.completeness = str(detection.facts.get("scan_completeness") or "COMPLETE")
        outcome.missing_evidence = list(verdict.missing_evidence)
        for signal in detection.signals:
            if not signal.rule_id:
                continue
            if signal.shadow:
                outcome.shadow_rules.append(signal.rule_id)
            elif signal.suppressed:
                outcome.suppressed_rules.append(signal.rule_id)
            else:
                outcome.fired_rules.append(signal.rule_id)
        return outcome

    def run(self, dataset: Dataset) -> EvaluationResult:
        result = EvaluationResult(
            dataset_id=dataset.id,
            dataset_version=dataset.version,
            dataset_checksum=dataset.checksum(),
            ruleset_fingerprint=self.ruleset.version_fingerprint,
        )
        for case in dataset:
            result.outcomes.append(self.run_case(case))
        result.metrics = score(result.outcomes, self.ruleset)
        return result


def score(outcomes: Iterable[CaseOutcome], ruleset: RuleSet | None = None) -> EvaluationMetrics:
    """Turn outcomes into metrics, keeping the ambiguous cases out of the headline numbers."""
    metrics = EvaluationMetrics()
    rule_lookup = {rule.id: rule for rule in (ruleset.rules if ruleset else [])}

    for outcome in outcomes:
        case = outcome.case
        if outcome.skipped:
            metrics.overall.skipped += 1
            metrics.category(case.category.value).matrix.skipped += 1
            continue

        metrics.latency_ms.append(outcome.latency_ms)
        category = metrics.category(case.category.value).matrix

        if outcome.completeness == ScanCompleteness.UNSCANNABLE.value:
            metrics.overall.unscannable += 1
            category.unscannable += 1
            continue

        if case.is_ambiguous:
            # Spam is counted on its own: it belongs in neither column of the matrix.
            metrics.spam_total += 1
            if RISK_ORDER[outcome.classification] >= RISK_ORDER[RiskLevel.HIGH_RISK]:
                metrics.spam_escalated += 1
        elif case.is_benign:
            if outcome.flagged:
                metrics.overall.false_positive += 1
                category.false_positive += 1
            else:
                metrics.overall.true_negative += 1
                category.true_negative += 1
        else:
            if outcome.classification is RiskLevel.UNKNOWN:
                # A case that *expects* UNKNOWN — a malformed message the platform correctly
                # refused to judge — is a right answer, not a miss. Counting it against recall
                # would penalise the platform for being honest about what it could not parse.
                if case.expected_classification is RiskLevel.UNKNOWN:
                    metrics.overall.correctly_uncertain += 1
                    category.correctly_uncertain += 1
                else:
                    metrics.overall.unknown += 1
                    category.unknown += 1
            elif outcome.flagged:
                metrics.overall.true_positive += 1
                category.true_positive += 1
            else:
                metrics.overall.false_negative += 1
                category.false_negative += 1

        _score_rules(metrics, outcome, rule_lookup)
    return metrics


def _metric(metrics: EvaluationMetrics, rule_lookup: dict[str, Any], rule_id: str) -> Any:
    """Fetch a rule's metric row, always carrying its metadata.

    Metadata is attached here rather than at each call site because a rule that is *expected*
    and does not fire is created through this path too. Leaving its owner and status at the
    dataclass defaults made such a rule look ownerless, and the ownership gate then blocked a
    release over a rule that has an owner — a false alarm that teaches people to ignore the
    gate.
    """
    rule_metric = metrics.rule(rule_id)
    rule = rule_lookup.get(rule_id)
    if rule is not None:
        rule_metric.version = rule.version
        rule_metric.status = rule.status.value
        rule_metric.owner = rule.owner
    return rule_metric


def _score_rules(metrics: EvaluationMetrics, outcome: CaseOutcome, rule_lookup: dict[str, Any]) -> None:
    case = outcome.case
    for rule_id in outcome.fired_rules:
        rule_metric = _metric(metrics, rule_lookup, rule_id)
        rule_metric.total_triggers += 1
        if case.is_ambiguous:
            rule_metric.confirmed_unknown += 1
        elif case.is_benign:
            rule_metric.false_positive += 1
        else:
            rule_metric.true_positive += 1
        if rule_id in case.forbidden_rules:
            rule_metric.forbidden_hits += 1

    for rule_id in outcome.suppressed_rules:
        rule_metric = _metric(metrics, rule_lookup, rule_id)
        rule_metric.suppressed += 1
        rule_metric.total_triggers += 1
    for rule_id in outcome.shadow_rules:
        rule_metric = _metric(metrics, rule_lookup, rule_id)
        rule_metric.total_triggers += 1
        if case.is_benign:
            rule_metric.false_positive += 1
        elif not case.is_ambiguous:
            rule_metric.true_positive += 1
    for rule_id in outcome.missing_expected_rules:
        _metric(metrics, rule_lookup, rule_id).missed_expectations += 1
