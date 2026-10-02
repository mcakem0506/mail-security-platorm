"""Run the golden dataset against the detection engine (ТЗ 1.0.3 §4, §9, §57).

This is what CI runs to block a detection regression, and what a detection engineer runs before
proposing a rule change.

Usage::

    python scripts/evaluate_detection.py                      # evaluate and print a summary
    python scripts/evaluate_detection.py --gate               # apply the release gate
    python scripts/evaluate_detection.py --markdown report.md
    python scripts/evaluate_detection.py --json result.json
    python scripts/evaluate_detection.py --update-baseline    # accept current results as the baseline
    python scripts/evaluate_detection.py --rules path/to/rules

Exit code is 1 when the gate blocks, so it can gate a pipeline step directly.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

from msp_contracts import (  # noqa: E402
    Severity,
)
from msp_detection.rules import RuleSet, find_rule_pack  # noqa: E402
from msp_detection_eval import (  # noqa: E402
    Baseline,
    EvaluationRunner,
    GateThresholds,
    check,
    evaluation_context,
    findings_factory,
    gateway_registry,
    render_markdown,
    render_text,
)
from msp_detection_eval.corpus import build_golden_dataset  # noqa: E402

CORP = "corp.example"
DEFAULT_BASELINE = REPO_ROOT / "datasets" / "baseline.json"
DEFAULT_GATE = REPO_ROOT / "datasets" / "detection_gate.yaml"


def main() -> int:
    parser = argparse.ArgumentParser(description="Оценка качества детектирования (ТЗ 1.0.3)")
    parser.add_argument("--rules", help="каталог с правилами (по умолчанию — найденный пакет)")
    parser.add_argument("--gate", action="store_true", help="применить релизный гейт")
    parser.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    parser.add_argument("--thresholds", default=str(DEFAULT_GATE))
    parser.add_argument("--update-baseline", action="store_true")
    parser.add_argument("--markdown", metavar="FILE")
    parser.add_argument("--json", metavar="FILE")
    parser.add_argument("--version", default="2026.09.1")
    args = parser.parse_args()

    ruleset = RuleSet.from_directory(args.rules) if args.rules else RuleSet.from_directory(find_rule_pack())
    dataset, messages = build_golden_dataset(args.version)

    problems = dataset.validate()
    if problems:
        print("Датасет не прошёл проверку:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    # Gateway trust is decided per message: a header is forged only relative to that message's
    # own delivery chain, so findings are computed per case rather than once for the run.
    findings_for = findings_factory(gateway_registry())

    runner = EvaluationRunner(
        ruleset=ruleset,
        context=evaluation_context(),
        resolver=lambda reference: messages[reference],
        findings_factory=findings_for,
    )
    result = runner.run(dataset)

    gate_result = None
    if args.gate:
        thresholds = (
            GateThresholds.load(args.thresholds) if Path(args.thresholds).is_file() else GateThresholds()
        )
        # Zero-weight rules carry context rather than detection, so they are exempt from the
        # noise check: "sender not seen before" is meant to fire on most mail.
        zero_weight = frozenset(
            rule.id for rule in ruleset.rules if rule.effective_weight == 0 or rule.severity is Severity.INFO
        )
        gate_result = check(result, thresholds, Baseline.load(args.baseline), zero_weight_rules=zero_weight)

    print(render_text(result, gate_result))

    if args.markdown:
        Path(args.markdown).write_text(render_markdown(result, gate_result), encoding="utf-8")
        print(f"\nMarkdown-отчёт: {args.markdown}")
    if args.json:
        Path(args.json).write_text(
            json.dumps(result.as_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"JSON-отчёт: {args.json}")

    if args.update_baseline:
        target = Baseline.from_result(result).write(args.baseline)
        print(f"Базовая линия обновлена: {target}")

    if gate_result is not None and not gate_result.passed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
