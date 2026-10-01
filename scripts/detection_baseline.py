"""Record the state of detection before a stage changes it (ТЗ 1.0.3B §3).

A baseline exists so that "we improved detection" can be checked rather than asserted. Its one
rule follows from that: **anything this script did not verify is recorded as ``unknown``, never
as ``passed``**. A baseline that reports a green dependency scan because nobody ran one is worse
than no baseline, because the later comparison inherits the lie.

Usage::

    python scripts/detection_baseline.py                       # print the snapshot
    python scripts/detection_baseline.py --out docs/MSP_1_0_3B_BASELINE.md
    python scripts/detection_baseline.py --json baseline.json
    python scripts/detection_baseline.py --with-scans         # also run bandit and pip-audit
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess  # nosec B404 - runs fixed local tooling, never user input
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

#: What a value looks like when nothing established it. Spelled once so it cannot drift into
#: an empty string somewhere and start reading as "fine".
UNKNOWN = "unknown"

#: How pytest reports a per-file test count under ``--collect-only -q``.
_COLLECTED_RE = re.compile(r"^tests[\\/]\S*?\.py: (\d+)$", re.MULTILINE)


def _run(command: list[str], timeout: int = 900) -> tuple[int | None, str]:
    """Run a local tool, returning ``(None, "")`` when it is not installed.

    A missing tool is not a failure and not a success — it is the absence of evidence, and the
    caller turns it into ``unknown``.
    """
    executable = shutil.which(command[0])
    if executable is None:
        return None, ""
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell
            [executable, *command[1:]],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None, ""
    return completed.returncode, (completed.stdout or "") + (completed.stderr or "")


def commit_state() -> dict[str, Any]:
    code, out = _run(["git", "rev-parse", "HEAD"], timeout=60)
    sha = out.strip() if code == 0 else UNKNOWN
    code, out = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], timeout=60)
    branch = out.strip() if code == 0 else UNKNOWN
    code, out = _run(["git", "status", "--porcelain"], timeout=60)
    dirty = bool(out.strip()) if code == 0 else UNKNOWN
    return {"commit_sha": sha, "branch": branch, "working_tree_dirty": dirty}


def rule_state() -> dict[str, Any]:
    from msp_detection.rules import RuleSet, find_rule_pack

    ruleset = RuleSet.from_directory(find_rule_pack())
    statuses = Counter(rule.status.value for rule in ruleset.rules)
    return {
        "rule_count": len(ruleset.rules),
        "by_status": dict(sorted(statuses.items())),
        "by_category": dict(sorted(Counter(r.category for r in ruleset.rules).items())),
        "without_owner": sorted(rule.id for rule in ruleset.rules if not rule.owner),
        "ruleset_fingerprint": ruleset.version_fingerprint[:64],
        "rule_pack_path": str(find_rule_pack()),
    }


def dataset_state() -> dict[str, Any]:
    from msp_detection_eval.corpus import build_golden_dataset, corpus_checksum

    dataset, _messages = build_golden_dataset()
    return {
        "dataset_id": dataset.id,
        "dataset_version": dataset.version,
        "case_count": len(dataset.cases),
        "checksum": corpus_checksum(),
        "by_category": dict(sorted(Counter(case.category.value for case in dataset.cases).items())),
        "cases_with_known_gap": sorted(c.id for c in dataset.cases if c.known_gap),
    }


def evaluation_state() -> dict[str, Any]:
    """Run the golden corpus and record metrics and latency percentiles."""
    from evaluate_detection import evaluation_context, gateway_registry  # local script
    from msp_detection import GatewayFindings
    from msp_detection.rules import RuleSet, find_rule_pack
    from msp_detection_eval import EvaluationRunner
    from msp_detection_eval.corpus import build_golden_dataset

    ruleset = RuleSet.from_directory(find_rule_pack())
    dataset, messages = build_golden_dataset()
    registry = gateway_registry()

    def findings_for(parsed):  # type: ignore[no-untyped-def]
        analysis = registry.analyze_message(
            parsed.headers,
            received=parsed.received,
            authentication_results=parsed.authentication_results,
            internet_message_id=parsed.message_id,
        )
        verification = analysis.verification
        return GatewayFindings(
            evidence=list(analysis.evidence),
            state=analysis.state,
            trusted_auth_results=list(analysis.trusted_auth_results),
            untrusted_auth_results=list(analysis.untrusted_auth_results),
            auth_tampering_suspected=analysis.auth_tampering_suspected,
            unverified_gateways=list(analysis.untrusted_gateways),
            position_mismatches=list(verification.position_mismatches) if verification else [],
            chain_verified=bool(verification and verification.matches),
        )

    runner = EvaluationRunner(
        ruleset=ruleset,
        context=evaluation_context(),
        resolver=lambda reference: messages[reference],
        findings_factory=findings_for,
    )
    result = runner.run(dataset)
    metrics = result.metrics
    overall = metrics.overall

    return {
        "precision": overall.precision,
        "recall": overall.recall,
        "f1": overall.f1,
        "false_positive_rate": overall.false_positive_rate,
        "false_negative_rate": overall.false_negative_rate,
        "unknown_rate": overall.unknown_rate,
        "coverage": metrics.coverage(),
        "true_positive": overall.true_positive,
        "false_positive": overall.false_positive,
        "false_negative": overall.false_negative,
        "unknown": overall.unknown,
        "correctly_uncertain": overall.correctly_uncertain,
        "unscannable": overall.unscannable,
        "failures": [outcome.case.id for outcome in result.failures],
        "by_category": {
            name: {
                "cases": metric.matrix.total,
                "precision": metric.matrix.precision,
                "recall": metric.matrix.recall,
                "false_positive": metric.matrix.false_positive,
                "false_negative": metric.matrix.false_negative,
            }
            for name, metric in sorted(metrics.by_category.items())
        },
        "latency_ms": {
            "p50": metrics.percentile(0.5),
            "p95": metrics.percentile(0.95),
            "p99": metrics.percentile(0.99),
            "samples": len(metrics.latency_ms),
        },
        "unowned_active_rules": metrics.unowned_active_rules(),
        # Spam is unwanted mail, not an attack: flagging it is not a false positive and
        # escalating it to an attack verdict is an error, so it is counted on its own and
        # excluded from precision and recall.
        "spam": {"total": metrics.spam_total, "escalated_to_attack": metrics.spam_escalated},
    }


def test_state(run_tests: bool) -> dict[str, Any]:
    """Count the tests, and run them only when asked.

    Counting is cheap and always truthful; a pass/fail claim requires actually running them, so
    without ``--with-tests`` the result is ``unknown`` rather than an optimistic default.
    """
    code, out = _run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--collect-only", "-q"])
    total: Any = UNKNOWN
    if code == 0:
        # Exact form only: "tests/path/to/file.py: 42". A looser filter also matched pytest's
        # own deprecation warnings, which reference a .py file and end in a digit, and silently
        # inflated the count by one — a wrong number is worse than "unknown", because nothing
        # about it looks wrong.
        counts = _COLLECTED_RE.findall(out)
        total = sum(int(value) for value in counts) if counts else UNKNOWN
    state: dict[str, Any] = {"collected": total, "result": UNKNOWN}
    if run_tests:
        code, _ = _run([sys.executable, "-m", "pytest", "-q"], timeout=3600)
        state["result"] = "passed" if code == 0 else "failed" if code is not None else UNKNOWN
    return state


def migration_state() -> dict[str, Any]:
    versions = REPO_ROOT / "apps" / "api" / "msp_api" / "migrations" / "versions"
    files = sorted(p.name for p in versions.glob("*.py")) if versions.is_dir() else []
    heads: list[str] = []
    revisions: set[str] = set()
    down: set[str] = set()
    for path in versions.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.startswith("revision: str"):
                revisions.add(line.split("=")[1].strip().strip("'\""))
            elif line.startswith("down_revision: str"):
                value = line.split("=")[1].strip().strip("'\"")
                if value not in {"None", ""}:
                    down.add(value)
    heads = sorted(revisions - down)
    return {
        "migration_files": files,
        "head": heads[0] if len(heads) == 1 else (heads or UNKNOWN),
        "multiple_heads": len(heads) > 1,
    }


def gap_state() -> dict[str, Any]:
    import yaml

    path = REPO_ROOT / "datasets" / "detection_gaps.yaml"
    if not path.is_file():
        return {"source": UNKNOWN, "gaps": []}
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {
        "source": str(path.relative_to(REPO_ROOT)),
        "gaps": [
            {
                "id": gap.get("id"),
                "status": gap.get("status"),
                "severity": gap.get("severity"),
                "owner": gap.get("owner"),
                "target_release": gap.get("target_release"),
            }
            for gap in payload.get("gaps", []) or []
        ],
    }


def scan_state(run_scans: bool) -> dict[str, Any]:
    """Security and dependency scans. ``unknown`` unless actually run here."""
    if not run_scans:
        return {
            "bandit": UNKNOWN,
            "pip_audit": UNKNOWN,
            "note": "сканирования не выполнялись в этом запуске (--with-scans)",
        }
    bandit_code, _ = _run(
        ["bandit", "-q", "-c", "pyproject.toml", "-r", "apps", "packages", "providers", "scripts", "-ll"]
    )
    audit_code, audit_out = _run(["pip-audit", "--progress-spinner", "off"])
    return {
        "bandit": UNKNOWN if bandit_code is None else ("clean" if bandit_code == 0 else "findings"),
        "pip_audit": UNKNOWN if audit_code is None else ("clean" if audit_code == 0 else "vulnerabilities"),
        "pip_audit_output": audit_out.strip()[-2000:] if audit_out else "",
    }


def collect(*, run_tests: bool, run_scans: bool) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "git": commit_state(),
        "rules": rule_state(),
        "dataset": dataset_state(),
        "evaluation": evaluation_state(),
        "tests": test_state(run_tests),
        "migrations": migration_state(),
        "gaps": gap_state(),
        "scans": scan_state(run_scans),
    }


def _fmt(value: Any, digits: int = 3) -> str:
    if value is None:
        return "—"
    if value is True:
        return "да"
    if value is False:
        return "нет"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def render_markdown(snapshot: dict[str, Any]) -> str:
    git = snapshot["git"]
    rules = snapshot["rules"]
    dataset = snapshot["dataset"]
    evaluation = snapshot["evaluation"]
    latency = evaluation["latency_ms"]
    lines = [
        "# Baseline MSP 1.0.3B",
        "",
        "ТЗ 1.0.3B §3. Состояние детектирования **до** изменений этапа, зафиксированное",
        "автоматически: `python scripts/detection_baseline.py --out docs/MSP_1_0_3B_BASELINE.md`.",
        "",
        "> Значение `unknown` означает, что в этом запуске проверка не выполнялась. Это не",
        "> «пройдено»: baseline, сообщающий о зелёном сканировании, которого никто не запускал,",
        "> хуже отсутствующего — последующее сравнение наследует неправду.",
        "",
        f"**Снято:** {snapshot['generated_at']}",
        "",
        "## Коммит",
        "",
        f"- SHA: `{git['commit_sha']}`",
        f"- ветка: `{git['branch']}`",
        f"- несохранённые изменения: {_fmt(git['working_tree_dirty'])}",
        "",
        "## Правила",
        "",
        f"- всего: **{rules['rule_count']}**",
        f"- по статусам: {', '.join(f'{k} — {v}' for k, v in rules['by_status'].items())}",
        f"- без владельца: {', '.join(rules['without_owner']) or 'нет'}",
        f"- пакет правил: `{rules['rule_pack_path']}`",
        "",
        "## Золотой корпус",
        "",
        f"- датасет: `{dataset['dataset_id']}` версия `{dataset['dataset_version']}`",
        f"- кейсов: **{dataset['case_count']}**",
        f"- контрольная сумма: `{dataset['checksum'][:16]}…`",
        f"- кейсов с зарегистрированным пробелом: {', '.join(dataset['cases_with_known_gap']) or 'нет'}",
        "",
        "## Метрики детектирования",
        "",
        "| Метрика | Значение |",
        "|---|---|",
        f"| precision | {_fmt(evaluation['precision'])} |",
        f"| recall | {_fmt(evaluation['recall'])} |",
        f"| F1 | {_fmt(evaluation['f1'])} |",
        f"| false positive rate | {_fmt(evaluation['false_positive_rate'])} |",
        f"| false negative rate | {_fmt(evaluation['false_negative_rate'])} |",
        f"| coverage | {_fmt(evaluation['coverage'])} |",
        f"| TP / FP / FN | {evaluation['true_positive']} / {evaluation['false_positive']} / "
        f"{evaluation['false_negative']} |",
        f"| UNKNOWN (ошибка) / корректная неопределённость | {evaluation['unknown']} / "
        f"{evaluation['correctly_uncertain']} |",
        f"| не проверено | {evaluation['unscannable']} |",
        "",
        "`—` означает, что метрику не на чем посчитать: это не ноль.",
        "",
        "## Задержка локального анализа",
        "",
        f"- P50: {_fmt(latency['p50'], 1)} мс",
        f"- P95: {_fmt(latency['p95'], 1)} мс",
        f"- P99: {_fmt(latency['p99'], 1)} мс",
        f"- измерений: {latency['samples']}",
        "",
        "## По категориям",
        "",
        "| Категория | Кейсов | precision | recall | FP | FN |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, metric in evaluation["by_category"].items():
        lines.append(
            f"| `{name}` | {metric['cases']} | {_fmt(metric['precision'])} | "
            f"{_fmt(metric['recall'])} | {metric['false_positive']} | {metric['false_negative']} |"
        )

    tests = snapshot["tests"]
    migrations = snapshot["migrations"]
    scans = snapshot["scans"]
    lines += [
        "",
        f"Спам считается отдельно: {evaluation['spam']['total']} писем, "
        f"поднято до уровня атаки — {evaluation['spam']['escalated_to_attack']}. "
        "Пометить спам подозрительным не является ложным срабатыванием; приравнять его к атаке "
        "— ошибка, поэтому в precision и recall он не входит.",
        "",
        "## Тесты",
        "",
        f"- собрано: {tests['collected']}",
        f"- результат прогона: {tests['result']}",
        "",
        "## Миграции",
        "",
        f"- head: `{migrations['head']}`",
        f"- файлов: {len(migrations['migration_files'])}",
        f"- несколько голов: {_fmt(migrations['multiple_heads'])}",
        "",
        "## Известные пробелы детектирования",
        "",
        "| Пробел | Статус | Серьёзность | Владелец | Релиз |",
        "|---|---|---|---|---|",
    ]
    for gap in snapshot["gaps"]["gaps"]:
        lines.append(
            f"| {gap['id']} | {gap['status']} | {gap['severity']} | {gap['owner']} | "
            f"{gap['target_release']} |"
        )
    lines += [
        "",
        "## Сканирования",
        "",
        f"- bandit: {scans['bandit']}",
        f"- pip-audit: {scans['pip_audit']}",
    ]
    if scans.get("note"):
        lines.append(f"- {scans['note']}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Зафиксировать baseline детектирования")
    parser.add_argument("--out", metavar="FILE", help="записать Markdown-снимок")
    parser.add_argument("--json", metavar="FILE", help="записать машинный снимок")
    parser.add_argument("--with-tests", action="store_true", help="прогнать тесты")
    parser.add_argument("--with-scans", action="store_true", help="выполнить bandit и pip-audit")
    args = parser.parse_args()

    snapshot = collect(run_tests=args.with_tests, run_scans=args.with_scans)
    markdown = render_markdown(snapshot)

    if args.out:
        Path(args.out).write_text(markdown, encoding="utf-8")
        print(f"Снимок записан: {args.out}")
    if args.json:
        Path(args.json).write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"JSON: {args.json}")
    if not args.out and not args.json:
        print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
