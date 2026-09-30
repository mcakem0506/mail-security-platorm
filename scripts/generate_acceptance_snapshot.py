"""Acceptance snapshot of the actual HEAD (ТЗ 1.0.1 §7).

An acceptance document that was written by hand drifts from the code within a week, and the drift
is invisible: it still reads as though everything was verified. This script collects the facts
that can be measured — commit, test count, migration head, rule count, dependency scan, frontend
build — so the document states what is true of this revision rather than what was true when
someone last edited it.

Anything it cannot establish is reported as ``unknown``, never as a pass. That distinction is the
whole point: an unavailable check is not a successful one.

Usage::

    python scripts/generate_acceptance_snapshot.py                    # print Markdown
    python scripts/generate_acceptance_snapshot.py --json             # machine-readable
    python scripts/generate_acceptance_snapshot.py --out docs/X.md    # write a file
    python scripts/generate_acceptance_snapshot.py --run-tests        # also execute the suite
"""

from __future__ import annotations

import argparse
import json
import re

# Runs fixed, literal argument lists only; never a shell string built from input.
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
UNKNOWN = "unknown"


@dataclass
class Snapshot:
    generated_at: str
    commit: str = UNKNOWN
    commit_subject: str = ""
    branch: str = UNKNOWN
    dirty: bool | None = None
    test_count: int | None = None
    test_result: str = UNKNOWN
    migration_head: str = UNKNOWN
    migration_count: int | None = None
    rule_count: int | None = None
    rule_files: int | None = None
    corpus_count: int | None = None
    corpus_categories: dict[str, int] = field(default_factory=dict)
    python_packages: list[str] = field(default_factory=list)
    frontend_build: str = UNKNOWN
    dependency_scan: str = UNKNOWN
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "commit": self.commit,
            "commit_subject": self.commit_subject,
            "branch": self.branch,
            "working_tree_dirty": self.dirty,
            "tests": {"count": self.test_count, "result": self.test_result},
            "migrations": {"head": self.migration_head, "count": self.migration_count},
            "detection": {"rules": self.rule_count, "rule_files": self.rule_files},
            "corpus": {"total": self.corpus_count, "by_category": self.corpus_categories},
            "packages": self.python_packages,
            "frontend_build": self.frontend_build,
            "dependency_scan": self.dependency_scan,
            "notes": self.notes,
        }


def _run(args: list[str], cwd: Path | None = None, timeout: int = 600) -> tuple[int, str]:
    """Run a fixed command and return (exit code, output).

    The argument list is always a literal built in this file, never assembled from input, and no
    shell is involved.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, shell=False
            args,
            cwd=str(cwd or REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, f"{type(exc).__name__}: {exc}"
    return completed.returncode, (completed.stdout or "") + (completed.stderr or "")


def collect_git(snapshot: Snapshot) -> None:
    code, out = _run(["git", "rev-parse", "HEAD"], timeout=30)
    if code == 0:
        snapshot.commit = out.strip()[:40]
    code, out = _run(["git", "log", "-1", "--pretty=%s"], timeout=30)
    if code == 0:
        snapshot.commit_subject = out.strip()[:200]
    code, out = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], timeout=30)
    if code == 0:
        snapshot.branch = out.strip()
    code, out = _run(["git", "status", "--porcelain"], timeout=30)
    if code == 0:
        snapshot.dirty = bool(out.strip())
        if snapshot.dirty:
            snapshot.notes.append(
                "рабочее дерево содержит незакоммиченные изменения: снимок не соответствует ни одному коммиту"
            )


def collect_detection(snapshot: Snapshot) -> None:
    try:
        sys.path.insert(0, str(REPO_ROOT / "packages" / "detection-engine"))
        from msp_detection import default_ruleset

        ruleset = default_ruleset()
        snapshot.rule_count = len(ruleset.rules)
        snapshot.rule_files = len(
            list((REPO_ROOT / "packages" / "detection-engine" / "msp_detection" / "rules").glob("*.yaml"))
        )
    except Exception as exc:  # noqa: BLE001 - a snapshot reports what it could not read
        snapshot.notes.append(f"не удалось загрузить правила: {type(exc).__name__}")


def collect_corpus(snapshot: Snapshot) -> None:
    try:
        sys.path.insert(0, str(REPO_ROOT / "tests"))
        from fixtures.corpus import CORPUS, by_category

        snapshot.corpus_count = len(CORPUS)
        snapshot.corpus_categories = {category: len(items) for category, items in by_category().items()}
    except Exception as exc:  # noqa: BLE001
        snapshot.notes.append(f"не удалось загрузить корпус: {type(exc).__name__}")


def collect_migrations(snapshot: Snapshot) -> None:
    versions = REPO_ROOT / "apps" / "api" / "msp_api" / "migrations" / "versions"
    files = sorted(versions.glob("*.py")) if versions.is_dir() else []
    snapshot.migration_count = len(files)

    # The head is the revision no other migration lists as its ancestor.
    revisions: dict[str, str | None] = {}
    for file in files:
        text = file.read_text(encoding="utf-8", errors="replace")
        revision = re.search(r"^revision(?::\s*str)?\s*=\s*[\"']([^\"']+)[\"']", text, re.MULTILINE)
        down = re.search(
            r"^down_revision(?::\s*str\s*\|\s*None)?\s*=\s*(?:[\"']([^\"']+)[\"']|None)",
            text,
            re.MULTILINE,
        )
        if revision:
            revisions[revision.group(1)] = down.group(1) if down and down.group(1) else None
    if revisions:
        parents = {down for down in revisions.values() if down}
        heads = [rev for rev in revisions if rev not in parents]
        snapshot.migration_head = heads[0] if len(heads) == 1 else ",".join(sorted(heads))
        if len(heads) > 1:
            snapshot.notes.append(f"несколько head-ревизий миграций ({len(heads)}): требуется слияние")


def collect_packages(snapshot: Snapshot) -> None:
    for base in ("packages", "providers", "apps"):
        root = REPO_ROOT / base
        if not root.is_dir():
            continue
        for package in sorted(root.glob("*/msp_*/__init__.py")):
            snapshot.python_packages.append(package.parent.name)
    snapshot.python_packages = sorted(set(snapshot.python_packages))


def collect_tests(snapshot: Snapshot, *, run: bool) -> None:
    """Count tests, and optionally execute them.

    Collection alone is cheap and always safe; running the suite is opt-in because an acceptance
    snapshot is often generated on a machine without the services the suite expects.
    """
    code, out = _run([sys.executable, "-m", "pytest", "--collect-only", "-q"], timeout=600)
    # Two output shapes have to be handled: a "N tests collected" summary, and — when the
    # project's own addopts already pass -q, making this -qq — one "path: count" line per file
    # with no total at all. Summing the per-file counts covers both.
    total = re.search(r"(\d+)\s+tests?\s+collected", out)
    if total:
        snapshot.test_count = int(total.group(1))
    else:
        per_file = re.findall(r"^\S+\.py:\s*(\d+)\s*$", out, re.MULTILINE)
        if per_file:
            snapshot.test_count = sum(int(n) for n in per_file)
    if snapshot.test_count is None:
        snapshot.notes.append(f"не удалось собрать список тестов (код выхода {code}): количество неизвестно")

    if not run:
        snapshot.test_result = "not executed"
        return
    code, out = _run([sys.executable, "-m", "pytest", "-q"], timeout=3600)
    tail = [line for line in out.splitlines() if line.strip()][-1:] or [""]
    snapshot.test_result = "passed" if code == 0 else f"failed: {tail[0][:200]}"


def collect_frontend(snapshot: Snapshot) -> None:
    dist = REPO_ROOT / "apps" / "security-console" / "dist"
    if (dist / "index.html").is_file():
        built_at = datetime.fromtimestamp(dist.stat().st_mtime, tz=UTC)
        snapshot.frontend_build = f"present ({built_at.date().isoformat()})"
    else:
        snapshot.frontend_build = "not built"


def collect_dependency_scan(snapshot: Snapshot) -> None:
    code, out = _run([sys.executable, "-m", "pip_audit", "--progress-spinner=off", "-f", "json"])
    if code == 0:
        snapshot.dependency_scan = "no known vulnerabilities"
        return
    try:
        payload = json.loads(out[out.index("{") :]) if "{" in out else {}
        findings = [dep for dep in payload.get("dependencies", []) if dep.get("vulns")]
        if findings:
            snapshot.dependency_scan = f"{len(findings)} package(s) with advisories"
            return
    except (ValueError, KeyError):
        pass
    snapshot.dependency_scan = UNKNOWN
    snapshot.notes.append("pip-audit не выполнен: результат неизвестен, а не успешен")


def build(*, run_tests: bool) -> Snapshot:
    snapshot = Snapshot(generated_at=datetime.now(UTC).isoformat(timespec="seconds"))
    collect_git(snapshot)
    collect_detection(snapshot)
    collect_corpus(snapshot)
    collect_migrations(snapshot)
    collect_packages(snapshot)
    collect_frontend(snapshot)
    collect_tests(snapshot, run=run_tests)
    collect_dependency_scan(snapshot)
    return snapshot


def render_markdown(snapshot: Snapshot) -> str:
    def value(item: Any) -> str:
        if item is None:
            return f"`{UNKNOWN}`"
        if isinstance(item, bool):
            return "да" if item else "нет"
        return str(item)

    lines = [
        "<!-- Сформировано scripts/generate_acceptance_snapshot.py. Не редактируйте вручную. -->",
        "## Снимок состояния HEAD",
        "",
        "| Показатель | Значение |",
        "|---|---|",
        f"| Сформирован | {snapshot.generated_at} |",
        f"| Коммит | `{snapshot.commit}` |",
        f"| Ветка | {snapshot.branch} |",
        f"| Незакоммиченные изменения | {value(snapshot.dirty)} |",
        f"| Тестов собрано | {value(snapshot.test_count)} |",
        f"| Результат тестов | {snapshot.test_result} |",
        f"| Head миграций | `{snapshot.migration_head}` |",
        f"| Миграций всего | {value(snapshot.migration_count)} |",
        f"| Правил детектирования | {value(snapshot.rule_count)} в {value(snapshot.rule_files)} файлах |",
        f"| Писем в корпусе | {value(snapshot.corpus_count)} |",
        f"| Python-пакетов | {len(snapshot.python_packages)} |",
        f"| Сборка консоли | {snapshot.frontend_build} |",
        f"| Проверка зависимостей | {snapshot.dependency_scan} |",
        "",
    ]
    if snapshot.commit_subject:
        lines += [f"Последний коммит: {snapshot.commit_subject}", ""]
    if snapshot.corpus_categories:
        lines += ["### Валидационный корпус", "", "| Категория | Писем |", "|---|---|"]
        lines += [f"| `{c}` | {n} |" for c, n in snapshot.corpus_categories.items()]
        lines.append("")
    if snapshot.python_packages:
        lines += [
            "### Пакеты",
            "",
            ", ".join(f"`{name}`" for name in snapshot.python_packages),
            "",
        ]
    if snapshot.notes:
        lines += ["### Замечания к снимку", ""]
        lines += [f"- {note}" for note in snapshot.notes]
        lines.append("")
    lines += [
        "Значение `unknown` означает, что проверка не выполнялась. Это не то же самое, что "
        "успешный результат: непроверенное нельзя считать пройденным.",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Снимок состояния HEAD для приёмки (ТЗ 1.0.1 §7)")
    parser.add_argument("--json", action="store_true", help="машиночитаемый вывод")
    parser.add_argument("--out", metavar="FILE", help="записать результат в файл")
    parser.add_argument("--run-tests", action="store_true", help="запустить тесты, а не только собрать")
    args = parser.parse_args()

    snapshot = build(run_tests=args.run_tests)
    rendered = (
        json.dumps(snapshot.as_dict(), ensure_ascii=False, indent=2)
        if args.json
        else render_markdown(snapshot)
    )
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
        print(f"Снимок записан: {args.out}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
