"""Готовность к inline-шлюзу: пройти или не пройти (ТЗ 1.0.4 §18-§21).

Вопрос, на который отвечает этот скрипт, — единственный, который имеет смысл задавать перед
MSP 1.1: **можно ли ставить платформу в разрыв почтового потока**. До сих пор она смотрела на
копию письма, и ошибка стоила ложного срабатывания в консоли аналитика. В разрыве потока ошибка
стоит недоставленного письма, и ответ «вроде бы готовы» перестаёт быть ответом.

Поэтому решение здесь — одно из трёх, а не число:

* ``READY_FOR_MSP_1_1`` — все обязательные условия выполнены, свидетельства есть;
* ``READY_WITH_WARNINGS`` — обязательные выполнены, необязательные нет; что именно, перечислено;
* ``NOT_READY`` — хотя бы одно обязательное условие не выполнено.

Два правила, из которых всё остальное следует:

1. **Непроверенное условие не считается выполненным.** Если скрипт не смог установить факт, он
   записывает ``unknown`` и это блокирует ``READY``. Готовность, выданная по отсутствию
   доказательств обратного, — ровно та ошибка, из-за которой платформы ставят в разрыв потока и
   потом снимают.
2. **Незарегистрированный критический пробел блокирует готовность** (ТЗ §29). Пробел, про
   который известно и который записан, — принятое ограничение; тот же пробел без записи — это
   то, что обнаружат на живой почте.

Запуск::

    python scripts/gateway_readiness.py
    python scripts/gateway_readiness.py --json readiness.json
    python scripts/gateway_readiness.py --out docs/GATEWAY_READINESS_REPORT.md
    python scripts/gateway_readiness.py --real-flow-summary summary.json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess  # nosec B404 - runs fixed local tooling, never user input
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Политика готовности общая с эндпоинтом ``GET /detection/readiness``: пороги, типы условий и
# проверки по сводке и по реестру пробелов. Своей копии порогов у скрипта нет намеренно.
from msp_api.services.gateway_readiness import (
    DECISION_WORDS,
    MIN_ANALYZED,
    MIN_REVIEWED,
    NOT_READY,
    READY,
    READY_WITH_WARNINGS,
    UNKNOWN,
    Check,
    Readiness,
    gap_checks,
    real_flow_checks,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------------------------
# Вспомогательное
# ---------------------------------------------------------------------------------------------
def _run(command: list[str], timeout: int = 900) -> tuple[int | None, str]:
    """Выполнить фиксированную локальную команду. ``None`` в коде — команда не запустилась."""
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell
            command,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return None, ""
    return completed.returncode, (completed.stdout or "") + (completed.stderr or "")


def _load_json(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


# ---------------------------------------------------------------------------------------------
# Условия: синтетический корпус (ТЗ §19)
# ---------------------------------------------------------------------------------------------
def corpus_checks(baseline: dict[str, Any] | None) -> list[Check]:
    """Регрессия на золотом корпусе.

    Корпус не доказывает готовности к живой почте — он содержит ровно те случаи, которые мы
    придумали. Но его провал доказывает неготовность, и поэтому он обязателен.
    """
    overall = (baseline or {}).get("overall") or {}
    precision = overall.get("precision")
    recall = overall.get("recall")
    # В baseline нет готового «порог пройден»: он выводится из того, что в нём есть. Так честнее —
    # иначе условие зависело бы от поля, которое кто-то мог бы выставить рукой.
    gate: bool | None = None
    if overall:
        gate = (
            overall.get("false_positive") == 0
            and overall.get("false_negative") == 0
            and overall.get("unknown") == 0
        )

    checks = [
        Check(
            key="corpus_gate",
            title="Порог качества на золотом корпусе пройден",
            required=True,
            passed=bool(gate) if gate is not None else None,
            value=gate if gate is not None else UNKNOWN,
            expected=True,
            detail="" if gate is not None else "baseline не прочитан или пуст",
        ),
        Check(
            key="corpus_no_false_negatives",
            title="На корпусе нет пропусков",
            required=True,
            passed=(recall == 1.0) if isinstance(recall, int | float) else None,
            value=recall if recall is not None else UNKNOWN,
            expected=1.0,
        ),
        Check(
            key="corpus_no_false_positives",
            title="На корпусе нет ложных срабатываний",
            required=True,
            passed=(precision == 1.0) if isinstance(precision, int | float) else None,
            value=precision if precision is not None else UNKNOWN,
            expected=1.0,
        ),
    ]
    return checks


def read_gap_registry() -> list[dict[str, Any]] | None:
    """Прочитать реестр пробелов из документа.

    Источник — ``docs/DETECTION_GAPS.md``: именно он публикуется и читается людьми, и
    расхождение между ним и базой означало бы, что опубликован не тот реестр, по которому
    принимают решение.

    Пустой результат возвращается как ``None``, а не как пустой список. Разница существенная:
    пустой список означает «пробелов нет» и условие по нему проходит, а ``None`` означает «не
    прочитали» и блокирует готовность. Первый прогон этого скрипта как раз и сообщил
    «критические пробелы зарегистрированы» при нуле найденных пробелов.
    """
    path = REPO_ROOT / "docs" / "DETECTION_GAPS.md"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None

    gaps: list[dict[str, Any]] = []
    heading = re.compile(r"^###\s+(GAP-\d+)\s*(?:[—-]\s*(.*))?$")
    # Раздел пробела кончается на любом заголовке. После реестра в документе идёт глоссарий
    # ``## Статусы`` с таблицей «Статус | Значение», и без этой границы она читалась как
    # продолжение последнего пробела и переписывала его статус словом «Значение».
    any_heading = re.compile(r"^#{1,6}\s")
    field = re.compile(r"^\|\s*([^|]+?)\s*\|\s*(.+?)\s*\|$")
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        stripped = line.strip()
        match = heading.match(stripped)
        if match is None and any_heading.match(stripped):
            current = None
            continue
        if match is not None:
            current = {
                "gap_id": match.group(1),
                "title": (match.group(2) or "").strip(),
                "severity": UNKNOWN,
                "status": "",
            }
            gaps.append(current)
            continue
        if current is None:
            continue
        cells = field.match(stripped)
        if cells is None:
            continue
        name = cells.group(1).lower()
        value = cells.group(2)
        if name.startswith("серьёзность") or name.startswith("серьезность"):
            current["severity"] = _severity_from_russian(value)
        elif name.startswith("статус"):
            current["status"] = _status_from_russian(value)

    return gaps or None


#: Реестр написан по-русски, и читать его надо по-русски. Таблица соответствия стоит рядом с
#: разбором, чтобы при добавлении слова в документ было видно, где его завести здесь.
_SEVERITY_RU = {
    "критическ": "CRITICAL",
    "высок": "HIGH",
    "средн": "MEDIUM",
    "низк": "LOW",
}
_STATUS_RU = {
    "принят": "ACCEPTED",
    "валидац": "VALIDATION",
    "на подтверждении": "VALIDATION",
    "в работе": "IN_PROGRESS",
    "исправлен": "RESOLVED",
    "закрыт": "RESOLVED",
    "не будет": "WONT_FIX",
    "открыт": "OPEN",
}


def _severity_from_russian(value: str) -> str:
    lowered = value.lower()
    for prefix, word in _SEVERITY_RU.items():
        if prefix in lowered:
            return word
    return UNKNOWN


def _status_from_russian(value: str) -> str:
    lowered = value.lower()
    for prefix, word in _STATUS_RU.items():
        if prefix in lowered:
            return word
    # Пустая строка означает «статус не записан», и условие о регистрации по ней не проходит.
    return ""


# ---------------------------------------------------------------------------------------------
# Условия: тесты и сборка
# ---------------------------------------------------------------------------------------------
def test_checks(run_tests: bool) -> list[Check]:
    """Регрессия обязана проходить (ТЗ §29).

    Без запуска — ``unknown``, а не «вероятно, зелёные». Этот скрипт уже однажды в истории
    проекта мог бы сообщить «CI зелёный», имея в виду «локально зелёный».
    """
    if not run_tests:
        return [
            Check(
                key="regression_suite",
                title="Регрессия проходит",
                required=True,
                passed=None,
                value=UNKNOWN,
                expected="все тесты зелёные",
                detail="не запускалось: --run-tests",
            )
        ]
    code, output = _run([sys.executable, "-m", "pytest", "-q", "-o", "addopts=-p no:cacheprovider"])
    if code is None:
        return [
            Check(
                key="regression_suite",
                title="Регрессия проходит",
                required=True,
                passed=None,
                value=UNKNOWN,
                expected="все тесты зелёные",
                detail="pytest не запустился",
            )
        ]
    tail = output.strip().splitlines()[-1] if output.strip() else ""
    return [
        Check(
            key="regression_suite",
            title="Регрессия проходит",
            required=True,
            passed=code == 0,
            value=tail[:200],
            expected="exit 0",
        )
    ]


# ---------------------------------------------------------------------------------------------
# Сбор и отчёт
# ---------------------------------------------------------------------------------------------
def collect(
    *,
    baseline: dict[str, Any] | None,
    real_flow_summary: dict[str, Any] | None,
    run_tests: bool,
) -> Readiness:
    readiness = Readiness()
    readiness.extend(corpus_checks(baseline))
    readiness.extend(real_flow_checks(real_flow_summary))
    readiness.extend(gap_checks(read_gap_registry()))
    readiness.extend(test_checks(run_tests))
    return readiness


def render_markdown(readiness: Readiness) -> str:
    lines = [
        "# Готовность к inline-шлюзу (MSP 1.0.4 §18-§21)",
        "",
        f"**Решение:** `{readiness.decision}` — {DECISION_WORDS[readiness.decision]}",
        "",
        f"Сформировано: {datetime.now(UTC).isoformat()}",
        "",
        "Непроверенное условие записано как `unknown` и блокирует готовность так же, как провал.",
        "Готовность, выданная по отсутствию доказательств обратного, — не готовность.",
        "",
        f"Минимальная выборка: {MIN_ANALYZED} проанализированных и {MIN_REVIEWED} разобранных писем "
        "(ТЗ §21). Пороги общие со страницей готовности в консоли.",
        "",
        "## Условия",
        "",
        "| Условие | Обязательное | Состояние | Значение | Ожидалось |",
        "| --- | --- | --- | --- | --- |",
    ]
    for check in readiness.checks:
        lines.append(
            f"| {check.title} | {'да' if check.required else 'нет'} | `{check.state}` | "
            f"`{check.value}` | `{check.expected}` |"
        )

    if readiness.blocking:
        lines += ["", "## Что блокирует", ""]
        for check in readiness.blocking:
            note = f" — {check.detail}" if check.detail else ""
            lines.append(f"- **{check.title}** (`{check.state}`){note}")
    if readiness.warnings:
        lines += ["", "## Замечания", ""]
        for check in readiness.warnings:
            note = f" — {check.detail}" if check.detail else ""
            lines.append(f"- {check.title} (`{check.state}`){note}")
    if readiness.decision == READY:
        lines += [
            "",
            "## Что это означает и что нет",
            "",
            "Означает: обязательные условия выполнены и свидетельства к ним есть.",
            "",
            "Не означает, что inline-шлюз безопасен. Он не входил в этот этап и не проверялся:",
            "в разрыве потока появляются отказы, которых на копии письма не бывает — очередь,",
            "таймаут, недоставленное письмо. Это предмет MSP 1.1, а не следствие этой строки.",
        ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Проверить готовность к inline-шлюзу")
    parser.add_argument("--baseline", type=Path, default=REPO_ROOT / "datasets" / "baseline.json")
    parser.add_argument("--real-flow-summary", type=Path, default=None)
    parser.add_argument("--run-tests", action="store_true")
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    readiness = collect(
        baseline=_load_json(args.baseline),
        real_flow_summary=_load_json(args.real_flow_summary),
        run_tests=args.run_tests,
    )

    if args.json:
        args.json.write_text(
            json.dumps(readiness.as_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    report = render_markdown(readiness)
    if args.out:
        args.out.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)

    # Код возврата различает три решения: конвейеру нужно отличать «не готово» от «готово с
    # замечаниями», а не только «ошибка / не ошибка».
    return {READY: 0, READY_WITH_WARNINGS: 0, NOT_READY: 1}[readiness.decision]


if __name__ == "__main__":
    raise SystemExit(main())
