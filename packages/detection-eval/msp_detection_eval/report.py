"""Human-readable evaluation reports (ТЗ 1.0.3 §4, §35, §51).

The report is written for someone deciding whether to release, so it leads with what would stop
them and puts the aggregate numbers after. A metric that could not be computed prints as `—`
rather than as a zero: "no data" and "nothing detected" are different findings and must not look
the same.
"""

from __future__ import annotations

from typing import Any

from .gate import GateResult
from .runner import EvaluationResult


def _fmt(value: Any, digits: int = 3) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value * 100:.1f}%"


def render_markdown(
    result: EvaluationResult, gate: GateResult | None = None, *, title: str = "Оценка детектирования"
) -> str:
    metrics = result.metrics
    overall = metrics.overall
    lines = [
        f"# {title}",
        "",
        f"**Датасет:** `{result.dataset_id}` версия `{result.dataset_version}`",
        f"**Контрольная сумма:** `{result.dataset_checksum[:16]}…`",
        f"**Кейсов:** {len(result.outcomes)}  ·  **Провалов:** {len(result.failures)}",
        "",
    ]

    if gate is not None:
        lines += [
            "## Решение гейта",
            "",
            f"**{'ПРОЙДЕН' if gate.passed else 'ЗАБЛОКИРОВАН'}**",
            "",
        ]
        if gate.violations:
            lines += ["### Блокеры", ""]
            for violation in gate.violations:
                lines.append(
                    f"- **{violation.kind}** — {violation.detail} "
                    f"(получено `{_fmt(violation.observed)}`, требуется `{_fmt(violation.required)}`)"
                )
            lines.append("")
        if gate.warnings:
            lines += ["### Предупреждения", ""]
            lines += [f"- {w}" for w in gate.warnings]
            lines.append("")

    lines += [
        "## Сводные метрики",
        "",
        "| Метрика | Значение |",
        "|---|---|",
        f"| precision | {_fmt(overall.precision)} |",
        f"| recall | {_fmt(overall.recall)} |",
        f"| F1 | {_fmt(overall.f1)} |",
        f"| false positive rate | {_fmt(overall.false_positive_rate)} |",
        f"| false negative rate | {_fmt(overall.false_negative_rate)} |",
        f"| unknown rate | {_fmt(overall.unknown_rate)} |",
        f"| unscannable rate | {_fmt(overall.unscannable_rate)} |",
        f"| coverage | {_fmt(metrics.coverage())} |",
        "",
        f"Обнаружено: {overall.true_positive} · Ложных срабатываний: {overall.false_positive} · "
        f"Пропущено: {overall.false_negative} · UNKNOWN: {overall.unknown}",
        "",
        "> `—` означает, что метрику не на чем посчитать. Это не ноль и не успех.",
        "",
    ]

    if metrics.spam_total:
        lines += [
            "### Спам",
            "",
            f"Писем: {metrics.spam_total}; поднято до уровня атаки: {metrics.spam_escalated}.",
            "",
            "Спам считается отдельно: пометить его подозрительным — не ложное срабатывание, а "
            "приравнять к атаке — ошибка.",
            "",
        ]

    lines += [
        "## По категориям",
        "",
        "| Категория | Кейсов | precision | recall | FP | FN | UNKNOWN |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, metric in sorted(metrics.by_category.items()):
        matrix = metric.matrix
        lines.append(
            f"| `{name}` | {matrix.total} | {_fmt(matrix.precision)} | {_fmt(matrix.recall)} | "
            f"{matrix.false_positive} | {matrix.false_negative} | {matrix.unknown} |"
        )
    lines.append("")

    latency = metrics.as_dict()["latency_ms"]
    lines += [
        "## Задержка локального анализа",
        "",
        f"медиана {_fmt(latency['median'], 1)} мс · P95 {_fmt(latency['p95'], 1)} мс · "
        f"P99 {_fmt(latency['p99'], 1)} мс · измерений {latency['samples']}",
        "",
    ]

    noisy = metrics.noisy_rules()
    if noisy:
        lines += [
            "## Шумные правила",
            "",
            "| Правило | Владелец | Срабатываний | TP | FP | precision |",
            "|---|---|---:|---:|---:|---:|",
        ]
        for rule in noisy:
            lines.append(
                f"| `{rule['rule_id']}` | {rule['owner'] or '—'} | {rule['total_triggers']} | "
                f"{rule['true_positive']} | {rule['false_positive']} | {_fmt(rule['precision'])} |"
            )
        lines.append("")

    effective = metrics.effective_rules()
    if effective:
        lines += [
            "## Результативные правила",
            "",
            "| Правило | Владелец | TP | precision |",
            "|---|---|---:|---:|",
        ]
        for rule in effective:
            lines.append(
                f"| `{rule['rule_id']}` | {rule['owner'] or '—'} | {rule['true_positive']} | "
                f"{_fmt(rule['precision'])} |"
            )
        lines.append("")

    if result.failures:
        lines += [
            "## Провалившиеся кейсы",
            "",
            "| Кейс | Категория | Ожидалось | Получено | Причина |",
            "|---|---|---|---|---|",
        ]
        for outcome in result.failures[:50]:
            lines.append(
                f"| `{outcome.case.id}` | {outcome.case.category.value} | "
                f"{outcome.case.expected_classification.value} | {outcome.classification.value} | "
                f"{outcome.failure_reason()} |"
            )
        if len(result.failures) > 50:
            lines.append(f"| … | | | | и ещё {len(result.failures) - 50} |")
        lines.append("")

    unowned = metrics.unowned_active_rules()
    if unowned:
        lines += [
            "## Правила без владельца",
            "",
            "Активное правило без владельца некому настраивать, когда оно начнёт шуметь "
            "(критерий выхода ТЗ 1.0.3 §60).",
            "",
        ]
        lines += [f"- `{rule_id}`" for rule_id in unowned]
        lines.append("")

    return "\n".join(lines)


def render_text(result: EvaluationResult, gate: GateResult | None = None) -> str:
    """Compact console summary."""
    metrics = result.metrics
    overall = metrics.overall
    lines = [
        f"Датасет {result.dataset_id} v{result.dataset_version}: "
        f"{len(result.outcomes)} кейсов, провалов {len(result.failures)}",
        f"  precision {_fmt(overall.precision)}  recall {_fmt(overall.recall)}  "
        f"F1 {_fmt(overall.f1)}  coverage {_pct(metrics.coverage())}",
        f"  TP {overall.true_positive}  FP {overall.false_positive}  "
        f"FN {overall.false_negative}  UNKNOWN {overall.unknown}  "
        f"не проверено {overall.unscannable}",
    ]
    latency = metrics.as_dict()["latency_ms"]
    lines.append(f"  задержка: медиана {_fmt(latency['median'], 1)} мс, P95 {_fmt(latency['p95'], 1)} мс")
    for outcome in result.failures[:15]:
        lines.append(f"    ПРОВАЛ {outcome.case.id}: {outcome.failure_reason()}")
    if len(result.failures) > 15:
        lines.append(f"    … и ещё {len(result.failures) - 15}")
    if gate is not None:
        lines.append("")
        lines.append(gate.render())
    return "\n".join(lines)
