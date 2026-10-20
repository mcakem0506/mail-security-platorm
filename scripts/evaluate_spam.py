"""Оценка синтетического корпуса спама по записям сканера и проверка на регрессию (ТЗ 1.2 §39, §37).

Не требует Docker: письма и записи сканера лежат в ``datasets/spam``. Результат сравнивается с
``datasets/spam/baseline.json``; метрика, упавшая ниже базовой больше допуска, — провал. Гейт проверяет,
что конфигурация, политика и разбор не ухудшились, и ничего не говорит о качестве на реальной почте.

    python scripts/evaluate_spam.py --gate            # сравнить с базовой линией
    python scripts/evaluate_spam.py --update-baseline # зафиксировать новую базовую линию (осознанно)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
for extra in ("packages/antispam", "packages/mail-parser", "packages/shared-contracts"):
    sys.path.insert(0, str(REPO / extra))

from msp_antispam import corpus  # noqa: E402
from msp_antispam.policy import SpamPolicy  # noqa: E402

DATASETS = REPO / "datasets" / "spam"
#: Допустимое ухудшение метрики относительно базовой линии.
TOLERANCE = 0.02
#: Метрики, которые не должны падать, и метрики, которые не должны расти.
HIGHER_IS_BETTER = ("spam_precision", "spam_recall", "bulk_precision", "suggested_reject_precision")


def load() -> tuple[list[corpus.Case], dict, dict]:
    cases = [
        corpus.case_from_dict(item)
        for item in json.loads((DATASETS / "cases.json").read_text(encoding="utf-8"))
    ]
    payload = json.loads((DATASETS / "records.json").read_text(encoding="utf-8"))
    return cases, payload["records"], payload["meta"]


def render(report: corpus.EvalReport, meta: dict) -> str:
    def fmt(value: float | None) -> str:
        return "нет данных" if value is None else f"{value:.3f}"

    lines = [
        "# Оценка корпуса спама MSP 1.2",
        "",
        f"Версия Rspamd: {meta.get('rspamd_version') or '—'}; конфигурация: {meta.get('config_version') or '—'}; "
        f"записано {meta.get('recorded')} из {meta.get('cases')}.",
        "",
        "> Корпус синтетический: это проверка на регрессию, а не оценка качества на реальной почте.",
        "",
        "| Метрика | Значение |",
        "|---|---|",
        f"| spam_precision | {fmt(report.spam_precision)} |",
        f"| spam_recall | {fmt(report.spam_recall)} |",
        f"| bulk_precision | {fmt(report.bulk_precision)} |",
        f"| suggested_reject_precision | {fmt(report.suggested_reject_precision)} (предложений отказа: {report.suggested_reject_count}) |",
        f"| authentication_conflict_rate | {fmt(report.authentication_conflict_rate)} (примеров с вышестоящим шлюзом: {report.upstream_cases}) |",
        f"| проверка GTUBE: принят, не отклонён (smoke) | {'пройдена' if report.smoke_ok else 'НЕ пройдена'} |",
        "",
        "## Классы по категориям",
        "",
        "| Категория | Распределение |",
        "|---|---|",
    ]
    for category, counts in sorted(report.class_by_category.items()):
        lines.append(f"| {category} | {', '.join(f'{k}: {v}' for k, v in sorted(counts.items()))} |")
    if report.ham_flagged_as_spam:
        lines += ["", "Легитимные и рассылки, признанные спамом: " + ", ".join(report.ham_flagged_as_spam)]
    if report.spam_missed:
        lines += ["", "Пропущенный спам: " + ", ".join(report.spam_missed)]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gate", action="store_true")
    parser.add_argument("--update-baseline", action="store_true")
    parser.add_argument("--markdown")
    args = parser.parse_args()

    cases, records, meta = load()
    report = corpus.evaluate(cases, records, SpamPolicy())
    text = render(report, meta)
    print(text)
    if args.markdown:
        Path(args.markdown).write_text(text, encoding="utf-8")

    current = {name: getattr(report, name) for name in HIGHER_IS_BETTER}
    current["authentication_conflict_rate"] = report.authentication_conflict_rate
    if args.update_baseline:
        (DATASETS / "baseline.json").write_text(
            json.dumps(
                {"corpus_checksum": meta.get("corpus_checksum"), "metrics": current}, indent=1, sort_keys=True
            )
            + "\n",
            encoding="utf-8",
        )
        print("Базовая линия обновлена.")
        return 0
    if not args.gate:
        return 0

    problems: list[str] = []
    if report.missing_records:
        problems.append(f"нет записей сканера для примеров: {', '.join(report.missing_records[:10])}")
    if not report.smoke_ok:
        problems.append("GTUBE не принят и не просканирован: сканер отклонил письмо или не отвечает")
    baseline = json.loads((DATASETS / "baseline.json").read_text(encoding="utf-8"))
    if baseline.get("corpus_checksum") != meta.get("corpus_checksum"):
        problems.append(
            "контрольная сумма корпуса не совпала с базовой линией: обновите базовую линию осознанно"
        )
    for name in HIGHER_IS_BETTER:
        before, now = baseline["metrics"].get(name), current.get(name)
        if before is not None and (now is None or now < before - TOLERANCE):
            problems.append(f"{name}: было {before}, стало {now}")
    if report.authentication_conflict_rate is not None and report.authentication_conflict_rate < 1.0:
        problems.append("часть расхождений с вышестоящим шлюзом не обнаружена")
    # Легитимная почта и рассылки не должны попадать в спам вообще, пока это не измерено на реальном потоке.
    if report.ham_flagged_as_spam:
        problems.append(f"легитимные письма признаны спамом: {', '.join(report.ham_flagged_as_spam[:10])}")
    if problems:
        print("Гейт корпуса спама: ПРОВАЛ")
        for item in problems:
            print(" -", item)
        return 1
    print("Гейт корпуса спама: пройден")
    return 0


if __name__ == "__main__":
    sys.exit(main())
