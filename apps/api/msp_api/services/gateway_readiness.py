"""Политика готовности к inline-шлюзу (ТЗ 1.0.4 §18-§21).

Пороги и типы живут здесь, а не в скрипте, по одной причине: решение о готовности принимают по
двум источникам — отчёту скрипта в конвейере и странице в консоли, — и если бы у них были свои
копии порогов, они расходились бы молча. Расхождение между «конвейер сказал готово» и «консоль
показывает не готово» хуже любого из двух ответов.

Скрипт ``scripts/gateway_readiness.py`` берёт условия из файлов (baseline, реестр пробелов,
прогон тестов). Эндпоинт ``GET /detection/readiness`` — из базы. Проверяемые утверждения и
пороги общие.

Главное правило: **непроверенное условие не считается выполненным**. ``passed is None`` —
``unknown``, и оно блокирует готовность так же, как провал. Готовность, выданная по отсутствию
доказательств обратного, — не готовность.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

#: Значение условия, которое установить не удалось. Пишется словом, чтобы его нельзя было
#: прочитать ни как «ложь», ни как «истина».
UNKNOWN = "unknown"

READY = "READY_FOR_MSP_1_1"
READY_WITH_WARNINGS = "READY_WITH_WARNINGS"
NOT_READY = "NOT_READY"

#: Минимальный объём выборки реального потока (ТЗ §21). Меньше — и метрики говорят о выборке, а
#: не о потоке: точность 1.000 на четырёх письмах не отличима от совпадения.
MIN_ANALYZED = 500
MIN_REVIEWED = 100
#: Непросмотренный высокий риск — не «ещё не дошли», а неизвестный ответ на самый дорогой вопрос.
MAX_HIGH_RISK_UNREVIEWED = 0
#: Шум правила на реальном потоке: повод для разбора человеком, а не для отказа в готовности.
MAX_FP_PER_1000 = 1.0

DECISION_WORDS = {
    READY: "Готово к MSP 1.1",
    READY_WITH_WARNINGS: "Готово с замечаниями",
    NOT_READY: "Не готово",
}

#: Серьёзности, при которых незарегистрированный пробел блокирует готовность (ТЗ §29).
CRITICAL_SEVERITIES = frozenset({"CRITICAL", "HIGH"})


@dataclass
class Check:
    """Одно условие готовности.

    ``value`` отделено от ``passed`` намеренно: читающему нужно не только «не прошло», но и чем
    именно оно не прошло. ``passed is None`` означает ``unknown``.
    """

    key: str
    title: str
    required: bool
    passed: bool | None
    value: Any = None
    expected: Any = None
    detail: str = ""

    @property
    def state(self) -> str:
        if self.passed is None:
            return UNKNOWN
        return "passed" if self.passed else "failed"

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "required": self.required,
            "state": self.state,
            "value": self.value,
            "expected": self.expected,
            "detail": self.detail,
        }


@dataclass
class Readiness:
    checks: list[Check] = field(default_factory=list)

    def add(self, check: Check) -> None:
        self.checks.append(check)

    def extend(self, checks: list[Check]) -> None:
        self.checks.extend(checks)

    @property
    def blocking(self) -> list[Check]:
        """Обязательные условия, которые не прошли **или не проверены**."""
        return [c for c in self.checks if c.required and c.passed is not True]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if not c.required and c.passed is not True]

    @property
    def decision(self) -> str:
        if self.blocking:
            return NOT_READY
        if self.warnings:
            return READY_WITH_WARNINGS
        return READY

    def as_dict(self) -> dict[str, Any]:
        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "decision": self.decision,
            "decision_label": DECISION_WORDS[self.decision],
            "blocking": [c.key for c in self.blocking],
            "warnings": [c.key for c in self.warnings],
            "checks": [c.as_dict() for c in self.checks],
            "thresholds": {
                "min_analyzed": MIN_ANALYZED,
                "min_reviewed": MIN_REVIEWED,
                "max_high_risk_unreviewed": MAX_HIGH_RISK_UNREVIEWED,
                "max_fp_per_1000": MAX_FP_PER_1000,
            },
            # Что READY не означает. Строка в ответе, а не только в документе: решение читают
            # из API, и там же должно стоять ограничение этого решения.
            "scope_note": (
                "Готовность означает, что обязательные условия выполнены и свидетельства к ним "
                "есть. Она не означает, что inline-шлюз безопасен: шлюз в этот этап не входил и "
                "не проверялся. В разрыве потока появляются отказы, которых на копии письма не "
                "бывает, — очередь, таймаут, недоставленное письмо. Это предмет MSP 1.1."
            ),
        }


# ---------------------------------------------------------------------------------------------
# Условия по сводке реального потока (ТЗ §20, §21)
# ---------------------------------------------------------------------------------------------
def real_flow_checks(summary: dict[str, Any] | None) -> list[Check]:
    """Объём выборки, разбор и честность метрик.

    Отсутствие сводки — ``unknown``, а не ноль. Платформа, про которую нечего сказать,
    отличается от платформы, про которую сказано «плохо»; в разрыв потока не идёт ни та, ни
    другая, но по разным причинам, и смешивать их в отчёте нельзя.
    """
    if summary is None:
        missing = "сводка реального потока недоступна"
        return [
            Check(
                "real_flow_sample",
                "Выборка реального потока набрана",
                True,
                None,
                UNKNOWN,
                f">= {MIN_ANALYZED}",
                missing,
            ),
            Check(
                "real_flow_reviewed",
                "Разобрано аналитиками достаточно писем",
                True,
                None,
                UNKNOWN,
                f">= {MIN_REVIEWED}",
                missing,
            ),
            Check(
                "real_flow_high_risk_reviewed",
                "Весь высокий риск разобран",
                True,
                None,
                UNKNOWN,
                MAX_HIGH_RISK_UNREVIEWED,
                missing,
            ),
            Check(
                "real_flow_precision_measured",
                "Точность на реальном потоке измерена",
                True,
                None,
                UNKNOWN,
                "не null",
                missing,
            ),
        ]

    sample = summary.get("sample") or {}
    analyzed = int(sample.get("analyzed") or summary.get("messages_total") or 0)
    reviewed = int(sample.get("reviewed") or summary.get("reviewed_total") or 0)
    unreviewed_high = sample.get("high_risk_unreviewed")
    precision = summary.get("precision")
    pressure = summary.get("rule_pressure")

    noisy = [
        row.get("rule_id")
        for row in (pressure or [])
        if float(row.get("fp_per_1000_messages") or 0.0) >= MAX_FP_PER_1000
    ]

    return [
        Check(
            "real_flow_sample",
            "Выборка реального потока набрана",
            True,
            analyzed >= MIN_ANALYZED,
            analyzed,
            f">= {MIN_ANALYZED}",
            "точность на нескольких письмах не отличима от совпадения",
        ),
        Check(
            "real_flow_reviewed",
            "Разобрано аналитиками достаточно писем",
            True,
            reviewed >= MIN_REVIEWED,
            reviewed,
            f">= {MIN_REVIEWED}",
        ),
        Check(
            "real_flow_high_risk_reviewed",
            "Весь высокий риск разобран",
            True,
            (int(unreviewed_high) <= MAX_HIGH_RISK_UNREVIEWED) if unreviewed_high is not None else None,
            unreviewed_high if unreviewed_high is not None else UNKNOWN,
            MAX_HIGH_RISK_UNREVIEWED,
            "непросмотренный высокий риск — неизвестный ответ на самый дорогой вопрос",
        ),
        Check(
            "real_flow_precision_measured",
            "Точность на реальном потоке измерена, а не выдумана",
            True,
            precision is not None,
            precision if precision is not None else UNKNOWN,
            "не null",
            "null означает отсутствие знаменателя: мерить ещё нечем",
        ),
        Check(
            "real_flow_recall_is_labelled_estimate",
            "Recall назван оценкой",
            True,
            summary.get("recall_is_estimate") is True and summary.get("ground_truth_complete") is False,
            {
                "recall_is_estimate": summary.get("recall_is_estimate"),
                "ground_truth_complete": summary.get("ground_truth_complete"),
            },
            {"recall_is_estimate": True, "ground_truth_complete": False},
            "полной разметки реального потока не существует, и ответ обязан это признавать",
        ),
        # Не обязательное: шум — повод для разбора. PRODUCTION_NOISY ставит человек (ТЗ §12).
        Check(
            "real_flow_rule_noise",
            "Нет правил с заметным шумом на реальном потоке",
            False,
            not noisy if pressure is not None else None,
            noisy,
            f"< {MAX_FP_PER_1000} ложных срабатываний на 1000 писем",
        ),
    ]


# ---------------------------------------------------------------------------------------------
# Условия по реестру пробелов (ТЗ §29)
# ---------------------------------------------------------------------------------------------
def gap_checks(gaps: list[dict[str, Any]] | None) -> list[Check]:
    """Критические пробелы должны быть зарегистрированы.

    Регистрация не закрывает пробел и не делает его безопасным. Она делает его известным, а
    известное ограничение и неизвестная дыра — разные вещи для того, кто ставит платформу в
    разрыв потока.

    ``None`` вместо списка означает «реестр не прочитан» и блокирует готовность. Пустой список
    означает «пробелов нет» и условие по нему проходит — разница существенная, и ровно на ней
    первая версия скрипта однажды сообщила «пробелы зарегистрированы», не найдя ни одного.
    """
    if gaps is None:
        return [
            Check(
                "critical_gaps_registered",
                "Критические пробелы зарегистрированы",
                True,
                None,
                UNKNOWN,
                "все",
                "реестр пробелов не прочитан",
            )
        ]

    unregistered = [
        gap.get("gap_id") or "(без номера)"
        for gap in gaps
        if str(gap.get("severity", "")).upper() in CRITICAL_SEVERITIES
        and not str(gap.get("status") or "").strip()
    ]
    open_critical = [
        gap.get("gap_id")
        for gap in gaps
        if str(gap.get("severity", "")).upper() in CRITICAL_SEVERITIES
        and str(gap.get("status", "")).upper() in {"OPEN", "IN_PROGRESS"}
    ]
    unvalidated = [
        gap.get("gap_id")
        for gap in gaps
        if str(gap.get("status", "")).upper() == "RESOLVED" and not gap.get("real_flow_validated_at")
    ]
    return [
        Check(
            "critical_gaps_registered",
            "Критические пробелы зарегистрированы",
            True,
            not unregistered,
            unregistered,
            [],
            f"разобрано пробелов: {len(gaps)}",
        ),
        # Открытый критический пробел — предупреждение, а не отказ: он может быть принятым
        # ограничением с компенсирующей мерой. Молча он при этом не проходит.
        Check(
            "critical_gaps_not_open",
            "Критические пробелы закрыты или приняты",
            False,
            not open_critical,
            open_critical,
            [],
        ),
        # Закрытый пробел без подтверждения на реальной почте — закрытый по синтетическому
        # корпусу, то есть по случаям, которые мы сами придумали.
        Check(
            "resolved_gaps_validated_on_real_mail",
            "Закрытые пробелы подтверждены на реальной почте",
            False,
            not unvalidated,
            unvalidated,
            [],
        ),
    ]
