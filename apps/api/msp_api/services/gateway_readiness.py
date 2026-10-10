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
#: Непросмотренный высокий риск — не «ещё не дошли», а неизвестный ответ на самый дорогой
#: вопрос. Условие при этом не блокирующее: §21 велит при недоборе выборки отвечать
#: ``READY_WITH_WARNINGS`` с фактическим числом, а не подделывать готовность и не прятать
#: недобор за отказом.
MAX_HIGH_RISK_UNREVIEWED = 0

#: Минимум, доказывающий, что конвейер реального потока вообще работает (§20). Ноль писем — это
#: не «мало данных», а «путь не пройден ни разу», и отличать одно от другого обязательно: иначе
#: пустой пилот был бы неотличим от пилота с недобором.
MIN_PROVEN_ANALYZED = 1
MIN_PROVEN_REVIEWED = 1
#: Шум правила на реальном потоке: повод для разбора человеком, а не для отказа в готовности.
MAX_FP_PER_1000 = 1.0

DECISION_WORDS = {
    READY: "Готово к MSP 1.1",
    READY_WITH_WARNINGS: "Готово с замечаниями",
    NOT_READY: "Не готово",
}

#: Серьёзности, при которых незарегистрированный пробел блокирует готовность (ТЗ §29).
CRITICAL_SEVERITIES = frozenset({"CRITICAL", "HIGH"})

#: Пробелы, названные в политике перехода поимённо (ТЗ §20), и что от каждого требуется.
#:
#: Поимённость — не костыль: §20 это политика именно этого этапа, и пробелы в ней названы
#: потому, что этап брался их закрыть. Общее правило «критические пробелы зарегистрированы»
#: остаётся отдельным условием и действует на всё остальное.
GATE_GAP_POLICY: dict[str, frozenset[str]] = {
    # Этап закрывал GAP-001 кодом, поэтому для готовности требуется именно RESOLVED.
    "GAP-001": frozenset({"RESOLVED"}),
    # Для GAP-002 VALIDATION допустим, но только с задокументированной операционной причиной:
    # «ещё проверяем» без объяснения — не причина, а отсутствие решения.
    "GAP-002": frozenset({"RESOLVED", "VALIDATION"}),
    # GAP-003 и GAP-004 этап не закрывал. От них требуется регистрация и компенсирующая мера:
    # принятый пробел без компенсирующей меры — это необъявленная дыра с номером.
    "GAP-003": frozenset({"ACCEPTED", "RESOLVED", "WONT_FIX", "VALIDATION", "IN_PROGRESS"}),
    "GAP-004": frozenset({"ACCEPTED", "RESOLVED", "WONT_FIX", "VALIDATION", "IN_PROGRESS"}),
}

#: Пробелы, которым обязательна компенсирующая мера, пока они не закрыты (ТЗ §20).
GATE_GAPS_NEEDING_CONTROLS = frozenset({"GAP-003", "GAP-004"})

#: Пробелы, которым при статусе VALIDATION обязательна операционная причина (ТЗ §20).
GATE_GAPS_NEEDING_REASON = frozenset({"GAP-002"})


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
    """Работает ли конвейер, набрана ли выборка и честны ли метрики.

    Разделение на обязательное и необязательное здесь взято прямо из ТЗ, и оно не очевидно.
    Обязательно то, без чего готовность — выдумка: конвейер должен быть доказан хотя бы одним
    письмом, прошедшим путь до разбора, а метрики — не выдавать оценку за измерение. Недобор
    выборки обязательным **не** считается: §21 велит отвечать ``READY_WITH_WARNINGS`` с
    фактическим числом, потому что 480 писем из 500 и ноль писем — разные состояния, и отказ,
    одинаковый для обоих, скрывает это различие.

    Отсутствие сводки — ``unknown``, а не ноль. Платформа, про которую нечего сказать,
    отличается от платформы, про которую сказано «плохо».
    """
    if summary is None:
        missing = "сводка реального потока недоступна"
        return [
            Check(
                "real_flow_pipeline_proven",
                "Конвейер реального потока доказан хотя бы одним письмом",
                True,
                None,
                UNKNOWN,
                f">= {MIN_PROVEN_ANALYZED} принято, >= {MIN_PROVEN_REVIEWED} разобрано",
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
            Check(
                "real_flow_recall_is_labelled_estimate",
                "Recall назван оценкой",
                True,
                None,
                UNKNOWN,
                {"recall_is_estimate": True, "ground_truth_complete": False},
                missing,
            ),
            Check(
                "real_flow_sample",
                "Выборка реального потока набрана",
                False,
                None,
                UNKNOWN,
                f">= {MIN_ANALYZED}",
                missing,
            ),
            Check(
                "real_flow_reviewed",
                "Разобрано аналитиками достаточно писем",
                False,
                None,
                UNKNOWN,
                f">= {MIN_REVIEWED}",
                missing,
            ),
            Check(
                "real_flow_high_risk_reviewed",
                "Весь высокий риск разобран",
                False,
                None,
                UNKNOWN,
                MAX_HIGH_RISK_UNREVIEWED,
                missing,
            ),
            Check(
                "real_flow_rule_noise_reviewed",
                "Шумные на реальном потоке правила разобраны человеком",
                True,
                None,
                UNKNOWN,
                "нет правил с шумом выше порога, либо каждое разобрано",
                missing,
            ),
            Check(
                "known_false_negatives_documented",
                "Все известные пропуски зарегистрированы как пробелы",
                True,
                None,
                UNKNOWN,
                [],
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
        str(row.get("rule_id"))
        for row in (pressure or [])
        if float(row.get("fp_per_1000_messages") or 0.0) >= MAX_FP_PER_1000
    ]
    # Шумное правило само готовность не блокирует — блокирует **неразобранное** шумное правило
    # (§20: «production noisy rules reviewed»). Разбор отмечает человек; платформа состояние
    # правила не меняет (§12).
    reviewed_noisy = {str(item) for item in (summary.get("reviewed_noisy_rules") or [])}
    unreviewed_noisy = [rule for rule in noisy if rule not in reviewed_noisy]

    # Пропуск без зарегистрированного пробела — это и есть незарегистрированный пробел, а его
    # §29 делает безусловным блокиратором (§21: «all known FN documented»).
    undocumented_fn = summary.get("undocumented_false_negatives")

    return [
        Check(
            "real_flow_pipeline_proven",
            "Конвейер реального потока доказан хотя бы одним письмом",
            True,
            analyzed >= MIN_PROVEN_ANALYZED and reviewed >= MIN_PROVEN_REVIEWED,
            {"analyzed": analyzed, "reviewed": reviewed},
            f">= {MIN_PROVEN_ANALYZED} принято, >= {MIN_PROVEN_REVIEWED} разобрано",
            "ноль писем — это не «мало данных», а «путь не пройден ни разу»",
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
        Check(
            "real_flow_rule_noise_reviewed",
            "Шумные на реальном потоке правила разобраны человеком",
            True,
            not unreviewed_noisy if pressure is not None else None,
            unreviewed_noisy if pressure is not None else UNKNOWN,
            "нет правил с шумом выше порога, либо каждое разобрано",
            f"порог: {MAX_FP_PER_1000} ложных на 1000 писем; всего шумных: {len(noisy)}",
        ),
        Check(
            "known_false_negatives_documented",
            "Все известные пропуски зарегистрированы как пробелы",
            True,
            not undocumented_fn if undocumented_fn is not None else None,
            undocumented_fn if undocumented_fn is not None else UNKNOWN,
            [],
            "пропуск без зарегистрированного пробела и есть незарегистрированный пробел",
        ),
        # Ниже — §21: недобор выборки даёт замечание с фактическим числом, а не отказ.
        Check(
            "real_flow_sample",
            "Выборка реального потока набрана",
            False,
            analyzed >= MIN_ANALYZED,
            analyzed,
            f">= {MIN_ANALYZED}",
            "точность на нескольких письмах не отличима от совпадения",
        ),
        Check(
            "real_flow_reviewed",
            "Разобрано аналитиками достаточно писем",
            False,
            reviewed >= MIN_REVIEWED,
            reviewed,
            f">= {MIN_REVIEWED}",
        ),
        Check(
            "real_flow_high_risk_reviewed",
            "Весь высокий риск разобран",
            False,
            (int(unreviewed_high) <= MAX_HIGH_RISK_UNREVIEWED) if unreviewed_high is not None else None,
            unreviewed_high if unreviewed_high is not None else UNKNOWN,
            MAX_HIGH_RISK_UNREVIEWED,
            "непросмотренный высокий риск — неизвестный ответ на самый дорогой вопрос",
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
    by_id = {str(gap.get("gap_id")): gap for gap in gaps}

    # §20: состояния названных пробелов.
    wrong_state: list[str] = []
    for gap_id, allowed in GATE_GAP_POLICY.items():
        found = by_id.get(gap_id)
        if found is None:
            wrong_state.append(f"{gap_id}: нет в реестре")
            continue
        status = str(found.get("status") or "").upper()
        if status not in allowed:
            wrong_state.append(f"{gap_id}: {status or UNKNOWN}, требуется {'/'.join(sorted(allowed))}")

    # §20: компенсирующая мера у незакрытых пробелов.
    without_controls = [
        gap_id
        for gap_id in sorted(GATE_GAPS_NEEDING_CONTROLS)
        if (found := by_id.get(gap_id)) is not None
        and str(found.get("status") or "").upper() != "RESOLVED"
        and not str(found.get("compensating_controls") or "").strip()
    ]

    # §20: операционная причина у пробела, оставленного в VALIDATION.
    without_reason = [
        gap_id
        for gap_id in sorted(GATE_GAPS_NEEDING_REASON)
        if (found := by_id.get(gap_id)) is not None
        and str(found.get("status") or "").upper() == "VALIDATION"
        and not str(found.get("operational_reason") or "").strip()
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
        Check(
            "gate_gaps_in_required_state",
            "Названные в политике перехода пробелы в требуемом состоянии",
            True,
            not wrong_state,
            wrong_state,
            [],
            "GAP-001 — RESOLVED; GAP-002 — RESOLVED или VALIDATION с причиной (ТЗ §20)",
        ),
        Check(
            "open_gaps_have_compensating_controls",
            "У незакрытых пробелов есть компенсирующие меры",
            True,
            not without_controls,
            without_controls,
            [],
            "принятый пробел без компенсирующей меры — это необъявленная дыра с номером",
        ),
        Check(
            "validation_gaps_have_operational_reason",
            "Пробел, оставленный на подтверждении, имеет операционную причину",
            True,
            not without_reason,
            without_reason,
            [],
            "«ещё проверяем» без объяснения — не причина, а отсутствие решения",
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
