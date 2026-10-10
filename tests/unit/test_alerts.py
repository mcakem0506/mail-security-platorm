"""Алерт, ссылающийся на несуществующую метрику, не срабатывает никогда (ТЗ 1.0.4 §25).

Повод практический: правило о просроченных исходных данных было написано как
``msp_realflow_promotion_state{state="RAW_OVERDUE"}``, тогда как метки этой метрики приходят из
``PromotionState``, где такого значения нет и быть не может. Правило выглядело осмысленным,
проходило разбор YAML и не могло сработать ни при каких обстоятельствах — то есть нарушение
срока хранения переписки осталось бы незамеченным.

Такую ошибку нельзя увидеть ни в Prometheus (выражение без данных — это пустой результат, а не
ошибка), ни глазами в ревью.
"""

from __future__ import annotations

import pathlib
import re

import pytest
import yaml

ALERTS = pathlib.Path("infrastructure/monitoring/alerts.yml")
OBSERVABILITY = pathlib.Path("apps/api/msp_api/observability.py")

#: Метрики, которые отдаёт не платформа. ``up`` — служебная метрика самого Prometheus,
#: остальные приходят из экспортеров инфраструктуры.
_EXTERNAL_METRICS = frozenset(
    {
        "up",
        "pg_stat_database_numbackends",
        "redis_connected_clients",
        "node_filesystem_avail_bytes",
        "node_filesystem_size_bytes",
        "container_memory_usage_bytes",
        "process_resident_memory_bytes",
    }
)

#: Функции PromQL и ключевые слова: в выражении они стоят там же, где имя метрики.
_PROMQL_WORDS = frozenset(
    {
        "sum",
        "rate",
        "increase",
        "avg",
        "max",
        "min",
        "count",
        "by",
        "without",
        "and",
        "or",
        "unless",
        "on",
        "ignoring",
        "absent",
        "histogram_quantile",
        "clamp_min",
        "clamp_max",
        "delta",
        "irate",
        "le",
        "job",
        "topk",
        "bottomk",
        "time",
        "changes",
        "predict_linear",
        "stddev",
        "quantile",
        "label_replace",
        "vector",
        "scalar",
        "sum_over_time",
        "avg_over_time",
        "max_over_time",
        "min_over_time",
        "offset",
        "group_left",
        "group_right",
    }
)

#: Имя метрики — слово, за которым **не** идёт открывающая скобка: ``hour()`` и ``rate(`` так
#: отсекаются без перечисления всех функций PromQL, которых со временем станет больше.
_METRIC_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b(?!\s*\()")
#: Группировка: ``by (provider)``, ``without (job)``, ``on () ``. В скобках здесь стоят метки, а
#: не метрики, и принимать их за метрики — ровно та ошибка, из-за которой проверка сначала
#: ругалась на верные выражения.
_GROUPING_RE = re.compile(r"\b(?:by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)")


def _metric_names(expression: str) -> set[str]:
    """Имена метрик в выражении PromQL.

    Разбор нарочно грубый: он не понимает PromQL, а только отделяет имена метрик от функций,
    меток и чисел. Этого достаточно для вопроса «существует ли такая метрика» и недостаточно ни
    для чего большего — и притворяться разборщиком выражений здесь не нужно.
    """
    # Сначала группировки, потом селекторы по меткам: и там и там стоят значения, не имена.
    stripped = _GROUPING_RE.sub(" ", expression)
    stripped = re.sub(r"\{[^}]*\}", " ", stripped)
    return {word for word in _METRIC_RE.findall(stripped) if word not in _PROMQL_WORDS and not word.isdigit()}


def _rules() -> list[dict]:
    parsed = yaml.safe_load(ALERTS.read_text(encoding="utf-8"))
    return [rule for group in parsed["groups"] for rule in group["rules"]]


def _exported_metrics() -> set[str]:
    """Имена метрик, объявленные в коде.

    Берутся из первого строкового аргумента ``Counter``/``Gauge``/``Histogram``/``Summary``.
    Prometheus дописывает к счётчикам суффикс ``_total``, если его нет, и к гистограммам —
    ``_bucket``, ``_sum`` и ``_count``; все варианты добавляются, иначе проверка ругалась бы на
    верные выражения.
    """
    text = OBSERVABILITY.read_text(encoding="utf-8")
    names: set[str] = set()
    for kind, name in re.findall(
        r"(Counter|Gauge|Histogram|Summary)\(\s*\n?\s*\"([a-zA-Z_][a-zA-Z0-9_]*)\"", text
    ):
        names.add(name)
        if kind == "Counter" and not name.endswith("_total"):
            names.add(f"{name}_total")
        if kind in ("Histogram", "Summary"):
            names.update({f"{name}_bucket", f"{name}_sum", f"{name}_count"})
    return names


def test_the_alert_file_parses_and_is_not_empty() -> None:
    """Проверка самой проверки: нулевой список правил прошёл бы всё, что ниже."""
    rules = _rules()
    assert len(rules) > 20
    assert all("expr" in rule and "alert" in rule for rule in rules)


def test_the_exported_metric_list_is_not_empty() -> None:
    """И вторая половина: пустой набор метрик сделал бы проверку ниже невыполнимой, а не пустой,
    но подтвердить разбор всё равно надо."""
    exported = _exported_metrics()
    assert len(exported) > 30
    assert "msp_realflow_messages_total" in exported
    assert "msp_realflow_raw_retention_overdue" in exported


def test_every_alert_references_a_metric_that_exists() -> None:
    unknown: dict[str, set[str]] = {}
    exported = _exported_metrics() | _EXTERNAL_METRICS
    for rule in _rules():
        missing = {word for word in _metric_names(str(rule["expr"])) if word not in exported}
        if missing:
            unknown[str(rule["alert"])] = missing
    assert unknown == {}, f"алерты ссылаются на метрики, которых нет: {unknown}"


def test_the_check_would_have_caught_the_label_that_cannot_exist() -> None:
    """Вторая половина той же ошибки: метрика существовала, а значение метки — нет.

    Проверка выше её не ловит, потому что смотрит имена, а не метки. Поэтому значения меток
    состояния продвижения сверяются с перечислением напрямую.
    """
    from msp_contracts import PromotionState

    states = {state.value for state in PromotionState}
    assert "RAW_OVERDUE" not in states, "именно это значение и было выдумано"

    for rule in _rules():
        for label_block in re.findall(r"msp_realflow_promotion_state\{([^}]*)\}", str(rule["expr"])):
            for value in re.findall(r'state\s*=\s*"([^"]*)"', label_block):
                assert value in states, f"{rule['alert']}: состояния {value} не существует"


@pytest.mark.parametrize(
    "required",
    [
        "MspRealFlowStalled",
        "MspRealFlowHighRiskUnreviewed",
        "MspRealFlowRuleNoisy",
        "MspRealFlowRawRetentionOverdue",
        "MspShortDomainLookalikeSpike",
        "MspQrDecoderUnhealthy",
    ],
)
def test_the_stage_alerts_are_present(required: str) -> None:
    assert required in {rule["alert"] for rule in _rules()}


def test_no_alert_claims_a_quality_threshold_on_real_mail() -> None:
    """ТЗ §12: доля без знаменателя — это не ноль.

    Алерт вида «точность ниже N процентов» срабатывал бы громче всего ровно тогда, когда мерить
    ещё нечем: в Prometheus отсутствующее значение читается как ноль. Поэтому таких правил здесь
    нет, и это проверяется, а не только написано в комментарии.
    """
    for rule in _rules():
        expression = str(rule["expr"])
        assert "precision" not in expression
        assert "recall" not in expression


def test_the_noisy_rule_alert_says_the_decision_is_a_humans() -> None:
    """ТЗ §12: правило может получить ``PRODUCTION_NOISY``, но не отключается автоматически.

    Описание алерта — это то, что человек прочитает в три часа ночи. Если из него не ясно, что
    делать, он не сделает ничего, а если из него следует, что платформа справится сама, — тем
    более. Поэтому текст обязан называть, кто принимает решение.

    Проверять обратное — что в описаниях нет обещаний автоматики — подстрочным поиском нельзя:
    первая версия этой проверки искала «отключается автоматически» и нашла эти слова в тексте
    «правило **не** отключается автоматически», то есть в прямо противоположном утверждении.
    """
    rules = {rule["alert"]: rule for rule in _rules()}
    text = " ".join(str(v) for v in rules["MspRealFlowRuleNoisy"]["annotations"].values())
    assert "вывод человека" in text
    assert "PRODUCTION_NOISY" in text
