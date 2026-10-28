"""Статистика пилота реального потока (MSP 1.3P, ТЗ §13, §20).

Чистые функции без базы и сети. Три правила, из-за которых модуль существует отдельно:

* **нет знаменателя — значение ``None``**, а не 0: «0 ошибок из 0» не означает «нет ошибок»;
* **0 ошибок не доказывает малую долю**: 0/100 даёт верхнюю границу Вильсона около 3,7 %, а до 1 % нужно около 381
  просмотренных кандидатов без единой ошибки;
* **наблюдаемая доля и верхняя граница хранятся порознь** вместе с размером выборки: по одной из них нельзя
  судить о другой.

Расчёт границы Вильсона не дублируется: берётся тот же, что использует готовность контролей этапа 1.3.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any

from .readiness import DEFAULT_MAX_FP_UPPER

Z95 = 1.96

#: Формальные минимумы допуска к рассмотрению MSP 1.4 (ТЗ 1.3P §13). Не доказательство малой доли ложных.
MIN_REAL_UNIQUE = 1000
MIN_REVIEWED_REAL = 200
MIN_REVIEWED_REJECT_CANDIDATES = 100

#: Исходы статистического условия для отказа.
STAT_PASS = "PASS"  # noqa: S105 - исход проверки, не пароль
#: Точечная доля в норме, но верхняя граница выше порога: допуск возможен только с письменным принятием риска.
STAT_RISK_ACCEPT_REQUIRED = "RISK_ACCEPT_REQUIRED"
STAT_FAIL = "FAIL"
STAT_NO_DATA = "NO_DATA"


def rate(failures: int, total: int) -> float | None:
    """Доля ошибок. Нет знаменателя — ``None``."""
    if total <= 0:
        return None
    return failures / total


def per_1000(count: int, total: int) -> float | None:
    """Число случаев на 1000 писем. Нет знаменателя — ``None``."""
    if total <= 0:
        return None
    return round(count * 1000 / total, 3)


def wilson_upper(failures: int, total: int) -> float | None:
    """Верхняя граница 95 % интервала Вильсона. Нет знаменателя — ``None`` (не 1.0 и не 0)."""
    if total <= 0:
        return None
    from msp_antispam.validation import wilson_upper as _wilson_upper  # единый расчёт этапов 1.2 и 1.3

    return _wilson_upper(failures, total, Z95)


def required_sample_for_zero_failures(max_upper: float = DEFAULT_MAX_FP_UPPER, z: float = Z95) -> int:
    """Сколько просмотренных кандидатов без единой ошибки нужно, чтобы верхняя граница не превышала порог.

    При нуле ошибок граница Вильсона равна ``z² / (n + z²)``, откуда ``n = z² · (1/u − 1)``.
    """
    if not 0 < max_upper < 1:
        raise ValueError("порог должен лежать между 0 и 1")
    return math.ceil(z * z * (1.0 / max_upper - 1.0))


def evaluate_reject_statistics(
    failures: int,
    reviewed: int,
    *,
    max_upper: float = DEFAULT_MAX_FP_UPPER,
    min_reviewed: int = MIN_REVIEWED_REJECT_CANDIDATES,
) -> dict[str, Any]:
    """Статистическое условие допуска отказа: размер выборки, наблюдаемая доля и верхняя граница — отдельно."""
    observed = rate(failures, reviewed)
    upper = wilson_upper(failures, reviewed)
    needed = required_sample_for_zero_failures(max_upper)
    if reviewed <= 0:
        status = STAT_NO_DATA
    elif reviewed < min_reviewed or (observed is not None and observed > max_upper):
        status = STAT_FAIL
    elif upper is not None and upper > max_upper:
        status = STAT_RISK_ACCEPT_REQUIRED
    else:
        status = STAT_PASS
    return {
        "sample_size": reviewed,
        "failures": failures,
        "observed_fp_rate": round(observed, 6) if observed is not None else None,
        "wilson_upper_95": round(upper, 6) if upper is not None else None,
        "max_upper": max_upper,
        "min_reviewed": min_reviewed,
        "sample_for_zero_failures": needed,
        "status": status,
    }


def percentile(values: Sequence[float], fraction: float) -> float | None:
    """Перцентиль по ближайшему рангу. Пустой ряд — ``None``."""
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return float(ordered[index])
