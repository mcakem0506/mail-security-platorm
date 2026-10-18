"""Метрики ложных срабатываний и пропусков по решениям аналитика (ТЗ 1.2 §29, §39, §43).

Что здесь важно понимать о числах:

* ``fp_per_1000`` отнесён к числу **просканированных** писем, а ложные срабатывания известны только
  среди **просмотренных**. Поэтому это нижняя граница, пока просмотрена не вся выборка;
  ``reviewed_fraction`` показывает, насколько ей можно верить.
* ``suggested_reject_fp_rate`` — доля ложных среди просмотренных писем, которым сканер предложил
  отклонение, с доверительным интервалом Вильсона. Допуск к отказу в этапе 1.3 требует и
  измеренной доли, и достаточной выборки; малая выборка с нулём ошибок ничего не доказывает.
* Рекall по спаму оценивается по случайной выборке писем с низкой оценкой (там, где сканер не
  сработал): пропуск — это письмо, которое аналитик признал спамом при низкой оценке.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum


class Selection(StrEnum):
    """Обязательная выборка для просмотра (ТЗ 1.2 §29)."""

    SUGGESTED_REJECT = "SUGGESTED_REJECT"
    DMARC_REJECT_FAILURE = "DMARC_REJECT_FAILURE"
    RBL_LISTED = "RBL_LISTED"
    HIGH_SCORE = "HIGH_SCORE"
    LOW_SCORE_SAMPLE = "LOW_SCORE_SAMPLE"
    AUTH_CONFLICT = "AUTH_CONFLICT"


class Verdict(StrEnum):
    HAM = "HAM"
    SPAM = "SPAM"
    BULK = "BULK"


@dataclass(frozen=True)
class ReviewedScan:
    selection: Selection
    verdict: Verdict
    score: float
    spam_class: str
    suggested_action: str
    symbols: tuple[str, ...] = ()


def wilson_upper(failures: int, total: int, z: float = 1.96) -> float:
    """Верхняя граница доверительного интервала Вильсона для доли. Без выборки — 1.0."""
    if total <= 0:
        return 1.0
    p = failures / total
    denom = 1 + z * z / total
    centre = p + z * z / (2 * total)
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
    return min(1.0, (centre + margin) / denom)


@dataclass
class ValidationMetrics:
    scanned: int
    reviewed: int
    reviewed_fraction: float
    spam_fp: int
    spam_fp_per_1000: float
    auth_fp: int
    auth_fp_per_1000: float
    rbl_fp: int
    rbl_fp_per_1000: float
    suggested_reject_reviewed: int
    suggested_reject_fp: int
    suggested_reject_fp_rate: float | None
    suggested_reject_fp_upper: float
    spam_fn: int
    low_score_reviewed: int
    spam_fn_rate: float | None
    score_at_fn: list[float] = field(default_factory=list)
    symbols_at_fn: dict[str, int] = field(default_factory=dict)
    by_selection: dict[str, int] = field(default_factory=dict)
    bulk_reviewed: int = 0
    bulk_precision: float | None = None
    spam_precision: float | None = None
    spam_recall: float | None = None


def _per_thousand(count: int, scanned: int) -> float:
    return round(count / scanned * 1000, 3) if scanned > 0 else 0.0


def compute(scanned: int, reviews: Iterable[ReviewedScan]) -> ValidationMetrics:
    rows = list(reviews)
    by_selection = Counter(r.selection.value for r in rows)
    is_spam_class = lambda r: r.spam_class in ("SPAM", "HIGH_CONFIDENCE_SPAM")  # noqa: E731
    spam_fp = sum(1 for r in rows if r.verdict is Verdict.HAM and is_spam_class(r))
    auth_fp = sum(
        1 for r in rows if r.selection is Selection.DMARC_REJECT_FAILURE and r.verdict is Verdict.HAM
    )
    rbl_fp = sum(1 for r in rows if r.selection is Selection.RBL_LISTED and r.verdict is Verdict.HAM)
    reject_rows = [r for r in rows if r.selection is Selection.SUGGESTED_REJECT]
    reject_fp = sum(1 for r in reject_rows if r.verdict is Verdict.HAM)
    low = [r for r in rows if r.selection is Selection.LOW_SCORE_SAMPLE]
    fn = [r for r in low if r.verdict is Verdict.SPAM]
    symbols: Counter[str] = Counter()
    for row in fn:
        symbols.update(row.symbols)

    flagged = [r for r in rows if is_spam_class(r)]
    true_spam_flagged = sum(1 for r in flagged if r.verdict is Verdict.SPAM)
    spam_precision = round(true_spam_flagged / len(flagged), 4) if flagged else None
    bulk_rows = [r for r in rows if r.spam_class == "BULK"]
    bulk_true = sum(1 for r in bulk_rows if r.verdict is Verdict.BULK)
    # Полнота по спаму: из реального спама среди просмотренных — сколько сканер заметил.
    real_spam = [r for r in rows if r.verdict is Verdict.SPAM]
    caught = sum(1 for r in real_spam if is_spam_class(r))
    return ValidationMetrics(
        scanned=scanned,
        reviewed=len(rows),
        reviewed_fraction=round(len(rows) / scanned, 4) if scanned > 0 else 0.0,
        spam_fp=spam_fp,
        spam_fp_per_1000=_per_thousand(spam_fp, scanned),
        auth_fp=auth_fp,
        auth_fp_per_1000=_per_thousand(auth_fp, scanned),
        rbl_fp=rbl_fp,
        rbl_fp_per_1000=_per_thousand(rbl_fp, scanned),
        suggested_reject_reviewed=len(reject_rows),
        suggested_reject_fp=reject_fp,
        suggested_reject_fp_rate=round(reject_fp / len(reject_rows), 4) if reject_rows else None,
        suggested_reject_fp_upper=round(wilson_upper(reject_fp, len(reject_rows)), 4),
        spam_fn=len(fn),
        low_score_reviewed=len(low),
        spam_fn_rate=round(len(fn) / len(low), 4) if low else None,
        score_at_fn=sorted(round(r.score, 2) for r in fn),
        symbols_at_fn=dict(symbols.most_common(20)),
        by_selection=dict(by_selection),
        bulk_reviewed=len(bulk_rows),
        bulk_precision=round(bulk_true / len(bulk_rows), 4) if bulk_rows else None,
        spam_precision=spam_precision,
        spam_recall=round(caught / len(real_spam), 4) if real_spam else None,
    )


@dataclass(frozen=True)
class RejectSafety:
    """Готовность к разговору об отказе в этапе 1.3. Сама ничего не включает."""

    ready: bool
    reasons: tuple[str, ...]


def reject_safety(
    metrics: ValidationMetrics,
    *,
    min_reviewed: int = 300,
    max_fp_upper: float = 0.01,
    min_fraction: float = 0.0,
) -> RejectSafety:
    reasons: list[str] = []
    if metrics.suggested_reject_reviewed < min_reviewed:
        reasons.append(
            f"INSUFFICIENT_SAMPLE: просмотрено {metrics.suggested_reject_reviewed} писем с предложенным отказом, "
            f"нужно не меньше {min_reviewed}"
        )
    elif metrics.suggested_reject_fp_upper > max_fp_upper:
        reasons.append(
            f"FP_NOT_PROVEN_LOW: верхняя граница доли ложных {metrics.suggested_reject_fp_upper:.2%} "
            f"выше допустимых {max_fp_upper:.2%}"
        )
    if metrics.low_score_reviewed == 0:
        reasons.append("NO_LOW_SCORE_SAMPLE: пропуски спама не измерялись")
    if metrics.reviewed_fraction < min_fraction:
        reasons.append("LOW_REVIEW_COVERAGE")
    return RejectSafety(ready=not reasons, reasons=tuple(reasons))
