"""Готовность Bayes и допуск обучающих примеров (ТЗ 1.2 §20).

Bayes включается только при готовности: пока не набрано минимум проверенных писем каждого
класса, состояние ``NOT_TRAINED``. Обучение по собственной оценке (autolearn) запрещено до
отдельной проверки: оно закрепляет собственные ошибки сканера (отравление через обратную связь).

Пример допускается к обучению только если:

* его подтвердил аналитик, либо он взят из утверждённого исторического корпуса;
* он не пришёл только как вердикт вышестоящего шлюза и не является жалобой пользователя без
  подтверждения аналитика;
* он не синтетический (тестовые письма не смешиваются с боевым корпусом).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

MIN_APPROVED_PER_CLASS = 200


class BayesState(StrEnum):
    NOT_TRAINED = "NOT_TRAINED"
    READY_TO_ENABLE = "READY_TO_ENABLE"
    TRAINED = "TRAINED"


class Label(StrEnum):
    HAM = "HAM"
    SPAM = "SPAM"


class Source(StrEnum):
    ANALYST_CONFIRMED_SPAM = "ANALYST_CONFIRMED_SPAM"
    ANALYST_CONFIRMED_LEGITIMATE = "ANALYST_CONFIRMED_LEGITIMATE"
    APPROVED_HISTORICAL_CORPUS = "APPROVED_HISTORICAL_CORPUS"
    # Ниже — источники, из которых обучать нельзя.
    UNREVIEWED = "UNREVIEWED"
    UPSTREAM_VERDICT = "UPSTREAM_VERDICT"
    USER_REPORT = "USER_REPORT"
    OWN_SCORE = "OWN_SCORE"
    SYNTHETIC_TEST = "SYNTHETIC_TEST"


_ALLOWED = {
    Source.ANALYST_CONFIRMED_SPAM,
    Source.ANALYST_CONFIRMED_LEGITIMATE,
    Source.APPROVED_HISTORICAL_CORPUS,
}


class LearnRefused(ValueError):
    pass


@dataclass(frozen=True)
class LearnSample:
    message_id: str
    label: Label
    source: Source
    confirmed_by: str = ""
    synthetic: bool = False


def check_learn(sample: LearnSample) -> None:
    """Исключение ``LearnRefused``, если пример нельзя использовать для обучения."""
    if sample.synthetic or sample.source is Source.SYNTHETIC_TEST:
        raise LearnRefused("синтетические письма не смешиваются с боевым корпусом")
    if sample.source not in _ALLOWED:
        raise LearnRefused(f"источник {sample.source.value} не допускается к обучению")
    if sample.source is not Source.APPROVED_HISTORICAL_CORPUS and not sample.confirmed_by:
        raise LearnRefused("нет подтверждения аналитика")
    expected = {
        Source.ANALYST_CONFIRMED_SPAM: Label.SPAM,
        Source.ANALYST_CONFIRMED_LEGITIMATE: Label.HAM,
    }.get(sample.source)
    if expected is not None and sample.label is not expected:
        raise LearnRefused("метка не соответствует подтверждению аналитика")


def state(
    approved_ham: int, approved_spam: int, *, trained: bool = False, minimum: int = MIN_APPROVED_PER_CLASS
) -> BayesState:
    if trained and approved_ham >= minimum and approved_spam >= minimum:
        return BayesState.TRAINED
    if approved_ham >= minimum and approved_spam >= minimum:
        return BayesState.READY_TO_ENABLE
    return BayesState.NOT_TRAINED


def can_enable(
    approved_ham: int, approved_spam: int, *, autolearn: bool, minimum: int = MIN_APPROVED_PER_CLASS
) -> tuple[bool, str]:
    if autolearn:
        return False, "автообучение по собственной оценке запрещено до проверки"
    if approved_ham < minimum or approved_spam < minimum:
        return False, f"нужно не меньше {minimum} утверждённых писем каждого класса"
    return True, ""
