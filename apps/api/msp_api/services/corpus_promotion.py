"""Продвижение письма реального потока в золотой корпус (ТЗ 1.0.4 §10).

Автоматического продвижения нет, и это не осторожность, а устройство: корпус — это то, по чему
измеряется качество детектирования, и письмо, попавшее в него само, измеряло бы платформу её же
мнением о себе. Правило, ошибочно сработавшее на рассылке бухгалтерии, добавило бы эту рассылку
в корпус как подтверждение своей правоты и закрепило бы ошибку навсегда.

Поэтому путь разбит на шаги, каждый из которых — отдельное действие отдельного человека:

1. **разбор** — аналитик говорит, что было на самом деле (``services.real_flow.review``);
2. **обезличивание** — автоматическое, но его результат ещё не проверен;
3. **проверка обезличивания** — человек подтверждает, что ничего не осталось (``PiiStatus``);
4. **заявка** — аналитик предлагает письмо в корпус, с номером разбора;
5. **согласование** — другой человек соглашается; тот же не может;
6. **проверка воспроизводимости** — детектирование прогоняется по обезличенной копии, и её
   вердикт сравнивается с тем, что было на исходном письме;
7. **повышение версии датасета** — явное, с номером версии; только после него письмо считается
   вошедшим в корпус.

Шаг 6 нужен потому, что обезличенное письмо — это другое письмо. Если вердикт по нему не
воспроизводится, кейс в корпусе измерял бы не то, что произошло в жизни, а последствия замен.
Такое письмо в корпус не идёт, и отказ фиксируется: это не неудача, а найденное ограничение
обезличивания.

Этот модуль **не записывает ничего в сам корпус**. Золотой корпус — код, и кейс в нём появляется
коммитом, который делает человек. Здесь готовится материал для этого коммита и хранится след:
кто предложил, кто согласовал, воспроизвелось ли, в какую версию вошло.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from msp_contracts import PiiStatus, PromotionState, RiskLevel, utcnow

from ..db.models import ValidationMessage

logger = logging.getLogger(__name__)

#: Состояния, из которых заявку ещё можно подать.
REQUESTABLE_STATES: frozenset[PromotionState] = frozenset(
    {PromotionState.NOT_REQUESTED, PromotionState.REJECTED}
)


class PromotionError(RuntimeError):
    """Отказ с причиной, а не общее «нельзя»."""


# ---------------------------------------------------------------------------------------------
# Необходимые условия
# ---------------------------------------------------------------------------------------------
def blockers(record: ValidationMessage) -> list[str]:
    """Чего письму не хватает, чтобы его можно было предлагать в корпус.

    Список, а не первое попавшееся препятствие: аналитику нужно знать всё, что придётся сделать,
    а не выяснять это по одному отказу за раз.
    """
    reasons: list[str] = []
    if record.analyst_classification is None:
        reasons.append("письмо не разобрано аналитиком: в корпусе нет кейсов без известного ответа")
    if not record.anonymized:
        reasons.append("письмо не обезличено")
    elif record.pii_status is not PiiStatus.REVIEWED:
        # Автоматическая замена находит то, что описано шаблоном. Фамилию в середине фразы — нет.
        reasons.append("обезличивание не проверено человеком: автоматическая замена — это не гарантия")
    if record.pii_status is PiiStatus.REJECTED:
        reasons.append("проверка нашла персональные данные: письмо в корпус не идёт")
    if not record.anonymized_object_key:
        reasons.append("обезличенной копии нет в хранилище: проверить воспроизводимость нечем")
    return reasons


# ---------------------------------------------------------------------------------------------
# Шаг 4: заявка
# ---------------------------------------------------------------------------------------------
def request(record: ValidationMessage, *, analyst: str, case_id: str) -> ValidationMessage:
    """Предложить письмо в корпус.

    Номер разбора обязателен: кейс в корпусе без ссылки на то, откуда он взялся, через год
    невозможно ни объяснить, ни оспорить.
    """
    if not analyst.strip():
        raise PromotionError("заявка без автора не принимается")
    if not case_id.strip():
        raise PromotionError("заявка без номера разбора не принимается")
    if record.promotion_state not in REQUESTABLE_STATES:
        raise PromotionError(
            f"письмо уже в состоянии {record.promotion_state.value}: повторная заявка не нужна"
        )
    remaining = blockers(record)
    if remaining:
        raise PromotionError("; ".join(remaining))

    record.promotion_state = PromotionState.REQUESTED
    record.promotion_requested_by = analyst.strip()
    record.promotion_case_id = case_id.strip()[:32]
    logger.info("corpus_promotion.requested", extra={"case_id": record.promotion_case_id})
    return record


# ---------------------------------------------------------------------------------------------
# Шаг 5: согласование
# ---------------------------------------------------------------------------------------------
def approve(record: ValidationMessage, *, approver: str) -> ValidationMessage:
    """Согласовать заявку.

    Согласует другой человек. Не из недоверия к аналитику: заявка и согласование проверяют
    разное — первая, что кейс интересен, второе, что его можно хранить. Один человек, делающий
    оба шага, делает фактически один.
    """
    if not approver.strip():
        raise PromotionError("согласование без автора не записывается")
    if record.promotion_state is not PromotionState.REQUESTED:
        raise PromotionError(f"согласовывать нечего: письмо в состоянии {record.promotion_state.value}")
    if approver.strip().lower() == record.promotion_requested_by.strip().lower():
        raise PromotionError("согласующий не может быть автором заявки")

    record.promotion_state = PromotionState.APPROVED
    record.promotion_approved_by = approver.strip()
    logger.info("corpus_promotion.approved", extra={"case_id": record.promotion_case_id})
    return record


def reject(record: ValidationMessage, *, approver: str, reason: str) -> ValidationMessage:
    """Отклонить заявку. Причина обязательна: отказ без причины повторят."""
    if not reason.strip():
        raise PromotionError("отказ без причины не записывается")
    if record.promotion_state not in (PromotionState.REQUESTED, PromotionState.APPROVED):
        raise PromotionError("отклонять нечего")
    record.promotion_state = PromotionState.REJECTED
    record.promotion_approved_by = approver.strip()
    record.review_comment = (f"{record.review_comment}\nотказ в корпус: {reason.strip()}").strip()[:2000]
    return record


# ---------------------------------------------------------------------------------------------
# Шаг 6: воспроизводимость
# ---------------------------------------------------------------------------------------------
@dataclass
class ReproducibilityResult:
    """Воспроизвёлся ли вердикт по обезличенной копии.

    ``reproduced`` False — не ошибка прогона, а найденное ограничение обезличивания: замены
    задели то, на чём держался вердикт. Такое письмо в корпус не идёт, и причина названа.
    """

    reproduced: bool
    production_verdict: str | None
    anonymized_verdict: str | None
    triggered_rules: list[str]
    lost_rules: list[str]
    gained_rules: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "reproduced": self.reproduced,
            "production_verdict": self.production_verdict,
            "anonymized_verdict": self.anonymized_verdict,
            "triggered_rules": list(self.triggered_rules),
            "lost_rules": list(self.lost_rules),
            "gained_rules": list(self.gained_rules),
        }


def check_reproducibility(
    record: ValidationMessage,
    *,
    anonymized_verdict: RiskLevel | None,
    anonymized_rules: list[str],
) -> ReproducibilityResult:
    """Сравнить вердикт по обезличенной копии с тем, что был на исходном письме.

    Сравниваются и вердикт, и набор правил. Совпавший вердикт при разошедшихся правилах — тоже
    расхождение, и притом самое неприятное: кейс в корпусе выглядел бы правильным, а проверял бы
    другое.
    """
    before = set(record.triggered_rules or [])
    after = set(anonymized_rules)
    lost = sorted(before - after)
    gained = sorted(after - before)
    result = ReproducibilityResult(
        reproduced=(record.production_verdict is anonymized_verdict and not lost and not gained),
        production_verdict=(record.production_verdict.value if record.production_verdict else None),
        anonymized_verdict=anonymized_verdict.value if anonymized_verdict else None,
        triggered_rules=sorted(after),
        lost_rules=lost,
        gained_rules=gained,
    )
    record.reproducibility_report = result.as_dict()
    if not result.reproduced:
        logger.warning(
            "corpus_promotion.not_reproducible",
            extra={"case_id": record.promotion_case_id, "lost": lost, "gained": gained},
        )
    return result


# ---------------------------------------------------------------------------------------------
# Шаг 7: повышение версии датасета
# ---------------------------------------------------------------------------------------------
def promote(
    record: ValidationMessage,
    *,
    dataset_version: str,
    current_dataset_version: str,
    promoted_by: str,
) -> ValidationMessage:
    """Отметить, что письмо вошло в корпус указанной версии.

    Версия обязана отличаться от текущей. Корпус, в который добавили кейс, не тот же корпус:
    оставить номер прежним значило бы, что два разных набора измерений называются одинаково, и
    сравнение выпусков потеряло бы смысл (ТЗ §10).

    Эта функция ничего не записывает в сам корпус — он код, и кейс появляется в нём коммитом
    человека. Здесь фиксируется след: в какую версию и чьим решением.
    """
    if record.promotion_state is not PromotionState.APPROVED:
        raise PromotionError(f"продвигать нечего: письмо в состоянии {record.promotion_state.value}")
    if not dataset_version.strip():
        raise PromotionError("версия датасета обязательна")
    if dataset_version.strip() == current_dataset_version.strip():
        raise PromotionError(
            "версия датасета должна быть повышена: корпус с новым кейсом — это другой корпус"
        )
    if not record.reproducibility_report:
        raise PromotionError("воспроизводимость не проверена")
    if not record.reproducibility_report.get("reproduced"):
        raise PromotionError(
            "вердикт не воспроизводится по обезличенной копии: кейс измерял бы последствия замен"
        )
    if not promoted_by.strip():
        raise PromotionError("продвижение без автора не записывается")

    record.promotion_state = PromotionState.PROMOTED
    record.promoted_dataset_version = dataset_version.strip()[:32]
    record.promotion_approved_by = record.promotion_approved_by or promoted_by.strip()
    logger.info(
        "corpus_promotion.promoted",
        extra={"case_id": record.promotion_case_id, "dataset_version": dataset_version},
    )
    return record


# ---------------------------------------------------------------------------------------------
# Материал для коммита
# ---------------------------------------------------------------------------------------------
def corpus_case_draft(record: ValidationMessage) -> dict[str, Any]:
    """Заготовка кейса для корпуса — то, что человек переносит в код.

    Намеренно не содержит ни текста письма, ни ключа исходного экземпляра: в корпус идёт
    обезличенная копия, и заготовка не должна быть способом достать исходную.
    """
    if record.promotion_state is not PromotionState.APPROVED:
        raise PromotionError("заготовка готовится только по согласованной заявке")
    return {
        "case_id": record.promotion_case_id,
        "source": record.source.value,
        "expected_classification": (
            record.analyst_classification.value if record.analyst_classification else None
        ),
        "production_verdict": (record.production_verdict.value if record.production_verdict else None),
        "triggered_rules": list(record.triggered_rules or []),
        "unscannable_reasons": list(record.unscannable_reasons or []),
        "anonymized_object_key": record.anonymized_object_key,
        "anonymization_report": dict(record.anonymization_report or {}),
        "reproducibility": dict(record.reproducibility_report or {}),
        "requested_by": record.promotion_requested_by,
        "approved_by": record.promotion_approved_by,
        # Человеку, который будет это коммитить: версию нужно повысить явно, и платформа её не
        # выберет за него.
        "dataset_version_required": True,
    }


def state_summary(records: list[ValidationMessage]) -> dict[str, Any]:
    """Сколько писем на каком шаге. Нужно, чтобы очередь на согласование было видно."""
    counts: dict[str, int] = {state.value: 0 for state in PromotionState}
    for record in records:
        counts[record.promotion_state.value] += 1
    not_reproducible = sum(
        1
        for record in records
        if record.reproducibility_report and not record.reproducibility_report.get("reproduced")
    )
    return {
        "by_state": counts,
        "awaiting_approval": counts[PromotionState.REQUESTED.value],
        "not_reproducible": not_reproducible,
        "promoted_versions": sorted(
            {record.promoted_dataset_version for record in records if record.promoted_dataset_version}
        ),
        # Автоматического продвижения нет ни при каких условиях (ТЗ §10).
        "automatic_promotion": False,
        "last_updated": utcnow().isoformat(),
    }
