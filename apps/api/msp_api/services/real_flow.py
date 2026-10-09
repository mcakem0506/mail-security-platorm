"""Валидация на реальном потоке (ТЗ 1.0.4 §8, §11–§14).

Этап 1.0.4 отвечает на вопрос, на который синтетический корпус ответить не может: **как
детектирование ведёт себя на настоящей почте**. Отсюда все решения этого модуля.

Режим ``REAL_FLOW_SHADOW`` (§11) — не «пониженная функциональность», а осознанное состояние
пилота: платформа смотрит на настоящую почту и ничего с ней не делает. Вердикты считаются и
сохраняются, ящик пользователя не меняется, реагирование выключено, уведомления сотрудникам не
уходят. Обратная связь аналитиков и метрики, наоборот, включены — ради них режим и существует.

Метрики (§12) устроены по правилу, общему для всей платформы: доля, у которой нет знаменателя,
возвращается как ``None``, а не как ноль. Для recall этого недостаточно, и поэтому он
называется оценкой: на реальном потоке полной разметки нет, и честный ответ — «не ниже
такого-то», а не число.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from msp_contracts import (
    CONFIRMED_BENIGN,
    CONFIRMED_THREAT,
    CONFIRMED_UNWANTED,
    AnalystClassification,
    PiiStatus,
    PromotionState,
    RiskLevel,
    RuleNoiseVerdict,
    ValidationSource,
    utcnow,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db.models import RealFlowRuleReview, ValidationMessage
from ..observability import (
    realflow_raw_retention_overdue,
    realflow_reviewed_total,
    record_realflow_ingest,
    record_realflow_summary,
    record_rule_pressure,
)

logger = logging.getLogger(__name__)

#: Вердикты, которые аналитик обязан разобрать (ТЗ §21): по ним решение платформы дороже всего.
MUST_REVIEW_VERDICTS: frozenset[RiskLevel] = frozenset({RiskLevel.HIGH_RISK, RiskLevel.MALICIOUS})

#: Доля легитимной почты, попадающая в выборку случайно (ТЗ §14). Нужна, чтобы ложные
#: срабатывания находились не только там, где их уже заметили.
DEFAULT_LEGITIMATE_SAMPLE_RATE = 0.02

#: Целевой объём выборки до перехода к MSP 1.1 (ТЗ §21).
TARGET_ANALYZED = 500
TARGET_REVIEWED = 100


class RealFlowError(RuntimeError):
    """Отказ с причиной."""


# ---------------------------------------------------------------------------------------------
# Причины попадания в выборку (ТЗ §14)
# ---------------------------------------------------------------------------------------------
HIGH_RISK = "HIGH_RISK"
MALICIOUS = "MALICIOUS"
EMPLOYEE_REPORT = "EMPLOYEE_REPORT"
GATEWAY_CONFLICT = "GATEWAY_CONFLICT"
QR_CODE = "QR_CODE"
CANDIDATE_RULE_MATCH = "CANDIDATE_RULE_MATCH"
RANDOM_LEGITIMATE = "RANDOM_LEGITIMATE"
UNCERTAIN = "UNCERTAIN"

#: Состояния, из-за которых письмо попадает в очередь неопределённых (ТЗ §14).
UNCERTAIN_VERDICTS: frozenset[RiskLevel] = frozenset({RiskLevel.UNKNOWN})


def sampling_reasons(
    *,
    verdict: RiskLevel | None,
    reported_by_employee: bool = False,
    gateway_conflict: bool = False,
    has_qr_code: bool = False,
    candidate_rule_matched: bool = False,
    unscannable: bool = False,
    random_draw: float | None = None,
    legitimate_sample_rate: float = DEFAULT_LEGITIMATE_SAMPLE_RATE,
) -> list[str]:
    """Почему письмо стоит взять в набор валидации.

    Причины перечисляются, а не сводятся к одной: письмо, попавшее и как высокий риск, и как
    обращение сотрудника, — это другое письмо, чем просто высокий риск, и при чтении метрик это
    различие нужно.

    Случайная доля легитимной почты существует не для полноты, а против слепого пятна: ложные
    срабатывания, которых никто не заметил, иначе не попадут в набор никогда.
    """
    reasons: list[str] = []
    if verdict is RiskLevel.MALICIOUS:
        reasons.append(MALICIOUS)
    elif verdict is RiskLevel.HIGH_RISK:
        reasons.append(HIGH_RISK)
    if reported_by_employee:
        reasons.append(EMPLOYEE_REPORT)
    if gateway_conflict:
        reasons.append(GATEWAY_CONFLICT)
    if has_qr_code:
        reasons.append(QR_CODE)
    if candidate_rule_matched:
        reasons.append(CANDIDATE_RULE_MATCH)
    if unscannable or verdict in UNCERTAIN_VERDICTS:
        reasons.append(UNCERTAIN)
    if not reasons and random_draw is not None and random_draw < legitimate_sample_rate:
        reasons.append(RANDOM_LEGITIMATE)
    return reasons


# ---------------------------------------------------------------------------------------------
# Приём
# ---------------------------------------------------------------------------------------------
@dataclass
class IngestRequest:
    organization_id: str
    source: ValidationSource
    message_fingerprint: str
    received_at: datetime | None = None
    message_id: str | None = None
    production_verdict: RiskLevel | None = None
    expected_classification: RiskLevel | None = None
    ruleset_version: str = ""
    parser_version: str = ""
    risk_engine_version: str = ""
    triggered_rules: list[str] = field(default_factory=list)
    sampling_reasons: list[str] = field(default_factory=list)
    unscannable_reasons: list[str] = field(default_factory=list)
    anonymized: bool = False
    anonymization_report: dict[str, Any] = field(default_factory=dict)
    raw_retention_days: int | None = None


def ingest(session: Session, request: IngestRequest) -> tuple[ValidationMessage, bool]:
    """Взять письмо в набор валидации.

    Возвращает ``(запись, создана ли она)``. Повторный приём того же письма — обычное дело:
    одно и то же письмо приходит и копией из журнала, и пересланным сотрудником. Отпечаток
    устойчив к обезличиванию, поэтому дубликат узнаётся, и у записи только обновляются причины
    попадания в выборку, а не создаётся вторая.
    """
    if not request.message_fingerprint:
        raise RealFlowError("отпечаток обязателен: без него письмо попадёт в набор дважды")

    existing = session.execute(
        select(ValidationMessage).where(
            ValidationMessage.organization_id == request.organization_id,
            ValidationMessage.message_fingerprint == request.message_fingerprint,
        )
    ).scalar_one_or_none()
    if existing is not None:
        merged = list(dict.fromkeys([*existing.sampling_reasons, *request.sampling_reasons]))
        existing.sampling_reasons = merged
        if existing.message_id is None and request.message_id:
            existing.message_id = request.message_id
        record_realflow_ingest(request.source.value, request.sampling_reasons, created=False)
        return existing, False

    retention_days = request.raw_retention_days
    record = ValidationMessage(
        organization_id=request.organization_id,
        message_id=request.message_id,
        source=request.source,
        received_at=request.received_at or utcnow(),
        message_fingerprint=request.message_fingerprint,
        anonymized=request.anonymized,
        pii_status=PiiStatus.ANONYMIZED if request.anonymized else PiiStatus.RAW,
        anonymization_report=dict(request.anonymization_report),
        expected_classification=request.expected_classification,
        production_verdict=request.production_verdict,
        ruleset_version=request.ruleset_version,
        parser_version=request.parser_version,
        risk_engine_version=request.risk_engine_version,
        triggered_rules=list(request.triggered_rules),
        sampling_reasons=list(request.sampling_reasons),
        unscannable_reasons=list(request.unscannable_reasons),
        raw_retained_until=(utcnow() + timedelta(days=retention_days) if retention_days else None),
    )
    session.add(record)
    record_realflow_ingest(request.source.value, request.sampling_reasons, created=True)
    logger.info(
        "real_flow.ingested",
        extra={"source": request.source.value, "reasons": request.sampling_reasons},
    )
    return record, True


def review(
    session: Session,
    *,
    record: ValidationMessage,
    classification: AnalystClassification,
    analyst: str,
    comment: str = "",
    gap_id: str = "",
) -> ValidationMessage:
    """Записать разбор аналитика.

    Разбор не продвигает письмо в золотой корпус и не меняет правила: он только фиксирует, что
    было на самом деле. Всё остальное — отдельные решения отдельных людей (ТЗ §10).

    ``gap_id`` указывается, когда разбор означает пропуск: аналитик говорит, в какой известный
    пробел письмо попадает. Пропуск без пробела гейт готовности блокирует (ТЗ §21), и это не
    формальность — пропуск без зарегистрированного пробела и есть незарегистрированный пробел.
    """
    if not analyst.strip():
        raise RealFlowError("разбор без автора не записывается")
    record.analyst_classification = classification
    record.reviewed_by = analyst.strip()
    record.reviewed_at = utcnow()
    record.review_comment = comment.strip()[:2000]
    if gap_id.strip():
        record.gap_id = gap_id.strip()[:32]
    realflow_reviewed_total.labels(classification=classification.value).inc()
    return record


# ---------------------------------------------------------------------------------------------
# Метрики (ТЗ §12)
# ---------------------------------------------------------------------------------------------
#: Разборы, подтверждающие, что платформа была права, отметив письмо.
#:
#: Спам входит сюда и **не** входит в подтверждённые угрозы: отметить спам — не ошибка, но и не
#: обнаруженная атака. Это разделение принято в 1.0.3 §22, и здесь оно только используется.
_PLATFORM_WAS_RIGHT = CONFIRMED_THREAT | CONFIRMED_UNWANTED
#: Разборы, говорящие, что отмечать письмо было не за что.
_PLATFORM_WAS_WRONG = CONFIRMED_BENIGN


def summary(session: Session, organization_id: str, *, days: int | None = None) -> dict[str, Any]:
    """Сводка по реальному потоку.

    Все доли — ``None``, пока нет знаменателя. Recall назван оценкой и считается только по
    разобранным письмам: на реальном потоке полной разметки не существует, и число, посчитанное
    как будто она есть, было бы вымыслом с точностью до третьего знака.
    """
    filters = [ValidationMessage.organization_id == organization_id]
    if days:
        filters.append(ValidationMessage.received_at >= utcnow() - timedelta(days=days))

    rows = session.execute(select(ValidationMessage).where(*filters)).scalars().all()
    total = len(rows)
    reviewed = [row for row in rows if row.analyst_classification is not None]

    true_positive = sum(1 for row in reviewed if row.analyst_classification in _PLATFORM_WAS_RIGHT)
    false_positive = sum(1 for row in reviewed if row.analyst_classification in _PLATFORM_WAS_WRONG)
    # Промах: аналитик подтвердил, что письмо стоило отметить, а платформа этого не сделала.
    #
    # ``UNKNOWN`` промахом не считается, и это осознанно. «Не смогли проверить» — не «сочли
    # безопасным»: это пробел, он попадает в ``unscannable`` и в очередь неопределённых, где его
    # видно как пробел. Записать его в промахи значило бы смешать два разных отказа платформы, а
    # записать в успехи — счесть отсутствие детекта безопасностью, чего делать нельзя.
    _MISSED = (RiskLevel.LOW_RISK, None)
    false_negative = sum(
        1
        for row in reviewed
        if row.analyst_classification in _PLATFORM_WAS_RIGHT and row.production_verdict in _MISSED
    )
    # «Не разобрались» — это не «верно» и не «неверно», и в доли оно не идёт ни той, ни другой
    # стороной. Отдельное число нужно, чтобы эта часть выборки была видна, а не растворилась.
    unknown = sum(1 for row in reviewed if row.analyst_classification is AnalystClassification.UNKNOWN)
    unscannable = sum(1 for row in rows if row.unscannable_reasons)

    # Пропуски без указанного пробела (ТЗ §21). Список, а не число: чтобы их задокументировать,
    # надо знать, какие именно.
    undocumented_false_negatives = sorted(
        row.id
        for row in reviewed
        if row.analyst_classification in _PLATFORM_WAS_RIGHT
        and row.production_verdict in _MISSED
        and not (row.gap_id or "").strip()
    )

    judged = true_positive + false_positive
    verdict_distribution: dict[str, int] = {}
    for row in rows:
        key = row.production_verdict.value if row.production_verdict else "NOT_ANALYSED"
        verdict_distribution[key] = verdict_distribution.get(key, 0) + 1

    result = {
        "messages_total": total,
        "reviewed_total": len(reviewed),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "unknown": unknown,
        "unscannable": unscannable,
        "verdict_distribution": verdict_distribution,
        "undocumented_false_negatives": undocumented_false_negatives,
        "reviewed_noisy_rules": sorted(reviewed_noisy_rules(session, organization_id)),
        # Доли без знаменателя — null. Ноль читался бы как «нет ложных срабатываний».
        "precision": (true_positive / judged) if judged else None,
        # Оценка, а не измерение: знаменатель — только разобранные письма.
        "recall_estimate": (
            true_positive / (true_positive + false_negative) if (true_positive + false_negative) else None
        ),
        "recall_is_estimate": True,
        "ground_truth_complete": False,
        "sample": {
            "analyzed": total,
            "analyzed_target": TARGET_ANALYZED,
            "reviewed": len(reviewed),
            "reviewed_target": TARGET_REVIEWED,
            "high_risk_unreviewed": sum(
                1
                for row in rows
                if row.production_verdict in MUST_REVIEW_VERDICTS and row.analyst_classification is None
            ),
        },
    }
    # Доли в метрики не идут: ``precision`` может быть ``None``, а Prometheus не умеет «нет
    # данных» — отсутствующее значение читается как ноль. Наружу идут числители, по которым
    # видно, есть ли знаменатель вообще.
    record_realflow_summary(result)
    return result


def rule_pressure(session: Session, organization_id: str, *, days: int | None = None) -> list[dict[str, Any]]:
    """Нагрузка правил на реальном потоке (ТЗ §12).

    Считается на тысячу писем, а не в штуках: абсолютное число срабатываний растёт вместе с
    объёмом почты и ничего не говорит о правиле. Отдельно считается число затронутых отправителей
    и доменов — правило, сработавшее сто раз на одном отправителе, и правило, сработавшее сто раз
    на ста разных, требуют разного.

    ``PRODUCTION_NOISY`` здесь не выставляется автоматически как состояние правила: это вывод,
    который делает человек, глядя на эти числа (ТЗ §12).
    """
    filters = [ValidationMessage.organization_id == organization_id]
    if days:
        filters.append(ValidationMessage.received_at >= utcnow() - timedelta(days=days))
    rows = session.execute(select(ValidationMessage).where(*filters)).scalars().all()
    total = len(rows)
    if not total:
        return []

    per_rule: dict[str, dict[str, Any]] = {}
    for row in rows:
        wrong = row.analyst_classification is AnalystClassification.FALSE_POSITIVE
        for rule_id in row.triggered_rules or []:
            entry = per_rule.setdefault(
                str(rule_id),
                {"rule_id": str(rule_id), "triggers": 0, "false_positives": 0, "fingerprints": set()},
            )
            entry["triggers"] += 1
            entry["fingerprints"].add(row.message_fingerprint)
            if wrong:
                entry["false_positives"] += 1

    out: list[dict[str, Any]] = []
    for entry in per_rule.values():
        triggers = entry["triggers"]
        out.append(
            {
                "rule_id": entry["rule_id"],
                "triggers": triggers,
                "triggers_per_1000_messages": round(triggers * 1000 / total, 2),
                "false_positives": entry["false_positives"],
                "fp_per_1000_messages": round(entry["false_positives"] * 1000 / total, 2),
                "distinct_messages": len(entry["fingerprints"]),
            }
        )
    out.sort(key=lambda item: item["triggers_per_1000_messages"], reverse=True)
    record_rule_pressure(out)
    return out


def review_rule_noise(
    session: Session,
    *,
    organization_id: str,
    rule_id: str,
    verdict: RuleNoiseVerdict,
    analyst: str,
    note: str = "",
    pressure: dict[str, Any] | None = None,
) -> RealFlowRuleReview:
    """Записать вывод человека о правиле, шумящем на реальном потоке (ТЗ §12, §20).

    Здесь и только здесь правило получает ``PRODUCTION_NOISY``. Платформа это состояние не
    выставляет: правило, впервые столкнувшееся с новой кампанией, по числам выглядит точно так
    же, как правило с дефектом, и автоматика выключила бы первое в самый неподходящий момент.

    Присвоение состояния правило **не отключает**. Отключение — отдельное изменение, проходящее
    ревью (1.0.3B §8); вывод о шуме только фиксирует, что человек посмотрел и что увидел.

    Числа на момент вывода сохраняются рядом: без них через полгода нельзя понять, относился ли
    вывод к тому же поведению правила, которое наблюдается сейчас.
    """
    if not analyst.strip():
        raise RealFlowError("вывод без автора не записывается")
    if not rule_id.strip():
        raise RealFlowError("вывод без правила не записывается")
    if verdict is RuleNoiseVerdict.PRODUCTION_NOISY and not note.strip():
        # Состояние, которое останется у правила надолго, требует объяснения: иначе через
        # полгода «шумит» будет единственным, что известно, и перепроверить будет нечего.
        raise RealFlowError("вывод PRODUCTION_NOISY требует пояснения")

    existing = session.execute(
        select(RealFlowRuleReview).where(
            RealFlowRuleReview.organization_id == organization_id,
            RealFlowRuleReview.rule_id == rule_id.strip(),
        )
    ).scalar_one_or_none()

    numbers = pressure or {}
    if existing is not None:
        existing.verdict = verdict
        existing.reviewed_by = analyst.strip()
        existing.reviewed_at = utcnow()
        existing.note = note.strip()[:2000]
        existing.triggers_per_1000 = numbers.get("triggers_per_1000_messages")
        existing.fp_per_1000 = numbers.get("fp_per_1000_messages")
        existing.distinct_messages = int(numbers.get("distinct_messages") or 0)
        return existing

    record = RealFlowRuleReview(
        organization_id=organization_id,
        rule_id=rule_id.strip()[:32],
        verdict=verdict,
        reviewed_by=analyst.strip(),
        note=note.strip()[:2000],
        triggers_per_1000=numbers.get("triggers_per_1000_messages"),
        fp_per_1000=numbers.get("fp_per_1000_messages"),
        distinct_messages=int(numbers.get("distinct_messages") or 0),
    )
    session.add(record)
    logger.info(
        "real_flow.rule_noise_reviewed",
        extra={"rule_id": record.rule_id, "verdict": verdict.value},
    )
    return record


def reviewed_noisy_rules(session: Session, organization_id: str) -> set[str]:
    """Правила, по которым вывод уже сделан — с любым исходом.

    Гейт спрашивает «разобрано ли», а не «признано ли шумным»: условие §20 — про то, что человек
    посмотрел, а не про то, что он решил.
    """
    rows = (
        session.execute(
            select(RealFlowRuleReview.rule_id).where(RealFlowRuleReview.organization_id == organization_id)
        )
        .scalars()
        .all()
    )
    return {str(row) for row in rows}


def rule_noise_reviews(session: Session, organization_id: str) -> list[dict[str, Any]]:
    rows = (
        session.execute(
            select(RealFlowRuleReview)
            .where(RealFlowRuleReview.organization_id == organization_id)
            .order_by(RealFlowRuleReview.rule_id)
        )
        .scalars()
        .all()
    )
    return [
        {
            "rule_id": row.rule_id,
            "verdict": row.verdict.value,
            "reviewed_by": row.reviewed_by,
            "reviewed_at": row.reviewed_at.isoformat(),
            "note": row.note,
            "triggers_per_1000": row.triggers_per_1000,
            "fp_per_1000": row.fp_per_1000,
            "distinct_messages": row.distinct_messages,
        }
        for row in rows
    ]


def uncertain_queue(session: Session, organization_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
    """Очередь неопределённых писем (ТЗ §14).

    Отдельная от обычной очереди намеренно. Письмо, которое не удалось проверить целиком, требует
    не того же, что письмо с высоким риском: по нему нет вердикта, который можно подтвердить или
    опровергнуть, — есть пробел, и решение принимается по контексту отправителя.
    """
    rows = (
        session.execute(
            select(ValidationMessage)
            .where(
                ValidationMessage.organization_id == organization_id,
                ValidationMessage.analyst_classification.is_(None),
            )
            .order_by(ValidationMessage.received_at.desc())
            .limit(limit * 4)
        )
        .scalars()
        .all()
    )
    out: list[dict[str, Any]] = []
    for row in rows:
        if not (row.unscannable_reasons or row.production_verdict in UNCERTAIN_VERDICTS):
            continue
        out.append(
            {
                "id": row.id,
                "received_at": row.received_at.isoformat(),
                "source": row.source.value,
                "production_verdict": (row.production_verdict.value if row.production_verdict else None),
                "unscannable_reasons": list(row.unscannable_reasons or []),
                "sampling_reasons": list(row.sampling_reasons or []),
            }
        )
        if len(out) >= limit:
            break
    return out


def as_dict(record: ValidationMessage) -> dict[str, Any]:
    return {
        "id": record.id,
        "source": record.source.value,
        "received_at": record.received_at.isoformat(),
        "message_fingerprint": record.message_fingerprint,
        "anonymized": record.anonymized,
        "pii_status": record.pii_status.value,
        "anonymization_report": dict(record.anonymization_report or {}),
        "expected_classification": (
            record.expected_classification.value if record.expected_classification else None
        ),
        "analyst_classification": (
            record.analyst_classification.value if record.analyst_classification else None
        ),
        "reviewed_by": record.reviewed_by,
        "reviewed_at": record.reviewed_at.isoformat() if record.reviewed_at else None,
        "production_verdict": (record.production_verdict.value if record.production_verdict else None),
        "validation_verdict": (record.validation_verdict.value if record.validation_verdict else None),
        "ruleset_version": record.ruleset_version,
        "parser_version": record.parser_version,
        "risk_engine_version": record.risk_engine_version,
        "triggered_rules": list(record.triggered_rules or []),
        "sampling_reasons": list(record.sampling_reasons or []),
        "unscannable_reasons": list(record.unscannable_reasons or []),
        "gap_id": record.gap_id,
        "promotion_state": record.promotion_state.value,
        "promotion_requested_by": record.promotion_requested_by,
        "promotion_approved_by": record.promotion_approved_by,
        "promotion_case_id": record.promotion_case_id,
        "promoted_dataset_version": record.promoted_dataset_version,
        "reproducibility_report": dict(record.reproducibility_report or {}),
        "raw_retained_until": (record.raw_retained_until.isoformat() if record.raw_retained_until else None),
    }


def expired_raw_records(session: Session, organization_id: str) -> list[ValidationMessage]:
    """Записи, у которых истёк срок хранения исходных данных (ТЗ §22).

    Обезличенные метрики живут дольше: они нужны для сравнения выпусков, а тела писем — нет.
    """
    now = utcnow()
    overdue = list(
        session.execute(
            select(ValidationMessage).where(
                ValidationMessage.organization_id == organization_id,
                ValidationMessage.raw_retained_until.is_not(None),
                ValidationMessage.raw_retained_until < now,
                ValidationMessage.pii_status == PiiStatus.RAW,
            )
        )
        .scalars()
        .all()
    )
    # Метрика ставится при каждом подсчёте, в том числе когда просроченных нет: иначе ноль
    # нечем было бы отличить от того, что проверку перестали запускать.
    realflow_raw_retention_overdue.set(len(overdue))
    return overdue


def promotion_candidates(session: Session, organization_id: str) -> list[ValidationMessage]:
    """Письма, которые **можно предложить** в золотой корпус (ТЗ §10).

    «Можно предложить» — это не «продвинуть». Условия здесь только необходимые: письмо разобрано
    аналитиком, обезличено и проверено человеком. Достаточными их делают согласование, проверка
    воспроизводимости и явное повышение версии датасета, и каждое из них — отдельное действие
    отдельного человека.
    """
    return list(
        session.execute(
            select(ValidationMessage).where(
                ValidationMessage.organization_id == organization_id,
                ValidationMessage.analyst_classification.is_not(None),
                ValidationMessage.anonymized.is_(True),
                ValidationMessage.pii_status == PiiStatus.REVIEWED,
                ValidationMessage.promotion_state.in_(
                    [PromotionState.NOT_REQUESTED, PromotionState.REQUESTED]
                ),
            )
        )
        .scalars()
        .all()
    )


def count_by_source(session: Session, organization_id: str) -> dict[str, int]:
    rows = session.execute(
        select(ValidationMessage.source, func.count(ValidationMessage.id))
        .where(ValidationMessage.organization_id == organization_id)
        .group_by(ValidationMessage.source)
    ).all()
    return {source.value: int(count) for source, count in rows}
