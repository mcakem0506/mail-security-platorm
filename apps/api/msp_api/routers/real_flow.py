"""Реальный поток, готовность и подтверждение пробелов (ТЗ 1.0.4 §23, §24).

Права разделены так же, как разделены решения. Смотреть набор валидации может наблюдатель:
метрики реального потока — то, из-за чего этап вообще существует, и прятать их не от кого.
Разбирать письма — аналитик. Предлагать письмо в золотой корпус и подтверждать, что пробел
закрылся на настоящей почте, — администратор ИБ: это утверждения, по которым платформу будут
мерить годами.

Все четыре события продвижения пишутся в журнал отдельно, а не как одно «изменение записи»: по
нему потом восстанавливают, кто что решил, и «кто-то поменял состояние» на этот вопрос не
отвечает.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from msp_contracts import utcnow
from sqlalchemy import select

from ..db.models import DetectionGapRecord, ValidationMessage
from ..deps import Actor, DbSession, client_ip, require_permission
from ..observability import record_promotion_states
from ..schemas import (
    GapValidationRequest,
    PromotionDecisionRequest,
    PromotionRequestIn,
    RealFlowMessageOut,
    RealFlowReviewRequest,
)
from ..security.audit import AuditAction, record
from ..security.rbac import Permission
from ..services import corpus_promotion, gateway_readiness, real_flow

logger = logging.getLogger(__name__)
router = APIRouter(tags=["real-flow"])

RealFlowReader = Annotated[Actor, Depends(require_permission(Permission.VIEW_REAL_FLOW))]
RealFlowReviewer = Annotated[Actor, Depends(require_permission(Permission.REVIEW_REAL_FLOW))]
RealFlowPromoter = Annotated[Actor, Depends(require_permission(Permission.PROMOTE_REAL_FLOW))]
ReadinessReader = Annotated[Actor, Depends(require_permission(Permission.VIEW_READINESS))]
GapValidator = Annotated[Actor, Depends(require_permission(Permission.VALIDATE_GAP))]


def _record_or_404(session: DbSession, actor: Actor, message_id: str) -> ValidationMessage:
    found = session.get(ValidationMessage, message_id)
    if found is None or found.organization_id != actor.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "запись валидации не найдена")
    return found


def _audit(
    session: DbSession,
    actor: Actor,
    request: Request,
    *,
    action: str,
    object_id: str,
    detail: dict[str, Any],
) -> None:
    record(
        session,
        action=action,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="validation_message",
        object_id=object_id,
        detail=detail,
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )


# ---------------------------------------------------------------------------------------------
# Сводка и очереди
# ---------------------------------------------------------------------------------------------
@router.get("/detection/real-flow/summary")
def real_flow_summary(
    actor: RealFlowReader,
    session: DbSession,
    days: Annotated[int | None, Query(ge=1, le=365)] = None,
) -> dict[str, Any]:
    """Качество детектирования на реальной почте (ТЗ §12).

    Доли возвращаются как ``null``, пока нет знаменателя, и recall помечен оценкой: полной
    разметки реального потока не существует. Рядом идут нагрузка правил и состояние продвижения
    в корпус — читать одно без другого бессмысленно, потому что высокая точность при одном
    разобранном письме — это не точность.
    """
    summary = real_flow.summary(session, actor.organization_id, days=days)
    records = (
        session.execute(
            select(ValidationMessage).where(ValidationMessage.organization_id == actor.organization_id)
        )
        .scalars()
        .all()
    )
    promotion = corpus_promotion.state_summary(list(records))
    record_promotion_states(promotion["by_state"])
    return {
        **summary,
        "by_source": real_flow.count_by_source(session, actor.organization_id),
        "rule_pressure": real_flow.rule_pressure(session, actor.organization_id, days=days),
        "promotion": promotion,
    }


@router.get("/detection/real-flow/messages", response_model=list[RealFlowMessageOut])
def list_real_flow_messages(
    actor: RealFlowReader,
    session: DbSession,
    uncertain_only: bool = False,
    unreviewed_only: bool = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[RealFlowMessageOut]:
    """Письма набора валидации.

    ``uncertain_only`` — отдельная очередь, а не фильтр для удобства (ТЗ §14): письмо, которое
    не удалось проверить целиком, требует не того же, что письмо с высоким риском — по нему нет
    вердикта, который можно подтвердить или опровергнуть.
    """
    if uncertain_only:
        rows = real_flow.uncertain_queue(session, actor.organization_id, limit=limit)
        ids = [str(row["id"]) for row in rows]
        found = {
            item.id: item
            for item in session.execute(select(ValidationMessage).where(ValidationMessage.id.in_(ids)))
            .scalars()
            .all()
        }
        return [
            RealFlowMessageOut(**real_flow.as_dict(found[item_id])) for item_id in ids if item_id in found
        ]

    query = select(ValidationMessage).where(ValidationMessage.organization_id == actor.organization_id)
    if unreviewed_only:
        query = query.where(ValidationMessage.analyst_classification.is_(None))
    rows2 = session.execute(query.order_by(ValidationMessage.received_at.desc()).limit(limit)).scalars().all()
    return [RealFlowMessageOut(**real_flow.as_dict(item)) for item in rows2]


@router.get("/detection/real-flow/messages/{message_id}", response_model=RealFlowMessageOut)
def get_real_flow_message(message_id: str, actor: RealFlowReader, session: DbSession) -> RealFlowMessageOut:
    found = _record_or_404(session, actor, message_id)
    return RealFlowMessageOut(**real_flow.as_dict(found))


# ---------------------------------------------------------------------------------------------
# Разбор
# ---------------------------------------------------------------------------------------------
@router.post("/detection/real-flow/messages/{message_id}/review", response_model=RealFlowMessageOut)
def review_real_flow_message(
    message_id: str,
    payload: RealFlowReviewRequest,
    actor: RealFlowReviewer,
    session: DbSession,
    request: Request,
) -> RealFlowMessageOut:
    """Записать, что было на самом деле.

    Разбор ничего не продвигает и не меняет правила. Он фиксирует факт, а всё остальное —
    отдельные решения отдельных людей (ТЗ §10).
    """
    found = _record_or_404(session, actor, message_id)
    previous = found.analyst_classification
    try:
        real_flow.review(
            session,
            record=found,
            classification=payload.classification,
            analyst=actor.email,
            comment=payload.comment,
        )
    except real_flow.RealFlowError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    _audit(
        session,
        actor,
        request,
        action=AuditAction.REALFLOW_REVIEWED,
        object_id=found.id,
        detail={
            "from": previous.value if previous else None,
            "to": payload.classification.value,
        },
    )
    session.commit()
    return RealFlowMessageOut(**real_flow.as_dict(found))


# ---------------------------------------------------------------------------------------------
# Продвижение в корпус (ТЗ §10)
# ---------------------------------------------------------------------------------------------
@router.post("/detection/real-flow/messages/{message_id}/promote-request", response_model=RealFlowMessageOut)
def request_promotion(
    message_id: str,
    payload: PromotionRequestIn,
    actor: RealFlowPromoter,
    session: DbSession,
    request: Request,
) -> RealFlowMessageOut:
    """Предложить письмо в золотой корпус.

    Это заявка, а не продвижение. Дальше нужны согласование другим человеком, проверка
    воспроизводимости по обезличенной копии и явное повышение версии датасета — три отдельных
    действия, ни одно из которых платформа не делает сама.
    """
    found = _record_or_404(session, actor, message_id)
    try:
        corpus_promotion.request(found, analyst=actor.email, case_id=payload.case_id)
    except corpus_promotion.PromotionError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    _audit(
        session,
        actor,
        request,
        action=AuditAction.REALFLOW_PROMOTION_REQUESTED,
        object_id=found.id,
        detail={"case_id": found.promotion_case_id},
    )
    session.commit()
    return RealFlowMessageOut(**real_flow.as_dict(found))


@router.post("/detection/real-flow/messages/{message_id}/promote-decision", response_model=RealFlowMessageOut)
def decide_promotion(
    message_id: str,
    payload: PromotionDecisionRequest,
    actor: RealFlowPromoter,
    session: DbSession,
    request: Request,
) -> RealFlowMessageOut:
    """Согласовать или отклонить заявку, а при наличии всех условий — продвинуть.

    Согласующий не может быть автором заявки, и отказ требует причины. Продвижение отдельным
    решением указывает версию датасета: корпус с новым кейсом — это другой корпус, и оставить
    номер прежним значило бы, что два разных набора измерений называются одинаково.
    """
    found = _record_or_404(session, actor, message_id)
    try:
        if payload.decision == "approve":
            corpus_promotion.approve(found, approver=actor.email)
            action = AuditAction.REALFLOW_PROMOTION_APPROVED
            detail: dict[str, Any] = {"case_id": found.promotion_case_id}
        elif payload.decision == "reject":
            corpus_promotion.reject(found, approver=actor.email, reason=payload.reason)
            action = AuditAction.REALFLOW_PROMOTION_REJECTED
            detail = {"case_id": found.promotion_case_id, "reason": payload.reason}
        else:
            corpus_promotion.promote(
                found,
                dataset_version=payload.dataset_version,
                current_dataset_version=payload.current_dataset_version,
                promoted_by=actor.email,
            )
            action = AuditAction.REALFLOW_PROMOTED
            detail = {
                "case_id": found.promotion_case_id,
                "dataset_version": found.promoted_dataset_version,
            }
    except corpus_promotion.PromotionError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    _audit(session, actor, request, action=action, object_id=found.id, detail=detail)
    session.commit()
    return RealFlowMessageOut(**real_flow.as_dict(found))


# ---------------------------------------------------------------------------------------------
# Подтверждение пробела реальным потоком (ТЗ §23)
# ---------------------------------------------------------------------------------------------
@router.post("/detection/gaps/{gap_id}/validation")
def validate_gap(
    gap_id: str,
    payload: GapValidationRequest,
    actor: GapValidator,
    session: DbSession,
    request: Request,
) -> dict[str, Any]:
    """Подтвердить, что пробел закрылся на настоящей почте.

    Отдельно от статуса в реестре. ``VALIDATION`` там означает согласие золотого корпуса, а
    корпус содержит ровно те случаи, которые мы придумали. Подтверждение требует свидетельства:
    писем реального потока, на которых это видно. Без них «проверено» было бы словом.
    """
    gap = session.execute(
        select(DetectionGapRecord).where(
            DetectionGapRecord.organization_id == actor.organization_id,
            DetectionGapRecord.gap_id == gap_id,
        )
    ).scalar_one_or_none()
    if gap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "пробел не найден")

    evidence = (
        session.execute(
            select(ValidationMessage).where(
                ValidationMessage.organization_id == actor.organization_id,
                ValidationMessage.id.in_(payload.validation_message_ids),
            )
        )
        .scalars()
        .all()
    )
    if len(evidence) != len(set(payload.validation_message_ids)):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "не все указанные письма найдены в наборе валидации этой организации",
        )
    unreviewed = [item.id for item in evidence if item.analyst_classification is None]
    if unreviewed:
        # Неразобранное письмо ничего не подтверждает: по нему неизвестно, что было на самом деле.
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"письма не разобраны аналитиком и свидетельством быть не могут: {', '.join(unreviewed)}",
        )

    gap.real_flow_validated_at = utcnow()
    gap.real_flow_validated_by = actor.email
    gap.real_flow_evidence = {
        "message_count": len(evidence),
        "message_ids": [item.id for item in evidence],
        "classifications": sorted(
            {
                item.analyst_classification.value
                for item in evidence
                if item.analyst_classification is not None
            }
        ),
        "comment": payload.comment,
    }
    record(
        session,
        action=AuditAction.GAP_VALIDATED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="detection_gap",
        object_id=gap_id,
        detail={"message_count": len(evidence), "status": gap.status.value},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return {
        "gap_id": gap.gap_id,
        "status": gap.status.value,
        "real_flow_validated_at": gap.real_flow_validated_at.isoformat(),
        "real_flow_validated_by": gap.real_flow_validated_by,
        "real_flow_evidence": gap.real_flow_evidence,
    }


# ---------------------------------------------------------------------------------------------
# Готовность к inline-шлюзу (ТЗ §18-§21, §23)
# ---------------------------------------------------------------------------------------------
@router.get("/detection/readiness")
def gateway_readiness_state(actor: ReadinessReader, session: DbSession) -> dict[str, Any]:
    """Можно ли ставить платформу в разрыв почтового потока.

    Решение одно из трёх, а не число: до сих пор платформа смотрела на копию письма, и ошибка
    стоила ложного срабатывания в консоли аналитика. В разрыве потока ошибка стоит
    недоставленного письма, и ответ «вроде бы готовы» перестаёт быть ответом.

    Пороги общие со скриптом scripts/gateway_readiness.py: расхождение между «конвейер
    сказал готово» и «консоль показывает не готово» хуже любого из двух ответов.
    """
    summary = real_flow.summary(session, actor.organization_id)
    summary["rule_pressure"] = real_flow.rule_pressure(session, actor.organization_id)

    gaps = [
        {
            "gap_id": row.gap_id,
            "severity": row.severity.value,
            "status": row.status.value,
            "real_flow_validated_at": (
                row.real_flow_validated_at.isoformat() if row.real_flow_validated_at else None
            ),
        }
        for row in session.execute(
            select(DetectionGapRecord).where(DetectionGapRecord.organization_id == actor.organization_id)
        )
        .scalars()
        .all()
    ]

    readiness = gateway_readiness.Readiness()
    readiness.extend(gateway_readiness.real_flow_checks(summary))
    # Пустой реестр — это не «пробелов нет», а «реестр не заполнен»: пробелы заводятся вручную,
    # и организация без ни одного пробела просто ещё не начинала их заводить.
    readiness.extend(gateway_readiness.gap_checks(gaps or None))
    return readiness.as_dict()
