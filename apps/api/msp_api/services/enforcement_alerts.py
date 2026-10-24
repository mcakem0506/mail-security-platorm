"""Тревоги принуждения (MSP 1.3, ТЗ 1.3 §65).

Тревога вычисляется из состояния, а не хранится. Принцип тот же, что у транспорта: молчание узла — тревога, а не «всё хорошо»;
но принуждение остаётся необязательным для транспорта, поэтому узел, который о нём не сообщал вовсе, тревог не получает.
"""

from __future__ import annotations

from datetime import timedelta

from msp_enforcement.model import ACTIVE_STATES, ControlState, ControlType
from msp_enforcement.readiness import blocking_gaps
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.base import utcnow
from ..db.models_enforcement import (
    EmergencyIncidentRecord,
    EnforcementControlRecord,
    EnforcementDecisionRecord,
    IncidentState,
)
from ..db.models_transport import TransportNode
from . import enforcement
from .transport_alerts import CRITICAL, WARNING, Alert

REJECT_SPIKE = 50
TEMPFAIL_SPIKE = 100
QUARANTINE_SPIKE = 100
TIMEOUT_SPIKE = 20


def compute(session: Session, organization_id: str, settings: Settings) -> list[Alert]:
    controls = (
        session.execute(
            select(EnforcementControlRecord).where(
                EnforcementControlRecord.organization_id == organization_id
            )
        )
        .scalars()
        .all()
    )
    if not controls:
        return []
    alerts: list[Alert] = []
    gaps = enforcement.gap_statuses(session, organization_id)

    switch = enforcement.switch_row(session, organization_id)
    if switch.kill_switch:
        alerts.append(
            Alert(
                "KILL_SWITCH_ACTIVE",
                CRITICAL,
                "Общий выключатель принуждения включён",
                f"Включил {switch.activated_by or '—'}: все контроли действуют как наблюдение. Снять должен второй человек.",
            )
        )

    for control in controls:
        state = ControlState(control.state)
        if state in ACTIVE_STATES and blocking_gaps(ControlType(control.control_type), gaps):
            alerts.append(
                Alert(
                    "CONTROL_ACTIVE_WHILE_GAP_BLOCKED",
                    CRITICAL,
                    f"Контроль {control.control_type} включён, но заблокирован известным пробелом",
                    "Узел решений не применяет (проверка по снимку пробелов), но состояние в панели недопустимо: приостановите контроль.",
                )
            )

    current = enforcement.current_policy(session, organization_id)
    for node in session.execute(
        select(TransportNode).where(TransportNode.organization_id == organization_id)
    ).scalars():
        ident = {"node_id": node.node_id, "node_name": node.name}
        reported = (node.details or {}).get("enforcement") or {}
        if reported:
            if reported.get("local_bypass"):
                alerts.append(
                    Alert(
                        "LOCAL_BYPASS_ACTIVE",
                        CRITICAL,
                        "На узле включён локальный обход принуждения",
                        "Решения принуждения на этом узле не применяются.",
                        **ident,
                    )
                )
            if current is not None and reported.get("policy_checksum") != current.checksum:
                alerts.append(
                    Alert(
                        "POLICY_DRIFT",
                        WARNING,
                        "Узел применяет не текущую политику принуждения",
                        f"Ожидается {current.version}, узел сообщает {reported.get('policy_version') or '—'}.",
                        **ident,
                    )
                )
            if reported.get("policy_status") in ("STALE", "SAFE_MODE", "INVALID"):
                level = CRITICAL if reported.get("policy_status") != "STALE" else WARNING
                alerts.append(
                    Alert(
                        "POLICY_STALE",
                        level,
                        "Политика принуждения на узле устарела",
                        f"Состояние политики: {reported.get('policy_status')}. В безопасном режиме принуждение не действует.",
                        **ident,
                    )
                )
        rspamd = (node.details or {}).get("rspamd") or {}
        actions = rspamd.get("effective_actions") or {}
        if actions.get("clean") is False:
            alerts.append(
                Alert(
                    "HIDDEN_RSPAMD_ACTION",
                    CRITICAL,
                    "Найден неизвестный источник действий сканера",
                    f"Источников без допуска: {actions.get('unknown', '?')}. Выпуск конфигурации сканера заблокирован.",
                    **ident,
                )
            )

    for incident in session.execute(
        select(EmergencyIncidentRecord).where(
            EmergencyIncidentRecord.organization_id == organization_id,
            EmergencyIncidentRecord.state != IncidentState.CLOSED,
        )
    ).scalars():
        alerts.append(
            Alert(
                "CRITICAL_FALSE_POSITIVE",
                CRITICAL,
                f"Открыт инцидент ложного срабатывания: {incident.control_type}",
                f"{incident.title}. Контроль не включается снова, пока инцидент не закрыт.",
            )
        )

    since = utcnow() - timedelta(minutes=15)
    counts = dict(
        session.execute(
            select(EnforcementDecisionRecord.applied_action, func.count())
            .where(
                EnforcementDecisionRecord.organization_id == organization_id,
                EnforcementDecisionRecord.decided_at >= since,
            )
            .group_by(EnforcementDecisionRecord.applied_action)
        ).all()
    )
    if counts.get("SMTP_REJECT", 0) > REJECT_SPIKE:
        alerts.append(
            Alert("REJECT_SPIKE", CRITICAL, "Всплеск отказов SMTP", f"За 15 минут: {counts['SMTP_REJECT']}.")
        )
    if counts.get("SMTP_TEMPFAIL", 0) > TEMPFAIL_SPIKE:
        alerts.append(
            Alert(
                "TEMPFAIL_SPIKE",
                WARNING,
                "Всплеск временных отказов",
                f"За 15 минут: {counts['SMTP_TEMPFAIL']}.",
            )
        )
    if counts.get("QUARANTINED", 0) > QUARANTINE_SPIKE:
        alerts.append(
            Alert(
                "QUARANTINE_SPIKE",
                WARNING,
                "Всплеск писем в карантине",
                f"За 15 минут: {counts['QUARANTINED']}.",
            )
        )
    timeouts = session.execute(
        select(func.count())
        .select_from(EnforcementDecisionRecord)
        .where(
            EnforcementDecisionRecord.organization_id == organization_id,
            EnforcementDecisionRecord.decided_at >= since,
            EnforcementDecisionRecord.fail_mode_applied != "",
        )
    ).scalar_one()
    if timeouts > TIMEOUT_SPIKE:
        alerts.append(
            Alert(
                "DECISION_TIMEOUT",
                WARNING,
                "Решения принуждения упираются в тайм-аут",
                f"За 15 минут: {timeouts}. Применён режим сбоя: письма идут дальше.",
            )
        )
    return alerts
