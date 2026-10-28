"""Пилот реального потока (MSP 1.3P, ТЗ 1.3P §4, §21, §24).

Три таблицы и ни одной копии существующих механизмов: выборка, разметка, безопасность отказов и готовность
контролей
берутся из ``validation_messages``, ``enforcement_decisions`` и ``enforcement_controls``. Здесь хранится
только то,
чего там быть не может:

* **подтверждения** (``pilot_attestations``) — что оператор проверил вне платформы (резервная копия ключа,
  отказ узла,
  согласование маршрута) и на какой документ ссылается. Запись только добавляется: прошлое подтверждение не
  правится;
* **решения о фазах** (``pilot_phase_decisions``) — подписанные GO / NO-GO. Решение вступает в силу, когда
  его подтвердили
  люди нужных ролей, каждый под своей учётной записью;
* **остановки** (``pilot_stops``) — запись об аварийной остановке; пока она открыта, ни одна фаза не
  получает GO.

Таблицы не включают и не выключают ни один контроль и ничего не меняют в почтовом потоке.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdMixin, TimestampMixin, UTCDateTime, utcnow


class PilotPhase(StrEnum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    P5 = "P5"


class PilotDecisionOutcome(StrEnum):
    GO = "GO"
    NO_GO = "NO_GO"


class PilotDecisionState(StrEnum):
    #: Предложено, ждёт подтверждений людей нужных ролей.
    PROPOSED = "PROPOSED"
    #: Подтверждения собраны, решение действует.
    EFFECTIVE = "EFFECTIVE"
    #: Закрыто остановкой или новым решением; на гейт больше не влияет.
    SUPERSEDED = "SUPERSEDED"


class PilotAttestationRecord(Base, IdMixin, TimestampMixin):
    __tablename__ = "pilot_attestations"
    __table_args__ = (Index("ix_pilot_attestation_key", "organization_id", "attestation_key", "recorded_at"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    attestation_key: Mapped[str] = mapped_column(String(64))
    #: PASS | FAIL | NOT_TESTED | BLOCKED_EXTERNAL
    status: Mapped[str] = mapped_column(String(20))
    #: Ссылка на документ в эксплуатационном хранилище. Содержимое документа в базу не попадает.
    evidence_ref: Mapped[str] = mapped_column(String(500), default="")
    note: Mapped[str] = mapped_column(String(1000), default="")
    recorded_by: Mapped[str] = mapped_column(String(320), default="")
    recorded_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class PilotPhaseDecisionRecord(Base, IdMixin, TimestampMixin):
    __tablename__ = "pilot_phase_decisions"
    __table_args__ = (Index("ix_pilot_decision_phase", "organization_id", "phase", "created_at"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    phase: Mapped[str] = mapped_column(String(4))
    outcome: Mapped[str] = mapped_column(String(8))
    state: Mapped[str] = mapped_column(String(12), default=PilotDecisionState.PROPOSED.value, index=True)
    reasons: Mapped[list[Any]] = mapped_column(default=list)
    proposed_by: Mapped[str] = mapped_column(String(320), default="")
    #: [{"role": "MAIL_ADMIN", "email": "...", "at": "..."}]. Личность берётся из сессии, а не из тела
    #: запроса.
    approvals: Mapped[list[Any]] = mapped_column(default=list)
    #: Состояние гейта в момент предложения: решение не должно зависеть от того, что проверят позже.
    gate_snapshot: Mapped[dict[str, Any]] = mapped_column(default=dict)
    #: Письменное принятие риска, если верхняя граница ложных выше порога. Пусто — риск не принимался.
    risk_accept: Mapped[str] = mapped_column(Text, default="")
    effective_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class PilotStopRecord(Base, IdMixin, TimestampMixin):
    __tablename__ = "pilot_stops"
    __table_args__ = (Index("ix_pilot_stop_state", "organization_id", "state"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    reason_code: Mapped[str] = mapped_column(String(48))
    description: Mapped[str] = mapped_column(String(2000), default="")
    #: Контроль, к которому относится остановка; пусто — область неизвестна или затронут весь пилот.
    control_type: Mapped[str] = mapped_column(String(24), default="")
    opened_by: Mapped[str] = mapped_column(String(320), default="")
    opened_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    state: Mapped[str] = mapped_column(String(10), default="OPEN", index=True)
    resolved_by: Mapped[str] = mapped_column(String(320), default="")
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    #: Разбор причины и регрессионный случай — условия закрытия.
    rca_ref: Mapped[str] = mapped_column(String(500), default="")
    regression_ref: Mapped[str] = mapped_column(String(500), default="")
