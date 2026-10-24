"""Принуждение, карантин и исключения (MSP 1.3, ТЗ 1.3 §6–§45, §59–§63).

Правила хранения: в базе нет закрытых ключей подписи политики, токенов узлов и тел писем в открытом виде.
Сырое письмо карантина лежит в хранилище объектов зашифрованным (``content_object_ref``), в таблице —
только ссылка, контрольная сумма и безопасные поля для списка.

Опубликованная политика неизменяема: правка создаёт новую версию. Контроль имеет собственное состояние
(``DISABLED``/``SHADOW``/``CANARY``/``PILOT``/``PAUSED``/``ROLLED_BACK``); состояния «глобально в бою» нет.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import Boolean, Enum, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdMixin, TimestampMixin, UTCDateTime, utcnow


def _enum(enum_cls: type, name: str) -> Enum:
    return Enum(enum_cls, name=name, native_enum=False, values_callable=lambda e: [i.value for i in e])


class PolicyReleaseState(StrEnum):
    DRAFT = "DRAFT"
    PUBLISHED = "PUBLISHED"
    SUPERSEDED = "SUPERSEDED"


class QuarantineState(StrEnum):
    QUARANTINED = "QUARANTINED"
    RELEASE_PENDING = "RELEASE_PENDING"
    RELEASED = "RELEASED"
    DELETED = "DELETED"
    EXPIRED = "EXPIRED"
    ERROR = "ERROR"


class IncidentState(StrEnum):
    OPEN = "OPEN"
    CONTAINED = "CONTAINED"
    ROOT_CAUSE_FOUND = "ROOT_CAUSE_FOUND"
    REGRESSION_ADDED = "REGRESSION_ADDED"
    CLOSED = "CLOSED"


class EnforcementControlRecord(Base, IdMixin, TimestampMixin):
    """Один контроль и его жизненный цикл (ТЗ §6). Общего флага принуждения нет."""

    __tablename__ = "enforcement_controls"
    __table_args__ = (
        UniqueConstraint("organization_id", "control_type", name="uq_enforcement_control_type"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    control_type: Mapped[str] = mapped_column(String(24))
    state: Mapped[str] = mapped_column(String(16), default="DISABLED", index=True)
    policy_version: Mapped[str] = mapped_column(String(64), default="")
    eligibility: Mapped[dict[str, Any]] = mapped_column(default=dict)
    readiness_status: Mapped[str] = mapped_column(String(24), default="NOT_READY")
    readiness_reasons: Mapped[list[Any]] = mapped_column(default=list)
    canary_scope: Mapped[dict[str, Any]] = mapped_column(default=dict)
    fail_mode: Mapped[str] = mapped_column(String(16), default="FAIL_OPEN")
    thresholds: Mapped[dict[str, Any]] = mapped_column(default=dict)
    justification: Mapped[str] = mapped_column(String(1000), default="")
    activated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    activated_by: Mapped[str] = mapped_column(String(320), default="")
    approved_by: Mapped[str] = mapped_column(String(320), default="")
    paused_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    rollback_version: Mapped[str] = mapped_column(String(64), default="")
    #: Ожидающий второго человека запрос на канарейку или пилот: кто, что и зачем (ТЗ §17).
    pending_request: Mapped[dict[str, Any]] = mapped_column(default=dict)
    #: Подтверждения проверок (тесты, отказоустойчивость и т. п.): значение, кто и на какой ревизии подтвердил.
    attestations: Mapped[dict[str, Any]] = mapped_column(default=dict)


class EnforcementPolicyRecord(Base, IdMixin, TimestampMixin):
    """Опубликованная политика: неизменяемая версия с подписью (ТЗ §16, §21)."""

    __tablename__ = "enforcement_policies"
    __table_args__ = (UniqueConstraint("organization_id", "version", name="uq_enforcement_policy_version"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    version: Mapped[str] = mapped_column(String(64))
    state: Mapped[PolicyReleaseState] = mapped_column(
        _enum(PolicyReleaseState, "enforcement_policy_state_enum"),
        default=PolicyReleaseState.DRAFT,
        index=True,
    )
    body: Mapped[dict[str, Any]] = mapped_column(default=dict)
    checksum: Mapped[str] = mapped_column(String(64), default="", index=True)
    #: Подписанный пакет распространения (подпись HMAC; ключ подписи в базе не хранится).
    bundle: Mapped[dict[str, Any]] = mapped_column(default=dict)
    owner: Mapped[str] = mapped_column(String(320), default="")
    reviewer: Mapped[str] = mapped_column(String(320), default="")
    rollback_target: Mapped[str] = mapped_column(String(64), default="")
    justification: Mapped[str] = mapped_column(String(1000), default="")
    valid_from: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    valid_until: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    published_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    #: Версия, которую узлы подтвердили (контрольная сумма) — для дрейфа политики (ТЗ §64).
    is_current: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


class EnforcementDecisionRecord(Base, IdMixin, TimestampMixin):
    """Решение с доказательствами и версией политики (ТЗ §9, §23). Предложенное и применённое — раздельно."""

    __tablename__ = "enforcement_decisions"
    __table_args__ = (
        Index("ix_enforcement_decision_when", "organization_id", "decided_at"),
        Index("ix_enforcement_decision_msg", "organization_id", "transport_message_id"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    node_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    transport_message_id: Mapped[str] = mapped_column(String(64), default="")
    internet_message_id: Mapped[str] = mapped_column(String(998), default="")
    control_type: Mapped[str] = mapped_column(String(24), index=True)
    decision: Mapped[str] = mapped_column(String(16), index=True)
    smtp_action: Mapped[str] = mapped_column(String(200), default="")
    suggested_action: Mapped[str] = mapped_column(String(24), default="")
    applied_action: Mapped[str] = mapped_column(String(24), default="OBSERVE_ONLY", index=True)
    reason_codes: Mapped[list[Any]] = mapped_column(default=list)
    evidence_ids: Mapped[list[Any]] = mapped_column(default=list)
    policy_version: Mapped[str] = mapped_column(String(64), default="", index=True)
    policy_checksum: Mapped[str] = mapped_column(String(64), default="")
    engine_versions: Mapped[dict[str, Any]] = mapped_column(default=dict)
    fail_mode_applied: Mapped[str] = mapped_column(String(16), default="")
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    recipient_count: Mapped[int] = mapped_column(Integer, default=1)
    previous_attempt: Mapped[str] = mapped_column(String(64), default="")
    sender_domain: Mapped[str] = mapped_column(String(255), default="")
    client_ip: Mapped[str] = mapped_column(String(64), default="")
    #: Разбор аналитиком: правильное ли решение (для метрик ложных срабатываний). Пусто — не разобрано.
    review_outcome: Mapped[str] = mapped_column(String(16), default="", index=True)
    review_critical: Mapped[bool] = mapped_column(Boolean, default=False)
    reviewed_by: Mapped[str] = mapped_column(String(320), default="")
    reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    decided_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class EnforcementExceptionRecord(Base, IdMixin, TimestampMixin):
    """Срочное исключение с владельцем и причиной (ТЗ §39–§41)."""

    __tablename__ = "enforcement_exceptions"

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    scope: Mapped[str] = mapped_column(String(24), index=True)
    control_type: Mapped[str] = mapped_column(String(24), default="")
    value: Mapped[str] = mapped_column(String(512))
    reason: Mapped[str] = mapped_column(String(1000))
    owner: Mapped[str] = mapped_column(String(320))
    approved_by: Mapped[str] = mapped_column(String(320), default="")
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    max_uses: Mapped[int | None] = mapped_column(Integer, default=None)
    uses: Mapped[int] = mapped_column(Integer, default=0)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    revoked_by: Mapped[str] = mapped_column(String(320), default="")


class EnforcementSwitchRecord(Base, IdMixin, TimestampMixin):
    """Общий выключатель (ТЗ §19). Одна строка на организацию; история — в журнале аудита."""

    __tablename__ = "enforcement_switches"
    __table_args__ = (UniqueConstraint("organization_id", name="uq_enforcement_switch_org"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    kill_switch: Mapped[bool] = mapped_column(Boolean, default=False)
    reason: Mapped[str] = mapped_column(String(1000), default="")
    activated_by: Mapped[str] = mapped_column(String(320), default="")
    activated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    cleared_by: Mapped[str] = mapped_column(String(320), default="")
    cleared_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    #: Снять выключатель вправе только второй человек: первый лишь запрашивает (ТЗ §19).
    clear_requested_by: Mapped[str] = mapped_column(String(320), default="")
    clear_requested_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    activation_count: Mapped[int] = mapped_column(Integer, default=0)


class QuarantineItemRecord(Base, IdMixin, TimestampMixin):
    """Письмо в карантине (ТЗ §32–§36). Исходное письмо неизменяемо и лежит зашифрованным."""

    __tablename__ = "quarantine_items"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "transport_message_id", "decision_ref", name="uq_quarantine_decision"
        ),
        Index("ix_quarantine_state_expiry", "organization_id", "state", "expires_at"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    node_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    transport_message_id: Mapped[str] = mapped_column(String(64), index=True)
    internet_message_id: Mapped[str] = mapped_column(String(998), default="")
    decision_ref: Mapped[str] = mapped_column(String(64), default="")
    content_object_ref: Mapped[str] = mapped_column(String(256), default="")
    content_sha256: Mapped[str] = mapped_column(String(64), default="")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sender: Mapped[str] = mapped_column(String(320), default="")
    recipients: Mapped[list[Any]] = mapped_column(default=list)
    subject_safe: Mapped[str] = mapped_column(String(300), default="")
    reason_codes: Mapped[list[Any]] = mapped_column(default=list)
    policy_version: Mapped[str] = mapped_column(String(64), default="")
    state: Mapped[QuarantineState] = mapped_column(
        _enum(QuarantineState, "quarantine_state_enum"), default=QuarantineState.QUARANTINED, index=True
    )
    quarantined_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    original_route: Mapped[str] = mapped_column(String(255), default="")
    release_requested_by: Mapped[str] = mapped_column(String(320), default="")
    release_approved_by: Mapped[str] = mapped_column(String(320), default="")
    #: Одноразовая ссылка выпуска: в базе только хэш; срок короткий; повтор не принимается (ТЗ §34).
    release_token_hash: Mapped[str] = mapped_column(String(64), default="")
    release_token_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    release_token_used: Mapped[bool] = mapped_column(Boolean, default=False)
    released_by: Mapped[str] = mapped_column(String(320), default="")
    released_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    delivered_count: Mapped[int] = mapped_column(Integer, default=0)
    deleted_by: Mapped[str] = mapped_column(String(320), default="")
    error: Mapped[str] = mapped_column(String(300), default="")


class EmergencyIncidentRecord(Base, IdMixin, TimestampMixin):
    """Аварийный сценарий ложного срабатывания (ТЗ §37). Включить контроль заново можно только после закрытия."""

    __tablename__ = "enforcement_incidents"

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    control_type: Mapped[str] = mapped_column(String(24), index=True)
    policy_version: Mapped[str] = mapped_column(String(64), default="")
    state: Mapped[IncidentState] = mapped_column(
        _enum(IncidentState, "enforcement_incident_state_enum"), default=IncidentState.OPEN, index=True
    )
    title: Mapped[str] = mapped_column(String(300))
    opened_by: Mapped[str] = mapped_column(String(320))
    impacted: Mapped[list[Any]] = mapped_column(default=list)
    released_count: Mapped[int] = mapped_column(Integer, default=0)
    root_cause: Mapped[str] = mapped_column(Text, default="")
    regression_case: Mapped[str] = mapped_column(String(300), default="")
    closed_by: Mapped[str] = mapped_column(String(320), default="")
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class ComponentCredentialSeen(Base, IdMixin, TimestampMixin):
    """Отпечатки токенов компонентов, замеченные приёмником (ТЗ §79, §80). Токены не хранятся."""

    __tablename__ = "component_credentials_seen"
    __table_args__ = (UniqueConstraint("scope", "fingerprint", name="uq_credential_seen"),)

    scope: Mapped[str] = mapped_column(String(32), index=True)
    fingerprint: Mapped[str] = mapped_column(String(16))
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    uses: Mapped[int] = mapped_column(Integer, default=0)
