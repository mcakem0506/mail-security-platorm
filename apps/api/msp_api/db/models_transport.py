"""Транспорт почты: узлы шлюза, версии конфигурации, справочник получателей (ТЗ 1.1 §37–§42).

Названия не совпадают с таблицами этапа 1.0.2 (``MailGateway`` и ``MailGatewayNode``) намеренно:
там описаны *внешние* шлюзы (KSMG и подобные), чьи заголовки платформа читает и оценивает; здесь
узлы *собственного* транспорта, которым платформа управляет. Это разные сущности, и общая
таблица смешала бы «чему верить» с «чем управлять».

В базе нет ни тел писем, ни паролей, ни закрытых ключей: письмо хранится в объектном хранилище
под строгим доступом, секреты — в смонтированных файлах (ТЗ 1.1 §41).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    Boolean,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdMixin, TimestampMixin, UTCDateTime, utcnow


class TransportNodeRole(StrEnum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    BOTH = "BOTH"
    LAB = "LAB"


class TransportConfigStatus(StrEnum):
    DRAFT = "DRAFT"
    VALIDATED = "VALIDATED"
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED = "FAILED"


class RecipientSyncStatus(StrEnum):
    ACCEPTED = "ACCEPTED"
    REFUSED = "REFUSED"
    FAILED = "FAILED"


class TransportMessageState(StrEnum):
    COLLECTED = "COLLECTED"
    ANALYSIS_QUEUED = "ANALYSIS_QUEUED"
    ANALYSED = "ANALYSED"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"


def _enum(enum_cls: type, name: str) -> Enum:
    return Enum(enum_cls, name=name, native_enum=False, values_callable=lambda e: [i.value for i in e])


class TransportNode(Base, IdMixin, TimestampMixin):
    """Узел транспорта. Идентификатор ``node_id`` постоянный и принадлежит узлу, а не контейнеру."""

    __tablename__ = "transport_nodes"
    __table_args__ = (UniqueConstraint("organization_id", "node_id", name="uq_transport_nodes_node"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    node_id: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    role: Mapped[TransportNodeRole] = mapped_column(
        _enum(TransportNodeRole, "transport_node_role_enum"), default=TransportNodeRole.LAB
    )
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None, index=True)
    config_version: Mapped[str] = mapped_column(String(64), default="")
    config_checksum: Mapped[str] = mapped_column(String(64), default="")
    queue_messages: Mapped[int] = mapped_column(Integer, default=0)
    pressure_state: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    unparsed_log_lines: Mapped[int] = mapped_column(Integer, default=0)
    #: Самый старый в очереди, секунд. Ноль — очередь пуста или данных ещё нет (см. last_heartbeat_at).
    oldest_message_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    #: Сводка последних проб и сторожей узла. ``None`` — не проверялось: это не «хорошо».
    exchange_ok: Mapped[bool | None] = mapped_column(Boolean, default=None)
    open_relay_safe: Mapped[bool | None] = mapped_column(Boolean, default=None)
    config_drift: Mapped[bool | None] = mapped_column(Boolean, default=None)
    collector_report_age: Mapped[float | None] = mapped_column(Float, default=None)
    shadow_pending_seconds: Mapped[float | None] = mapped_column(Float, default=None)
    #: Оператор просит слить узел. Узел исполняет команду при следующем опросе панели.
    drain_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    drain_requested_by: Mapped[str] = mapped_column(String(320), default="")
    drain_requested_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    #: Разовая команда «повторить доставку отложенной почты» (postqueue -f). Узел подтверждает событием.
    flush_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    flush_requested_by: Mapped[str] = mapped_column(String(320), default="")
    flush_requested_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)


class TransportConfigVersion(Base, IdMixin):
    __tablename__ = "transport_config_versions"
    __table_args__ = (
        UniqueConstraint("organization_id", "version", name="uq_transport_config_version"),
        Index("ix_transport_config_status", "organization_id", "status"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    status: Mapped[TransportConfigStatus] = mapped_column(
        _enum(TransportConfigStatus, "transport_config_status_enum"), default=TransportConfigStatus.DRAFT
    )
    #: Описание топологии (GatewaySpec) в виде JSON. Секретов в нём нет по построению модели.
    spec: Mapped[dict[str, Any]] = mapped_column(default=dict)
    checksum: Mapped[str] = mapped_column(String(64), default="")
    #: Готовые файлы пакета. Хранятся, чтобы откат возвращал в точности то, что работало, а не то,
    #: что получится при пересборке сегодняшним кодом из сегодняшнего справочника.
    bundle: Mapped[dict[str, Any]] = mapped_column(default=dict)
    recipients_checksum: Mapped[str] = mapped_column(String(64), default="")
    validation_errors: Mapped[list[Any]] = mapped_column(default=list)
    note: Mapped[str] = mapped_column(String(500), default="")
    created_by: Mapped[str] = mapped_column(String(320), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    activated_by: Mapped[str] = mapped_column(String(320), default="")
    activated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class AcceptedRecipient(Base, IdMixin, TimestampMixin):
    """Адрес, которому шлюз вправе принимать почту. Не путать с ``MailboxIdentity`` (каталог AD)."""

    __tablename__ = "accepted_recipients"
    __table_args__ = (UniqueConstraint("organization_id", "address", name="uq_accepted_recipient_address"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    address: Mapped[str] = mapped_column(String(320), index=True)
    kind: Mapped[str] = mapped_column(String(24), default="USER")
    aliases: Mapped[list[Any]] = mapped_column(default=list)
    source: Mapped[str] = mapped_column(String(64), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)


class RecipientSyncRun(Base, IdMixin):
    """Попытка обновить справочник. Отказ записывается так же подробно, как успех."""

    __tablename__ = "recipient_sync_runs"

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    status: Mapped[RecipientSyncStatus] = mapped_column(
        _enum(RecipientSyncStatus, "recipient_sync_status_enum"), index=True
    )
    source: Mapped[str] = mapped_column(String(64), default="")
    recipient_count: Mapped[int] = mapped_column(Integer, default=0)
    previous_count: Mapped[int] = mapped_column(Integer, default=0)
    rejected_count: Mapped[int] = mapped_column(Integer, default=0)
    conflict_count: Mapped[int] = mapped_column(Integer, default=0)
    checksum: Mapped[str] = mapped_column(String(64), default="")
    reason: Mapped[str] = mapped_column(String(500), default="")
    #: Время формирования выгрузки у источника. Возраст справочника считается от него.
    source_generated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    requested_by: Mapped[str] = mapped_column(String(320), default="")
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class TransportCertificate(Base, IdMixin, TimestampMixin):
    """Только метаданные сертификата (ТЗ §41). Закрытый ключ сюда не попадает."""

    __tablename__ = "transport_certificates"
    __table_args__ = (
        UniqueConstraint("organization_id", "node_id", "fingerprint", name="uq_transport_cert"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    node_id: Mapped[str] = mapped_column(String(32), index=True)
    usage: Mapped[str] = mapped_column(String(32))
    subject: Mapped[str] = mapped_column(String(500), default="")
    issuer: Mapped[str] = mapped_column(String(500), default="")
    not_before: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    not_after: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None, index=True)
    fingerprint: Mapped[str] = mapped_column(String(128))


class MailTransportEvent(Base, IdMixin):
    """Событие транспорта без содержимого письма: что произошло, где и когда."""

    __tablename__ = "mail_transport_events"
    __table_args__ = (Index("ix_transport_event_node_time", "organization_id", "node_id", "occurred_at"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    node_id: Mapped[str] = mapped_column(String(32), index=True)
    event_type: Mapped[str] = mapped_column(String(48), index=True)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    data: Mapped[dict[str, Any]] = mapped_column(default=dict)


class TransportMessage(Base, IdMixin, TimestampMixin):
    """Копия письма, снятая шлюзом, и её связь с анализом (ТЗ §35)."""

    __tablename__ = "transport_messages"
    __table_args__ = (
        UniqueConstraint("organization_id", "idempotency_key", name="uq_transport_message_key"),
        Index("ix_transport_message_state", "organization_id", "state"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    node_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    idempotency_key: Mapped[str] = mapped_column(String(64))
    direction: Mapped[str] = mapped_column(String(16), default="UNKNOWN", index=True)
    queue_id: Mapped[str] = mapped_column(String(40), default="")
    internet_message_id: Mapped[str] = mapped_column(String(998), default="", index=True)
    content_sha256: Mapped[str] = mapped_column(String(64), default="", index=True)
    envelope_fingerprint: Mapped[str] = mapped_column(String(64), default="")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    client_address: Mapped[str] = mapped_column(String(64), default="")
    journaled_at: Mapped[float] = mapped_column(Float, default=0.0)
    state: Mapped[TransportMessageState] = mapped_column(
        _enum(TransportMessageState, "transport_message_state_enum"),
        default=TransportMessageState.COLLECTED,
        index=True,
    )
    raw_storage_key: Mapped[str | None] = mapped_column(String(512), default=None)
    analysis_job_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_jobs.id", ondelete="SET NULL"), default=None, index=True
    )
    #: Сколько раз копия приходила повторно (идемпотентность): полезно для разбора сбоев доставки.
    duplicate_count: Mapped[int] = mapped_column(Integer, default=0)
    note: Mapped[str] = mapped_column(Text, default="")
