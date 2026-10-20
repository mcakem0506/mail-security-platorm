"""Анти-спам, аутентификация и репутация отправителя (MSP 1.2, ТЗ 1.2 §7–§35).

Правила хранения те же, что у транспорта: в базе нет тел писем, закрытых ключей подписи, токенов
провайдеров и секретных имён DNS-зон. Закрытый ключ лежит в смонтированном хранилище секретов,
в базе — только ссылка ``private_key_ref``; секретная зона провайдера — файл на узле, в базе —
только пометка ``has_secret_zone``.

На этапе 1.2 ничего из этого не исполняется над почтой: результаты сканера хранятся как
свидетельства, предложенное действие — как ``suggested_action``, а применённое всегда
``OBSERVE_ONLY``.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import Boolean, Enum, Float, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdMixin, TimestampMixin, UTCDateTime, utcnow


def _enum(enum_cls: type, name: str) -> Enum:
    return Enum(enum_cls, name=name, native_enum=False, values_callable=lambda e: [i.value for i in e])


class ProviderApprovalState(StrEnum):
    #: Заведён, лицензия не одобрена: ``DISABLED_BY_POLICY``.
    DRAFT = "DRAFT"
    #: Один человек запросил включение, ждёт второго (четыре глаза).
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    SUSPENDED = "SUSPENDED"


class ConflictDisposition(StrEnum):
    OPEN = "OPEN"
    EXPECTED = "EXPECTED"
    REAL_PROBLEM = "REAL_PROBLEM"
    FALSE_ALARM = "FALSE_ALARM"


class SpamPolicyState(StrEnum):
    DRAFT = "DRAFT"
    SHADOW = "SHADOW"
    VALIDATION = "VALIDATION"
    APPROVED = "APPROVED"
    ACTIVE_SHADOW = "ACTIVE_SHADOW"


class DkimKeyStatus(StrEnum):
    GENERATED = "GENERATED"
    DNS_PENDING = "DNS_PENDING"
    READY = "READY"
    ACTIVE = "ACTIVE"
    RETIRING = "RETIRING"
    RETIRED = "RETIRED"
    FAILED = "FAILED"


class SpamScan(Base, IdMixin, TimestampMixin):
    """Результат сканирования одного письма Rspamd (ТЗ 1.2 §7). Источник — запись самого сканера."""

    __tablename__ = "spam_scans"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "node_id", "queue_id", "internet_message_id", name="uq_spam_scan_key"
        ),
        Index("ix_spam_scan_received", "organization_id", "received_at"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    node_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    queue_id: Mapped[str] = mapped_column(String(40), default="", index=True)
    internet_message_id: Mapped[str] = mapped_column(String(998), default="", index=True)
    transport_message_id: Mapped[str | None] = mapped_column(
        ForeignKey("transport_messages.id", ondelete="SET NULL"), default=None, index=True
    )
    direction: Mapped[str] = mapped_column(String(16), default="INBOUND", index=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    required_score: Mapped[float] = mapped_column(Float, default=0.0)
    suggested_action: Mapped[str] = mapped_column(String(24), default="UNKNOWN", index=True)
    #: Всегда OBSERVE_ONLY на этапе 1.2.
    applied_action: Mapped[str] = mapped_column(String(24), default="OBSERVE_ONLY")
    spam_class: Mapped[str] = mapped_column(String(32), default="UNKNOWN", index=True)
    #: Вердикт безопасности — отдельная ось, не смешивается с классом спама (§13).
    security_verdict: Mapped[str | None] = mapped_column(String(32), default=None)
    symbols: Mapped[list[Any]] = mapped_column(default=list)
    groups: Mapped[list[Any]] = mapped_column(default=list)
    auth: Mapped[dict[str, Any]] = mapped_column(default=dict)
    helo: Mapped[dict[str, Any]] = mapped_column(default=dict)
    signals: Mapped[list[Any]] = mapped_column(default=list)
    unmapped_symbols: Mapped[list[Any]] = mapped_column(default=list)
    missing_evidence: Mapped[list[Any]] = mapped_column(default=list)
    scan_time_ms: Mapped[int] = mapped_column(Integer, default=0)
    rspamd_version: Mapped[str] = mapped_column(String(32), default="")
    rspamd_config_version: Mapped[str] = mapped_column(String(64), default="")
    symbol_mapping_version: Mapped[str] = mapped_column(String(32), default="")
    client_ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    sender_domain: Mapped[str] = mapped_column(String(255), default="", index=True)
    #: Прочее: число получателей, признаки рассылки, аномалии частоты, подозрение на подделку заголовков.
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class AuthConflictRecord(Base, IdMixin, TimestampMixin):
    """Расхождение результатов вышестоящего шлюза и MSP (ТЗ 1.2 §25). Не скрывается и не гасится."""

    __tablename__ = "auth_conflicts"

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("spam_scans.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    upstream_value: Mapped[str] = mapped_column(String(64), default="")
    msp_value: Mapped[str] = mapped_column(String(64), default="")
    note: Mapped[str] = mapped_column(String(500), default="")
    disposition: Mapped[ConflictDisposition] = mapped_column(
        _enum(ConflictDisposition, "auth_conflict_disposition_enum"),
        default=ConflictDisposition.OPEN,
        index=True,
    )
    reviewed_by: Mapped[str] = mapped_column(String(320), default="")
    reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class ReputationProviderRecord(Base, IdMixin, TimestampMixin):
    """Провайдер репутации с лицензионным допуском (ТЗ 1.2 §14, §15). Секретной зоны здесь нет."""

    __tablename__ = "reputation_providers"
    __table_args__ = (UniqueConstraint("organization_id", "slug", name="uq_reputation_provider_slug"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    slug: Mapped[str] = mapped_column(String(48))
    #: Определение провайдера без секретов (ReputationProvider.model_dump).
    definition: Mapped[dict[str, Any]] = mapped_column(default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    approval_state: Mapped[ProviderApprovalState] = mapped_column(
        _enum(ProviderApprovalState, "provider_approval_state_enum"), default=ProviderApprovalState.DRAFT
    )
    requested_by: Mapped[str] = mapped_column(String(320), default="")
    approved_by: Mapped[str] = mapped_column(String(320), default="")
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    usage_scope: Mapped[str] = mapped_column(String(256), default="")
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    last_error: Mapped[str] = mapped_column(String(300), default="")


class SpamPolicyRecord(Base, IdMixin, TimestampMixin):
    """Политика спама и кандидат (ТЗ 1.2 §28). ``enforcement_enabled`` всегда ложь."""

    __tablename__ = "spam_policies"
    __table_args__ = (UniqueConstraint("organization_id", "version", name="uq_spam_policy_version"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    state: Mapped[SpamPolicyState] = mapped_column(
        _enum(SpamPolicyState, "spam_policy_state_enum"), default=SpamPolicyState.DRAFT, index=True
    )
    body: Mapped[dict[str, Any]] = mapped_column(default=dict)
    edited_by: Mapped[str] = mapped_column(String(320), default="")
    approved_by: Mapped[str] = mapped_column(String(320), default="")
    note: Mapped[str] = mapped_column(String(500), default="")


class SourceIpReputationRecord(Base, IdMixin):
    __tablename__ = "source_ip_reputation"
    __table_args__ = (UniqueConstraint("organization_id", "ip", name="uq_source_ip_reputation"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    message_count: Mapped[float] = mapped_column(Float, default=0.0)
    threat_count: Mapped[float] = mapped_column(Float, default=0.0)
    spam_count: Mapped[float] = mapped_column(Float, default=0.0)
    legitimate_count: Mapped[float] = mapped_column(Float, default=0.0)
    distinct_senders: Mapped[int] = mapped_column(Integer, default=0)
    distinct_domains: Mapped[int] = mapped_column(Integer, default=0)
    analyst_confirmed: Mapped[str | None] = mapped_column(String(16), default=None)
    #: Известные отправители/домены (ограниченные множества) для подсчёта различных значений.
    known_senders: Mapped[list[Any]] = mapped_column(default=list)
    known_domains: Mapped[list[Any]] = mapped_column(default=list)


class DomainReputationRecord(Base, IdMixin):
    __tablename__ = "domain_reputation"
    __table_args__ = (UniqueConstraint("organization_id", "domain", name="uq_domain_reputation"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    message_count: Mapped[float] = mapped_column(Float, default=0.0)
    threat_count: Mapped[float] = mapped_column(Float, default=0.0)
    spam_count: Mapped[float] = mapped_column(Float, default=0.0)
    legitimate_count: Mapped[float] = mapped_column(Float, default=0.0)
    auth_pass_count: Mapped[float] = mapped_column(Float, default=0.0)
    analyst_confirmed: Mapped[str | None] = mapped_column(String(16), default=None)


class DkimKeyRecord(Base, IdMixin, TimestampMixin):
    """Ключ подписи DKIM (ТЗ 1.2 §22). Закрытая часть в базу не попадает: только ``private_key_ref``."""

    __tablename__ = "dkim_signing_keys"
    __table_args__ = (UniqueConstraint("organization_id", "domain", "selector", name="uq_dkim_key_selector"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    selector: Mapped[str] = mapped_column(String(63))
    algorithm: Mapped[str] = mapped_column(String(24), default="rsa-sha256")
    public_record: Mapped[str] = mapped_column(String(1024), default="")
    private_key_ref: Mapped[str] = mapped_column(String(256), default="")
    status: Mapped[DkimKeyStatus] = mapped_column(
        _enum(DkimKeyStatus, "dkim_key_status_enum"), default=DkimKeyStatus.GENERATED, index=True
    )
    activate_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    retire_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    generated_by: Mapped[str] = mapped_column(String(320), default="")
    activated_by: Mapped[str] = mapped_column(String(320), default="")
    failure: Mapped[str] = mapped_column(String(200), default="")


class BayesSample(Base, IdMixin, TimestampMixin):
    """Пример, допущенный к обучению Bayes (ТЗ 1.2 §20). Не подтверждённые аналитиком не попадают."""

    __tablename__ = "bayes_samples"
    __table_args__ = (
        UniqueConstraint("organization_id", "internet_message_id", name="uq_bayes_sample_message"),
    )

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    internet_message_id: Mapped[str] = mapped_column(String(998), index=True)
    label: Mapped[str] = mapped_column(String(8), index=True)
    source: Mapped[str] = mapped_column(String(40))
    confirmed_by: Mapped[str] = mapped_column(String(320), default="")
    learned: Mapped[bool] = mapped_column(Boolean, default=False)
    unlearned_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class SpamReview(Base, IdMixin, TimestampMixin):
    """Решение аналитика по письму: основа метрик ложных срабатываний и пропусков (ТЗ 1.2 §29)."""

    __tablename__ = "spam_reviews"
    __table_args__ = (UniqueConstraint("scan_id", name="uq_spam_review_scan"),)

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("spam_scans.id", ondelete="CASCADE"), index=True)
    #: Что аналитик решил про письмо на самом деле.
    verdict: Mapped[str] = mapped_column(String(16), index=True)
    #: Почему письмо попало на проверку (обязательная выборка §29).
    selection: Mapped[str] = mapped_column(String(32), index=True)
    reviewed_by: Mapped[str] = mapped_column(String(320), default="")
    reviewed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    note: Mapped[str] = mapped_column(String(500), default="")
