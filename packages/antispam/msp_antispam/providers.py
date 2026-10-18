"""Провайдеры репутации и лицензионный допуск (ТЗ 1.2 §14, §15, §31).

Публичный DNSBL нельзя включать в коммерческой или корпоративной эксплуатации, не проверив
условия лицензии, поэтому провайдер без одобрения получает статус ``DISABLED_BY_POLICY``,
сколько бы раз его ни включили флагом ``enabled``. Одобрение — отдельное действие с
фиксацией: кто, когда, на какую область применения и до какого срока.

Запросы к чужому DNS уносят данные из письма (адрес клиента, домен отправителя, хосты ссылок),
поэтому у провайдера есть класс приватности, а типы запросов включаются по одному — «включить
всё» не существует.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .model import QueryType, RblResult


class ProviderType(StrEnum):
    DNSBL = "DNSBL"
    DNSWL = "DNSWL"
    URIBL = "URIBL"


class LicenseMode(StrEnum):
    #: Публичная зона с бесплатным некоммерческим использованием — для корпорации не подходит без письма.
    PUBLIC_NONCOMMERCIAL = "PUBLIC_NONCOMMERCIAL"
    COMMERCIAL_LICENSED = "COMMERCIAL_LICENSED"
    #: Собственное зеркало или зона организации.
    SELF_HOSTED = "SELF_HOSTED"
    #: Лабораторная зона стенда; к реальной почте не применяется.
    LAB_ZONE = "LAB_ZONE"


class PrivacyClass(StrEnum):
    #: Запрос уходит в публичный DNS: внешний оператор видит, о каком адресе или домене спрашивали.
    EXTERNAL_DNS = "EXTERNAL_DNS"
    #: Зона обслуживается внутри организации.
    INTERNAL = "INTERNAL"


class ProviderStatus(StrEnum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    DISABLED_BY_POLICY = "DISABLED_BY_POLICY"
    LICENSE_EXPIRED = "LICENSE_EXPIRED"
    ERROR = "ERROR"


_ID = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_ZONE = re.compile(r"^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_PATH = re.compile(r"^/[A-Za-z0-9._/\-]{1,200}$")


class LicenseApproval(BaseModel):
    """Одобрение условий лицензии. Без него провайдер не используется."""

    model_config = ConfigDict(extra="forbid")

    license_approved: bool = False
    approved_by: str | None = Field(default=None, max_length=128)
    #: Второй человек (четыре глаза, §34): тот, кто включил провайдера, не может его же одобрить.
    second_approver: str | None = Field(default=None, max_length=128)
    approved_at: datetime | None = None
    usage_scope: str = Field(default="", max_length=256)
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def _complete(self) -> Self:
        if self.license_approved:
            if not self.approved_by or not self.approved_at or not self.usage_scope:
                raise ValueError("одобрение без исполнителя, времени и области применения недействительно")
            if self.second_approver and self.second_approver == self.approved_by:
                raise ValueError("одобряющие должны быть разными людьми")
        return self


class ReputationProvider(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    type: ProviderType = ProviderType.DNSBL
    provider_name: str = Field(max_length=128)
    enabled: bool = False
    license_mode: LicenseMode = LicenseMode.PUBLIC_NONCOMMERCIAL
    query_types: tuple[QueryType, ...] = ()
    privacy_class: PrivacyClass = PrivacyClass.EXTERNAL_DNS
    approval: LicenseApproval = LicenseApproval()
    #: Публичное имя зоны. Для зон с секретом не задаётся: имя лежит в хранилище секретов.
    zone: str | None = None
    zone_secret_file: str | None = None
    timeout_seconds: float = Field(default=2.0, ge=0.2, le=10)
    cache_ttl_seconds: int = Field(default=300, ge=0, le=86400)

    @field_validator("id")
    @classmethod
    def _id_ok(cls, value: str) -> str:
        if not _ID.match(value):
            raise ValueError("id: неверный формат")
        return value

    @field_validator("zone")
    @classmethod
    def _zone_ok(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.lower().rstrip(".")
        if not _ZONE.match(value):
            raise ValueError("zone: неверное имя")
        return value

    @field_validator("zone_secret_file")
    @classmethod
    def _secret_ok(cls, value: str | None) -> str | None:
        if value is not None and not _PATH.match(value):
            raise ValueError("zone_secret_file: неверный путь")
        return value

    @model_validator(mode="after")
    def _one_zone(self) -> Self:
        if (self.zone is None) == (self.zone_secret_file is None):
            raise ValueError("нужно указать ровно одно: публичную зону или файл с секретной зоной")
        return self

    # ----- статус и допуск -----------------------------------------------------------------
    def effective_status(self, now: datetime | None = None) -> ProviderStatus:
        now = now or datetime.now(UTC)
        if not self.enabled:
            return ProviderStatus.DISABLED
        # Лабораторная зона и собственное зеркало не требуют внешней лицензии.
        if self.license_mode in (LicenseMode.LAB_ZONE, LicenseMode.SELF_HOSTED):
            return ProviderStatus.ACTIVE
        if not self.approval.license_approved:
            return ProviderStatus.DISABLED_BY_POLICY
        if self.approval.expires_at is not None:
            expires = self.approval.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if expires <= now:
                return ProviderStatus.LICENSE_EXPIRED
        return ProviderStatus.ACTIVE

    def is_usable(self, now: datetime | None = None) -> bool:
        return self.effective_status(now) is ProviderStatus.ACTIVE and bool(self.query_types)

    def zone_reference(self) -> str:
        """Имя зоны для конфигурации. Для секретной зоны сюда попадает только ссылка на файл."""
        if self.zone is not None:
            return self.zone
        raise ValueError("у провайдера секретная зона: имя берётся из хранилища секретов на узле")

    def public_view(self) -> dict[str, object]:
        """Что можно показывать в интерфейсе и журнале: без зоны с секретом (§15)."""
        return {
            "id": self.id,
            "provider_name": self.provider_name,
            "type": self.type.value,
            "license_mode": self.license_mode.value,
            "privacy_class": self.privacy_class.value,
            "query_types": [q.value for q in self.query_types],
            "status": self.effective_status().value,
            "zone": self.zone if self.zone is not None else None,
            "has_secret_zone": self.zone_secret_file is not None,
        }


# ---------------------------------------------------------------------------------------------
# Маскирование секрета в именах запросов и результатах
# ---------------------------------------------------------------------------------------------
MASK = "[скрыто]"


def mask_query_hostname(hostname: str, provider: ReputationProvider, secret_zone: str | None = None) -> str:
    """Имя запроса для журнала. У секретной зоны полное имя не показывается никогда (§15)."""
    if provider.zone is not None:
        return hostname
    if secret_zone and hostname.lower().endswith(secret_zone.lower()):
        return f"{MASK}.{provider.id}"
    return f"{MASK}.{provider.id}"


def scrub_secret(text: str, secrets: list[str]) -> str:
    """Убрать секретные зоны из любого текста (ошибки, опции символов)."""
    out = text
    for secret in secrets:
        if secret:
            out = re.sub(re.escape(secret), MASK, out, flags=re.IGNORECASE)
    return out


def normalize_dnsbl_answer(
    answer: str | None, error: str | None = None, *, lookup_enabled: bool = True
) -> RblResult:
    """Свести ответ DNS к результату §15. ``NOT_LISTED`` не снижает риск."""
    if not lookup_enabled:
        return RblResult.DISABLED
    if error:
        lowered = error.lower()
        if "timeout" in lowered or "timed out" in lowered or "servfail" in lowered:
            return RblResult.TEMPERROR
        if "nxdomain" in lowered:
            return RblResult.NXDOMAIN
        return RblResult.PROVIDER_ERROR
    if answer is None:
        return RblResult.NOT_LISTED
    # Ответы 127.255.255.x по соглашению DNSBL — ошибка использования (превышен лимит, закрытый
    # резолвер), а не «в списке».
    if answer.startswith("127.255.255."):
        return RblResult.PROVIDER_ERROR
    if answer.startswith("127."):
        return RblResult.LISTED
    return RblResult.PROVIDER_ERROR
