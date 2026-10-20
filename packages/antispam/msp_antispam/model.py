"""Нормализованные доказательства (ТЗ 1.2 §7–§13).

Все типы здесь — данные. Источник правды о том, что увидел сканер, — запись, пришедшая от самого
Rspamd; заголовки ``X-Spamd-*`` внутри письма доказательством не являются (§7): их мог написать
отправитель.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False)


def utcnow() -> datetime:
    return datetime.now(UTC)


class Direction(StrEnum):
    """Направление берётся из транспортного контекста (слушатель Postfix), а не из From (§5)."""

    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    INTERNAL_TEST = "INTERNAL_TEST"


class SuggestedAction(StrEnum):
    """Родное действие Rspamd. Хранится как предложение, а не исполняется (§6)."""

    NO_ACTION = "NO_ACTION"
    GREYLIST = "GREYLIST"
    ADD_HEADER = "ADD_HEADER"
    REWRITE_SUBJECT = "REWRITE_SUBJECT"
    SOFT_REJECT = "SOFT_REJECT"
    REJECT = "REJECT"
    UNKNOWN = "UNKNOWN"


class AppliedAction(StrEnum):
    """Реальное действие MTA на этапе 1.2 единственное."""

    OBSERVE_ONLY = "OBSERVE_ONLY"


class ActionMode(StrEnum):
    """Режимы ``RspamdActionPolicy`` (§6). Режима, который что-то исполняет, нет."""

    SHADOW = "SHADOW"
    PILOT_HEADER_ONLY = "PILOT_HEADER_ONLY"
    ENFORCEMENT_DISABLED = "ENFORCEMENT_DISABLED"


class SpamClass(StrEnum):
    NOT_SPAM = "NOT_SPAM"
    BULK = "BULK"
    SUSPECTED_SPAM = "SUSPECTED_SPAM"
    SPAM = "SPAM"
    HIGH_CONFIDENCE_SPAM = "HIGH_CONFIDENCE_SPAM"
    UNKNOWN = "UNKNOWN"


class SpfResult(StrEnum):
    PASS = "PASS"  # noqa: S105
    FAIL = "FAIL"
    SOFTFAIL = "SOFTFAIL"
    NEUTRAL = "NEUTRAL"
    NONE = "NONE"
    TEMPERROR = "TEMPERROR"
    PERMERROR = "PERMERROR"


class DkimResult(StrEnum):
    PASS = "PASS"  # noqa: S105
    FAIL = "FAIL"
    NONE = "NONE"
    TEMPERROR = "TEMPERROR"
    PERMERROR = "PERMERROR"


class DmarcResult(StrEnum):
    PASS = "PASS"  # noqa: S105
    FAIL = "FAIL"
    NONE = "NONE"
    TEMPERROR = "TEMPERROR"
    PERMERROR = "PERMERROR"


class ArcResult(StrEnum):
    PASS = "PASS"  # noqa: S105
    FAIL = "FAIL"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class DmarcPolicy(StrEnum):
    NONE = "none"
    QUARANTINE = "quarantine"
    REJECT = "reject"


class SuggestedDisposition(StrEnum):
    """Что DMARC-политика домена предлагает сделать. Доставка продолжается (§10)."""

    NONE = "NONE"
    QUARANTINE = "QUARANTINE"
    REJECT = "REJECT"


class RspamdSymbol(Strict):
    name: str = Field(max_length=128)
    score: float = 0.0
    group: str = Field(default="", max_length=64)
    description: str = Field(default="", max_length=512)
    options: list[str] = Field(default_factory=list, max_length=32)


class RspamdEvidence(Strict):
    """Результат сканирования, как его записал Rspamd (§7)."""

    message_id: str = Field(default="", max_length=998)
    transport_message_id: str = Field(default="", max_length=64)
    scan_id: str = Field(default="", max_length=64)
    score: float = 0.0
    required_score: float = 0.0
    suggested_action: SuggestedAction = SuggestedAction.UNKNOWN
    symbols: list[RspamdSymbol] = Field(default_factory=list, max_length=512)
    groups: list[str] = Field(default_factory=list)
    scan_time_ms: int = 0
    rspamd_version: str = ""
    config_version: str = ""
    direction: Direction = Direction.INBOUND
    client_ip: str = ""
    envelope_from: str = ""
    helo: str = ""
    created_at: datetime = Field(default_factory=utcnow)

    def symbol(self, name: str) -> RspamdSymbol | None:
        for item in self.symbols:
            if item.name == name:
                return item
        return None

    def has(self, name: str) -> bool:
        return self.symbol(name) is not None


# ---------------------------------------------------------------------------------------------
# Аутентификация
# ---------------------------------------------------------------------------------------------
class SpfEvidence(Strict):
    result: SpfResult = SpfResult.NONE
    #: Проверенный идентификатор: домен MAIL FROM или, для пустого отправителя, HELO (§8).
    identity: str = ""
    identity_kind: str = "MAIL_FROM"
    client_ip: str = ""
    reason: str = ""
    error_class: str = ""


class DkimSignatureEvidence(Strict):
    domain: str = ""
    selector: str = ""
    result: DkimResult = DkimResult.NONE
    aligned: bool = False
    algorithm: str = ""
    key_state: str = ""
    #: Подпись есть, но проверить её нельзя или она слабая — это не PASS (§9).
    unsupported_or_weak: bool = False
    reason: str = ""


class DkimEvidence(Strict):
    """Итог — лучшая подпись: одна неудачная не отменяет другую корректную выровненную (§9)."""

    result: DkimResult = DkimResult.NONE
    signatures: list[DkimSignatureEvidence] = Field(default_factory=list, max_length=16)


class DmarcEvidence(Strict):
    result: DmarcResult = DmarcResult.NONE
    policy: DmarcPolicy | None = None
    subdomain_policy: DmarcPolicy | None = None
    policy_domain: str = ""
    from_domain: str = ""
    spf_aligned: bool | None = None
    dkim_aligned: bool | None = None
    suggested_disposition: SuggestedDisposition = SuggestedDisposition.NONE
    #: Метаданные политики: np, psd, t, adkim, aspf, pct — как их сообщил сканер.
    policy_meta: dict[str, str] = Field(default_factory=dict)
    discovery: str = ""


class ArcEvidence(Strict):
    result: ArcResult = ArcResult.UNKNOWN
    instances: int = 0
    signing_domains: list[str] = Field(default_factory=list, max_length=16)


class AuthEvidence(Strict):
    spf: SpfEvidence = Field(default_factory=SpfEvidence)
    dkim: DkimEvidence = Field(default_factory=DkimEvidence)
    dmarc: DmarcEvidence = Field(default_factory=DmarcEvidence)
    arc: ArcEvidence = Field(default_factory=ArcEvidence)
    #: Хотя бы один результат не удалось получить из-за DNS/сканера — это не FAIL (§30).
    incomplete: bool = False
    incomplete_reasons: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------------------------
# HELO / PTR
# ---------------------------------------------------------------------------------------------
class PtrState(StrEnum):
    NONE = "NONE"
    PTR_PRESENT = "PTR_PRESENT"
    FCRDNS_PASS = "FCrDNS_PASS"  # noqa: S105
    FCRDNS_FAIL = "FCrDNS_FAIL"
    TEMPERROR = "TEMPERROR"


class HeloSignal(StrEnum):
    MISSING = "HELO_MISSING"
    IP_LITERAL = "HELO_IP_LITERAL"
    INVALID_SYNTAX = "HELO_INVALID_SYNTAX"
    MISMATCH = "HELO_MISMATCH"
    PROTECTED_DOMAIN = "HELO_PROTECTED_DOMAIN_IMPERSONATION"
    INTERNAL_ONLY_FROM_EXTERNAL = "HELO_INTERNAL_ONLY_FROM_EXTERNAL"


class HeloEvidence(Strict):
    helo: str = ""
    signals: list[HeloSignal] = Field(default_factory=list)
    ptr_state: PtrState = PtrState.NONE
    ptr_name: str = ""


# ---------------------------------------------------------------------------------------------
# Репутация провайдеров
# ---------------------------------------------------------------------------------------------
class RblResult(StrEnum):
    LISTED = "LISTED"
    NOT_LISTED = "NOT_LISTED"
    TEMPERROR = "TEMPERROR"
    NXDOMAIN = "NXDOMAIN"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    DISABLED = "DISABLED"


class QueryType(StrEnum):
    CLIENT_IP = "CLIENT_IP"
    HELO = "HELO"
    RDNS = "RDNS"
    SENDER_DOMAIN = "SENDER_DOMAIN"
    DKIM_DOMAIN = "DKIM_DOMAIN"
    URL_HOST = "URL_HOST"
    REPLY_TO_DOMAIN = "REPLY_TO_DOMAIN"


class ReputationHit(Strict):
    provider_id: str
    provider_name: str
    query_type: QueryType
    result: RblResult
    #: Что именно вернул провайдер (код зоны), без имени запроса: оно может содержать секрет (§15).
    detail: str = ""
