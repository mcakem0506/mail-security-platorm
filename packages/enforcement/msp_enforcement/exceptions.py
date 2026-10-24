"""Исключения принуждения (ТЗ §39–§41).

Исключение всегда срочное, объяснимое и не скрывает сигналы: оно меняет применённое действие
(``BYPASS_BY_EXCEPTION``), а предложенное и свидетельства остаются (§41). Бессрочного списка разрешённых
исключение не создаёт (§38).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta

from pydantic import Field, model_validator

from .model import SENSITIVE_CONTROLS, ControlType, ExceptionScope, Strict, utcnow

#: Предельный срок исключения (дни). Бессрочных нет.
MAX_LIFETIME = timedelta(days=90)


class ExceptionError(ValueError):
    pass


class EnforcementException(Strict):
    id: str
    scope: ExceptionScope
    control: ControlType | None = None  # None допустим только для области CONTROL
    value: str
    reason: str = Field(min_length=5)
    owner: str
    approved_by: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    max_uses: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _check(self) -> EnforcementException:
        if self.expires_at <= self.created_at:
            raise ExceptionError("срок исключения должен быть позже его создания")
        if self.expires_at - self.created_at > MAX_LIFETIME:
            raise ExceptionError("исключение не может быть бессрочным или дольше 90 дней")
        if self.scope is ExceptionScope.SOURCE_IP:
            ipaddress.ip_network(self.value, strict=False)
        if self.scope is ExceptionScope.CONTROL and self.control is None:
            raise ExceptionError("область CONTROL требует указать контроль")
        return self

    def needs_four_eyes(self) -> bool:
        """§40: обход вредоносного, DMARC, RBL и имперсонации — только вдвоём. Область CONTROL — тоже."""
        return self.scope is ExceptionScope.CONTROL or (
            self.control is not None and self.control in SENSITIVE_CONTROLS
        )

    def is_approved(self) -> bool:
        if not self.needs_four_eyes():
            return True
        return bool(self.approved_by) and self.approved_by != self.owner

    def is_active(self, now: datetime, uses: int = 0) -> bool:
        if now >= self.expires_at or not self.is_approved():
            return False
        return self.max_uses is None or uses < self.max_uses


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def matching(
    exceptions: Iterable[EnforcementException],
    control: ControlType,
    *,
    now: datetime,
    sender: str,
    recipients: Iterable[str],
    source_ip: str,
    message_id: str = "",
    campaign: str = "",
    groups: Mapping[str, Iterable[str]] | None = None,
    uses: Mapping[str, int] | None = None,
) -> EnforcementException | None:
    """Первое действующее исключение для этого письма. Разрешает письмо только целиком: если получателей
    несколько, исключение должно покрывать каждого (иначе часть адресатов осталась бы без защиты)."""
    rcpts = [r.lower() for r in recipients]
    for item in exceptions:
        if item.control is not None and item.control is not control:
            continue
        if not item.is_active(now, (uses or {}).get(item.id, 0)):
            continue
        value = item.value.lower()
        hit = False
        if item.scope is ExceptionScope.SENDER:
            hit = sender.lower() == value
        elif item.scope is ExceptionScope.SENDER_DOMAIN:
            hit = _domain(sender) == value
        elif item.scope is ExceptionScope.RECIPIENT:
            hit = bool(rcpts) and all(r == value for r in rcpts)
        elif item.scope is ExceptionScope.RECIPIENT_GROUP:
            members = {m.lower() for m in (groups or {}).get(item.value, ())}
            hit = bool(rcpts) and all(r in members for r in rcpts)
        elif item.scope is ExceptionScope.SOURCE_IP:
            try:
                hit = ipaddress.ip_address(source_ip) in ipaddress.ip_network(item.value, strict=False)
            except ValueError:
                hit = False
        elif item.scope is ExceptionScope.MESSAGE_ID:
            hit = bool(message_id) and message_id.strip("<>").lower() == value.strip("<>")
        elif item.scope is ExceptionScope.CAMPAIGN:
            hit = bool(campaign) and campaign.lower() == value
        elif item.scope is ExceptionScope.CONTROL:
            hit = True
        if hit:
            return item
    return None
