"""Область канарейки (ТЗ §18, §68, §69).

Выбор детерминирован: один и тот же получатель при повторе попадает в ту же сторону. Процент считается по
хэшу, а не по случайному числу, поэтому повтор SMTP-сессии не меняет область действия.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Iterable, Mapping

from pydantic import Field, field_validator

from .model import ControlType, Strict


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip().lower() if "@" in address else ""


class CanaryScope(Strict):
    """Селекторы объединяются по «или»; процент — дополнительное условие «и» (если задан).

    Пустая область (нет селекторов и процента) не выбирает никого: канарейка без явной области не должна
    молча стать «всей почтой».
    """

    recipients: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()
    sender_domains: tuple[str, ...] = ()
    source_cidrs: tuple[str, ...] = ()
    #: Домены получателей пилота.
    pilot_domains: tuple[str, ...] = ()
    percentage: float | None = Field(default=None, ge=0, le=100)
    salt: str = ""

    @field_validator("recipients", "sender_domains", "pilot_domains")
    @classmethod
    def _lower(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(v.strip().lower() for v in value)

    @field_validator("source_cidrs")
    @classmethod
    def _cidrs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            ipaddress.ip_network(item, strict=False)
        return value

    def is_empty(self) -> bool:
        return not (
            self.recipients
            or self.groups
            or self.sender_domains
            or self.source_cidrs
            or self.pilot_domains
            or self.percentage is not None
        )


def bucket(salt: str, control: ControlType | str, key: str) -> float:
    """Число от 0 до 100 (не включая 100), стабильное для (соль, контроль, ключ)."""
    digest = hashlib.sha256(f"{salt}|{getattr(control, 'value', control)}|{key.lower()}".encode()).digest()
    return int.from_bytes(digest[:8], "big") % 10000 / 100.0


def recipient_in_scope(
    scope: CanaryScope,
    control: ControlType,
    *,
    recipient: str,
    sender: str,
    source_ip: str,
    groups: Mapping[str, Iterable[str]] | None = None,
) -> bool:
    if scope.is_empty():
        return False
    rcpt = recipient.strip().lower()
    selectors = bool(
        scope.recipients or scope.groups or scope.sender_domains or scope.source_cidrs or scope.pilot_domains
    )
    matched = not selectors
    if selectors:
        if (
            rcpt in scope.recipients
            or _domain_of(rcpt) in scope.pilot_domains
            or _domain_of(sender.lower()) in scope.sender_domains
            or any(rcpt in {m.lower() for m in (groups or {}).get(g, ())} for g in scope.groups)
        ):
            matched = True
        elif source_ip:
            try:
                addr = ipaddress.ip_address(source_ip)
            except ValueError:
                addr = None
            if addr is not None and any(
                addr in ipaddress.ip_network(n, strict=False) for n in scope.source_cidrs
            ):
                matched = True
    if not matched:
        return False
    if scope.percentage is not None:
        return bucket(scope.salt, control, rcpt) < scope.percentage
    return True


def all_recipients_in_scope(
    scope: CanaryScope,
    control: ControlType,
    *,
    recipients: Iterable[str],
    sender: str,
    source_ip: str,
    groups: Mapping[str, Iterable[str]] | None = None,
) -> bool:
    """§68: разрушительное действие допустимо, только если в области все получатели письма."""
    items = list(recipients)
    if not items:
        return False
    return all(
        recipient_in_scope(scope, control, recipient=r, sender=sender, source_ip=source_ip, groups=groups)
        for r in items
    )
