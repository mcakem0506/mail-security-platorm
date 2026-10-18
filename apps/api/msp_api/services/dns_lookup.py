"""Проверка опубликованных записей DNS для ключей подписи DKIM (ТЗ 1.2 §23).

Активация ключа разрешена только после того, как запись TXT видна в DNS и совпадает с ключом. Эта
проверка выполняется самой панелью, а не со слов оператора: «опубликовано» должно быть
подтверждено тем же способом, каким запись увидит получатель.
"""

from __future__ import annotations

import logging

import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)


def txt_records(
    name: str, *, nameservers: tuple[str, ...] = (), timeout: float = 3.0
) -> tuple[list[str] | None, bool]:
    """(записи, ошибка). ``None`` без ошибки — записи нет; ошибка — DNS недоступен или ответил сбоем."""
    resolver = dns.resolver.Resolver(configure=not nameservers)
    if nameservers:
        resolver.nameservers = list(nameservers)
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None, False
    except (dns.exception.DNSException, OSError) as exc:
        logger.info("dns_lookup.failed", extra={"error": type(exc).__name__})
        return None, True
    records = [b"".join(item.strings).decode("utf-8", "replace") for item in answer]
    return records, False
