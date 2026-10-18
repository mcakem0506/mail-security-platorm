"""Жизненный цикл ключей подписи DKIM и ротация (ТЗ 1.2 §22–§24).

Закрытый ключ не хранится в базе: модель знает только ссылку на секрет (``private_key_ref``),
а само значение возвращается один раз при генерации и должно сразу попасть в хранилище секретов.

Цепочка ротации::

    generate selector → publish DNS → verify DNS → activate → overlap → retire old

Активация запрещена, пока не выполнено всё: запись TXT существует, ключ в ней совпадает с
сгенерированным, селектор правильный, DNS виден. Подпись допускается только на доверенном
исходящем пути Exchange → шлюз; внешний отправитель корпоративной подписи не получает.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyStatus(StrEnum):
    GENERATED = "GENERATED"
    DNS_PENDING = "DNS_PENDING"
    READY = "READY"
    ACTIVE = "ACTIVE"
    RETIRING = "RETIRING"
    RETIRED = "RETIRED"
    FAILED = "FAILED"


class KeyError_(ValueError):
    pass


_SELECTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{0,62}$")
_DOMAIN = re.compile(r"^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

#: Минимальный размер ключа: слабее считается небезопасным.
MIN_BITS = 2048
DEFAULT_OVERLAP = timedelta(days=7)


@dataclass(frozen=True)
class DkimSigningKey:
    domain: str
    selector: str
    algorithm: str
    public_record: str
    private_key_ref: str
    created_at: datetime
    status: KeyStatus = KeyStatus.GENERATED
    activate_at: datetime | None = None
    retire_at: datetime | None = None
    generated_by: str = ""
    activated_by: str = ""
    failure: str = ""

    @property
    def dns_name(self) -> str:
        return f"{self.selector}._domainkey.{self.domain}"

    @property
    def public_key_b64(self) -> str:
        match = re.search(r"\bp=([A-Za-z0-9+/=\s]+)", self.public_record)
        return re.sub(r"\s+", "", match.group(1)) if match else ""

    @property
    def is_signing(self) -> bool:
        return self.status in (KeyStatus.ACTIVE, KeyStatus.RETIRING)


def generate(
    domain: str,
    selector: str,
    *,
    generated_by: str,
    secret_dir: str = "/run/secrets/rspamd/dkim",  # noqa: S107
    now: datetime | None = None,
) -> tuple[DkimSigningKey, bytes]:
    """Новый ключ. Закрытая часть (PEM) возвращается ОДИН раз и в модель не попадает."""
    domain = domain.lower().strip(".")
    if not _DOMAIN.match(domain):
        raise KeyError_("неверное имя домена")
    if not _SELECTOR.match(selector):
        raise KeyError_("неверный селектор")
    private = rsa.generate_private_key(public_exponent=65537, key_size=MIN_BITS)
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    public = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    record = f"v=DKIM1; k=rsa; p={base64.b64encode(public).decode()}"
    key = DkimSigningKey(
        domain=domain,
        selector=selector,
        algorithm="rsa-sha256",
        public_record=record,
        private_key_ref=f"{secret_dir}/{domain}.{selector}.key",
        created_at=now or datetime.now(UTC),
        generated_by=generated_by,
    )
    return key, pem


def mark_dns_pending(key: DkimSigningKey) -> DkimSigningKey:
    if key.status is not KeyStatus.GENERATED:
        raise KeyError_("публикация возможна только для только что созданного ключа")
    return replace(key, status=KeyStatus.DNS_PENDING)


@dataclass(frozen=True)
class DnsCheck:
    ok: bool
    problems: tuple[str, ...] = ()


def check_dns(key: DkimSigningKey, txt_records: list[str] | None, *, dns_error: bool = False) -> DnsCheck:
    """Сверить опубликованную запись с ключом. ``txt_records=None`` — записи нет."""
    problems: list[str] = []
    if dns_error:
        return DnsCheck(False, ("DNS_NOT_VISIBLE",))
    if not txt_records:
        return DnsCheck(False, ("TXT_MISSING",))
    published = [" ".join(str(r).split()) for r in txt_records]
    candidates = [r for r in published if "v=DKIM1" in r or "p=" in r]
    if not candidates:
        return DnsCheck(False, ("TXT_NOT_DKIM",))
    matched = False
    for record in candidates:
        m = re.search(r"\bp=([A-Za-z0-9+/=\s]*)", record)
        value = re.sub(r"\s+", "", m.group(1)) if m else ""
        if value == key.public_key_b64:
            matched = True
        elif not value:
            problems.append("KEY_REVOKED_OR_EMPTY")
    if not matched:
        problems.append("KEY_MISMATCH")
    return DnsCheck(matched and not problems, tuple(problems))


def verify_dns(
    key: DkimSigningKey, txt_records: list[str] | None, *, dns_error: bool = False
) -> DkimSigningKey:
    if key.status not in (KeyStatus.DNS_PENDING, KeyStatus.READY):
        raise KeyError_("проверка DNS возможна для ключа, ожидающего публикации")
    result = check_dns(key, txt_records, dns_error=dns_error)
    if result.ok:
        return replace(key, status=KeyStatus.READY, failure="")
    # Проблема публикации — не поломка ключа: остаётся DNS_PENDING, активация запрещена.
    return replace(key, status=KeyStatus.DNS_PENDING, failure=",".join(result.problems))


def activate(
    key: DkimSigningKey, *, approver: str, trusted_domains: set[str], now: datetime | None = None
) -> DkimSigningKey:
    """Активация: только READY, только лабораторный/пилотный домен, только вторым человеком."""
    if key.status is not KeyStatus.READY:
        raise KeyError_("активация запрещена: запись DNS не проверена")
    if key.domain not in trusted_domains:
        raise KeyError_("подпись разрешена только для лабораторного или пилотного домена")
    if not approver or approver == key.generated_by:
        raise KeyError_("ключ активирует не тот, кто его создал (четыре глаза)")
    return replace(key, status=KeyStatus.ACTIVE, activate_at=now or datetime.now(UTC), activated_by=approver)


def begin_retirement(
    key: DkimSigningKey, *, now: datetime | None = None, overlap: timedelta = DEFAULT_OVERLAP
) -> DkimSigningKey:
    if key.status is not KeyStatus.ACTIVE:
        raise KeyError_("выводить из работы можно только действующий ключ")
    moment = now or datetime.now(UTC)
    return replace(key, status=KeyStatus.RETIRING, retire_at=moment + overlap)


def retire(key: DkimSigningKey, *, now: datetime | None = None) -> DkimSigningKey:
    if key.status is not KeyStatus.RETIRING:
        raise KeyError_("сначала ключ должен перейти в RETIRING")
    moment = now or datetime.now(UTC)
    if key.retire_at and moment < key.retire_at:
        raise KeyError_("период перекрытия ещё не истёк: старые подписи ещё проверяются получателями")
    return replace(key, status=KeyStatus.RETIRED)


def fail(key: DkimSigningKey, reason: str) -> DkimSigningKey:
    return replace(key, status=KeyStatus.FAILED, failure=reason[:200])


def signing_selectors(keys: list[DkimSigningKey]) -> dict[str, DkimSigningKey]:
    """Ключ для подписи по домену. Новый (ACTIVE) предпочтительнее старого (RETIRING)."""
    out: dict[str, DkimSigningKey] = {}
    for key in sorted(keys, key=lambda k: (k.status is not KeyStatus.ACTIVE, k.created_at)):
        if key.is_signing and key.domain not in out:
            out[key.domain] = key
    return out
