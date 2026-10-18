"""Подпись DKIM исходящей почты Rspamd (ТЗ 1.2 §22–§24, §40).

Подписывает Rspamd, а проверяет независимая программа (dkimpy) по доставленным байтам и по открытому
ключу из DNS стенда. Главное свойство: корпоративную подпись получает только письмо с доверенного
пути Exchange → шлюз; внешний отправитель её получить не может.
"""

from __future__ import annotations

import base64
import re

import dkim
import pytest
from msp_antispam import dkim_keys
from msp_antispam.rspamd_config import DkimSigning, SigningDomain

from tests.gateway.harness import TRUSTED_NETWORK

from .harness import SENDER_IP, build_message, node_config

DOMAIN = "corp.example"
KEY_DIR = "/run/secrets/rspamd/dkim"


def install_key(spam, selector: str, *, domain: str = DOMAIN):  # type: ignore[no-untyped-def]
    key, pem = dkim_keys.generate(domain, selector, generated_by="alice", secret_dir=KEY_DIR)
    directory = spam.workdir / "secrets" / "rspamd" / "dkim"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{domain}.{selector}.key"
    path.write_bytes(pem)
    path.chmod(0o644)
    return key


def signing(*keys: dkim_keys.DkimSigningKey, networks: tuple[str, ...] = (TRUSTED_NETWORK,)) -> DkimSigning:
    return DkimSigning(
        enabled=True,
        sign_networks=networks,
        domains=tuple(SigningDomain(domain=k.domain, selector=k.selector, private_key_file=k.private_key_ref) for k in keys),
    )


@pytest.fixture
def active(spam):  # type: ignore[no-untyped-def]
    def apply(*keys: dkim_keys.DkimSigningKey) -> None:
        outcome = spam.reapply_rspamd(node_config(dkim_signing=signing(*keys)))
        assert outcome["outcome"] == "ACTIVE", outcome

    yield apply
    spam.reapply_rspamd(node_config())


def verify(raw: bytes, *keys: dkim_keys.DkimSigningKey) -> bool:
    """Независимая проверка подписи по открытым ключам (как их видел бы получатель)."""
    table = {k.dns_name: k.public_record.encode() for k in keys}

    def lookup(name: bytes | str, timeout: int = 5) -> bytes | None:
        key = name.decode() if isinstance(name, bytes) else name
        return table.get(key.rstrip("."))

    return bool(dkim.verify(raw, dnsfunc=lookup))


def delivered_raw(control, message_id: str) -> bytes:  # type: ignore[no-untyped-def]
    for item in control.received():
        if message_id in str(item.get("message_id", "")):
            return base64.b64decode(str(item["raw_b64"]))
    raise AssertionError(f"письмо {message_id} не найдено")


def wait_sink(spam, mid: str) -> bytes:  # type: ignore[no-untyped-def]
    spam.wait_until(lambda: any(mid in m for m in spam.sink.message_ids()), timeout=90, what="письмо у приёмника")
    return delivered_raw(spam.sink, mid)


def signature_headers(raw: bytes) -> list[bytes]:
    head = raw.split(b"\r\n\r\n", 1)[0]
    return re.findall(rb"(?im)^DKIM-Signature:.*(?:\r?\n[ \t].*)*", head)


def test_corporate_mail_from_the_trusted_path_is_signed_and_verifies(clean_spam, active) -> None:  # type: ignore[no-untyped-def]
    key = install_key(clean_spam, "s2026")
    active(key)
    mid, result = clean_spam.send_outbound(mail_from=f"ivan@{DOMAIN}")
    assert result.get("ok"), result
    raw = wait_sink(clean_spam, mid)
    headers = signature_headers(raw)
    assert len(headers) == 1 and b"d=corp.example" in headers[0] and b"s=s2026" in headers[0]
    assert verify(raw, key), "независимая проверка подписи не прошла"


def test_an_alias_address_is_signed_with_the_same_domain_key(clean_spam, active) -> None:  # type: ignore[no-untyped-def]
    key = install_key(clean_spam, "s2026")
    active(key)
    mid, _ = clean_spam.send_outbound(mail_from=f"i.petrov@{DOMAIN}")
    raw = wait_sink(clean_spam, mid)
    assert verify(raw, key)


def test_a_null_envelope_sender_with_a_corporate_from_is_signed(clean_spam, active) -> None:  # type: ignore[no-untyped-def]
    key = install_key(clean_spam, "s2026")
    active(key)
    mid = "so-null-sender"
    raw = build_message(mid, f"ivan@{DOMAIN}", "partner@elsewhere.example")
    result = clean_spam.smtp_from(
        "10.77.0.70", "", ["partner@elsewhere.example"], raw, helo="exchange.lab.example", port=2525, starttls=True
    )
    assert result.get("ok"), result
    delivered = wait_sink(clean_spam, mid)
    assert verify(delivered, key)


def test_a_foreign_from_domain_from_trusted_exchange_is_not_signed(clean_spam, active) -> None:  # type: ignore[no-untyped-def]
    key = install_key(clean_spam, "s2026")
    active(key)
    mid, result = clean_spam.send_outbound(mail_from="someone@thirdparty.example")
    assert result.get("ok"), result
    raw = wait_sink(clean_spam, mid)
    assert signature_headers(raw) == [], "чужой домен подписан корпоративным ключом"


def test_a_spoofed_corporate_from_from_the_internet_is_never_signed(clean_spam, active) -> None:  # type: ignore[no-untyped-def]
    key = install_key(clean_spam, "s2026")
    active(key)
    mid, result = clean_spam.send_inbound(ip=SENDER_IP, mail_from=f"ceo@{DOMAIN}")
    assert result.get("ok"), result
    clean_spam.delivered(mid)
    raw = delivered_raw(clean_spam.exchange1 if mid in "".join(clean_spam.exchange1.message_ids()) else clean_spam.exchange2, mid)
    assert signature_headers(raw) == [], "внешний отправитель получил корпоративную подпись"


def test_an_untrusted_client_on_the_internal_port_cannot_get_a_signature(clean_spam, active) -> None:  # type: ignore[no-untyped-def]
    key = install_key(clean_spam, "s2026")
    active(key)
    result = clean_spam.smtp_from(
        "10.77.0.200", f"ceo@{DOMAIN}", ["partner@elsewhere.example"],
        build_message("untrusted-out", f"ceo@{DOMAIN}", "partner@elsewhere.example"),
        helo="evil.example", port=2525, starttls=True,
    )
    assert not result.get("ok"), "недоверенный источник принят на внутреннем порту"
    assert not any("untrusted-out" in m for m in clean_spam.sink.message_ids())


def test_two_from_headers_are_not_signed(clean_spam, active) -> None:  # type: ignore[no-untyped-def]
    key = install_key(clean_spam, "s2026")
    active(key)
    mid = "so-two-from"
    raw = build_message(mid, f"ivan@{DOMAIN}", "partner@elsewhere.example", extra_headers=f"From: ceo@{DOMAIN}\r\n")
    result = clean_spam.smtp_from(
        "10.77.0.70", f"ivan@{DOMAIN}", ["partner@elsewhere.example"], raw, helo="exchange.lab.example", port=2525, starttls=True
    )
    if not result.get("ok"):
        pytest.skip("Postfix отверг письмо с двумя From раньше сканера")
    delivered = wait_sink(clean_spam, mid)
    assert signature_headers(delivered) == []


def test_a_missing_private_key_means_unsigned_mail_not_lost_mail(clean_spam, active) -> None:  # type: ignore[no-untyped-def]
    key, _ = dkim_keys.generate(DOMAIN, "s-missing", generated_by="alice", secret_dir=KEY_DIR)  # файл ключа не создаётся
    active(key)
    mid, result = clean_spam.send_outbound(mail_from=f"ivan@{DOMAIN}")
    assert result.get("ok"), result
    raw = wait_sink(clean_spam, mid)
    assert signature_headers(raw) == []


def test_a_wrong_dns_record_fails_independent_verification(clean_spam, active) -> None:  # type: ignore[no-untyped-def]
    key = install_key(clean_spam, "s2026")
    other, _ = dkim_keys.generate(DOMAIN, "s2026", generated_by="alice")
    active(key)
    mid, _ = clean_spam.send_outbound(mail_from=f"ivan@{DOMAIN}")
    raw = wait_sink(clean_spam, mid)
    assert verify(raw, key)
    assert not verify(raw, other), "подпись прошла по чужому ключу"
    assert not dkim_keys.check_dns(key, [other.public_record]).ok


def test_selector_rotation_signs_with_the_new_selector_and_both_keys_verify(clean_spam, active) -> None:  # type: ignore[no-untyped-def]
    old = install_key(clean_spam, "s2026")
    new = install_key(clean_spam, "s2027")
    active(old)
    mid1, _ = clean_spam.send_outbound(mail_from=f"ivan@{DOMAIN}")
    raw1 = wait_sink(clean_spam, mid1)
    assert b"s=s2026" in signature_headers(raw1)[0]
    # Ротация: новый селектор опубликован и активирован, старый остаётся в DNS на время перекрытия.
    active(new)
    mid2, _ = clean_spam.send_outbound(mail_from=f"ivan@{DOMAIN}")
    raw2 = wait_sink(clean_spam, mid2)
    assert b"s=s2027" in signature_headers(raw2)[0]
    assert verify(raw1, old, new) and verify(raw2, old, new)
    assert not verify(raw2, old), "новая подпись не должна проходить без нового ключа в DNS"
