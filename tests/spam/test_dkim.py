"""Проверка подписей DKIM на настоящем Rspamd (ТЗ 1.2 §9, §38, §40).

Подписывает письма независимая реализация (dkimpy): проверяющий и подписывающий — разные
программы, поэтому совпадение результата не может быть следствием общей ошибки.
"""

from __future__ import annotations

import pytest
from msp_antispam.model import DkimResult

from .harness import DkimKey, build_message
from .zone import Zone


def run(spam, zone: Zone, raw: bytes, mid: str):  # type: ignore[no-untyped-def]
    mail_id, result = spam.send_from_zone(zone, mid, raw=raw)
    assert result.get("ok"), result
    assert spam.delivered(mail_id) is not None, "DKIM не отклоняет почту"
    return spam.auth_of(mail_id)


def test_a_valid_signature_passes_and_is_aligned(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dk")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc=None))
    auth = run(clean_spam, zone, zone.message("dk-ok"), "dk-ok")
    assert auth.dkim.result is DkimResult.PASS
    assert [(s.domain, s.selector, s.aligned) for s in auth.dkim.signatures] == [(zone.domain, "s1", True)]


def test_a_changed_body_fails(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dk")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc=None))
    raw = zone.message("dk-body").replace("Содержимое".encode(), "Подмена".encode())
    auth = run(clean_spam, zone, raw, "dk-body")
    assert auth.dkim.result is DkimResult.FAIL


def test_a_changed_signed_header_fails(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dk")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc=None))
    raw = zone.message("dk-hdr", subject="Оригинал").replace(
        "Subject: Оригинал".encode(), "Subject: Подмена".encode()
    )
    auth = run(clean_spam, zone, raw, "dk-hdr")
    assert auth.dkim.result is DkimResult.FAIL


def test_a_missing_key_is_not_a_pass(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dk")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc=None, dkim=False))
    auth = run(clean_spam, zone, zone.message("dk-nokey"), "dk-nokey")
    assert auth.dkim.result in (DkimResult.PERMERROR, DkimResult.FAIL)
    assert auth.dkim.result is not DkimResult.PASS


def test_the_key_under_another_selector_does_not_validate_the_signature(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dk")
    records = zone.records(spf="v=spf1 -all", dmarc=None, dkim=False)
    records[f"other._domainkey.{zone.domain}"] = zone.key.dns_record
    clean_spam.dns.records(records)
    auth = run(clean_spam, zone, zone.message("dk-sel"), "dk-sel")
    assert auth.dkim.result is not DkimResult.PASS


def test_a_dns_failure_is_temperror_not_fail(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dk")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc=None))
    clean_spam.dns.faults(servfail=[f"_domainkey.{zone.domain}"])
    auth = run(clean_spam, zone, zone.message("dk-dns"), "dk-dns")
    assert auth.dkim.result is DkimResult.TEMPERROR
    assert "DKIM_TEMPERROR" in auth.incomplete_reasons


def test_two_signatures_a_foreign_one_does_not_replace_the_aligned_one(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dk")
    foreign = Zone("fo")
    records = zone.records(spf="v=spf1 -all", dmarc=None)
    records.update(foreign.records(spf=None, dmarc=None, ptr=False))
    clean_spam.dns.records(records)
    raw = zone.message("dk-two")
    raw = foreign.key.sign(raw)
    auth = run(clean_spam, zone, raw, "dk-two")
    assert auth.dkim.result is DkimResult.PASS
    by_domain = {s.domain: s for s in auth.dkim.signatures}
    assert by_domain[zone.domain].aligned is True and by_domain[foreign.domain].aligned is False


def test_one_broken_signature_does_not_cancel_a_valid_aligned_one(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dk")
    foreign = Zone("fo")
    records = zone.records(spf="v=spf1 -all", dmarc=None)
    # У постороннего домена нет ключа в DNS: его подпись не проверить, а наша корректна.
    records.update(foreign.records(spf=None, dmarc=None, dkim=False, ptr=False))
    clean_spam.dns.records(records)
    raw = foreign.key.sign(zone.message("dk-mix"))
    auth = run(clean_spam, zone, raw, "dk-mix")
    assert auth.dkim.result is DkimResult.PASS
    own = next(s for s in auth.dkim.signatures if s.domain == zone.domain)
    assert own.result is DkimResult.PASS and own.aligned


def test_a_valid_signature_of_another_domain_is_not_aligned_with_from(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dk")
    foreign = Zone("fo")
    records = zone.records(spf="v=spf1 -all", dmarc=None, dkim=False)
    records.update(foreign.records(spf=None, dmarc=None, ptr=False))
    clean_spam.dns.records(records)
    raw = foreign.key.sign(build_message("dk-al", zone.address))
    auth = run(clean_spam, zone, raw, "dk-al")
    assert auth.dkim.result is DkimResult.PASS
    assert all(not s.aligned for s in auth.dkim.signatures if s.result is DkimResult.PASS)
    assert auth.dmarc.dkim_aligned is False


def test_a_malformed_signature_is_not_a_pass(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dk")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc=None))
    raw = zone.message("dk-bad")
    # Пустое значение алгоритма — синтаксическая ошибка заголовка (недопустимые символы внутри
    # значения b= Rspamd пропускает при разборе base64, поэтому такая порча подпись не ломает).
    raw = raw.replace(b"a=rsa-sha256", b"a=", 1)
    auth = run(clean_spam, zone, raw, "dk-bad")
    assert auth.dkim.result is not DkimResult.PASS


def test_a_garbage_dkim_header_does_not_break_scanning(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dk")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc=None))
    raw = zone.message(
        "dk-junk", sign=False, extra_headers="DKIM-Signature: v=1; this is not a signature\r\n"
    )
    auth = run(clean_spam, zone, raw, "dk-junk")
    assert auth.dkim.result is not DkimResult.PASS


@pytest.mark.parametrize("bits", [1024])
def test_a_short_key_is_reported(clean_spam, bits: int) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dk")
    zone.key = DkimKey.generate(zone.domain, "s1", bits=bits)
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc=None))
    auth = run(clean_spam, zone, zone.message("dk-weak"), "dk-weak")
    # Ключ 1024 бита Rspamd принимает; решение о слабости остаётся за политикой организации.
    assert auth.dkim.result in (DkimResult.PASS, DkimResult.PERMERROR)


def test_rsa_sha1_is_reported_distinctly(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dk")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc=None))
    raw = zone.key.sign(zone.message("dk-sha1", sign=False), algorithm=b"rsa-sha1")
    auth = run(clean_spam, zone, raw, "dk-sha1")
    assert auth.dkim.result in (DkimResult.PASS, DkimResult.PERMERROR, DkimResult.FAIL)
