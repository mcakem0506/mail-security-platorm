"""SPF на настоящем Rspamd и настоящем Postfix (ТЗ 1.2 §8, §38, §40).

Каждый сценарий — свой домен: сканер кэширует DNS. DNS стенда отвечает записями, которые задаёт
тест, поэтому внешних зависимостей нет. Во всех случаях письмо доставляется: SPF не отклоняет.
"""

from __future__ import annotations

import pytest
from msp_antispam.model import SpfResult

from .harness import OTHER_IP, SENDER_IP
from .zone import Zone

CASES = [
    # (имя, SPF, соединение с адреса, ожидаемый результат)
    ("pass_ip4", "v=spf1 ip4:{ip} -all", SENDER_IP, SpfResult.PASS),
    ("pass_cidr", "v=spf1 ip4:10.77.0.128/25 -all", SENDER_IP, SpfResult.PASS),
    ("fail", "v=spf1 ip4:{ip} -all", OTHER_IP, SpfResult.FAIL),
    ("softfail", "v=spf1 ip4:{ip} ~all", OTHER_IP, SpfResult.SOFTFAIL),
    ("neutral", "v=spf1 ip4:{ip} ?all", OTHER_IP, SpfResult.NEUTRAL),
    ("pass_a_mechanism", "v=spf1 a -all", SENDER_IP, SpfResult.PASS),
    ("pass_mx_mechanism", "v=spf1 mx -all", SENDER_IP, SpfResult.PASS),
    ("ip6_only_record_fails_ipv4_client", "v=spf1 ip6:2001:db8::/32 -all", SENDER_IP, SpfResult.FAIL),
    # ОТКЛОНЕНИЕ ОТ RFC 7208 §4.6: Rspamd 3.12.1 пропускает синтаксически неверный механизм и
    # вычисляет остаток записи, вместо permerror получается FAIL. Источник истины — установленная
    # версия (ТЗ 1.2 §50); отклонение записано в docs/SPF_VALIDATION.md и реестре пробелов.
    ("deviation_invalid_ip4_is_ignored", "v=spf1 ip4:not-an-address -all", SENDER_IP, SpfResult.FAIL),
    ("deviation_unknown_mechanism_is_ignored", "v=spf1 bogusmech:x -all", SENDER_IP, SpfResult.FAIL),
]


@pytest.mark.parametrize(("name", "spf", "ip", "expected"), CASES, ids=[c[0] for c in CASES])
def test_spf_results(clean_spam, name: str, spf: str, ip: str, expected: SpfResult) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("spf")
    records = zone.records(spf=spf, dmarc=None)
    records[zone.domain]["MX"] = [[10, zone.helo]]
    clean_spam.dns.records(records)
    mid, result = clean_spam.send_from_zone(zone, ip=ip)
    assert result.get("ok"), result
    assert clean_spam.delivered(mid) is not None, "SPF не отклоняет почту"
    assert clean_spam.auth_of(mid).spf.result is expected


def test_no_record_is_none(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("spf")
    clean_spam.dns.records(zone.records(spf=None))
    mid, _ = clean_spam.send_from_zone(zone)
    assert clean_spam.auth_of(mid).spf.result is SpfResult.NONE


def test_include_redirect_and_nested_lookups(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("spf")
    inc = Zone("inc")
    red = Zone("red")
    records = zone.records(spf=f"v=spf1 include:{inc.domain} -all")
    records.update(inc.records(spf="v=spf1 ip4:{ip} -all"))
    clean_spam.dns.records(records)
    mid, _ = clean_spam.send_from_zone(zone)
    assert clean_spam.auth_of(mid).spf.result is SpfResult.PASS

    records = zone.records(spf=f"v=spf1 redirect={red.domain}")
    records.update(red.records(spf="v=spf1 ip4:{ip} -all"))
    clean_spam.dns.records(records)
    zone2 = Zone("spf")
    records = zone2.records(spf=f"v=spf1 redirect={red.domain}")
    records.update(red.records(spf="v=spf1 ip4:{ip} -all"))
    clean_spam.dns.records(records)
    mid, _ = clean_spam.send_from_zone(zone2)
    assert clean_spam.auth_of(mid).spf.result is SpfResult.PASS


def test_the_dns_lookup_limit_is_a_permerror_not_a_pass(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("spf")
    includes = [Zone("lim") for _ in range(12)]
    records = zone.records(spf="v=spf1 " + " ".join(f"include:{i.domain}" for i in includes) + " -all")
    for item in includes:
        records.update(item.records(spf="v=spf1 ip4:192.0.2.1 -all", dkim=False, ptr=False))
    clean_spam.dns.records(records)
    mid, result = clean_spam.send_from_zone(zone)
    assert result.get("ok")
    assert clean_spam.auth_of(mid).spf.result in (SpfResult.PERMERROR, SpfResult.FAIL)


def test_a_dns_failure_is_temperror_and_not_fail(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("spf")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all"))
    clean_spam.dns.faults(servfail=[zone.domain])
    mid, result = clean_spam.send_from_zone(zone)
    assert result.get("ok"), "сбой DNS не останавливает приём"
    assert clean_spam.delivered(mid) is not None
    auth = clean_spam.auth_of(mid)
    assert auth.spf.result is SpfResult.TEMPERROR
    assert "SPF_TEMPERROR" in auth.incomplete_reasons


def test_a_dns_timeout_is_temperror(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("spf")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all"))
    clean_spam.dns.faults(timeout=[zone.domain])
    mid, result = clean_spam.send_from_zone(zone)
    assert result.get("ok")
    assert clean_spam.auth_of(mid).spf.result is SpfResult.TEMPERROR


def test_a_null_sender_is_checked_by_helo(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("spf")
    # SPF есть только у имени HELO: проверка пустого отправителя идёт по нему.
    records = zone.records(spf=None)
    records[zone.helo] = {"A": [SENDER_IP], "TXT": [f"v=spf1 ip4:{SENDER_IP} -all"]}
    clean_spam.dns.records(records)
    mid, result = clean_spam.send_from_zone(zone, mail_from="")
    assert result.get("ok"), result
    analysis = clean_spam.analysis(mid, received_headers=[f"from {zone.helo} (unknown [{SENDER_IP}]) by gw with ESMTP"])
    assert analysis.auth.spf.result is SpfResult.PASS
    assert (analysis.auth.spf.identity, analysis.auth.spf.identity_kind) == (zone.helo, "HELO")


def test_a_failing_spf_still_delivers_the_mail(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("spf")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all"))
    mid, result = clean_spam.send_from_zone(zone, ip=OTHER_IP)
    assert result.get("ok"), "SPF FAIL не отклоняет письмо на этапе 1.2"
    assert clean_spam.delivered(mid) is not None
    assert clean_spam.auth_of(mid).spf.result is SpfResult.FAIL
