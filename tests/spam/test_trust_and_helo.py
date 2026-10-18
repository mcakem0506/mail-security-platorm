"""Доверие к заголовкам, непрозрачный идентификатор и HELO/PTR на настоящем стенде (ТЗ 1.2 §7, §12, §16, §31)."""

from __future__ import annotations

import base64
import re

from msp_antispam.authres import inspect_headers
from msp_antispam.model import HeloSignal, PtrState

from .harness import OTHER_IP, SENDER_IP, build_message
from .zone import Zone, reverse_name

SCANNER_HEADERS = re.compile(rb"(?im)^(X-Spam[a-z\-]*|X-Rspamd[a-z\-]*|X-Spamd[a-z\-]*):")


def raw_at_exchange(spam, mid: str) -> bytes:  # type: ignore[no-untyped-def]
    for control in (spam.exchange1, spam.exchange2):
        for item in control.received():
            if mid in str(item.get("message_id", "")):
                return base64.b64decode(str(item["raw_b64"]))
    raise AssertionError(f"письмо {mid} не найдено у Exchange")


def test_no_scanner_verdict_or_score_headers_reach_the_recipient(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("tr")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject"))
    # Письмо с очень плохой оценкой: сканер обычно добавил бы X-Spam и другие заголовки.
    mid, result = clean_spam.send_from_zone(zone, ip=OTHER_IP, sign=False)
    assert result.get("ok")
    assert clean_spam.delivered(mid) is not None
    raw = raw_at_exchange(clean_spam, mid)
    assert not SCANNER_HEADERS.search(raw), "оценка или решение сканера попали в письмо"
    assert b"X-MSP-Scan-ID:" in raw, "непрозрачный идентификатор сканирования отсутствует"


def test_forged_scanner_headers_from_the_internet_are_removed(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("tr")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject"))
    forged = (
        "X-Spamd-Result: default: False [-99.00 / 15.00]\r\nX-Spam-Status: No, score=-99\r\n"
        "X-Spam: No\r\nX-Rspamd-Score: -99\r\nX-MSP-Scan-ID: forged-scan-id\r\n"
    )
    raw = zone.message("tr-forged", sign=False, extra_headers=forged)
    mid, result = clean_spam.send_from_zone(zone, "tr-forged", ip=OTHER_IP, raw=raw)
    assert result.get("ok") and clean_spam.delivered(mid) is not None
    delivered = raw_at_exchange(clean_spam, mid)
    assert not SCANNER_HEADERS.search(delivered.replace(b"X-MSP-Scan-ID", b"")), "подделка дошла до получателя"
    assert b"forged-scan-id" not in delivered, "подделанный идентификатор сканирования остался"


def test_the_evidence_comes_from_the_scan_record_not_from_forged_headers(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("tr")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject"))
    forged = "X-Spamd-Result: default: False [-99.00 / 15.00]\r\nX-Spam-Status: No\r\n"
    raw = zone.message("tr-ev", sign=False, extra_headers=forged)
    mid, _ = clean_spam.send_from_zone(zone, "tr-ev", ip=OTHER_IP, raw=raw)
    analysis = clean_spam.analysis(mid)
    assert analysis.evidence.score > 0, "оценка взята из заголовка письма"
    assert analysis.auth.spf.result.value == "FAIL"


def test_a_forged_authentication_results_with_our_id_is_flagged(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("tr")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject"))
    forged = "Authentication-Results: gw.lab.example; spf=pass; dkim=pass; dmarc=pass\r\n"
    raw = zone.message("tr-ar", sign=False, extra_headers=forged)
    mid, _ = clean_spam.send_from_zone(zone, "tr-ar", ip=OTHER_IP, raw=raw)
    assert clean_spam.delivered(mid) is not None
    delivered = raw_at_exchange(clean_spam, mid)
    headers = re.findall(rb"(?im)^Authentication-Results:.*(?:\r?\n[ \t].*)*", delivered.split(b"\r\n\r\n", 1)[0])
    texts = [h.decode("utf-8", "replace") for h in headers]
    assert len(texts) >= 2, "ожидались собственный и подделанный заголовки"
    analysis = clean_spam.analysis(mid)
    finding = inspect_headers(texts, "gw.lab.example", analysis.auth)
    assert finding.tampered, "подделка с нашим authserv-id не обнаружена"
    # Подделка не повлияла на доказательство: SPF по записи сканера — FAIL, а не заявленный pass.
    assert analysis.auth.spf.result.value == "FAIL"


def test_our_authentication_results_uses_a_unique_authserv_id(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("tr")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all", dmarc="v=DMARC1; p=reject"))
    mid, _ = clean_spam.send_from_zone(zone)
    delivered = raw_at_exchange(clean_spam, mid)
    match = re.search(rb"(?im)^Authentication-Results:\s*([^;\s]+)", delivered)
    assert match and match.group(1) == b"gw.lab.example", "authserv-id должен совпадать с именем узла"


def test_an_upstream_authentication_results_is_kept_for_comparison(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("tr")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all", dmarc="v=DMARC1; p=reject"))
    upstream = "Authentication-Results: ksmg.corp.example; spf=pass; dkim=pass; dmarc=pass\r\n"
    raw = zone.message("tr-up", extra_headers=upstream)
    mid, _ = clean_spam.send_from_zone(zone, "tr-up", raw=raw)
    delivered = raw_at_exchange(clean_spam, mid)
    assert b"ksmg.corp.example" in delivered, "результаты вышестоящего шлюза удалены"
    assert b"gw.lab.example" in delivered


# --- HELO и PTR ---------------------------------------------------------------------------
def test_a_published_ptr_is_present_but_not_confirmed_when_postfix_lookup_is_off(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("hp")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all", dmarc=None))  # PTR и A для HELO заданы
    mid, _ = clean_spam.send_from_zone(zone)
    received = [f"from {zone.helo} (unknown [{SENDER_IP}]) by gw"]
    analysis = clean_spam.analysis(mid, received_headers=received, peername_lookup=False)
    # Поиск имени в Postfix стенда выключен: прямая проверка не выполнялась, подтверждения нет.
    assert analysis.helo.ptr_state is PtrState.PTR_PRESENT
    # Если бы Postfix её выполнил и записал имя, состояние было бы FCrDNS_PASS.
    confirmed = [f"from {zone.helo} ({zone.helo} [{SENDER_IP}]) by gw"]
    assert clean_spam.analysis(mid, received_headers=confirmed).helo.ptr_state is PtrState.FCRDNS_PASS


def test_a_missing_ptr_is_reported_as_none_not_as_a_verdict(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("hp")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all", dmarc=None, ptr=False))
    mid, result = clean_spam.send_from_zone(zone)
    assert result.get("ok") and clean_spam.delivered(mid) is not None
    analysis = clean_spam.analysis(mid, received_headers=[f"from {zone.helo} (unknown [{SENDER_IP}]) by gw"])
    assert analysis.helo.ptr_state is PtrState.NONE


def test_a_ptr_that_does_not_resolve_back_is_fcrdns_fail_when_postfix_checked_it(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("hp")
    records = zone.records(spf="v=spf1 ip4:{ip} -all", dmarc=None, ptr=False)
    records[reverse_name(SENDER_IP)] = {"PTR": ["liar.elsewhere.com"]}
    records["liar.elsewhere.com"] = {"A": ["192.0.2.99"]}
    clean_spam.dns.records(records)
    mid, _ = clean_spam.send_from_zone(zone)
    # Postfix с включённым поиском имени пишет «unknown», когда прямая запись не подтвердила адрес, а
    # сканер при этом PTR видит. Именно это сочетание и есть провал FCrDNS.
    analysis = clean_spam.analysis(mid, received_headers=[f"from {zone.helo} (unknown [{SENDER_IP}]) by gw"])
    assert analysis.helo.ptr_state is PtrState.FCRDNS_FAIL


def test_helo_signals_are_evidence_and_never_reject(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("hp")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all", dmarc=None))
    for helo, expected in (("[10.77.0.150]", HeloSignal.IP_LITERAL), ("exchange01.corp.local", HeloSignal.INTERNAL_ONLY_FROM_EXTERNAL)):
        mid, result = clean_spam.send_from_zone(zone, helo=helo)
        assert result.get("ok"), f"HELO {helo} отвергнут: {result}"
        assert clean_spam.delivered(mid) is not None
        analysis = clean_spam.analysis(mid, received_headers=[f"from {helo} (unknown [{SENDER_IP}]) by gw"])
        assert expected in analysis.helo.signals
    assert build_message("x", "a@b.example")
