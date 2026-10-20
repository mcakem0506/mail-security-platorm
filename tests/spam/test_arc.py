"""ARC на настоящем Rspamd (ТЗ 1.2 §11, §38).

Цепочку ARC строит независимая реализация (dkimpy), как это делал бы список рассылки или
пересылающий сервер. ARC — контекст для пересылки и списков и DMARC автоматически не отменяет.
"""

from __future__ import annotations

from dkim import ARC
from msp_antispam.model import ArcResult, DmarcResult

from .harness import OTHER_IP, DkimKey
from .zone import Zone


def seal(raw: bytes, key: DkimKey, *, srv_id: bytes, results: bytes = b"spf=pass; dkim=pass") -> bytes:
    """Добавить набор ARC (i=N) к письму: Authentication-Results от srv_id и печать."""
    message = b"Authentication-Results: " + srv_id + b"; " + results + b"\r\n" + raw
    arc = ARC(message)
    headers = arc.sign(key.selector.encode(), key.domain.encode(), key.private_pem, srv_id)
    return b"".join(headers) + message


def chain_records(spam, zone: Zone, *others: DkimKey) -> None:  # type: ignore[no-untyped-def]
    records = zone.records(spf="v=spf1 ip4:192.0.2.1 -all", dmarc="v=DMARC1; p=reject")
    for key in others:
        records[key.dns_name] = key.dns_record
        records[key.domain] = {"A": ["192.0.2.50"]}
    spam.dns.records(records)


def test_a_valid_single_hop_chain_is_arc_pass(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("arc")
    lists = DkimKey.generate("lists-hop.com", "arc1")
    chain_records(clean_spam, zone, lists)
    raw = seal(zone.message("arc-ok"), lists, srv_id=b"lists-hop.com")
    mid, result = clean_spam.send_from_zone(zone, "arc-ok", ip=OTHER_IP, raw=raw)
    assert result.get("ok"), result
    assert clean_spam.delivered(mid) is not None
    arc = clean_spam.auth_of(mid).arc
    assert arc.result is ArcResult.PASS and "lists-hop.com" in arc.signing_domains


def test_a_broken_seal_is_not_a_pass(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("arc")
    lists = DkimKey.generate("lists-bad.com", "arc1")
    chain_records(clean_spam, zone, lists)
    raw = seal(zone.message("arc-bad"), lists, srv_id=b"lists-bad.com")
    raw = raw.replace(b"d=lists-bad.com", b"d=other-bad.com")
    mid, result = clean_spam.send_from_zone(zone, "arc-bad", ip=OTHER_IP, raw=raw)
    assert result.get("ok")
    assert clean_spam.auth_of(mid).arc.result is not ArcResult.PASS


def test_a_chain_without_a_published_key_is_not_a_pass(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("arc")
    lists = DkimKey.generate("lists-nokey.com", "arc1")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject"))
    raw = seal(zone.message("arc-nokey"), lists, srv_id=b"lists-nokey.com")
    mid, _ = clean_spam.send_from_zone(zone, "arc-nokey", ip=OTHER_IP, raw=raw)
    assert clean_spam.auth_of(mid).arc.result is not ArcResult.PASS


def test_no_chain_is_none(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("arc")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc=None))
    mid, _ = clean_spam.send_from_zone(zone, "arc-none")
    assert clean_spam.auth_of(mid).arc.result is ArcResult.NONE


def test_a_valid_chain_does_not_rescue_a_failed_dmarc(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("arc")
    lists = DkimKey.generate("lists-keep.com", "arc1")
    chain_records(clean_spam, zone, lists)
    # Список изменил тело: подпись автора сломана, SPF не выровнен, ARC цел.
    raw = zone.message("arc-keep").replace("Содержимое".encode(), "Футер списка".encode())
    raw = seal(raw, lists, srv_id=b"lists-keep.com", results=b"spf=pass; dkim=pass; dmarc=pass")
    mid, result = clean_spam.send_from_zone(zone, "arc-keep", ip=OTHER_IP, raw=raw)
    assert result.get("ok")
    auth = clean_spam.auth_of(mid)
    assert auth.arc.result is ArcResult.PASS
    assert auth.dmarc.result is DmarcResult.FAIL, "ARC не отменяет DMARC автоматически"
