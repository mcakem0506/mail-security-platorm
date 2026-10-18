"""Rspamd подключён через Milter, почта доставляется, результат сканирования приходит в MSP
(ТЗ 1.2 §4, §5, §40)."""

from __future__ import annotations

from .harness import SENDER_IP, build_message


def test_inbound_mail_is_scanned_and_delivered(clean_spam) -> None:  # type: ignore[no-untyped-def]
    spam = clean_spam
    mid, result = spam.send_inbound()
    assert result.get("ok"), result
    assert spam.delivered(mid) is not None, spam.rspamd_log()
    scan = spam.scan_for(mid)
    names = set(scan["symbols"]) if isinstance(scan["symbols"], dict) else {s["name"] for s in scan["symbols"]}
    assert "MSP_DIRECTION_INBOUND" in names, sorted(names)


def test_outbound_mail_gets_the_outbound_direction(clean_spam) -> None:  # type: ignore[no-untyped-def]
    spam = clean_spam
    mid, result = spam.send_outbound()
    assert result.get("ok"), result
    scan = spam.scan_for(mid)
    names = set(scan["symbols"]) if isinstance(scan["symbols"], dict) else {s["name"] for s in scan["symbols"]}
    assert "MSP_DIRECTION_OUTBOUND" in names, sorted(names)
    assert SENDER_IP and build_message("x", "a@b.example")
