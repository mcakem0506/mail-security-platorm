"""Послеочередной шлюз: разбор письма, внутренние получатели, форма письма при повторной подаче."""

from __future__ import annotations

from msp_enforcement.afterqueue import INTERNAL_RECIPIENT_DOMAINS, AfterQueue, wire_form


def test_bare_lf_becomes_crlf_and_crlf_is_left_alone() -> None:
    assert wire_form(b"a\nb\r\nc\n") == b"a\r\nb\r\nc\r\n"
    already = b"From: a\r\nTo: b\r\n\r\nbody\r\n"
    assert wire_form(already) == already


def test_wire_form_is_idempotent() -> None:
    once = wire_form(b"x\ny\n")
    assert wire_form(once) == once


def test_the_journal_copy_address_is_not_a_recipient() -> None:
    assert "journal.msp.invalid" in INTERNAL_RECIPIENT_DOMAINS


def test_the_postfix_received_header_gives_queue_id_and_client_address() -> None:
    raw = (
        b"Received: from mail.example.test (unknown [203.0.113.7])\r\n\tby gw.lab.example (Postfix) with ESMTP id 4ABC123DEF\r\n"
        b"\tfor <ivan@corp.example>; Mon, 12 Oct 2026 10:00:00 +0000\r\n"
        b"Message-ID: <m1@example.test>\r\nSubject: Hello\r\n\r\nbody\r\n"
    )
    meta = AfterQueue.parse(raw)
    assert meta["queue_id"] == "4ABC123DEF" and meta["client_ip"] == "203.0.113.7"
    assert meta["message_id"] == "m1@example.test" and meta["subject"] == "Hello"


def test_a_message_without_received_headers_does_not_break_parsing() -> None:
    meta = AfterQueue.parse(b"Subject: x\r\n\r\nbody\r\n")
    assert meta["queue_id"] == "" and meta["client_ip"] == ""
