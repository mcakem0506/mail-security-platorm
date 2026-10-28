"""Разбор журнального отчёта Exchange (MSP 1.3P, ТЗ §6, §10, §15)."""

from __future__ import annotations

from email.message import EmailMessage
from email.policy import SMTP

import pytest
from msp_mail_parser import journal as j


def original_message(
    body: str = "See attached invoice.", message_id: str = "<orig-1@corp.example>"
) -> EmailMessage:
    m = EmailMessage(policy=SMTP)
    m["From"] = "Ivan <ivan@corp.example>"
    m["To"] = "petr@corp.example"
    m["Subject"] = "Счёт"
    m["Message-ID"] = message_id
    m.set_content(body)
    return m


def report(
    originals: list[EmailMessage] | None = None,
    *,
    marked: bool = True,
    text: str | None = None,
    report_id: str = "<rep-1@exchange.corp.example>",
) -> bytes:
    r = EmailMessage(policy=SMTP)
    r["From"] = "journal@exchange.corp.example"
    r["To"] = "journal-in@corp.example"
    r["Subject"] = "Счёт"
    r["Message-ID"] = report_id
    if marked:
        r["X-MS-Journal-Report"] = ""
    r.set_content(
        text
        if text is not None
        else "Sender: ivan@corp.example\r\nSubject: Счёт\r\nMessage-Id: <orig-1@corp.example>\r\nRecipient: petr@corp.example\r\n"
    )
    for original in originals if originals is not None else [original_message()]:
        r.add_attachment(original, disposition="attachment")
    return r.as_bytes(policy=SMTP)


LIMIT = 1_000_000


class TestExtraction:
    def test_the_original_is_taken_from_the_attachment_and_not_the_report(self) -> None:
        result = j.extract_journal_report(report(), max_original_bytes=LIMIT)

        assert result.usable and result.is_journal_report
        assert b"Message-ID: <orig-1@corp.example>" in result.original
        assert b"X-MS-Journal-Report" not in result.original, "в анализ ушёл отчёт, а не письмо"
        assert result.original_message_id == "<orig-1@corp.example>"
        assert result.report_message_id == "<rep-1@exchange.corp.example>"
        assert result.problems == ()

    def test_the_envelope_is_kept_as_provenance(self) -> None:
        result = j.extract_journal_report(report(), max_original_bytes=LIMIT)
        assert result.envelope_sender == "ivan@corp.example"
        assert result.envelope_recipients == ("petr@corp.example",)

    def test_the_hashes_describe_the_original_and_the_report_separately(self) -> None:
        a = j.extract_journal_report(report(report_id="<rep-1@x>"), max_original_bytes=LIMIT)
        b = j.extract_journal_report(report(report_id="<rep-2@x>"), max_original_bytes=LIMIT)

        assert a.report_sha256 != b.report_sha256
        assert a.original_sha256 == b.original_sha256, (
            "два отчёта об одном письме должны давать один отпечаток оригинала"
        )


class TestUnusableReports:
    def test_a_message_without_the_journal_header_is_not_a_report(self) -> None:
        result = j.extract_journal_report(report(marked=False), max_original_bytes=LIMIT)
        assert not result.usable and not result.is_journal_report
        assert result.problems == (j.PROBLEM_NOT_A_REPORT,)

    def test_a_report_without_the_original_is_unusable_and_not_clean(self) -> None:
        result = j.extract_journal_report(report(originals=[]), max_original_bytes=LIMIT)
        assert not result.usable and result.original == b""
        assert j.PROBLEM_NO_ORIGINAL in result.problems

    def test_an_oversized_original_is_not_truncated_and_not_returned(self) -> None:
        big = original_message(body="x" * 5000)
        result = j.extract_journal_report(report([big]), max_original_bytes=1000)

        assert not result.usable
        assert result.original == b"", "оригинал сверх предела усечён и отдан на анализ"
        assert result.original_size > 1000
        assert j.PROBLEM_OVERSIZED in result.problems

    def test_a_report_inside_a_report_is_refused_so_the_journal_cannot_loop(self) -> None:
        inner = EmailMessage(policy=SMTP)
        inner["X-MS-Journal-Report"] = ""
        inner["Message-ID"] = "<inner@x>"
        inner.set_content("вложенный отчёт")
        result = j.extract_journal_report(report([inner]), max_original_bytes=LIMIT)

        assert not result.usable
        assert j.PROBLEM_NESTED in result.problems

    def test_several_originals_take_the_first_and_flag_the_rest(self) -> None:
        result = j.extract_journal_report(
            report([original_message(), original_message("другое", "<orig-2@corp.example>")]),
            max_original_bytes=LIMIT,
        )
        assert result.usable
        assert result.original_message_id == "<orig-1@corp.example>"
        assert j.PROBLEM_MULTIPLE in result.problems

    @pytest.mark.parametrize("garbage", [b"", b"\x00\x01\x02", b"\xff" * 5000, b"not a message at all"])
    def test_garbage_never_raises_and_is_never_usable(self, garbage: bytes) -> None:
        result = j.extract_journal_report(garbage, max_original_bytes=LIMIT)
        assert not result.usable
        assert result.problems


class TestEnvelopeHygiene:
    def test_control_characters_and_html_are_dropped_from_addresses(self) -> None:
        text = "Sender: <b>x</b>\x00evil@corp.example\r\nRecipient: a@corp.example\x07, b@corp.example\r\n"
        result = j.extract_journal_report(report(text=text), max_original_bytes=LIMIT)

        assert result.envelope_sender == "evil@corp.example"
        assert result.envelope_recipients == ("a@corp.example", "b@corp.example")

    def test_the_number_of_envelope_recipients_is_bounded(self) -> None:
        lines = "".join(f"Recipient: user{i}@corp.example\r\n" for i in range(1000))
        result = j.extract_journal_report(
            report(text="Sender: s@corp.example\r\n" + lines), max_original_bytes=LIMIT
        )
        assert len(result.envelope_recipients) == j.MAX_ENVELOPE_ADDRESSES

    def test_a_missing_envelope_is_empty_and_does_not_fail(self) -> None:
        result = j.extract_journal_report(report(text="нет конверта\r\n"), max_original_bytes=LIMIT)
        assert result.usable
        assert result.envelope_sender == "" and result.envelope_recipients == ()
