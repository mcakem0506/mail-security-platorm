"""Safe parser tests (ТЗ 8, 38)."""

from __future__ import annotations

import io
import zipfile

import pytest
from msp_mail_parser import (
    ParserLimits,
    detect_type,
    inspect_archive,
    normalize_url,
    parse_message,
    sanitize_html,
    split_domain,
)


class TestMimeParsing:
    def test_decodes_rfc2047_headers(self) -> None:
        raw = (
            b"From: =?utf-8?B?0JjQstCw0L0g0J/QtdGC0YDQvtCy?= <i@example.test>\r\n"
            b"Subject: =?utf-8?B?0KLQtdGB0YI=?=\r\n\r\nbody"
        )
        msg = parse_message(raw)
        assert msg.from_ is not None
        assert msg.from_.display_name == "Иван Петров"
        assert msg.subject == "Тест"

    def test_repairs_raw_8bit_headers(self) -> None:
        """Unencoded UTF-8 in headers violates RFC 2047 but is common in the wild."""
        raw = 'From: "Иван Петров" <i@example.test>\r\nSubject: Привет\r\n\r\nbody'.encode()
        msg = parse_message(raw)
        assert msg.from_ is not None
        assert msg.from_.display_name == "Иван Петров"
        assert msg.subject == "Привет"

    def test_malformed_message_yields_partial_result(self) -> None:
        raw = b"From: broken\r\nContent-Type: multipart/mixed; boundary=\r\n\r\n--\r\ngarbage"
        msg = parse_message(raw)
        assert isinstance(msg.errors, list)  # never raises
        assert msg.sha256

    def test_oversized_message_rejected(self) -> None:
        limits = ParserLimits(max_message_size=1000)
        msg = parse_message(b"x" * 2000, limits)
        assert "FATAL:MAX_MESSAGE_SIZE" in msg.errors
        assert not msg.parse_ok

    def test_mime_depth_limit(self) -> None:
        inner = b"Content-Type: text/plain\r\n\r\ndeep"
        for i in range(30):
            inner = (
                f"Content-Type: multipart/mixed; boundary=b{i}\r\n\r\n--b{i}\r\n".encode()
                + inner
                + f"\r\n--b{i}--\r\n".encode()
            )
        msg = parse_message(b"From: a@b.test\r\n" + inner)
        assert "MAX_MIME_DEPTH" in msg.limits_hit or msg.mime_depth <= ParserLimits().max_mime_depth

    def test_attachment_count_limit(self) -> None:
        from email.message import EmailMessage

        msg = EmailMessage()
        msg["From"] = "a@b.test"
        msg.set_content("body")
        for i in range(60):
            msg.add_attachment(
                b"x" * 10, maintype="application", subtype="octet-stream", filename=f"f{i}.bin"
            )
        parsed = parse_message(msg.as_bytes(), ParserLimits(max_attachments=10))
        assert "MAX_ATTACHMENTS" in parsed.limits_hit
        assert len([a for a in parsed.attachments if a.meta.depth == 0]) <= 10


class TestHtmlSanitization:
    @pytest.mark.parametrize(
        "payload",
        [
            "<script>alert(1)</script><p>ok</p>",
            '<img src=x onerror="alert(1)">',
            '<iframe src="http://evil.test"></iframe>',
            '<a href="javascript:alert(1)">click</a>',
            '<div style="background:url(http://evil.test/x.png)">text</div>',
            "<svg/onload=alert(1)>",
            '<body onload="alert(1)">text</body>',
            '<form action="http://evil.test"><input type="password"></form>',
            '<object data="http://evil.test"></object>',
            '<link rel="stylesheet" href="http://evil.test/s.css">',
            '<meta http-equiv="refresh" content="0;url=http://evil.test">',
            '<base href="http://evil.test/">',
        ],
    )
    def test_active_content_removed(self, payload: str) -> None:
        clean = sanitize_html(payload).lower()
        for banned in ("script", "onerror", "onload", "javascript:", "iframe", "<form", "<object", "url("):
            assert banned not in clean, f"{banned!r} survived sanitisation of {payload!r}"

    def test_no_remote_resources_survive(self) -> None:
        clean = sanitize_html('<a href="http://evil.test">x</a><img src="http://evil.test/p.png">')
        assert "http://evil.test" not in clean
        assert "href" not in clean  # links must not be clickable in preview

    def test_plain_text_preserved(self) -> None:
        clean = sanitize_html("<p>Привет, <b>мир</b></p>")
        assert "Привет" in clean
        assert "<b>мир</b>" in clean


class TestArchiveSafety:
    def test_detects_zip_bomb_by_real_size(self) -> None:
        """A lying header must not defeat the limit: the real stream is what gets measured."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bomb.txt", b"0" * (20 * 1024 * 1024))
        report = inspect_archive(buffer.getvalue(), "zip", ParserLimits(max_extracted_file=1024))
        assert report.flags & {"EXTRACTION_LIMIT", "ZIP_BOMB", "EXCESSIVE_COMPRESSION_RATIO"}
        assert not any(e.extracted and e.size > 1024 for e in report.entries)

    def test_detects_path_traversal(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("../../etc/passwd", b"root")
        report = inspect_archive(buffer.getvalue(), "zip")
        assert "PATH_TRAVERSAL" in report.flags

    def test_detects_absolute_path(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("/etc/shadow", b"x")
        report = inspect_archive(buffer.getvalue(), "zip")
        assert "ABSOLUTE_PATH" in report.flags

    def test_nesting_limit_enforced(self) -> None:
        def wrap(data: bytes, name: str) -> bytes:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as zf:
                zf.writestr(name, data)
            return buffer.getvalue()

        data = wrap(b"payload", "a.txt")
        for i in range(8):
            data = wrap(data, f"n{i}.zip")
        report = inspect_archive(data, "zip", ParserLimits(max_archive_depth=2))
        assert "NESTING_LIMIT" in report.flags

    def test_file_count_limit(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            for i in range(200):
                zf.writestr(f"f{i}.txt", b"x")
        report = inspect_archive(buffer.getvalue(), "zip", ParserLimits(max_archive_files=50))
        assert "TOO_MANY_FILES" in report.flags

    def test_encrypted_archive_flagged_not_malicious(self) -> None:
        from fixtures.corpus import set_encrypted_flag

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("secret.bin", b"data")
        report = inspect_archive(set_encrypted_flag(buffer.getvalue()), "zip")
        assert report.encrypted
        assert "ENCRYPTED_ARCHIVE" in report.flags

    def test_corrupt_archive_handled(self) -> None:
        report = inspect_archive(b"PK\x03\x04garbage-not-a-zip", "zip")
        assert "CORRUPT_ARCHIVE" in report.flags

    def test_unsupported_format_reported_not_executed(self) -> None:
        report = inspect_archive(b"Rar!\x1a\x07\x00rest", "rar")
        assert "UNSUPPORTED_ARCHIVE_FORMAT" in report.flags


class TestFileTypeDetection:
    @pytest.mark.parametrize(
        ("data", "expected"),
        [
            (b"MZ\x90\x00", "pe_executable"),
            (b"\x7fELF\x02", "elf_executable"),
            (b"%PDF-1.7", "pdf"),
            (b"{\\rtf1", "rtf"),
            (b"\x89PNG\r\n\x1a\n", "png"),
            (b"<html><body>x</body></html>", "html"),
            (b"plain text content", "text"),
        ],
    )
    def test_magic_bytes(self, data: bytes, expected: str) -> None:
        assert detect_type(data).type == expected

    def test_extension_mismatch_detected(self) -> None:
        from msp_mail_parser.filetype import extension_mismatch

        assert extension_mismatch("pdf", detect_type(b"MZ\x90\x00"))
        assert not extension_mismatch("pdf", detect_type(b"%PDF-1.7"))

    def test_rtlo_and_control_chars_stripped(self) -> None:
        from msp_mail_parser import normalize_filename

        # RIGHT-TO-LEFT OVERRIDE, built from its code point so this source file stays free of
        # literal bidirectional control characters.
        rlo = chr(0x202E)
        assert rlo not in normalize_filename(f"doc{rlo}gnp.exe")
        assert normalize_filename("../../etc/passwd") == "passwd"


class TestUrlNormalization:
    def test_punycode_and_unicode(self) -> None:
        url = normalize_url("http://xn--80ak6aa92e.com/path")
        assert url.host_ascii == "xn--80ak6aa92e.com"
        assert url.host != url.host_ascii

    def test_sensitive_query_redacted(self) -> None:
        url = normalize_url("https://x.test/p?token=supersecretvalue123&id=5")
        assert "supersecretvalue123" not in url.redacted
        assert "token" in url.redacted

    def test_obfuscated_ip_decoded(self) -> None:
        assert normalize_url("http://3232235777/").host == "192.168.1.1"
        assert normalize_url("http://0xC0A80001/").host == "192.168.0.1"

    def test_userinfo_detected(self) -> None:
        url = normalize_url("https://microsoft.com@evil.test/login")
        assert url.has_userinfo
        assert url.registrable_domain == "evil.test"

    def test_dangerous_schemes_not_expanded(self) -> None:
        url = normalize_url("javascript:alert(document.cookie)")
        assert url.scheme == "javascript"
        assert "alert" not in url.normalized

    def test_unparseable_url_does_not_raise(self) -> None:
        url = normalize_url("http://[malformed")
        assert url.redacted


class TestDomainSplitting:
    @pytest.mark.parametrize(
        ("host", "registrable"),
        [
            ("mail.corp.example", "corp.example"),
            ("a.b.c.example.co.uk", "example.co.uk"),
            ("example.com", "example.com"),
            ("192.168.1.1", "192.168.1.1"),
            # Internal TLDs have no public suffix; the last two labels are the organisation.
            ("host.corp.local", "corp.local"),
            ("exchange.internal.lan", "internal.lan"),
        ],
    )
    def test_registrable_domain(self, host: str, registrable: str) -> None:
        assert split_domain(host).registrable_ascii == registrable
