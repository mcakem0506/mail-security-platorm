"""Вложения 7z, RAR и PDF в конвейере разбора письма (ТЗ 1.1 §56, §57, §69; GAP-003, GAP-004).

Что обязано выполняться, какими бы ни были вложения:

* то, что не удалось просмотреть, названо в вердикте (``scan_completeness`` и ``missing_evidence``);
* зашифрованный, повреждённый и слишком большой файл не превращаются в «чистое письмо»;
* сбой изолированного разбора одного вложения не уносит анализ остального письма;
* найденное — опасное имя внутри архива, URL в QR на странице PDF — доходит до фактов и сигналов.
"""

from __future__ import annotations

from email.message import EmailMessage

import pytest
from fixtures import attachments as make
from msp_detection import analyze
from msp_mail_parser import parse_message
from msp_mail_parser.images import decoder_available

requires_decoder = pytest.mark.skipif(
    not decoder_available(), reason="необязательный компонент «qr» не установлен"
)


def mail(*attachments: tuple[str, str, bytes], body: str = "Добрый день, документы во вложении.") -> bytes:
    message = EmailMessage()
    message["From"] = "Бухгалтерия <accounting@partner.example>"
    message["To"] = "buh@corp.example"
    message["Subject"] = "Документы"
    message["Message-ID"] = "<pipeline@partner.example>"
    message.set_content(body)
    for filename, subtype, data in attachments:
        message.add_attachment(data, maintype="application", subtype=subtype, filename=filename)
    return message.as_bytes()


def facts(raw: bytes, context, ruleset):  # type: ignore[no-untyped-def]
    parsed = parse_message(raw)
    return parsed, analyze(parsed, context, ruleset=ruleset)


class TestSevenZipAndRarInTheMessage:
    def test_the_dangerous_member_name_reaches_the_facts(self, context, ruleset) -> None:  # type: ignore[no-untyped-def]
        raw = mail(
            ("docs.7z", "x-7z-compressed", make.make_7z({"invoice.pdf.exe": b"MZ", "readme.txt": b"hi"}))
        )
        parsed, result = facts(raw, context, ruleset)
        children = [a.meta for a in parsed.attachments if a.meta.depth > 0]
        assert {c.normalized_filename for c in children} == {"invoice.pdf.exe", "readme.txt"}
        assert all("LISTED_ONLY" in c.flags for c in children)
        assert all(c.sha256 == "" for c in children), (
            "хэша у неразвёрнутого файла нет, и выдумывать его нельзя"
        )
        assert result.facts.get("archive_contains_dangerous_file")

    def test_a_listed_member_never_becomes_a_threat_intelligence_indicator(self, context, ruleset) -> None:  # type: ignore[no-untyped-def]
        raw = mail(("docs.7z", "x-7z-compressed", make.make_7z({"a.exe": b"MZ"})))
        _, result = facts(raw, context, ruleset)
        assert all(indicator.value for indicator in result.indicators)

    def test_listing_only_keeps_the_scan_incomplete(self, context, ruleset) -> None:  # type: ignore[no-untyped-def]
        """Оглавление — не проверка содержимого: письмо не вправе выглядеть проверенным целиком."""
        raw = mail(("docs.7z", "x-7z-compressed", make.make_7z({"readme.txt": b"hi"})))
        _, result = facts(raw, context, ruleset)
        assert result.facts.get("scan_completeness") == "LIMIT_EXCEEDED"
        assert result.facts.get("limit_archive_listing_only")
        assert any("только по оглавлению" in item for item in result.facts.missing_evidence)

    def test_an_encrypted_archive_is_named_not_clean(self, context, ruleset) -> None:  # type: ignore[no-untyped-def]
        raw = mail(("locked.7z", "x-7z-compressed", make.make_7z({"a.txt": b"x"}, password="pw")))
        parsed, result = facts(raw, context, ruleset)
        assert parsed.attachments[0].meta.encrypted is True
        assert result.facts.get("limit_archive_encrypted_unscannable")
        assert result.facts.get("scan_completeness") != "COMPLETE"

    def test_a_rar_goes_the_same_way(self, context, ruleset) -> None:  # type: ignore[no-untyped-def]
        raw = mail(("docs.rar", "vnd.rar", make.make_rar5({"setup.exe": b"MZ"})))
        parsed, result = facts(raw, context, ruleset)
        assert {a.meta.normalized_filename for a in parsed.attachments if a.meta.depth > 0} == {"setup.exe"}
        assert result.facts.get("archive_contains_dangerous_file")

    def test_a_damaged_archive_is_reported_and_the_rest_of_the_message_is_analysed(  # type: ignore[no-untyped-def]
        self, context, ruleset
    ) -> None:
        raw = mail(
            ("broken.7z", "x-7z-compressed", make.make_7z({"a.txt": b"x" * 100})[:30]),
            body="Срочно подтвердите пароль: http://corp-example-login.test/verify",
        )
        parsed, result = facts(raw, context, ruleset)
        assert "CORRUPT_ARCHIVE" in parsed.attachments[0].meta.flags
        assert parsed.urls, "письмо разобрано целиком, несмотря на сбой вложения"
        assert result.facts.get("scan_completeness") != "COMPLETE"

    def test_a_bomb_is_flagged_without_being_unpacked(self, context, ruleset) -> None:  # type: ignore[no-untyped-def]
        raw = mail(("bomb.7z", "x-7z-compressed", make.make_7z({"z.bin": b"\0" * (52 * 1024 * 1024)})))
        parsed, result = facts(raw, context, ruleset)
        assert "EXCESSIVE_COMPRESSION_RATIO" in parsed.attachments[0].meta.flags
        assert result.facts.get("attachment_archive_bomb")

    def test_the_sandbox_failing_is_a_named_gap(self, context, ruleset, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from msp_attachment_sandbox import runner

        monkeypatch.setattr(runner, "run_local", lambda *a, **k: runner.SandboxResult("CRASHED", detail="x"))
        raw = mail(("docs.7z", "x-7z-compressed", make.make_7z({"a.txt": b"x"})))
        parsed, result = facts(raw, context, ruleset)
        assert "ARCHIVE_SANDBOX_FAILED" in parsed.attachments[0].meta.flags
        assert result.facts.get("limit_archive_sandbox_failed")
        assert result.facts.get("scan_completeness") != "COMPLETE"


@requires_decoder
class TestPdfInTheMessage:
    def test_a_qr_code_inside_a_pdf_gives_its_url(self, context, ruleset) -> None:  # type: ignore[no-untyped-def]
        raw = mail(
            ("invoice.pdf", "pdf", make.pdf_with_embedded_qr("https://corp-example-login.test/pay")),
            body="Отсканируйте код из вложения, чтобы оплатить счёт.",
        )
        parsed, result = facts(raw, context, ruleset)
        assert "https://corp-example-login.test/pay" in parsed.qr["decoded_urls"] or any(
            "corp-example-login.test" in url.normalized for url in parsed.urls
        )
        assert result.facts.get("qr_url_present")

    def test_a_vector_qr_is_found_too(self, context, ruleset) -> None:  # type: ignore[no-untyped-def]
        raw = mail(("scan.pdf", "pdf", make.pdf_with_vector_qr("https://corp-example-login.test/vec")))
        parsed, _ = facts(raw, context, ruleset)
        assert any("corp-example-login.test/vec" in url.normalized for url in parsed.urls)

    def test_a_clean_pdf_completes_the_scan(self, context, ruleset) -> None:  # type: ignore[no-untyped-def]
        raw = mail(("letter.pdf", "pdf", make.pdf_text_only()))
        parsed, result = facts(raw, context, ruleset)
        assert "PDF_UNSCANNABLE" not in parsed.limits_hit
        assert result.facts.get("scan_completeness") == "COMPLETE"

    @pytest.mark.parametrize(
        ("data", "reason"),
        [
            (make.pdf_encrypted(), "зашифрованный"),
            (b"%PDF-1.4 garbage", "повреждённый"),
            (make.pdf_pages(1, size=(14400, 14400)), "страница сверх предела"),
        ],
    )
    def test_a_pdf_that_cannot_be_read_is_missing_evidence_not_clean(  # type: ignore[no-untyped-def]
        self, context, ruleset, data: bytes, reason: str
    ) -> None:
        parsed, result = facts(mail(("x.pdf", "pdf", data)), context, ruleset)
        assert "PDF_UNSCANNABLE" in parsed.limits_hit, reason
        assert result.facts.get("limit_pdf_unscannable")
        assert result.facts.get("scan_completeness") != "COMPLETE"

    def test_a_long_pdf_names_the_pages_it_did_not_render(self, context, ruleset) -> None:  # type: ignore[no-untyped-def]
        parsed, result = facts(mail(("long.pdf", "pdf", make.pdf_pages(30))), context, ruleset)
        assert "PDF_NOT_FULLY_RENDERED" in parsed.limits_hit
        assert result.facts.get("scan_completeness") != "COMPLETE"

    def test_only_a_few_pdfs_per_message_are_rendered_and_the_rest_are_named(self, context, ruleset) -> None:  # type: ignore[no-untyped-def]
        pdfs = tuple((f"p{i}.pdf", "pdf", make.pdf_text_only()) for i in range(5))
        parsed, _ = facts(mail(*pdfs), context, ruleset)
        assert "PDF_NOT_FULLY_RENDERED" in parsed.limits_hit

    def test_a_crash_in_pdf_rendering_does_not_lose_the_message(self, context, ruleset, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from msp_attachment_sandbox import runner

        monkeypatch.setattr(runner, "run_local", lambda *a, **k: runner.SandboxResult("CRASHED", detail="x"))
        raw = mail(
            ("x.pdf", "pdf", make.pdf_text_only()),
            body="Подтвердите пароль: http://corp-example-login.test/a",
        )
        parsed, result = facts(raw, context, ruleset)
        assert parsed.urls
        assert "PDF_UNSCANNABLE" in parsed.limits_hit
        assert result.facts.get("scan_completeness") != "COMPLETE"

    def test_without_the_decoder_the_pdf_is_named_as_not_examined(
        self, context, ruleset, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        import msp_mail_parser.images as images

        monkeypatch.setattr(images, "decoder_available", lambda: False)
        parsed, result = facts(mail(("x.pdf", "pdf", make.pdf_text_only())), context, ruleset)
        assert "PDF_NOT_EXAMINED" in parsed.limits_hit
        assert result.facts.get("scan_completeness") != "COMPLETE"
