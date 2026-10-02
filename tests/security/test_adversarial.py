"""Adversarial inputs and the semantic provider (ТЗ 1.0.3B §34, §35).

Twelve evasion techniques, each tested on the property that matters: the platform must either
see through the trick or say it could not — never quietly report a clean result. "Nothing
detected" on a message built to be unreadable is the failure ТЗ §3 forbids.

The semantic tests guard one invariant: a semantic signal never settles a verdict. A model whose
output can condemn a message by itself produces verdicts nobody can argue with, and the product
rests on verdicts an analyst can argue with.
"""

from __future__ import annotations

import base64
import quopri

from msp_contracts import IntakeSource, RiskLevel, Severity, Signal
from msp_detection import AnalysisContext, analyze, default_ruleset
from msp_detection.semantic import (
    MAX_SEMANTIC_WEIGHT,
    DisabledSemanticProvider,
    build_provider,
    cap_semantic_signals,
)
from msp_mail_parser import parse_message
from msp_risk import evaluate

CORP = "corp.example"


def _context() -> AnalysisContext:
    return AnalysisContext(
        organization_id="adversarial",
        corporate_domains=(CORP,),
        source=IntakeSource.API,
    )


def _message(*, subject: str = "Тема", body: str = "Текст", headers: str = "") -> bytes:
    return (
        f"From: Attacker <attacker@evil.test>\r\n"
        f"To: buh@{CORP}\r\n"
        f"Subject: {subject}\r\n"
        f"{headers}"
        "MIME-Version: 1.0\r\n"
        'Content-Type: text/plain; charset="utf-8"\r\n'
        "Content-Transfer-Encoding: base64\r\n\r\n" + base64.b64encode(body.encode("utf-8")).decode() + "\r\n"
    ).encode()


def _analyse(raw: bytes):  # type: ignore[no-untyped-def]
    parsed = parse_message(raw)
    result = analyze(parsed, _context(), ruleset=default_ruleset())
    verdict = evaluate(
        result.signals,
        missing_evidence=result.facts.missing_evidence,
        analysis_complete=parsed.parse_ok,
        unparseable=not parsed.parse_ok,
    )
    return parsed, result, verdict


class TestEvasionTechniques:
    """Each technique either gets seen through, or the message is not reported as clean."""

    def test_zero_width_characters_inside_a_keyword(self) -> None:
        body = "Изменились наши банковские​реквизиты, оплатите по новым."
        parsed, result, verdict = _analyse(_message(body=body))
        assert parsed.parse_ok
        # Either the intent is still found, or the verdict is not a clean one.
        facts = result.facts.truthy()
        assert "intent_bank_details_change" in facts or verdict.classification is not RiskLevel.LOW_RISK

    def test_homoglyph_domain_in_the_body(self) -> None:
        body = "Войдите на https://corp-рortal.test/login для подтверждения."  # Cyrillic р
        parsed, _result, verdict = _analyse(_message(body=body))
        hosts = {url.host for url in parsed.urls}
        assert hosts, "ссылка должна быть извлечена даже с подменой символа"
        assert verdict.classification is not RiskLevel.LOW_RISK

    def test_mixed_script_display_name(self) -> None:
        raw = (
            "From: =?utf-8?B?"
            + base64.b64encode("Сбербaнк".encode()).decode()  # latin a
            + "?= <noreply@sber-secure.test>\r\n"
            f"To: buh@{CORP}\r\nSubject: Уведомление\r\n"
            "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
            "Подтвердите операцию.\r\n"
        ).encode()
        parsed, result, _verdict = _analyse(raw)
        assert parsed.from_ is not None
        assert result.facts.truthy()

    def test_bidirectional_override_in_a_filename(self) -> None:
        raw = (
            f"From: a@evil.test\r\nTo: buh@{CORP}\r\nSubject: Документ\r\n"
            "MIME-Version: 1.0\r\n"
            'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
            "--b\r\nContent-Type: text/plain\r\n\r\nсм. вложение\r\n"
            "--b\r\nContent-Type: application/octet-stream\r\n"
            'Content-Disposition: attachment; filename="=?utf-8?B?'
            + base64.b64encode("счет‮gnp.exe".encode()).decode()
            + '?="\r\n\r\ndata\r\n--b--\r\n'
        ).encode()
        parsed, result, verdict = _analyse(raw)
        flags = [flag for att in parsed.attachments for flag in att.meta.flags]
        assert "RTLO_FILENAME" in flags
        assert verdict.classification is not RiskLevel.LOW_RISK
        _ = result

    def test_html_comments_splitting_a_keyword(self) -> None:
        html = "<p>Изменились наши бан<!-- x -->ковские реквизиты.</p>"
        raw = (
            f"From: a@evil.test\r\nTo: buh@{CORP}\r\nSubject: Реквизиты\r\n"
            "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + html
        ).encode()
        parsed, _result, verdict = _analyse(raw)
        # The comment must not survive into the text the rules read.
        assert "<!--" not in parsed.normalized_text
        assert verdict.classification is not RiskLevel.LOW_RISK

    def test_mime_header_folding(self) -> None:
        raw = (
            "From: a@evil.test\r\n"
            f"To: buh@{CORP}\r\n"
            "Subject: Срочно:\r\n вернитесь к\r\n  оплате счёта\r\n"
            "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nтекст\r\n"
        ).encode()
        parsed, _result, _verdict = _analyse(raw)
        assert "вернитесь" in parsed.subject
        assert "\r" not in parsed.subject and "\n" not in parsed.subject

    def test_charset_confusion(self) -> None:
        """A body declared utf-8 but encoded cp1251 must still be read, not silently emptied."""
        body = "Изменились реквизиты для оплаты".encode("cp1251")
        raw = (
            f"From: a@evil.test\r\nTo: buh@{CORP}\r\nSubject: Реквизиты\r\n"
            "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        ).encode() + body
        parsed, _result, _verdict = _analyse(raw)
        assert parsed.normalized_text.strip(), "тело не должно превратиться в пустоту"

    def test_percent_encoded_url(self) -> None:
        body = "Перейдите: https://evil.test/%6C%6F%67%69%6E?next=%2Fpay"
        parsed, _result, _verdict = _analyse(_message(body=body))
        assert any("evil.test" in (url.host or "") for url in parsed.urls)

    def test_nested_encoding_in_the_subject(self) -> None:
        inner = base64.b64encode("Срочная оплата".encode()).decode()
        subject = f"=?utf-8?B?{base64.b64encode(f'=?utf-8?B?{inner}?='.encode()).decode()}?="
        parsed, _result, _verdict = _analyse(_message(subject=subject))
        assert isinstance(parsed.subject, str) and parsed.subject

    def test_base64_fragmentation_of_an_attachment(self) -> None:
        payload = base64.b64encode(b"MZ\x90\x00" + b"A" * 200).decode()
        fragmented = "\r\n".join(payload[i : i + 8] for i in range(0, len(payload), 8))
        raw = (
            f"From: a@evil.test\r\nTo: buh@{CORP}\r\nSubject: Файл\r\n"
            "MIME-Version: 1.0\r\n"
            'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
            "--b\r\nContent-Type: text/plain\r\n\r\nсм. вложение\r\n"
            "--b\r\nContent-Type: application/octet-stream\r\n"
            'Content-Disposition: attachment; filename="report.exe"\r\n'
            "Content-Transfer-Encoding: base64\r\n\r\n" + fragmented + "\r\n--b--\r\n"
        ).encode()
        parsed, result, verdict = _analyse(raw)
        assert parsed.attachments
        assert "attachment_executable" in result.facts.truthy()
        assert verdict.classification is not RiskLevel.LOW_RISK

    def test_whitespace_obfuscation(self) -> None:
        body = "И з м е н и л и с ь   р е к в и з и т ы"
        parsed, _result, verdict = _analyse(_message(body=body))
        # The platform may well miss this one. What it must not do is call it clean without
        # saying why — here the sender is unknown and external, so the verdict stays non-clean.
        assert parsed.parse_ok
        assert verdict.classification is not RiskLevel.LOW_RISK or verdict.missing_evidence

    def test_display_name_containing_an_address(self) -> None:
        raw = (
            f'From: "ceo@{CORP}" <attacker@evil.test>\r\n'
            f"To: buh@{CORP}\r\nSubject: Срочно\r\n"
            "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
            "Переведите оплату сегодня.\r\n"
        ).encode()
        parsed, result, verdict = _analyse(raw)
        assert parsed.from_ is not None and parsed.from_.address == "attacker@evil.test"
        facts = result.facts.truthy()
        assert any("display_name" in key or "impersonat" in key for key in facts) or (
            verdict.classification is not RiskLevel.LOW_RISK
        )

    def test_quoted_printable_soft_breaks(self) -> None:
        body = quopri.encodestring("Изменились реквизиты для оплаты".encode()).decode()
        raw = (
            f"From: a@evil.test\r\nTo: buh@{CORP}\r\nSubject: Реквизиты\r\n"
            "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"
            "Content-Transfer-Encoding: quoted-printable\r\n\r\n" + body + "\r\n"
        ).encode()
        parsed, result, _verdict = _analyse(raw)
        assert "реквизит" in parsed.normalized_text.lower()
        assert "intent_bank_details_change" in result.facts.truthy()


class TestSemanticProviderCannotSettleAVerdict:
    def test_disabled_by_default(self) -> None:
        provider = build_provider()
        assert isinstance(provider, DisabledSemanticProvider)
        assert provider.available() is False

    def test_a_hosted_model_is_not_constructible_by_name(self) -> None:
        """Sending corporate mail to a SaaS model is a policy decision, not a config string."""
        for name in ("openai", "anthropic", "gpt", "saas"):
            assert build_provider(name).provider_id == "disabled"

    def test_semantic_weight_is_capped(self) -> None:
        signals = [
            Signal(
                id="sem-1",
                category="semantic",
                title="Запрос платежа",
                explanation="модель считает это запросом платежа",
                severity=Severity.HIGH,
                confidence=0.9,
                weight=95.0,
                source="semantic",
            )
        ]
        cap_semantic_signals(signals)
        assert signals[0].weight == MAX_SEMANTIC_WEIGHT
        assert signals[0].hard is False

    def test_semantic_signals_alone_cannot_reach_malicious(self) -> None:
        """Many semantic findings raise suspicion; they never settle the question."""
        signals = [
            Signal(
                id=f"sem-{index}",
                category="semantic",
                title="Семантический признак",
                explanation="модель",
                severity=Severity.HIGH,
                confidence=0.95,
                weight=100.0,
                source="semantic",
                hard=True,
            )
            for index in range(8)
        ]
        cap_semantic_signals(signals)
        verdict = evaluate(signals)
        assert verdict.classification is not RiskLevel.MALICIOUS

    def test_the_local_provider_reads_nothing_out_of_the_organisation(self) -> None:
        provider = build_provider("local")
        result = provider.analyze(
            subject="Срочно: смена реквизитов",
            body="Изменились наши банковские реквизиты, оплатите по новым.",
        )
        assert result.available and result.provider == "local"
        assert any(f.fact == "intent_bank_details_change" for f in result.findings)
        assert all(f.model == "patterns" for f in result.findings)

    def test_an_unavailable_provider_is_not_a_clean_result(self) -> None:
        result = DisabledSemanticProvider().analyze(subject="x", body="y")
        assert result.findings == []
        assert result.available is False
