"""Coexistence with an existing Secure Email Gateway (ТЗ 2.1, 21)."""

from __future__ import annotations

import pytest
from msp_contracts import RISK_ORDER, RiskLevel
from msp_detection.gateway import gateway_facts, inspect_gateway_headers


def headers(**pairs: str) -> list[tuple[str, str]]:
    return [(name.replace("_", "-"), value) for name, value in pairs.items()]


class TestKsmg:
    def test_detected_malware_is_read(self) -> None:
        inspection = inspect_gateway_headers(
            headers(
                X_KSMG_Antivirus_Status="Detected: EICAR-Test-File",
                X_KSMG_Antivirus_Method="Signature",
            ),
            trusted_gateways=("ksmg",),
        )
        assert len(inspection.verdicts) == 1
        verdict = inspection.verdicts[0]
        assert verdict.gateway == "ksmg"
        assert verdict.verdict == "malicious"
        assert "EICAR" in verdict.threat_name

    def test_clean_verdict_is_recorded_but_creates_no_risk_reducing_fact(self) -> None:
        """A gateway that found nothing has not proved the message is safe (ТЗ 49.9)."""
        facts = {
            key: value
            for key, value, _ in gateway_facts(
                headers(X_KSMG_Antivirus_Status="Clean"), trusted_gateways=("ksmg",)
            )
        }
        assert facts.get("upstream_gateway_present") is True
        assert "gateway_detected_malware" not in facts
        # Nothing in the fact set can lower risk: there is no "safe" or "clean" fact at all.
        assert not any("safe" in key or "clean" in key for key in facts)

    def test_spam_and_phishing_statuses(self) -> None:
        inspection = inspect_gateway_headers(
            headers(
                X_KSMG_Antispam_Status="Spam",
                X_KSMG_Antiphishing_Status="Detected",
                X_KSMG_Antispam_Rate="score=9.8",
            ),
            trusted_gateways=("ksmg",),
        )
        verdicts = {v.verdict for v in inspection.verdicts}
        assert "spam" in verdicts
        assert "malicious" in verdicts
        assert any(v.score == pytest.approx(9.8) for v in inspection.verdicts)

    def test_probable_spam_is_suspicious_not_spam(self) -> None:
        inspection = inspect_gateway_headers(
            headers(X_KSMG_Antispam_Status="Probable spam"), trusted_gateways=("ksmg",)
        )
        assert inspection.verdicts[0].verdict == "suspicious"

    def test_unparseable_ksmg_headers_are_reported_as_unknown(self) -> None:
        inspection = inspect_gateway_headers(
            headers(X_KSMG_Some_Future_Header="value the parser does not know"),
            trusted_gateways=("ksmg",),
        )
        assert inspection.verdicts[0].verdict == "unknown"
        assert "ksmg" in inspection.gateways_seen


class TestOtherGateways:
    @pytest.mark.parametrize(
        ("scl", "expected"),
        [("-1", "clean"), ("1", "clean"), ("5", "spam"), ("9", "spam"), ("3", "suspicious")],
    )
    def test_exchange_online_protection_scl(self, scl: str, expected: str) -> None:
        inspection = inspect_gateway_headers(
            [("X-Forefront-Antispam-Report", f"CIP:1.2.3.4;CTRY:RU;SCL:{scl};SFV:NSPM")],
            trusted_gateways=("eop",),
        )
        assert inspection.verdicts[0].verdict == expected

    def test_spamassassin(self) -> None:
        inspection = inspect_gateway_headers(
            [("X-Spam-Flag", "YES"), ("X-Spam-Status", "Yes, score=12.4 required=5.0")],
            trusted_gateways=("spamassassin",),
        )
        assert inspection.verdicts[0].verdict == "spam"
        assert inspection.verdicts[0].score == pytest.approx(12.4)

    def test_generic_virus_scanner(self) -> None:
        inspection = inspect_gateway_headers(
            [("X-Virus-Status", "Infected: Trojan.Generic")], trusted_gateways=("virus_scanner",)
        )
        assert inspection.verdicts[0].verdict == "malicious"


class TestTrustBoundary:
    def test_untrusted_gateway_headers_are_not_used(self) -> None:
        """A sender can add these headers; only the organisation's own gateway is believed."""
        inspection = inspect_gateway_headers(
            headers(X_KSMG_Antivirus_Status="Clean"), trusted_gateways=("eop",)
        )
        assert inspection.verdicts == []
        assert "ksmg" in inspection.untrusted_claims

    def test_untrusted_claim_raises_suspicion_instead(self) -> None:
        facts = {
            key: value
            for key, value, _ in gateway_facts(
                [("X-Spam-Flag", "NO"), ("X-Spam-Status", "No, score=-5.0")],
                trusted_gateways=(),
            )
        }
        assert facts.get("untrusted_gateway_header") is True
        assert "gateway_detected_spam" not in facts

    def test_forged_clean_verdict_cannot_suppress_detection(self, context, ruleset) -> None:
        """An attacker adding a clean gateway header must not change the verdict."""
        from dataclasses import replace

        from fixtures.corpus import BY_NAME
        from msp_detection import analyze
        from msp_mail_parser import parse_message
        from msp_risk import evaluate

        raw = BY_NAME["09_bank_details_change"].raw
        forged = raw.replace(
            b"Subject:",
            b"X-KSMG-Antivirus-Status: Clean\r\nX-Spam-Flag: NO\r\nSubject:",
            1,
        )
        trusting = replace(context, trusted_gateways=("ksmg",))

        baseline = evaluate(analyze(parse_message(raw), context, ruleset=ruleset).signals)
        with_forged = evaluate(analyze(parse_message(forged), trusting, ruleset=ruleset).signals)

        assert RISK_ORDER[with_forged.classification] >= RISK_ORDER[baseline.classification], (
            "a clean gateway header must never reduce the verdict"
        )


class TestIntegrationWithDetection:
    def test_gateway_malware_detection_reaches_the_verdict(self, context, ruleset) -> None:
        from dataclasses import replace

        from fixtures.corpus import BY_NAME
        from msp_detection import analyze
        from msp_mail_parser import parse_message
        from msp_risk import evaluate

        raw = BY_NAME["02_normal_external"].raw.replace(
            b"Subject:",
            b"X-KSMG-Antivirus-Status: Detected: Trojan.Win32.Generic\r\nSubject:",
            1,
        )
        trusting = replace(context, trusted_gateways=("ksmg",))
        result = analyze(parse_message(raw), trusting, ruleset=ruleset)
        verdict = evaluate(result.signals)

        assert result.facts.get("gateway_detected_malware")
        assert verdict.classification is RiskLevel.MALICIOUS
        assert verdict.hard_signals, "a gateway antivirus detection is a hard signal"
        assert any("шлюз" in reason.title.lower() for reason in verdict.reasons)

    def test_clean_gateway_does_not_hide_bec(self, context, ruleset) -> None:
        """The case this coexistence exists for: a gateway passes BEC, the platform catches it."""
        from dataclasses import replace

        from fixtures.corpus import BY_NAME
        from msp_detection import analyze
        from msp_mail_parser import parse_message
        from msp_risk import evaluate

        raw = BY_NAME["09_bank_details_change"].raw.replace(
            b"Subject:", b"X-KSMG-Antivirus-Status: Clean\r\nX-KSMG-Antispam-Status: Clean\r\nSubject:", 1
        )
        trusting = replace(context, trusted_gateways=("ksmg",))
        verdict = evaluate(analyze(parse_message(raw), trusting, ruleset=ruleset).signals)
        assert RISK_ORDER[verdict.classification] >= RISK_ORDER[RiskLevel.HIGH_RISK]
