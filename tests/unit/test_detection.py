"""Detection and risk engine tests (ТЗ 41: acceptance criteria for anti-phishing)."""

from __future__ import annotations

import pytest
from msp_contracts import RISK_ORDER, IOCType, RiskLevel, Severity, TIStatus, TIResult
from msp_detection import EnrichmentInput, ScanFinding, analyze
from msp_detection.similarity import compare_labels, name_similarity, skeleton
from msp_mail_parser import parse_message
from msp_risk import RiskThresholds, employee_reasons, evaluate

from fixtures.corpus import BY_NAME, CORPUS


def run(raw: bytes, context, ruleset, enrichment=None):  # type: ignore[no-untyped-def]
    parsed = parse_message(raw)
    detection = analyze(parsed, context, enrichment, ruleset=ruleset)
    verdict = evaluate(
        detection.signals,
        missing_evidence=detection.facts.missing_evidence,
        thresholds=RiskThresholds(),
        analysis_complete=True,
        content_encrypted=parsed.encrypted,
        unparseable=not parsed.parse_ok,
    )
    return parsed, detection, verdict


class TestAcceptanceAntiPhishing:
    """Each test maps to a numbered acceptance criterion in ТЗ §41."""

    def test_41_1_display_name_impersonation(self, context, ruleset) -> None:
        _, detection, verdict = run(BY_NAME["03_display_name_impersonation"].raw, context, ruleset)
        assert detection.facts.get("protected_identity_impersonation")
        assert RISK_ORDER[verdict.classification] >= RISK_ORDER[RiskLevel.HIGH_RISK]

    def test_41_2_lookalike_corporate_domain(self, context, ruleset) -> None:
        _, detection, verdict = run(BY_NAME["04_lookalike_domain"].raw, context, ruleset)
        assert detection.facts.get("from_domain_lookalike_corporate")
        assert RISK_ORDER[verdict.classification] >= RISK_ORDER[RiskLevel.SUSPICIOUS]

    def test_41_3_punycode_identity(self, context, ruleset) -> None:
        _, detection, verdict = run(BY_NAME["05_punycode_homoglyph"].raw, context, ruleset)
        assert detection.facts.get("from_domain_punycode")
        assert RISK_ORDER[verdict.classification] >= RISK_ORDER[RiskLevel.SUSPICIOUS]

    def test_41_4_reply_to_mismatch(self, context, ruleset) -> None:
        _, detection, _ = run(BY_NAME["06_reply_to_mismatch"].raw, context, ruleset)
        assert detection.facts.get("reply_to_domain_mismatch")

    def test_41_5_urls_extracted_and_normalized(self, context, ruleset) -> None:
        parsed, _, _ = run(BY_NAME["07_fake_microsoft_login"].raw, context, ruleset)
        assert parsed.urls
        assert all(u.normalized for u in parsed.urls)
        assert all(u.registrable_domain or u.is_ip_literal or u.parse_error for u in parsed.urls)

    def test_41_6_visible_link_mismatch(self, context, ruleset) -> None:
        _, detection, _ = run(BY_NAME["05_punycode_homoglyph"].raw, context, ruleset)
        assert detection.facts.get("url_visible_href_mismatch")

    @pytest.mark.parametrize(
        ("fixture", "fact"),
        [
            ("08_invoice_bec", "intent_invoice_fraud"),
            ("09_bank_details_change", "intent_bank_details_change"),
            ("10_mfa_request", "intent_mfa_code_request"),
        ],
    )
    def test_41_7_bec_fixtures_detected(self, context, ruleset, fixture: str, fact: str) -> None:
        _, detection, verdict = run(BY_NAME[fixture].raw, context, ruleset)
        assert detection.facts.get(fact), f"{fact} not detected in {fixture}"
        assert RISK_ORDER[verdict.classification] >= RISK_ORDER[RiskLevel.SUSPICIOUS]

    def test_41_9_every_verdict_is_explained(self, context, ruleset) -> None:
        """No verdict may be a bare score: every raised verdict carries reasons (ТЗ 2.2)."""
        for fixture in CORPUS:
            _, _, verdict = run(fixture.raw, context, ruleset)
            if verdict.classification is not RiskLevel.LOW_RISK and verdict.score > 0:
                assert verdict.reasons, f"{fixture.name}: verdict without reasons"
                for reason in verdict.reasons:
                    assert reason.title and reason.explanation
                    assert reason.source and reason.observed_at

    def test_41_11_detection_works_without_virustotal(self, context, ruleset) -> None:
        """Absence of VirusTotal must not disable detection (ТЗ 42.10)."""
        _, detection, verdict = run(
            BY_NAME["09_bank_details_change"].raw,
            context,
            ruleset,
            EnrichmentInput(ti_results=[], ti_configured=False),
        )
        assert detection.active_signals
        assert RISK_ORDER[verdict.classification] >= RISK_ORDER[RiskLevel.HIGH_RISK]

    def test_41_12_unknown_never_presented_as_safe(self, context, ruleset) -> None:
        _, _, verdict = run(BY_NAME["17_encrypted_smime"].raw, context, ruleset)
        assert verdict.classification is not RiskLevel.LOW_RISK
        assert verdict.missing_evidence
        assert "SAFE" not in verdict.classification.value


class TestRiskEngine:
    def test_no_safe_level_exists(self) -> None:
        assert "SAFE" not in {level.value for level in RiskLevel}

    def test_provider_outage_yields_unknown_not_low_risk(self, context, ruleset) -> None:
        enrichment = EnrichmentInput(
            ti_results=[
                TIResult(
                    provider_id="virustotal",
                    ioc_type=IOCType.DOMAIN,
                    indicator="provider-outage.test",
                    status=TIStatus.PROVIDER_UNAVAILABLE,
                    error="timeout",
                )
            ],
            ti_configured=True,
        )
        _, detection, verdict = run(BY_NAME["18_provider_unavailable"].raw, context, ruleset, enrichment)
        assert detection.facts.get("ti_providers_unavailable")
        assert verdict.classification is RiskLevel.UNKNOWN
        assert verdict.missing_evidence

    def test_no_negative_reputation_is_not_safe(self, context, ruleset) -> None:
        enrichment = EnrichmentInput(
            ti_results=[
                TIResult(
                    provider_id="virustotal",
                    ioc_type=IOCType.DOMAIN,
                    indicator="provider-outage.test",
                    status=TIStatus.NO_NEGATIVE_REPUTATION,
                )
            ],
            ti_configured=True,
        )
        _, detection, _ = run(BY_NAME["18_provider_unavailable"].raw, context, ruleset, enrichment)
        # A clean provider answer must not create a "safe" fact of any kind.
        assert not any(key.endswith("_safe") for key in detection.facts.facts)

    def test_hard_signal_raises_classification_and_keeps_source(self, context, ruleset) -> None:
        enrichment = EnrichmentInput(
            scan_findings=[
                ScanFinding(sha256="a" * 64, filename="test.txt", malicious=True, signature="Eicar", scanner="mock")
            ],
            ti_configured=False,
        )
        _, _, verdict = run(BY_NAME["02_normal_external"].raw, context, ruleset, enrichment)
        assert verdict.classification is RiskLevel.MALICIOUS
        assert verdict.hard_signals
        assert verdict.hard_signals[0].source and verdict.hard_signals[0].observed_at

    def test_many_weak_signals_do_not_reach_malicious(self) -> None:
        from msp_contracts import Signal

        weak = [
            Signal(
                id=f"W-{i}",
                category=f"cat{i}",
                title=f"Weak {i}",
                explanation="weak signal",
                severity=Severity.LOW,
                confidence=0.4,
                weight=10,
                source="rule_engine",
            )
            for i in range(20)
        ]
        verdict = evaluate(weak, analysis_complete=True)
        assert verdict.classification is not RiskLevel.MALICIOUS

    def test_employee_view_hides_internal_reasons(self, context, ruleset) -> None:
        _, _, verdict = run(BY_NAME["09_bank_details_change"].raw, context, ruleset)
        shown = employee_reasons(verdict)
        assert len(shown) <= 5
        assert all(not r.internal for r in shown)

    def test_benign_internal_mail_stays_low_risk(self, context, ruleset) -> None:
        _, _, verdict = run(BY_NAME["01_normal_internal"].raw, context, ruleset)
        assert verdict.classification in {RiskLevel.LOW_RISK, RiskLevel.UNKNOWN}
        assert verdict.score < 25

    def test_legitimate_bulk_sender_not_flagged_high(self, context, ruleset) -> None:
        """False-positive control: a trusted bulk sender must not reach HIGH_RISK (ТЗ 39.20)."""
        _, _, verdict = run(BY_NAME["20_false_positive_bulk"].raw, context, ruleset)
        assert RISK_ORDER[verdict.classification] < RISK_ORDER[RiskLevel.HIGH_RISK]


class TestExceptions:
    def test_trusted_sender_suppresses_signals(self, context, ruleset) -> None:
        from dataclasses import replace

        from msp_contracts import ExceptionType
        from msp_detection import ActiveException

        raw = BY_NAME["04_lookalike_domain"].raw
        _, before, _ = run(raw, context, ruleset)
        assert before.active_signals

        with_exception = replace(
            context,
            exceptions=(
                ActiveException(
                    exception_id="exc-1",
                    exception_type=ExceptionType.TRUSTED_SENDER,
                    value="info@corp-example.test",
                    owner="admin@corp.example",
                    reason="verified partner",
                ),
            ),
        )
        _, after, verdict = run(raw, with_exception, ruleset)
        assert after.suppressed_signals
        assert all(s.suppressed_by for s in after.suppressed_signals)
        assert verdict.suppressed

    def test_expired_exception_does_not_suppress(self, context) -> None:
        from datetime import timedelta

        from msp_contracts import ExceptionType, utcnow
        from msp_detection import ActiveException

        expired = ActiveException(
            exception_id="exc-old",
            exception_type=ExceptionType.TRUSTED_SENDER,
            value="info@corp-example.test",
            expires_at=utcnow() - timedelta(days=1),
        )
        assert not expired.is_active()


class TestSimilarity:
    @pytest.mark.parametrize(
        ("candidate", "target"),
        [
            ("micr0soft", "microsoft"),
            ("rnicrosoft", "microsoft"),
            ("microsofl", "microsoft"),
            ("sbelbank", "sberbank"),
            ("corp-example", "corpexample"),
        ],
    )
    def test_detects_lookalikes(self, candidate: str, target: str) -> None:
        assert compare_labels(candidate, target) is not None

    @pytest.mark.parametrize(
        ("candidate", "target"),
        [
            ("yandex", "microsoft"),
            ("partner", "corp"),
            ("mail", "gmail"),  # too short a difference relative to length
        ],
    )
    def test_avoids_false_lookalikes(self, candidate: str, target: str) -> None:
        match = compare_labels(candidate, target)
        assert match is None or match.confidence < 0.7

    def test_cyrillic_homoglyph_folds_to_latin(self) -> None:
        assert skeleton("аррӏе") == skeleton("apple")

    def test_name_similarity_order_independent(self) -> None:
        assert name_similarity("Иван Петров", "Петров Иван") == 1.0
        assert name_similarity("Иван Петров", "Мария Кузнецова") < 0.5


class TestRuleIntegrity:
    def test_all_rules_have_explanations(self, ruleset) -> None:
        for rule in ruleset.rules:
            assert rule.explanation or rule.name, f"{rule.id} lacks an explanation"
            assert 0 <= rule.confidence <= 1
            assert rule.version >= 1

    def test_rule_ids_unique_and_versioned(self, ruleset) -> None:
        ids = [r.id for r in ruleset.rules]
        assert len(ids) == len(set(ids))
        assert ruleset.version_fingerprint

    def test_high_severity_rules_have_recommendations(self, ruleset) -> None:
        for rule in ruleset.rules:
            if rule.severity is Severity.CRITICAL and not rule.internal:
                assert rule.recommendation or rule.explanation

    def test_condition_dsl_rejects_unknown_operator(self) -> None:
        from msp_detection.rules import RuleError, parse_condition

        with pytest.raises(RuleError):
            parse_condition({"unsupported_combinator": ["a"]})

    def test_condition_dsl_does_not_evaluate_python(self) -> None:
        """The DSL is interpreted, never eval'd: an injection attempt is inert."""
        from msp_detection.rules import parse_condition

        condition = parse_condition("some_fact == '__import__(\"os\").system(\"echo pwned\")'")
        assert condition.evaluate({"some_fact": "harmless"}) is False
