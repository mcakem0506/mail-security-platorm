"""Coexistence with an upstream Secure Email Gateway (ТЗ 2.1, ТЗ 1.0.1 §4.3-4.4, ТЗ 1.0.2).

The single question these tests exist to answer: can a header decide anything about a message?
Since 1.0.1 the answer is "only when the delivery chain proves the message really passed the hop
that writes it". Everything else here follows from that.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from msp_contracts import (
    RISK_ORDER,
    GatewayCapability,
    GatewayState,
    GatewayVerdictType,
    RiskLevel,
    TrustedMailHop,
    TrustState,
)
from msp_detection import GatewayFindings, gateway_facts
from msp_mail_gateway import (
    GatewayProviderConfig,
    GatewayRegistry,
    KsmgGatewayProvider,
    build_provider,
    detect_conflicts,
    parse_received,
    skeleton_summary,
    upstream_hard_signal,
    verify_chain,
)

KSMG_HOST = "ksmg-01.corp.example"
EXCHANGE_HOST = "exch-mbx-01.corp.example"

#: A delivery chain that really did pass the organisation's gateway. Newest hop first.
DELIVERED_VIA_KSMG = [
    f"from {KSMG_HOST} (ksmg-01 [10.20.0.11]) by {EXCHANGE_HOST} with ESMTPS id aa11;"
    " Mon, 1 Sep 2025 10:02:00 +0300",
    f"from mx.vendor.example (mx.vendor.example [203.0.113.9]) by {KSMG_HOST} with ESMTPS id bb22;"
    " Mon, 1 Sep 2025 10:00:00 +0300",
]
#: The same message delivered straight to Exchange: whatever its headers claim, it never met KSMG.
DELIVERED_DIRECTLY = [
    f"from mx.attacker.example (unknown [198.51.100.7]) by {EXCHANGE_HOST} with ESMTP id cc33;"
    " Mon, 1 Sep 2025 10:00:00 +0300",
]


def ksmg_hop(**overrides: object) -> TrustedMailHop:
    defaults: dict[str, object] = {
        "id": "hop-ksmg",
        "provider_id": "ksmg",
        "hostname": KSMG_HOST,
        "ip_networks": ["10.20.0.0/24"],
        "authserv_ids": [KSMG_HOST],
    }
    defaults.update(overrides)
    return TrustedMailHop(**defaults)  # type: ignore[arg-type]


def ksmg_registry(**hop_overrides: object) -> GatewayRegistry:
    return GatewayRegistry(
        [
            KsmgGatewayProvider(
                GatewayProviderConfig(
                    provider_id="ksmg",
                    provider_type="ksmg",
                    display_name="KSMG",
                    trusted_hops=[ksmg_hop(**hop_overrides)],
                )
            )
        ]
    )


def facts_from(findings: GatewayFindings) -> dict[str, object]:
    return {key: value for key, value, _ in gateway_facts(findings)}


def findings_from(analysis, verdict: RiskLevel | None = None) -> GatewayFindings:  # type: ignore[no-untyped-def]
    verification = analysis.verification
    return GatewayFindings(
        evidence=list(analysis.evidence),
        state=analysis.state,
        trusted_auth_results=list(analysis.trusted_auth_results),
        untrusted_auth_results=list(analysis.untrusted_auth_results),
        auth_tampering_suspected=analysis.auth_tampering_suspected,
        unverified_gateways=list(analysis.untrusted_gateways),
        position_mismatches=list(verification.position_mismatches) if verification else [],
        chain_verified=bool(verification and verification.matches),
        conflicts=detect_conflicts(analysis.evidence, verdict),
    )


class TestReceivedChain:
    def test_hops_are_decomposed(self) -> None:
        hops = parse_received(DELIVERED_VIA_KSMG)
        assert [hop.by_host for hop in hops] == [EXCHANGE_HOST, KSMG_HOST]
        assert str(hops[1].ip) == "203.0.113.9"
        assert hops[0].queue_id == "aa11"
        assert hops[0].encrypted, "ESMTPS means the hop was encrypted"

    def test_unresolved_source_is_recorded(self) -> None:
        assert parse_received(DELIVERED_DIRECTLY)[0].unresolved

    def test_hop_is_proved_by_hostname_or_by_address(self) -> None:
        by_name = verify_chain(DELIVERED_VIA_KSMG, [ksmg_hop(ip_networks=[])])
        by_address = verify_chain(DELIVERED_VIA_KSMG, [ksmg_hop(hostname="")])
        assert by_name.matches and by_address.matches
        assert by_address.matches[0].matched_by == "ip_from"

    def test_subdomain_match_stops_at_a_label_boundary(self) -> None:
        """``corp.example.attacker.tld`` must not satisfy a hop configured as ``corp.example``."""
        chain = ["from a by ksmg-01.corp.example.attacker.tld; Mon, 1 Sep 2025 10:00:00 +0300"]
        assert not verify_chain(chain, [ksmg_hop(ip_networks=[])]).matches

    def test_a_hop_reports_one_position_however_it_matched(self) -> None:
        """KSMG appears twice: as the ``by`` host of hop 1 and the ``from`` host of hop 0.

        Both prove the message passed it, and both must yield the same position, or a
        configured ``position_in_chain`` could never be checked reliably.
        """
        by_name = verify_chain(DELIVERED_VIA_KSMG, [ksmg_hop(ip_networks=[])])
        by_address = verify_chain(DELIVERED_VIA_KSMG, [ksmg_hop(hostname="")])
        assert by_name.matches[0].chain_position == 1
        assert by_address.matches[0].chain_position == 1

    def test_position_in_chain_is_enforced(self) -> None:
        verification = verify_chain(DELIVERED_VIA_KSMG, [ksmg_hop(position_in_chain=0)])
        assert not verification.matches, "KSMG sits at position 1, behind the mailbox server"
        assert verification.position_mismatches
        assert verify_chain(DELIVERED_VIA_KSMG, [ksmg_hop(position_in_chain=1)]).matches


class TestHeaderTrust:
    def test_verified_detection_becomes_a_hard_signal(self) -> None:
        analysis = ksmg_registry().analyze_message(
            [("X-KSMG-Antivirus-Status", "Detected: EICAR-Test-File")],
            received=DELIVERED_VIA_KSMG,
        )
        evidence = analysis.evidence[0]
        assert evidence.trusted and evidence.trust_state is TrustState.TRUSTED
        assert evidence.verdict is GatewayVerdictType.MALICIOUS
        assert evidence.threat_name == "EICAR-Test-File"
        assert facts_from(findings_from(analysis)).get("upstream_malware_detection") is True
        assert upstream_hard_signal(analysis.evidence) is not None

    def test_the_same_headers_are_worthless_without_the_chain(self) -> None:
        """The core of §4.3: naming the gateway is not proof the message went through it."""
        analysis = ksmg_registry().analyze_message(
            [("X-KSMG-Antivirus-Status", "Detected: EICAR-Test-File")],
            received=DELIVERED_DIRECTLY,
        )
        evidence = analysis.evidence[0]
        assert not evidence.trusted
        assert evidence.trust_state is TrustState.UNVERIFIED_CHAIN
        facts = facts_from(findings_from(analysis))
        assert "upstream_malware_detection" not in facts
        # Not silence either: a copied gateway header is itself worth reporting.
        assert facts.get("unverified_gateway_header") is True
        assert upstream_hard_signal(analysis.evidence) is None

    def test_headers_of_a_gateway_the_organisation_does_not_run(self) -> None:
        analysis = ksmg_registry().analyze_message(
            [("X-Forefront-Antispam-Report", "CIP:1.2.3.4;SCL:1;CAT:NONE")],
            received=DELIVERED_VIA_KSMG,
        )
        assert analysis.evidence[0].trust_state is TrustState.UNKNOWN_GATEWAY
        assert facts_from(findings_from(analysis)).get("untrusted_gateway_header") is True

    def test_clean_verdict_produces_no_risk_reducing_fact(self) -> None:
        analysis = ksmg_registry().analyze_message(
            [("X-KSMG-Antivirus-Status", "Clean"), ("X-KSMG-AntiSpam-Status", "Clean")],
            received=DELIVERED_VIA_KSMG,
        )
        facts = facts_from(findings_from(analysis))
        assert facts.get("upstream_gateway_clean_observed") is True
        assert not any(key.startswith("gateway_detected") for key in facts)
        # Structural: no verdict of any kind is allowed to lower risk.
        assert not any(verdict.lowers_risk for verdict in GatewayVerdictType)

    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            ("Clean", GatewayVerdictType.CLEAN_OBSERVED),
            ("Not detected", GatewayVerdictType.CLEAN_OBSERVED),
            ("Detected", GatewayVerdictType.MALICIOUS),
            ("Probable spam", GatewayVerdictType.SUSPICIOUS),
        ],
    )
    def test_ksmg_status_words(self, status: str, expected: GatewayVerdictType) -> None:
        analysis = ksmg_registry().analyze_message(
            [("X-KSMG-Antivirus-Status", status)], received=DELIVERED_VIA_KSMG
        )
        assert analysis.evidence[0].verdict is expected

    def test_unreadable_ksmg_headers_are_unknown_never_clean(self) -> None:
        analysis = ksmg_registry().analyze_message(
            [("X-KSMG-Some-Future-Header", "a value this parser does not know")],
            received=DELIVERED_VIA_KSMG,
        )
        assert analysis.evidence[0].verdict is GatewayVerdictType.UNKNOWN


class TestAuthenticationResultsTrust:
    """ТЗ 1.0.1 §4.4: a forged Authentication-Results must not suppress detection."""

    HEADER = "spf=pass smtp.mailfrom=ceo@corp.example; dkim=pass; dmarc=pass"

    def test_results_from_a_verified_server_are_read(self) -> None:
        analysis = ksmg_registry().analyze_message(
            [],
            received=DELIVERED_VIA_KSMG,
            authentication_results=[f"{KSMG_HOST}; {self.HEADER}"],
        )
        assert len(analysis.trusted_auth_results) == 1
        assert not analysis.auth_tampering_suspected

    def test_results_from_an_unverified_server_are_refused(self) -> None:
        analysis = ksmg_registry().analyze_message(
            [],
            received=DELIVERED_DIRECTLY,
            authentication_results=[f"{KSMG_HOST}; {self.HEADER}"],
        )
        assert analysis.trusted_auth_results == []
        assert analysis.auth_tampering_suspected, "a passing claim we cannot verify is a forgery shape"
        assert facts_from(findings_from(analysis)).get("authentication_results_forged") is True

    def test_a_deployment_with_no_topology_still_reads_its_headers(self) -> None:
        """Without any declared authentication server, refusing to read them would only weaken
        detection; the missing allowlist is a readiness warning instead."""
        registry = GatewayRegistry(
            [KsmgGatewayProvider(GatewayProviderConfig(provider_id="ksmg", provider_type="ksmg"))]
        )
        analysis = registry.analyze_message(
            [], received=DELIVERED_DIRECTLY, authentication_results=[f"mx.corp.example; {self.HEADER}"]
        )
        assert len(analysis.trusted_auth_results) == 1


class TestRegistry:
    def test_no_gateway_is_a_valid_state(self) -> None:
        registry = GatewayRegistry()
        assert registry.state() is GatewayState.NOT_PRESENT
        assert not registry.configured
        assert gateway_facts(GatewayFindings(state=GatewayState.NOT_PRESENT)) == []

    def test_capabilities_are_reported_per_provider(self) -> None:
        registry = ksmg_registry()
        assert GatewayCapability.HEADER_VERDICT in registry.providers[0].capabilities()
        assert registry.supports(GatewayCapability.HEADER_VERDICT) == ["ksmg"]
        # Nothing claims a write capability at 1.0.2.
        assert registry.supports(GatewayCapability.QUARANTINE_WRITE) == []

    def test_write_actions_are_refused(self) -> None:
        provider = ksmg_registry().providers[0]
        plan = provider.propose_quarantine([])
        assert not plan.executable and plan.blockers
        assert not provider.execute_quarantine([], dry_run=False).executed

    def test_generic_provider_needs_no_code_for_a_new_gateway(self) -> None:
        config = GatewayProviderConfig(
            provider_id="acme",
            provider_type="generic_header",
            trusted_hops=[ksmg_hop(id="acme-hop", provider_id="acme")],
            settings={
                "headers": {"verdict": ["X-Acme-Scan"], "score": ["X-Acme-Score"]},
                "verdict_map": {"MALICIOUS": ["bad"], "CLEAN_OBSERVED": ["good"]},
            },
        )
        registry = GatewayRegistry([build_provider(config)])
        analysis = registry.analyze_message(
            [("X-Acme-Scan", "bad"), ("X-Acme-Score", "9.5")], received=DELIVERED_VIA_KSMG
        )
        assert analysis.evidence[0].verdict is GatewayVerdictType.MALICIOUS
        assert analysis.evidence[0].score == pytest.approx(9.5)
        assert analysis.evidence[0].trusted

    def test_skeletons_declare_what_is_and_is_not_implemented(self) -> None:
        summary = {item["provider_type"]: item for item in skeleton_summary()}
        assert {"fortimail", "proofpoint", "mimecast", "cisco_esa"} <= set(summary)
        for item in summary.values():
            assert "HEADER_VERDICT" in item["implemented"]
            assert "API_VERDICT" in item["planned"]
            assert item["prerequisites"], "an unimplemented API must say what it needs"


class TestConflicts:
    def test_gateway_clean_with_high_platform_risk_is_expected_and_visible(self) -> None:
        analysis = ksmg_registry().analyze_message(
            [("X-KSMG-Antivirus-Status", "Clean")], received=DELIVERED_VIA_KSMG
        )
        conflicts = detect_conflicts(analysis.evidence, RiskLevel.HIGH_RISK)
        assert [c.kind.value for c in conflicts] == ["GATEWAY_CLEAN_PLATFORM_HIGH"]

    def test_gateway_malware_with_low_platform_risk_is_flagged(self) -> None:
        analysis = ksmg_registry().analyze_message(
            [("X-KSMG-Antivirus-Status", "Detected: Trojan.Generic")], received=DELIVERED_VIA_KSMG
        )
        conflicts = detect_conflicts(analysis.evidence, RiskLevel.LOW_RISK)
        assert [c.kind.value for c in conflicts] == ["GATEWAY_MALICIOUS_PLATFORM_LOW"]

    def test_untrusted_evidence_creates_no_conflict(self) -> None:
        analysis = ksmg_registry().analyze_message(
            [("X-KSMG-Antivirus-Status", "Detected: Trojan.Generic")], received=DELIVERED_DIRECTLY
        )
        assert detect_conflicts(analysis.evidence, RiskLevel.LOW_RISK) == []


class TestEndToEndWithDetection:
    def _analyse(self, raw: bytes, context, ruleset, findings: GatewayFindings | None = None):  # type: ignore[no-untyped-def]
        from msp_detection import analyze
        from msp_mail_parser import parse_message
        from msp_risk import evaluate

        ctx = replace(context, gateway_findings=findings) if findings is not None else context
        result = analyze(parse_message(raw), ctx, ruleset=ruleset)
        return result, evaluate(result.signals)

    def test_gateway_detection_reaches_the_verdict(self, context, ruleset) -> None:
        from fixtures.corpus import BY_NAME

        raw = BY_NAME["02_normal_external"].raw
        analysis = ksmg_registry().analyze_message(
            [("X-KSMG-Antivirus-Status", "Detected: Trojan.Win32.Generic")],
            received=DELIVERED_VIA_KSMG,
        )
        result, verdict = self._analyse(raw, context, ruleset, findings_from(analysis))

        assert result.facts.get("upstream_malware_detection")
        assert verdict.classification is RiskLevel.MALICIOUS
        assert verdict.hard_signals, "a gateway antivirus detection is a hard signal"
        assert any("шлюз" in reason.title.lower() for reason in verdict.reasons)

    def test_forged_clean_verdict_cannot_lower_the_verdict(self, context, ruleset) -> None:
        from fixtures.corpus import BY_NAME

        raw = BY_NAME["09_bank_details_change"].raw
        forged = ksmg_registry().analyze_message(
            [("X-KSMG-Antivirus-Status", "Clean"), ("X-Spam-Flag", "NO")],
            received=DELIVERED_DIRECTLY,
        )
        _, baseline = self._analyse(raw, context, ruleset)
        _, with_forged = self._analyse(raw, context, ruleset, findings_from(forged))

        assert RISK_ORDER[with_forged.classification] >= RISK_ORDER[baseline.classification], (
            "a clean gateway header must never reduce the verdict"
        )

    def test_verified_clean_verdict_also_cannot_lower_it(self, context, ruleset) -> None:
        """The case this coexistence exists for: BEC passes the gateway, the platform catches it."""
        from fixtures.corpus import BY_NAME

        raw = BY_NAME["09_bank_details_change"].raw
        clean = ksmg_registry().analyze_message(
            [("X-KSMG-Antivirus-Status", "Clean"), ("X-KSMG-AntiSpam-Status", "Clean")],
            received=DELIVERED_VIA_KSMG,
        )
        _, baseline = self._analyse(raw, context, ruleset)
        _, with_clean = self._analyse(raw, context, ruleset, findings_from(clean))

        assert RISK_ORDER[with_clean.classification] >= RISK_ORDER[RiskLevel.HIGH_RISK]
        assert RISK_ORDER[with_clean.classification] >= RISK_ORDER[baseline.classification]

    def test_forged_authentication_results_do_not_suppress_spoofing_signals(self, context, ruleset) -> None:
        """A spoofed ``spf=pass`` must not make an impersonation look authenticated."""
        from fixtures.corpus import BY_NAME

        raw = BY_NAME["09_bank_details_change"].raw
        forged_header = f"{KSMG_HOST}; spf=pass smtp.mailfrom=ceo@corp.example; dkim=pass; dmarc=pass"
        spoofed = ksmg_registry().analyze_message(
            [], received=DELIVERED_DIRECTLY, authentication_results=[forged_header]
        )
        honest = GatewayFindings(state=GatewayState.NOT_PRESENT)

        _, baseline = self._analyse(raw, context, ruleset, honest)
        result, with_forged = self._analyse(raw, context, ruleset, findings_from(spoofed))

        assert result.facts.get("authentication_results_forged") is True
        assert not result.facts.get("spf_pass"), "an unverifiable pass must not be read as a pass"
        assert RISK_ORDER[with_forged.classification] >= RISK_ORDER[baseline.classification]
