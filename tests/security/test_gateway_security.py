"""Security requirements for the multi-gateway framework (ТЗ 1.0.2 §34).

The specification lists twelve required tests. Each has a class or test below, and each is
written as an attack rather than as a feature check: the question is not "does the parser read
this header" but "can someone who does not control the gateway make the platform act as if they
did".

The common thread is that gateway evidence arrives over channels the sender may control
(headers), over channels with no authentication at all (syslog), or over channels that can be
impersonated (an API endpoint). Each one needs its own proof of origin, and none of them may be
able to *lower* a verdict even when the proof succeeds.
"""

from __future__ import annotations

from typing import ClassVar

import pytest
from msp_contracts import (
    GatewayVerdictType,
    RemediationType,
    RiskLevel,
    TrustedMailHop,
    TrustState,
)
from msp_mail_gateway import (
    ApiConfigurationError,
    ApiUnavailable,
    GatewayApiClient,
    GatewayApiConfig,
    GatewayProviderConfig,
    GatewayRegistry,
    KsmgGatewayProvider,
    SyslogIngestor,
    SyslogIngestorConfig,
    SyslogRejected,
    build_url,
    detect_conflicts,
    parse_syslog,
    validate_base_url,
)
from msp_mail_gateway.syslog import event_to_evidence

GATEWAY_HOST = "ksmg-01.corp.example"
GATEWAY_IP = "10.20.0.11"
RELAY = "mx.corp.example"

VERIFIED_CHAIN = [
    f"from {GATEWAY_HOST} (ksmg-01 [{GATEWAY_IP}]) by {RELAY} with ESMTPS id aa11;"
    " Mon, 1 Sep 2025 10:02:00 +0300",
    f"from mx.sender.example (mx.sender.example [203.0.113.9]) by {GATEWAY_HOST} with ESMTPS id bb22;"
    " Mon, 1 Sep 2025 10:00:00 +0300",
]
FORGED_CHAIN = [
    f"from evil.example (unknown [198.51.100.7]) by {RELAY} with ESMTP id cc33;"
    " Mon, 1 Sep 2025 10:00:00 +0300",
]


def registry() -> GatewayRegistry:
    hop = TrustedMailHop(
        id="hop-ksmg",
        provider_id="ksmg",
        hostname=GATEWAY_HOST,
        ip_networks=["10.20.0.0/24"],
        authserv_ids=[GATEWAY_HOST],
    )
    return GatewayRegistry(
        [
            KsmgGatewayProvider(
                GatewayProviderConfig(provider_id="ksmg", provider_type="ksmg", trusted_hops=[hop])
            )
        ]
    )


class TestSpoofedGatewayHeader:
    """§34: spoofed KSMG header."""

    HEADERS: ClassVar[list[tuple[str, str]]] = [
        ("X-KSMG-Antivirus-Status", "Clean"),
        ("X-KSMG-AntiSpam-Status", "Clean"),
        ("X-KSMG-AntiPhishing-Status", "Clean"),
    ]

    def test_forged_clean_verdict_is_not_trusted(self) -> None:
        analysis = registry().analyze_message(self.HEADERS, received=FORGED_CHAIN)
        assert analysis.evidence
        assert all(not item.trusted for item in analysis.evidence)
        assert all(item.trust_state is TrustState.UNVERIFIED_CHAIN for item in analysis.evidence)

    def test_forged_detection_cannot_force_a_malicious_verdict(self) -> None:
        """The reverse attack: forcing MALICIOUS floods the analyst queue."""
        analysis = registry().analyze_message(
            [("X-KSMG-Antivirus-Status", "Detected: Trojan.Fake")], received=FORGED_CHAIN
        )
        from msp_mail_gateway import upstream_hard_signal

        assert upstream_hard_signal(analysis.evidence) is None
        assert analysis.negative_evidence == []

    def test_attacker_cannot_claim_the_gateway_by_hostname_alone(self) -> None:
        """A ``by`` clause naming our gateway, written by a machine we do not control."""
        chain = [
            f"from evil.example (unknown [198.51.100.7]) by {GATEWAY_HOST}.evil.example;"
            " Mon, 1 Sep 2025 10:00:00 +0300"
        ]
        analysis = registry().analyze_message(self.HEADERS, received=chain)
        assert all(not item.trusted for item in analysis.evidence), (
            "a suffix that is not on a label boundary must not match"
        )

    def test_verified_chain_is_required_not_merely_a_registered_gateway(self) -> None:
        """Naming the product in configuration is not evidence about a message."""
        bare = GatewayRegistry(
            [KsmgGatewayProvider(GatewayProviderConfig(provider_id="ksmg", provider_type="ksmg"))]
        )
        analysis = bare.analyze_message(self.HEADERS, received=VERIFIED_CHAIN)
        assert all(not item.trusted for item in analysis.evidence)


class TestSpoofedAuthenticationResults:
    """§34: spoofed Authentication-Results."""

    PASSING = f"{GATEWAY_HOST}; spf=pass smtp.mailfrom=ceo@corp.example; dkim=pass; dmarc=pass"

    def test_our_own_authserv_id_on_an_unverified_path_is_forgery(self) -> None:
        analysis = registry().analyze_message(
            [], received=FORGED_CHAIN, authentication_results=[self.PASSING]
        )
        assert analysis.trusted_auth_results == []
        assert analysis.auth_tampering_suspected

    def test_a_third_party_authserv_id_is_untrusted_but_not_forgery(self) -> None:
        """Legitimate forwarded mail carries a stranger's Authentication-Results.

        Treating that as tampering would flag a large share of ordinary mail, so it is recorded
        as unusable rather than as an attack.
        """
        analysis = registry().analyze_message(
            [],
            received=FORGED_CHAIN,
            authentication_results=["mx.forwarder.example; spf=pass; dkim=pass"],
        )
        assert analysis.trusted_auth_results == []
        assert not analysis.auth_tampering_suspected

    def test_verified_server_results_are_read(self) -> None:
        analysis = registry().analyze_message(
            [], received=VERIFIED_CHAIN, authentication_results=[self.PASSING]
        )
        assert len(analysis.trusted_auth_results) == 1
        assert not analysis.auth_tampering_suspected

    def test_prepended_header_does_not_override_the_genuine_one(self) -> None:
        """An attacker can only *add* headers; the genuine one must still be found."""
        analysis = registry().analyze_message(
            [],
            received=VERIFIED_CHAIN,
            authentication_results=[
                "attacker.example; spf=pass; dkim=pass; dmarc=pass",
                f"{GATEWAY_HOST}; spf=fail; dkim=none; dmarc=fail",
            ],
        )
        assert len(analysis.trusted_auth_results) == 1
        assert "spf=fail" in analysis.trusted_auth_results[0], (
            "the verified server's verdict is the one that counts, even when it is worse"
        )


class TestForgedReceivedChain:
    """§34: forged Received chain."""

    def test_a_hop_invented_below_the_real_chain_is_at_the_wrong_position(self) -> None:
        """The attacker controls only the bottom of the chain.

        Our relay's own header cannot be forged — if it says it received the message from the
        gateway's address, that is genuine evidence. What an attacker *can* do is prepend hops
        below the real ones, claiming the gateway's identity somewhere it does not belong. That
        is what ``position_in_chain`` catches.
        """
        chain = [
            # Written by our relay: the message came straight from the internet.
            f"from evil.example (unknown [198.51.100.7]) by {RELAY}; Mon, 1 Sep 2025 10:02:00 +0300",
            # Invented by the attacker, claiming to be our gateway.
            f"from sender.example by {GATEWAY_HOST}; Mon, 1 Sep 2025 10:01:00 +0300",
        ]
        hop = TrustedMailHop(
            id="hop-ksmg",
            provider_id="ksmg",
            hostname=GATEWAY_HOST,
            ip_networks=["10.20.0.0/24"],
            # The gateway sits directly in front of the relay, so it writes hop 1 and appears
            # in hop 0. Anywhere else is not our topology.
            position_in_chain=1,
        )
        strict = GatewayRegistry(
            [
                KsmgGatewayProvider(
                    GatewayProviderConfig(provider_id="ksmg", provider_type="ksmg", trusted_hops=[hop])
                )
            ]
        )
        analysis = strict.analyze_message([("X-KSMG-Antivirus-Status", "Clean")], received=chain)
        verification = analysis.verification
        assert verification is not None
        assert not verification.matches, (
            "a Received header naming our gateway, on a path our own relay says came straight "
            "from the internet, is a forged chain"
        )
        assert verification.position_mismatches
        assert all(not item.trusted for item in analysis.evidence)

    def test_a_hop_our_own_relay_recorded_is_genuine_evidence(self) -> None:
        """The other side of the same coin: a real path must still verify."""
        chain = [
            f"from {GATEWAY_HOST} (ksmg-01 [{GATEWAY_IP}]) by {RELAY}; Mon, 1 Sep 2025 10:02:00 +0300",
            f"from sender.example by {GATEWAY_HOST}; Mon, 1 Sep 2025 10:01:00 +0300",
        ]
        analysis = registry().analyze_message(
            [("X-KSMG-Antivirus-Status", "Detected: EICAR-Test-File")], received=chain
        )
        assert analysis.evidence[0].trusted

    def test_a_missing_chain_is_never_trusted(self) -> None:
        analysis = registry().analyze_message([("X-KSMG-Antivirus-Status", "Clean")], received=[])
        assert all(not item.trusted for item in analysis.evidence)

    def test_out_of_order_timestamps_are_reported(self) -> None:
        from msp_mail_gateway import parse_received, summarise

        chain = [
            f"from a by {RELAY}; Mon, 1 Sep 2025 09:00:00 +0300",
            f"from b by {GATEWAY_HOST}; Mon, 1 Sep 2025 10:00:00 +0300",
        ]
        summary = summarise(parse_received(chain))
        assert summary.out_of_order, "a hop older than its successor is a forged or skewed chain"


class TestSyslogSource:
    """§34: untrusted syslog sender, syslog replay, oversized gateway event."""

    LINE = (
        "<134>1 2025-09-01T10:00:00+03:00 ksmg-01 ksmg 1234 ID47 "
        'verdict=detected threat="EICAR-Test-File" message_id=<x@sender.example> queue_id=ab12'
    )

    def ingestor(self, **overrides: object) -> SyslogIngestor:
        # A very wide default window, so only the replay tests below exercise the age check.
        settings: dict[str, object] = {
            "provider_id": "ksmg-syslog",
            "allowed_sources": ("10.20.0.0/24",),
            "max_age_seconds": 10**9,
        }
        settings.update(overrides)
        return SyslogIngestor(SyslogIngestorConfig(**settings))  # type: ignore[arg-type]

    def test_event_from_an_unlisted_source_is_refused(self) -> None:
        with pytest.raises(SyslogRejected) as exc:
            self.ingestor().ingest(self.LINE, "198.51.100.7")
        assert exc.value.reason == "source_not_allowed"

    def test_an_empty_allowlist_accepts_nothing(self) -> None:
        """Plain syslog has no authentication, so an unset allowlist must fail closed."""
        ingestor = SyslogIngestor(SyslogIngestorConfig(provider_id="s", allowed_sources=()))
        with pytest.raises(SyslogRejected):
            ingestor.ingest(self.LINE, "10.20.0.11")

    def test_refused_events_are_dead_lettered_with_a_reason(self) -> None:
        ingestor = self.ingestor()
        with pytest.raises(SyslogRejected):
            ingestor.ingest(self.LINE, "198.51.100.7")
        letters = ingestor.dead_letters
        assert len(letters) == 1
        assert letters[0].reason == "source_not_allowed"
        assert letters[0].source_ip == "198.51.100.7"

    def test_replayed_event_is_refused(self) -> None:
        ingestor = self.ingestor(max_age_seconds=60)
        with pytest.raises(SyslogRejected) as exc:
            # A captured log line from last year, re-sent to reopen a closed verdict.
            ingestor.ingest(self.LINE, "10.20.0.11")
        assert exc.value.reason == "replay_too_old"

    def test_future_timestamp_is_refused(self) -> None:
        from datetime import timedelta

        from msp_contracts import utcnow

        future = (utcnow() + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        line = f"<134>1 {future} ksmg-01 ksmg 1 ID1 verdict=detected"
        with pytest.raises(SyslogRejected) as exc:
            self.ingestor(max_age_seconds=600).ingest(line, "10.20.0.11")
        assert exc.value.reason == "timestamp_in_future"

    def test_event_without_a_timestamp_is_refused(self) -> None:
        """Without a timestamp a replay cannot be told apart from a fresh event."""
        with pytest.raises(SyslogRejected) as exc:
            self.ingestor().ingest("<134>1 - ksmg-01 ksmg 1 ID1 verdict=detected", "10.20.0.11")
        assert exc.value.reason == "missing_timestamp"

    def test_duplicate_event_is_counted_once(self) -> None:
        ingestor = self.ingestor()
        ingestor.ingest(self.LINE, "10.20.0.11")
        with pytest.raises(SyslogRejected) as exc:
            ingestor.ingest(self.LINE, "10.20.0.11")
        assert exc.value.reason == "duplicate_event"
        assert ingestor.accepted == 1
        assert ingestor.duplicates == 1
        # A retransmission is expected traffic, not an integration gap: not dead-lettered.
        assert ingestor.dead_letters == []

    def test_oversized_event_is_refused_before_parsing(self) -> None:
        oversized = "<134>1 2025-09-01T10:00:00+03:00 h a 1 ID1 " + "x" * (40 * 1024)
        with pytest.raises(SyslogRejected) as exc:
            self.ingestor().ingest(oversized, "10.20.0.11")
        assert exc.value.reason == "oversized_event"

    def test_unknown_format_is_dead_lettered_not_dropped(self) -> None:
        ingestor = self.ingestor()
        with pytest.raises(SyslogRejected) as exc:
            ingestor.ingest("this is not syslog at all", "10.20.0.11")
        assert exc.value.reason == "unparseable_format"
        assert ingestor.dead_letters[0].raw.startswith("this is not syslog")

    def test_accepted_event_is_trusted_and_normalised(self) -> None:
        event = parse_syslog(self.LINE, "10.20.0.11", "tls")
        evidence = event_to_evidence(event, "ksmg-syslog", "syslog")
        assert evidence.trusted
        assert evidence.verdict is GatewayVerdictType.MALICIOUS
        assert evidence.threat_name == "EICAR-Test-File"
        assert evidence.normalized_detail["queue_id"] == "ab12"

    def test_unauthenticated_transport_can_be_refused(self) -> None:
        with pytest.raises(SyslogRejected) as exc:
            self.ingestor(require_authenticated_transport=True).ingest(self.LINE, "10.20.0.11", "udp")
        assert exc.value.reason == "unauthenticated_transport"


class TestGatewayApi:
    """§34: API TLS validation, timeout, rate limit, malicious API payload."""

    def config(self, **overrides: object) -> GatewayApiConfig:
        base = {
            "provider_id": "vendor-api",
            "base_url": "https://gateway.corp.example/api/v1/",
            "credential": "not-a-real-token",
        }
        base.update(overrides)
        return GatewayApiConfig(**base)  # type: ignore[arg-type]

    def test_tls_verification_cannot_be_disabled_in_production(self) -> None:
        with pytest.raises(ApiConfigurationError, match="verify_tls"):
            GatewayApiClient(self.config(verify_tls=False), environment="production")

    def test_plain_http_is_refused(self) -> None:
        with pytest.raises(ApiConfigurationError, match="HTTPS"):
            validate_base_url("http://gateway.corp.example/api/", environment="production")

    def test_non_http_schemes_are_refused(self) -> None:
        for url in ("file:///etc/passwd", "gopher://x/", "ftp://host/"):
            with pytest.raises(ApiConfigurationError):
                validate_base_url(url, environment="production")

    def test_a_path_cannot_leave_the_configured_host(self) -> None:
        """The SSRF gate: a path that carries its own host is refused, not normalised."""
        base = "https://gateway.corp.example/api/v1/"
        for path in (
            "https://attacker.example/steal",
            "//attacker.example/steal",
            "../../../../admin",
        ):
            with pytest.raises(ApiConfigurationError):
                build_url(base, path)

    def test_control_characters_in_a_path_are_refused(self) -> None:
        with pytest.raises(ApiConfigurationError, match="control characters"):
            build_url("https://gateway.corp.example/api/", "messages\r\nX-Injected: 1")

    def test_loopback_targets_are_refused(self) -> None:
        with pytest.raises(ApiConfigurationError):
            validate_base_url("https://127.0.0.1/api/", environment="production")
            build_url("https://127.0.0.1/api/", "x")

    def test_a_relative_path_is_allowed(self) -> None:
        url = build_url("https://gateway.corp.example/api/v1/", "messages/42")
        assert url == "https://gateway.corp.example/api/v1/messages/42"

    def test_the_credential_never_appears_in_the_description(self) -> None:
        client = GatewayApiClient(
            self.config(credential="super-secret-value"),
            environment="test",
        )
        rendered = repr(client.describe())
        assert "super-secret-value" not in rendered
        assert client.describe()["credential"] == "inline"

    def test_rate_limit_is_enforced_locally(self) -> None:
        client = GatewayApiClient(self.config(rate_limit_per_minute=1), environment="test")
        client._rate_limiter.allow()
        with pytest.raises(ApiUnavailable, match="rate limit"):
            client.get_json("messages", cache=False)

    def test_circuit_breaker_opens_after_repeated_failures(self) -> None:
        client = GatewayApiClient(self.config(failure_threshold=2), environment="test")
        for _ in range(2):
            client._breaker.record_failure()
        assert client._breaker.is_open
        with pytest.raises(ApiUnavailable, match="circuit breaker"):
            client.get_json("messages", cache=False)
        assert client.health().status == "unavailable"

    def test_a_missing_credential_is_reported_not_assumed(self) -> None:
        client = GatewayApiClient(self.config(credential=""), environment="test")
        assert client.health().status == "not_configured"


class TestCrossOrganisationIsolation:
    """§34: cross-org leakage."""

    def test_evidence_is_scoped_to_one_organisation(self, db, organization) -> None:
        from msp_api.db.models import GatewayEvidenceRecord, Organization

        other = Organization(name="Other", corporate_domains=["other.example"])
        db.add(other)
        db.flush()
        db.add(
            GatewayEvidenceRecord(
                organization_id=other.id,
                message_id=None,
                provider_id="ksmg",
                verdict="MALICIOUS",
                trusted=True,
            )
        )
        db.commit()

        from sqlalchemy import select

        ours = (
            db.execute(
                select(GatewayEvidenceRecord).where(GatewayEvidenceRecord.organization_id == organization.id)
            )
            .scalars()
            .all()
        )
        assert ours == [], "evidence belonging to another organisation must not be visible"

    def test_the_registry_only_loads_one_organisation(self, db, settings, organization) -> None:
        from msp_api.db.models import MailGateway, Organization
        from msp_api.services.gateways import build_registry

        other = Organization(name="Other", corporate_domains=["other.example"])
        db.add(other)
        db.flush()
        db.add(
            MailGateway(
                organization_id=other.id,
                provider_id="their-ksmg",
                provider_type="ksmg",
                enabled=True,
            )
        )
        db.commit()

        registry = build_registry(db, settings, organization.id)
        assert "their-ksmg" not in {p.provider_id for p in registry.providers}


class TestRemediationScope:
    """§34: remediation outside mailbox scope."""

    def test_gateway_remediation_is_refused_at_1_0_2(self, settings) -> None:
        from msp_api.services.remediation_providers import GatewayRemediationProvider

        provider = GatewayRemediationProvider(registry())
        plan = provider.propose(RemediationType.QUARANTINE, [])
        assert not plan.executable
        assert any("read-only" in blocker for blocker in plan.blockers)
        result = provider.execute(plan, [], dry_run=False)
        assert result["executed"] is False
        assert result["errors"]

    def test_exchange_remediation_requires_a_scope(self, settings) -> None:
        from dataclasses import replace as dc_replace

        from msp_api.services.remediation_providers import ExchangeRemediationProvider

        enabled = settings.model_copy(update={"remediation_enabled": True, "remediation_dry_run_only": False})
        provider = ExchangeRemediationProvider(provider=None, settings=enabled)
        plan = provider.propose(RemediationType.QUARANTINE, [])
        assert not plan.executable
        assert any("область ящиков" in blocker for blocker in plan.blockers)
        del dc_replace

    def test_out_of_scope_mailbox_is_refused_by_the_ews_adapter(self) -> None:
        from msp_exchange.ews import EwsConfig, MailboxOutOfScope, OnPremEwsExchangeProvider

        adapter = OnPremEwsExchangeProvider(
            EwsConfig(
                username="svc@corp.example",
                primary_smtp_address="svc@corp.example",
                mailbox_scope=("pilot@corp.example",),
            )
        )
        with pytest.raises(MailboxOutOfScope):
            adapter._account_for("ceo@corp.example")

    def test_verification_reports_a_partially_applied_remediation(self) -> None:
        """An action that left messages in place must not be reported as complete."""
        from msp_api.services.remediation_providers import (
            ExchangeRemediationProvider,
            RemediationPlan,
            RemediationTarget,
        )

        class HalfWorkingProvider:
            provider_id = "fake"

            def _find_item(self, ref):  # type: ignore[no-untyped-def]
                if getattr(ref, "item_id", "") == "still-there":
                    return object()
                raise KeyError("gone")

        plan = RemediationPlan(target=RemediationTarget.EXCHANGE, action=RemediationType.QUARANTINE)
        provider = ExchangeRemediationProvider(HalfWorkingProvider(), settings=None)

        class Ref:
            def __init__(self, item_id: str) -> None:
                self.item_id = item_id
                self.mailbox = "pilot@corp.example"

        verification = provider.verify(plan, [Ref("gone"), Ref("still-there")])
        assert verification.verified
        assert verification.confirmed == 1
        assert verification.still_present == 1
        assert not verification.complete, "a partial remediation is not a complete one"


class TestVerdictsCannotLowerRisk:
    """The invariant that outlives every individual adapter (ТЗ 1.0.2 §17, §27)."""

    def test_no_verdict_type_lowers_risk(self) -> None:
        assert not any(verdict.lowers_risk for verdict in GatewayVerdictType)

    def test_clean_observed_is_not_a_safe_verdict(self) -> None:
        assert GatewayVerdictType.CLEAN_OBSERVED.name != "SAFE"
        assert not GatewayVerdictType.CLEAN_OBSERVED.is_negative
        assert not GatewayVerdictType.CLEAN_OBSERVED.lowers_risk

    def test_a_clean_gateway_with_a_high_platform_verdict_is_a_visible_conflict(self) -> None:
        analysis = registry().analyze_message([("X-KSMG-Antivirus-Status", "Clean")], received=VERIFIED_CHAIN)
        conflicts = detect_conflicts(analysis.evidence, RiskLevel.HIGH_RISK)
        assert [c.kind.value for c in conflicts] == ["GATEWAY_CLEAN_PLATFORM_HIGH"]
        assert "штатная ситуация" in conflicts[0].summary
