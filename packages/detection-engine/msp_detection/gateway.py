"""Turning upstream gateway evidence into facts (ТЗ 2.1, ТЗ 1.0.2 §17, §27).

The platform is a companion, not a replacement. Where an organisation already runs a gateway —
Kaspersky Secure Mail Gateway, Exchange Online Protection, FortiMail, Rspamd — that gateway
examined the message at delivery with capabilities this platform deliberately does not have,
notably a full antivirus engine and sometimes a sandbox.

Since 1.0.2 this module no longer parses headers. Parsing, vendor normalisation and the trust
decision belong to ``msp_mail_gateway``, which can prove from the ``Received`` chain whether the
message really passed the gateway whose headers it carries. What remains here is the mapping from
normalised evidence to facts, under three rules that do not change per vendor:

* a verdict is a *signal*, never the final word (ТЗ 2.1);
* a "clean" verdict never lowers risk — the attacks this platform targets are precisely the
  payload-free ones a gateway passes through (ТЗ 49.9, ТЗ 1.0.2 §17);
* only *trusted* evidence produces a detection fact. An unverified claim becomes a fact about
  the claim itself, because forged "already scanned" headers are a known technique.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from msp_contracts import (
    GatewayCategory,
    GatewayEvidence,
    GatewayState,
    GatewayVerdictType,
    ProviderConflict,
)


@dataclass
class GatewayFindings:
    """What the gateway layer established about one message.

    Assembled by the API/worker from ``msp_mail_gateway`` and handed to the detection engine, so
    the engine keeps no dependency on any provider implementation.
    """

    evidence: list[GatewayEvidence] = field(default_factory=list)
    state: GatewayState = GatewayState.NOT_PRESENT
    #: Authentication-Results headers written by a verified authentication server (§4.4).
    trusted_auth_results: list[str] = field(default_factory=list)
    untrusted_auth_results: list[str] = field(default_factory=list)
    auth_tampering_suspected: bool = False
    #: Registered gateways whose headers appeared but could not be verified in the chain.
    unverified_gateways: list[str] = field(default_factory=list)
    #: Hops the topology expects that this message did not pass.
    missing_hops: list[str] = field(default_factory=list)
    position_mismatches: list[str] = field(default_factory=list)
    chain_verified: bool = False
    conflicts: list[ProviderConflict] = field(default_factory=list)

    @property
    def present(self) -> bool:
        return bool(self.evidence) or self.state is not GatewayState.NOT_PRESENT

    @property
    def trusted_evidence(self) -> list[GatewayEvidence]:
        return [item for item in self.evidence if item.trusted]

    @property
    def untrusted_evidence(self) -> list[GatewayEvidence]:
        return [item for item in self.evidence if not item.trusted]


def _evidence_payload(item: GatewayEvidence) -> dict[str, Any]:
    return {
        "gateway": item.provider_id,
        "verdict": item.verdict.value,
        "category": item.category.value,
        "engine": item.engine,
        "threat_name": item.threat_name,
        "score": item.score,
        "source": item.source.value,
        "trust_reason": item.trust_reason,
    }


def gateway_facts(findings: GatewayFindings | None) -> list[tuple[str, Any, dict[str, Any]]]:
    """Map normalised gateway evidence onto facts for the rule engine.

    Nothing here can lower risk. The only "clean" fact produced,
    ``upstream_gateway_clean_observed``, exists so the console can show the analyst what the
    gateway said; the rule that reads it carries zero weight.
    """
    out: list[tuple[str, Any, dict[str, Any]]] = []
    if findings is None or not findings.present:
        return out

    trusted = findings.trusted_evidence
    malware = [
        item
        for item in trusted
        if item.verdict is GatewayVerdictType.MALICIOUS
        or (item.verdict is GatewayVerdictType.PHISHING and item.category is GatewayCategory.ANTIVIRUS)
    ]
    phishing = [item for item in trusted if item.verdict is GatewayVerdictType.PHISHING]
    spam = [item for item in trusted if item.verdict is GatewayVerdictType.SPAM]
    suspicious = [item for item in trusted if item.verdict is GatewayVerdictType.SUSPICIOUS]
    clean = [item for item in trusted if item.verdict is GatewayVerdictType.CLEAN_OBSERVED]

    if malware:
        # The hard signal of ТЗ 1.0.2 §27: the gateway has an AV engine this platform has not,
        # so its detection raises the verdict even when our own score is low.
        best = max(malware, key=lambda item: (item.confidence, bool(item.threat_name)))
        out.append(("upstream_malware_detection", True, _evidence_payload(best)))
        out.append(("gateway_detected_malware", True, _evidence_payload(best)))
    if phishing and not malware:
        out.append(("gateway_detected_phishing", True, _evidence_payload(phishing[0])))
    if spam:
        out.append(("gateway_detected_spam", True, _evidence_payload(spam[0])))
    if suspicious:
        out.append(("gateway_marked_suspicious", True, _evidence_payload(suspicious[0])))
    if clean:
        # Recorded for the analyst's benefit only. No rule may reduce risk from this fact.
        out.append(
            (
                "upstream_gateway_clean_observed",
                True,
                {"gateways": sorted({item.provider_id for item in clean})},
            )
        )

    if findings.evidence:
        out.append(
            (
                "upstream_gateway_present",
                True,
                {
                    "gateways": sorted({item.provider_id for item in findings.evidence}),
                    "state": findings.state.value,
                    "chain_verified": findings.chain_verified,
                },
            )
        )

    untrusted = findings.untrusted_evidence
    if untrusted:
        unknown = sorted({item.provider_id for item in untrusted if item.trust_state == "unknown_gateway"})
        unverified = sorted({item.provider_id for item in untrusted if item.trust_state != "unknown_gateway"})
        if unknown:
            out.append(("untrusted_gateway_header", True, {"gateways": unknown}))
        if unverified:
            # The organisation does run this gateway, but the chain does not show the message
            # passing it — the shape of a copied header.
            out.append(
                (
                    "unverified_gateway_header",
                    True,
                    {
                        "gateways": unverified,
                        "reason": untrusted[0].trust_reason,
                        "claimed": [item.verdict.value for item in untrusted[:3]],
                    },
                )
            )

    if findings.auth_tampering_suspected:
        out.append(
            (
                "authentication_results_forged",
                True,
                {
                    "headers": len(findings.untrusted_auth_results),
                    "sample": findings.untrusted_auth_results[:1],
                },
            )
        )
    elif findings.untrusted_auth_results:
        out.append(
            ("authentication_results_untrusted", True, {"headers": len(findings.untrusted_auth_results)})
        )

    if findings.position_mismatches:
        out.append(("mail_flow_topology_mismatch", True, {"detail": findings.position_mismatches[:3]}))
    if findings.conflicts:
        out.append(
            (
                "provider_verdict_conflict",
                True,
                {"kinds": sorted({c.kind.value for c in findings.conflicts})},
            )
        )
    return out
