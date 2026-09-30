"""Kaspersky Secure Mail Gateway header adapter (ТЗ 1.0.2 §18).

KSMG is the first full provider because it is what the pilot organisation runs, but nothing here
leaks into the platform core: it is one implementation of :class:`~msp_mail_gateway.base.
MailGatewayProvider` among several, and the platform works with none of them.

The header set differs between KSMG versions and policies, so the adapter reads what is present
rather than requiring a fixed layout. A header it does not recognise is reported as the gateway
having processed the message with an unread verdict — never as "clean".

Any KSMG API that a particular version exposes belongs in a separate adapter
(:mod:`msp_mail_gateway.api_base`), not in this parser: mixing the two would make header trust
depend on API availability.
"""

from __future__ import annotations

from msp_contracts import (
    GatewayCapability,
    GatewayCategory,
    GatewayEvidence,
    GatewayEvidenceSource,
    GatewayVerdictType,
)

from .base import BaseGatewayProvider, GatewayContext, GatewayProviderConfig
from .headers import HeaderIndex, classify_value, extract_score, extract_threat_name
from .trust import decide_header_trust

#: Header groups KSMG writes, mapped to the engine that produced them. Several spellings occur
#: across versions; all known ones are listed rather than guessed at runtime.
_ENGINE_HEADERS: tuple[tuple[GatewayCategory, tuple[str, ...], tuple[str, ...]], ...] = (
    (
        GatewayCategory.ANTIVIRUS,
        ("x-ksmg-antivirus-status", "x-ksmg-av-status", "x-ksmg-antivirus"),
        ("x-ksmg-antivirus-method", "x-ksmg-av-method"),
    ),
    (
        GatewayCategory.ANTISPAM,
        ("x-ksmg-antispam-status", "x-ksmg-as-status", "x-ksmg-antispam"),
        ("x-ksmg-antispam-rate", "x-ksmg-antispam-info", "x-ksmg-antispam-version"),
    ),
    (
        GatewayCategory.ANTIPHISHING,
        ("x-ksmg-antiphishing-status", "x-ksmg-ap-status", "x-ksmg-antiphishing"),
        ("x-ksmg-antiphishing-info",),
    ),
)
_POLICY_HEADERS = ("x-ksmg-rule-id", "x-ksmg-rule-name", "x-ksmg-policy", "x-ksmg-action")


class KsmgGatewayProvider(BaseGatewayProvider):
    provider_type = "ksmg"

    def capabilities(self) -> set[GatewayCapability]:
        # Header parsing is all this adapter does. AV/spam/phishing results are listed because
        # KSMG reports them separately and the console shows them as separate lines.
        return {
            GatewayCapability.HEADER_VERDICT,
            GatewayCapability.AV_RESULT,
            GatewayCapability.SPAM_RESULT,
            GatewayCapability.PHISHING_RESULT,
        }

    def parse_message_headers(
        self, headers: list[tuple[str, str]], context: GatewayContext
    ) -> list[GatewayEvidence]:
        index = HeaderIndex(headers)
        if not index.with_prefix("x-ksmg-"):
            return []

        decision = decide_header_trust(
            self.provider_id, verification=context.verification, registered=context.registered
        )
        policy = " ".join(value for name in _POLICY_HEADERS if (value := index.first(name))).strip()[:200]

        out: list[GatewayEvidence] = []
        for category, status_names, detail_names in _ENGINE_HEADERS:
            status = index.first(*status_names)
            if not status:
                continue
            detail = index.first(*detail_names)
            verdict = classify_value(status)
            if verdict is None:
                verdict = GatewayVerdictType.UNKNOWN
            elif verdict is GatewayVerdictType.MALICIOUS and category is GatewayCategory.ANTISPAM:
                # "Detected" from the anti-spam engine means spam, not malware.
                verdict = GatewayVerdictType.SPAM
            elif verdict is GatewayVerdictType.MALICIOUS and category is GatewayCategory.ANTIPHISHING:
                verdict = GatewayVerdictType.PHISHING
            out.append(
                GatewayEvidence(
                    provider_id=self.provider_id,
                    provider_type=self.provider_type,
                    message_id=context.internet_message_id,
                    verdict=verdict,
                    category=category,
                    confidence=0.85 if decision.trusted else 0.0,
                    score=extract_score(detail, status),
                    threat_name=extract_threat_name(status),
                    engine=category.value,
                    policy=policy,
                    source=GatewayEvidenceSource.HEADER,
                    trusted=decision.trusted,
                    trust_state=decision.state,
                    trust_reason=decision.reason,
                    raw_reference=status_names[0],
                    normalized_detail={"status": status[:200], "detail": detail[:200]},
                )
            )

        if not out:
            # KSMG headers exist but none of the known status headers could be read. Record the
            # fact; an unreadable verdict is not a clean one.
            out.append(
                GatewayEvidence(
                    provider_id=self.provider_id,
                    provider_type=self.provider_type,
                    message_id=context.internet_message_id,
                    verdict=GatewayVerdictType.UNKNOWN,
                    category=GatewayCategory.UNKNOWN,
                    confidence=0.0,
                    source=GatewayEvidenceSource.HEADER,
                    trusted=decision.trusted,
                    trust_state=decision.state,
                    trust_reason=decision.reason,
                    raw_reference="x-ksmg-*",
                    normalized_detail={
                        "headers_present": sorted(name for name, _ in index.with_prefix("x-ksmg-"))[:10]
                    },
                )
            )
        return out


def build(config: GatewayProviderConfig) -> KsmgGatewayProvider:
    return KsmgGatewayProvider(config)
