"""Built-in header parsers: EOP, SpamAssassin/Rspamd and generic AV (ТЗ 1.0.2 §36).

These are adapters rather than a vendor integration: they read headers that are widespread enough
to be worth recognising out of the box. Each one follows the same rules as every other provider —
its verdict is evidence, its "clean" means nothing, and its headers are believed only when the
delivery chain proves the message passed the hop that writes them.
"""

from __future__ import annotations

import re

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

_SCL_RE = re.compile(r"(?i)\bSCL:\s*(-?\d+)")
_BCL_RE = re.compile(r"(?i)\bBCL:\s*(\d+)")
_PCL_RE = re.compile(r"(?i)\bPCL:\s*(-?\d+)")
_CAT_RE = re.compile(r"(?i)\bCAT:\s*([A-Z]+)")
# Microsoft's CAT values that mean a detection, as opposed to routing or bulk classification.
_EOP_CATEGORIES = {
    "PHSH": (GatewayVerdictType.PHISHING, GatewayCategory.ANTIPHISHING),
    "MALW": (GatewayVerdictType.MALICIOUS, GatewayCategory.ANTIVIRUS),
    "SPM": (GatewayVerdictType.SPAM, GatewayCategory.ANTISPAM),
    "HSPM": (GatewayVerdictType.SPAM, GatewayCategory.ANTISPAM),
    "SPOOF": (GatewayVerdictType.PHISHING, GatewayCategory.ANTIPHISHING),
    "BULK": (GatewayVerdictType.SPAM, GatewayCategory.ANTISPAM),
}


class _HeaderProviderBase(BaseGatewayProvider):
    """Trust handling shared by the built-in parsers."""

    def capabilities(self) -> set[GatewayCapability]:
        return {GatewayCapability.HEADER_VERDICT}

    def _decision(self, context: GatewayContext):  # type: ignore[no-untyped-def]
        return decide_header_trust(
            self.provider_id, verification=context.verification, registered=context.registered
        )

    def _evidence(
        self,
        context: GatewayContext,
        decision,  # type: ignore[no-untyped-def]
        *,
        verdict: GatewayVerdictType,
        category: GatewayCategory,
        reference: str,
        confidence: float = 0.7,
        **fields: object,
    ) -> GatewayEvidence:
        return GatewayEvidence(
            provider_id=self.provider_id,
            provider_type=self.provider_type,
            message_id=context.internet_message_id,
            verdict=verdict,
            category=category,
            confidence=confidence if decision.trusted else 0.0,
            source=GatewayEvidenceSource.HEADER,
            trusted=decision.trusted,
            trust_state=decision.state,
            trust_reason=decision.reason,
            raw_reference=reference,
            **fields,  # type: ignore[arg-type]
        )


class EopGatewayProvider(_HeaderProviderBase):
    """Exchange Online Protection / Microsoft Defender for Office."""

    provider_type = "eop"

    def parse_message_headers(
        self, headers: list[tuple[str, str]], context: GatewayContext
    ) -> list[GatewayEvidence]:
        index = HeaderIndex(headers)
        report = index.first("x-forefront-antispam-report", "x-microsoft-antispam")
        if not report:
            return []
        decision = self._decision(context)
        out: list[GatewayEvidence] = []

        category_match = _CAT_RE.search(report)
        if category_match:
            key = category_match.group(1).upper()
            mapped = _EOP_CATEGORIES.get(key)
            if mapped is not None:
                verdict, category = mapped
                out.append(
                    self._evidence(
                        context,
                        decision,
                        verdict=verdict,
                        category=category,
                        reference="X-Forefront-Antispam-Report",
                        confidence=0.8,
                        engine="eop",
                        normalized_detail={"category": key},
                    )
                )

        scl_match = _SCL_RE.search(report)
        if scl_match:
            scl = int(scl_match.group(1))
            # Microsoft's scale: -1 trusted, 0-1 not spam, 5-6 spam, 9 high-confidence spam.
            verdict = (
                GatewayVerdictType.SPAM
                if scl >= 5
                else GatewayVerdictType.CLEAN_OBSERVED
                if scl <= 1
                else GatewayVerdictType.SUSPICIOUS
            )
            out.append(
                self._evidence(
                    context,
                    decision,
                    verdict=verdict,
                    category=GatewayCategory.ANTISPAM,
                    reference="SCL",
                    confidence=0.7,
                    score=float(scl),
                    engine="eop",
                    normalized_detail={"scl": scl},
                )
            )

        bcl_match = _BCL_RE.search(report)
        if bcl_match and int(bcl_match.group(1)) >= 7:
            out.append(
                self._evidence(
                    context,
                    decision,
                    verdict=GatewayVerdictType.SPAM,
                    category=GatewayCategory.ANTISPAM,
                    reference="BCL",
                    confidence=0.6,
                    score=float(bcl_match.group(1)),
                    engine="eop",
                    normalized_detail={"bcl": int(bcl_match.group(1))},
                )
            )

        pcl_match = _PCL_RE.search(report)
        if pcl_match and int(pcl_match.group(1)) >= 4:
            out.append(
                self._evidence(
                    context,
                    decision,
                    verdict=GatewayVerdictType.PHISHING,
                    category=GatewayCategory.ANTIPHISHING,
                    reference="PCL",
                    confidence=0.7,
                    score=float(pcl_match.group(1)),
                    engine="eop",
                    normalized_detail={"pcl": int(pcl_match.group(1))},
                )
            )
        return out


class SpamAssassinGatewayProvider(_HeaderProviderBase):
    """SpamAssassin, Rspamd and the other filters that write X-Spam-* headers."""

    provider_type = "spamassassin"

    def parse_message_headers(
        self, headers: list[tuple[str, str]], context: GatewayContext
    ) -> list[GatewayEvidence]:
        index = HeaderIndex(headers)
        flag = index.first("x-spam-flag")
        status = index.first("x-spam-status")
        level = index.first("x-spam-level")
        if not (flag or status or level):
            return []
        decision = self._decision(context)
        is_spam = flag.strip().lower().startswith("yes") or status.strip().lower().startswith("yes")
        score = extract_score(status, index.first("x-spam-score"))
        if score is None and level:
            # X-Spam-Level encodes the score as a run of asterisks.
            score = float(level.count("*")) or None
        return [
            self._evidence(
                context,
                decision,
                verdict=GatewayVerdictType.SPAM if is_spam else GatewayVerdictType.CLEAN_OBSERVED,
                category=GatewayCategory.ANTISPAM,
                reference="X-Spam-Status",
                confidence=0.6,
                score=score,
                engine="spamassassin",
                normalized_detail={"status": (status or flag)[:200]},
            )
        ]


class GenericAvGatewayProvider(_HeaderProviderBase):
    """X-Virus-Scanned / X-Virus-Status, written by amavis, ClamSMTP and many MTAs."""

    provider_type = "generic_av"

    def parse_message_headers(
        self, headers: list[tuple[str, str]], context: GatewayContext
    ) -> list[GatewayEvidence]:
        index = HeaderIndex(headers)
        status = index.first("x-virus-status")
        scanned = index.first("x-virus-scanned")
        name = index.first("x-virus-name", "x-amavis-alert")
        if not (status or scanned or name):
            return []
        decision = self._decision(context)
        verdict = classify_value(status) or (
            GatewayVerdictType.MALICIOUS if name else GatewayVerdictType.CLEAN_OBSERVED
        )
        if verdict is GatewayVerdictType.CLEAN_OBSERVED and not status and not name:
            # Only "X-Virus-Scanned" is present: the scanner ran, and said nothing about it.
            verdict = GatewayVerdictType.CLEAN_OBSERVED
        return [
            self._evidence(
                context,
                decision,
                verdict=verdict,
                category=GatewayCategory.ANTIVIRUS,
                reference="X-Virus-Status",
                confidence=0.75,
                threat_name=name[:120] or extract_threat_name(status),
                engine=scanned[:120] or "generic_av",
                normalized_detail={"status": (status or scanned)[:200]},
            )
        ]


BUILTIN_PROVIDERS: dict[str, type[_HeaderProviderBase]] = {
    "eop": EopGatewayProvider,
    "spamassassin": SpamAssassinGatewayProvider,
    "generic_av": GenericAvGatewayProvider,
}


def build(config: GatewayProviderConfig) -> _HeaderProviderBase:
    cls = BUILTIN_PROVIDERS.get(config.provider_type)
    if cls is None:
        raise ValueError(f"unknown built-in gateway provider: {config.provider_type}")
    return cls(config)
