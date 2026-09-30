"""Disagreements between sources, made visible (ТЗ 1.0.2 §27, §28).

A conflict is not an error. Two of the four kinds are *expected* in normal operation and are the
reason the platform exists:

* ``KSMG=clean`` with ``MSP=HIGH_RISK`` is the ordinary case for BEC and impersonation — mail
  with no attachment and no link, which a gateway has no reason to stop. It is surfaced so an
  analyst sees why the two differ, not because something went wrong.
* ``KSMG=malware detected`` with ``MSP=LOW_RISK`` is the opposite and matters more: the gateway
  has an antivirus engine this platform deliberately does not. That case raises the verdict
  through a hard signal rather than being left for a human to notice (ТЗ 1.0.2 §27).

The remaining two — two gateways disagreeing, or a vendor's headers disagreeing with its own API
— usually mean a configuration or correlation problem, and are reported as such.
"""

from __future__ import annotations

from msp_contracts import (
    RISK_ORDER,
    ConflictKind,
    GatewayEvidence,
    GatewayEvidenceSource,
    GatewayVerdictType,
    ProviderConflict,
    RiskLevel,
)

#: Platform verdicts that count as "we did not consider this dangerous".
_LOW_PLATFORM = {RiskLevel.LOW_RISK, RiskLevel.UNKNOWN}
#: Platform verdicts that count as "we consider this dangerous".
_HIGH_PLATFORM = {RiskLevel.HIGH_RISK, RiskLevel.MALICIOUS}


def detect_conflicts(
    evidence: list[GatewayEvidence], platform_verdict: RiskLevel | None
) -> list[ProviderConflict]:
    """Compare gateway evidence with the platform's own verdict and with itself."""
    conflicts: list[ProviderConflict] = []
    trusted = [item for item in evidence if item.trusted]

    if platform_verdict is not None:
        detections = [
            item
            for item in trusted
            if item.verdict in {GatewayVerdictType.MALICIOUS, GatewayVerdictType.PHISHING}
        ]
        if detections and platform_verdict in _LOW_PLATFORM:
            conflicts.append(
                ProviderConflict(
                    kind=ConflictKind.GATEWAY_MALICIOUS_PLATFORM_LOW,
                    summary=(
                        "Почтовый шлюз обнаружил вредоносное содержимое, а платформа оценила письмо "
                        "как неопасное. Вердикт повышен по сигналу шлюза."
                    ),
                    providers=sorted({item.provider_id for item in detections}),
                    detail={
                        "platform_verdict": platform_verdict.value,
                        "gateway_verdicts": [
                            {
                                "provider": item.provider_id,
                                "verdict": item.verdict.value,
                                "threat": item.threat_name,
                            }
                            for item in detections[:5]
                        ],
                    },
                )
            )

        clean = [item for item in trusted if item.verdict is GatewayVerdictType.CLEAN_OBSERVED]
        if clean and platform_verdict in _HIGH_PLATFORM:
            conflicts.append(
                ProviderConflict(
                    kind=ConflictKind.GATEWAY_CLEAN_PLATFORM_HIGH,
                    summary=(
                        "Почтовый шлюз не обнаружил угроз, платформа оценила письмо как опасное. "
                        "Это штатная ситуация: атаки без вложений и ссылок шлюз пропускает."
                    ),
                    providers=sorted({item.provider_id for item in clean}),
                    detail={"platform_verdict": platform_verdict.value},
                )
            )

    conflicts.extend(_cross_gateway(trusted))
    conflicts.extend(_header_versus_api(trusted))
    return conflicts


def _severity_rank(verdict: GatewayVerdictType) -> int:
    return {
        GatewayVerdictType.MALICIOUS: 4,
        GatewayVerdictType.PHISHING: 4,
        GatewayVerdictType.SPAM: 2,
        GatewayVerdictType.SUSPICIOUS: 2,
        GatewayVerdictType.CLEAN_OBSERVED: 0,
        GatewayVerdictType.UNKNOWN: 1,
        GatewayVerdictType.ERROR: 1,
    }[verdict]


def _cross_gateway(trusted: list[GatewayEvidence]) -> list[ProviderConflict]:
    """Two gateways that looked at the same message and reached different conclusions."""
    by_provider: dict[str, list[GatewayEvidence]] = {}
    for item in trusted:
        by_provider.setdefault(item.provider_id, []).append(item)
    if len(by_provider) < 2:
        return []

    worst = {
        provider: max(items, key=lambda i: _severity_rank(i.verdict))
        for provider, items in by_provider.items()
    }
    ranks = {provider: _severity_rank(item.verdict) for provider, item in worst.items()}
    # Only a real disagreement counts: "malicious" against "clean", not "spam" against "unknown".
    if max(ranks.values()) < 4 or min(ranks.values()) > 0:
        return []
    return [
        ProviderConflict(
            kind=ConflictKind.GATEWAY_DISAGREEMENT,
            summary="Два почтовых шлюза дали разные вердикты по одному письму.",
            providers=sorted(worst),
            detail={
                provider: {"verdict": item.verdict.value, "engine": item.engine}
                for provider, item in worst.items()
            },
        )
    ]


def _header_versus_api(trusted: list[GatewayEvidence]) -> list[ProviderConflict]:
    """A vendor's headers saying one thing and its own API another.

    Usually a correlation mistake — the API was asked about a different message — so it is worth
    an analyst's attention before either verdict is acted on.
    """
    conflicts: list[ProviderConflict] = []
    by_provider: dict[str, list[GatewayEvidence]] = {}
    for item in trusted:
        by_provider.setdefault(item.provider_id, []).append(item)
    for provider, items in by_provider.items():
        headers = [i for i in items if i.source is GatewayEvidenceSource.HEADER]
        api = [i for i in items if i.source is GatewayEvidenceSource.API]
        if not headers or not api:
            continue
        header_rank = max(_severity_rank(i.verdict) for i in headers)
        api_rank = max(_severity_rank(i.verdict) for i in api)
        if abs(header_rank - api_rank) >= 2:
            conflicts.append(
                ProviderConflict(
                    kind=ConflictKind.HEADER_API_MISMATCH,
                    summary=f"Заголовки и API {provider} сообщают разные вердикты по одному письму.",
                    providers=[provider],
                    detail={
                        "header": [i.verdict.value for i in headers][:3],
                        "api": [i.verdict.value for i in api][:3],
                    },
                )
            )
    return conflicts


def upstream_hard_signal(evidence: list[GatewayEvidence]) -> GatewayEvidence | None:
    """The trusted malware detection that must raise the verdict regardless of our own score.

    This is the ``upstream_malware_detection`` hard signal of ТЗ 1.0.2 §27. It requires a
    *trusted* detection: an unverified header claiming malware would otherwise let anyone force
    a message to MALICIOUS, which is a denial-of-service against the analyst queue.
    """
    detections = [
        item
        for item in evidence
        if item.trusted and item.verdict in {GatewayVerdictType.MALICIOUS, GatewayVerdictType.PHISHING}
    ]
    if not detections:
        return None
    return max(detections, key=lambda i: (i.confidence, bool(i.threat_name)))


def worst_platform_level(levels: list[RiskLevel]) -> RiskLevel:
    """Helper for cross-provider correlation: the most severe of several verdicts."""
    if not levels:
        return RiskLevel.UNKNOWN
    return max(levels, key=lambda level: RISK_ORDER[level])
