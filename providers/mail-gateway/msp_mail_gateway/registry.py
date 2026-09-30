"""Provider registry and per-message evidence collection (ТЗ 1.0.2 §22, §26, §31).

One registry holds every configured gateway. It owns the topology — which hops the organisation
operates — so the trust decision is made once per message and every provider sees the same
verified chain.

Having no gateway at all is a supported configuration, not a degraded one: with an empty registry
:meth:`GatewayRegistry.state` reports ``NOT_PRESENT`` and the platform's own analysis is
unaffected (ТЗ 1.0.2 §31).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from msp_contracts import (
    GatewayCapability,
    GatewayEvidence,
    GatewayState,
    ProviderHealth,
    TrustedMailHop,
)

from .base import BaseGatewayProvider, GatewayContext, GatewayProviderConfig
from .builtin import (
    BUILTIN_PROVIDERS,
    EopGatewayProvider,
    GenericAvGatewayProvider,
    SpamAssassinGatewayProvider,
)
from .generic_header import GenericHeaderGatewayProvider
from .ksmg import KsmgGatewayProvider
from .syslog import SyslogGatewayProvider
from .trust import ChainVerification, filter_authentication_results, verify_chain

logger = logging.getLogger(__name__)

#: provider_type -> constructor. New vendors are added here or, better, as a YAML profile
#: consumed by ``generic_header`` — which needs no code at all.
PROVIDER_TYPES: dict[str, Callable[[GatewayProviderConfig], BaseGatewayProvider]] = {
    "ksmg": KsmgGatewayProvider,
    "generic_header": GenericHeaderGatewayProvider,
    "syslog": SyslogGatewayProvider,
    "eop": EopGatewayProvider,
    "spamassassin": SpamAssassinGatewayProvider,
    "generic_av": GenericAvGatewayProvider,
}
PROVIDER_TYPES.update(dict(BUILTIN_PROVIDERS))


def build_provider(config: GatewayProviderConfig) -> BaseGatewayProvider:
    factory = PROVIDER_TYPES.get(config.provider_type)
    if factory is None:
        raise ValueError(f"unknown gateway provider type: {config.provider_type}")
    return factory(config)


@dataclass
class GatewayAnalysis:
    """Everything the registry could establish about one message's upstream handling."""

    evidence: list[GatewayEvidence] = field(default_factory=list)
    verification: ChainVerification | None = None
    #: Authentication-Results headers that may be interpreted (ТЗ 1.0.1 §4.4).
    trusted_auth_results: list[str] = field(default_factory=list)
    untrusted_auth_results: list[str] = field(default_factory=list)
    auth_tampering_suspected: bool = False
    state: GatewayState = GatewayState.NOT_PRESENT
    #: Gateways whose headers appeared but could not be believed.
    untrusted_gateways: list[str] = field(default_factory=list)

    @property
    def trusted_evidence(self) -> list[GatewayEvidence]:
        return [e for e in self.evidence if e.trusted]

    @property
    def negative_evidence(self) -> list[GatewayEvidence]:
        return [e for e in self.evidence if e.counts_as_signal]

    def by_provider(self) -> dict[str, list[GatewayEvidence]]:
        out: dict[str, list[GatewayEvidence]] = {}
        for item in self.evidence:
            out.setdefault(item.provider_id, []).append(item)
        return out


class GatewayRegistry:
    """The set of gateways this deployment knows about."""

    def __init__(
        self,
        providers: Iterable[BaseGatewayProvider] = (),
        *,
        extra_hops: Iterable[TrustedMailHop] = (),
        extra_authserv_ids: tuple[str, ...] = (),
    ) -> None:
        self._providers: dict[str, BaseGatewayProvider] = {}
        for provider in providers:
            self._providers[provider.provider_id] = provider
        self._extra_hops = list(extra_hops)
        self._extra_authserv_ids = tuple(extra_authserv_ids)

    # -- composition ---------------------------------------------------------------------------
    @classmethod
    def from_configs(
        cls,
        configs: Iterable[GatewayProviderConfig],
        *,
        extra_hops: Iterable[TrustedMailHop] = (),
        extra_authserv_ids: tuple[str, ...] = (),
    ) -> GatewayRegistry:
        providers: list[BaseGatewayProvider] = []
        for config in configs:
            if not config.enabled:
                continue
            try:
                providers.append(build_provider(config))
            except ValueError as exc:
                # An unknown provider type is a configuration error, not a reason to lose the
                # gateways that are configured correctly.
                logger.error("gateway.unknown_provider_type", extra={"error": str(exc)})
        return cls(providers, extra_hops=extra_hops, extra_authserv_ids=extra_authserv_ids)

    def add(self, provider: BaseGatewayProvider) -> None:
        self._providers[provider.provider_id] = provider

    @property
    def providers(self) -> list[BaseGatewayProvider]:
        return list(self._providers.values())

    def get(self, provider_id: str) -> BaseGatewayProvider | None:
        return self._providers.get(provider_id)

    @property
    def configured(self) -> bool:
        return bool(self._providers)

    def hops(self) -> list[TrustedMailHop]:
        out = list(self._extra_hops)
        for provider in self._providers.values():
            out.extend(provider.config.trusted_hops)
        return out

    # -- reporting -----------------------------------------------------------------------------
    def capabilities(self) -> dict[str, list[str]]:
        return {
            provider.provider_id: sorted(c.value for c in provider.capabilities())
            for provider in self._providers.values()
        }

    def health(self) -> list[ProviderHealth]:
        out: list[ProviderHealth] = []
        for provider in self._providers.values():
            try:
                out.append(provider.health())
            except Exception as exc:  # noqa: BLE001 - one bad provider must not hide the rest
                out.append(
                    ProviderHealth(
                        provider_id=provider.provider_id, status="unavailable", detail=type(exc).__name__
                    )
                )
        return out

    def state(self) -> GatewayState:
        """Absence of gateways is ``NOT_PRESENT``, which is a valid deployment (§31)."""
        if not self._providers:
            return GatewayState.NOT_PRESENT
        statuses = [health.status for health in self.health()]
        if any(status == "ok" for status in statuses):
            return GatewayState.DEGRADED if any(s != "ok" for s in statuses) else GatewayState.HEALTHY
        if all(status in {"disabled", "not_configured"} for status in statuses):
            return GatewayState.NOT_PRESENT
        return GatewayState.UNAVAILABLE

    def supports(self, capability: GatewayCapability) -> list[str]:
        return [p.provider_id for p in self._providers.values() if capability in p.capabilities()]

    # -- per-message ---------------------------------------------------------------------------
    def analyze_message(
        self,
        headers: list[tuple[str, str]],
        *,
        received: list[str],
        authentication_results: list[str] = (),  # type: ignore[assignment]
        internet_message_id: str = "",
    ) -> GatewayAnalysis:
        """Collect evidence from every provider under one shared trust decision."""
        verification = verify_chain(list(received), self.hops())
        analysis = GatewayAnalysis(verification=verification, state=self.state())

        auth_trust = filter_authentication_results(
            list(authentication_results or []),
            verification=verification,
            extra_allowlist=self._extra_authserv_ids,
        )
        analysis.trusted_auth_results = auth_trust.trusted_headers
        analysis.untrusted_auth_results = auth_trust.untrusted_headers
        analysis.auth_tampering_suspected = auth_trust.tampering_suspected

        for provider in self._providers.values():
            if not provider.config.enabled:
                continue
            context = GatewayContext(
                verification=verification, registered=True, internet_message_id=internet_message_id
            )
            try:
                evidence = provider.parse_message_headers(headers, context)
            except Exception as exc:  # noqa: BLE001 - a parser bug must not fail the analysis
                logger.warning(
                    "gateway.parse_failed",
                    extra={"provider": provider.provider_id, "error": type(exc).__name__},
                )
                continue
            analysis.evidence.extend(evidence)
            if evidence and not any(e.trusted for e in evidence):
                analysis.untrusted_gateways.append(provider.provider_id)

        # Headers of a gateway nobody registered: recorded as an untrusted claim, because making
        # a message look pre-screened is a known technique.
        analysis.evidence.extend(self._unregistered_claims(headers, verification, internet_message_id))
        return analysis

    def _unregistered_claims(
        self,
        headers: list[tuple[str, str]],
        verification: ChainVerification,
        internet_message_id: str,
    ) -> list[GatewayEvidence]:
        """Detect gateway headers from products this organisation does not run."""
        known_types = {p.provider_type for p in self._providers.values()}
        out: list[GatewayEvidence] = []
        for provider_type, cls in PROVIDER_TYPES.items():
            if provider_type in known_types or provider_type in {"generic_header", "syslog"}:
                continue
            probe = cls(GatewayProviderConfig(provider_id=provider_type, provider_type=provider_type))
            context = GatewayContext(
                verification=verification, registered=False, internet_message_id=internet_message_id
            )
            try:
                found = probe.parse_message_headers(headers, context)
            except Exception as exc:  # noqa: BLE001 - a probe must never fail the analysis
                logger.debug(
                    "gateway.probe_failed",
                    extra={"provider_type": provider_type, "error": type(exc).__name__},
                )
                continue
            if found:
                out.extend(found)
        return out

    def describe(self) -> dict[str, Any]:
        """Settings → Mail Gateways (ТЗ 1.0.2 §25)."""
        return {
            "state": self.state().value,
            "providers": [
                {
                    "provider_id": provider.provider_id,
                    "provider_type": provider.provider_type,
                    "display_name": provider.config.display_name or provider.provider_id,
                    "enabled": provider.config.enabled,
                    "direction": provider.config.direction.value,
                    "capabilities": sorted(c.value for c in provider.capabilities()),
                    "trusted_hops": [
                        {
                            "hostname": hop.hostname,
                            "ip_networks": hop.ip_networks,
                            "authserv_ids": hop.authserv_ids,
                            "position_in_chain": hop.position_in_chain,
                            "enabled": hop.enabled,
                        }
                        for hop in provider.config.trusted_hops
                    ],
                    "health": provider.health().model_dump(mode="json"),
                }
                for provider in self._providers.values()
            ],
        }
