"""Configurable header gateway provider (ТЗ 1.0.2 §19).

A new gateway should not require new code. This provider is driven entirely by configuration:

.. code-block:: yaml

    provider: generic
    provider_id: fortimail-edge
    display_name: FortiMail
    trusted_hops:
      - hostname: mail-edge.corp.example
        ip_networks: [10.20.0.0/24]
    headers:
      verdict:
        - X-Virus-Status
        - X-Spam-Status
      score:
        - X-Spam-Score
      threat:
        - X-Virus-Name
    verdict_map:
      MALICIOUS: [infected, detected]
      SPAM: [yes, spam]
      CLEAN_OBSERVED: [clean, no]

``verdict_map`` is optional: without it the built-in vocabulary in :mod:`msp_mail_gateway.headers`
is used, which already covers the common spellings. Anything unrecognised becomes ``UNKNOWN`` —
never ``CLEAN_OBSERVED``, because a verdict that could not be read has not said the message is
fine.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from msp_contracts import (
    GatewayCapability,
    GatewayDirection,
    GatewayEvidence,
    GatewayEvidenceSource,
    GatewayVerdictType,
    TrustedMailHop,
)

from .base import BaseGatewayProvider, GatewayContext, GatewayProviderConfig
from .headers import HeaderIndex, category_for_header, classify_value, extract_score
from .trust import decide_header_trust


class GenericHeaderGatewayProvider(BaseGatewayProvider):
    provider_type = "generic_header"

    def capabilities(self) -> set[GatewayCapability]:
        return {GatewayCapability.HEADER_VERDICT}

    # -- configuration -------------------------------------------------------------------------
    @property
    def _headers_config(self) -> dict[str, list[str]]:
        raw = self.config.settings.get("headers") or {}
        return {key: [str(v) for v in (values or [])] for key, values in raw.items()}

    @property
    def _verdict_map(self) -> dict[str, GatewayVerdictType]:
        """Lower-cased vendor token -> normalised verdict, from the optional ``verdict_map``."""
        out: dict[str, GatewayVerdictType] = {}
        for verdict_name, tokens in (self.config.settings.get("verdict_map") or {}).items():
            try:
                verdict = GatewayVerdictType(str(verdict_name).upper())
            except ValueError:
                continue
            for token in tokens or []:
                out[str(token).strip().lower()] = verdict
        return out

    def _classify(self, value: str) -> GatewayVerdictType | None:
        lowered = (value or "").strip().lower()
        for token, verdict in self._verdict_map.items():
            if token and token in lowered:
                return verdict
        return classify_value(value)

    # -- parsing -------------------------------------------------------------------------------
    def parse_message_headers(
        self, headers: list[tuple[str, str]], context: GatewayContext
    ) -> list[GatewayEvidence]:
        config = self._headers_config
        verdict_headers = config.get("verdict") or []
        if not verdict_headers:
            return []
        index = HeaderIndex(headers)
        present = [name for name in verdict_headers if index.present(name)]
        if not present:
            return []

        decision = decide_header_trust(
            self.provider_id, verification=context.verification, registered=context.registered
        )
        score = extract_score(*[index.first(name) for name in (config.get("score") or [])])
        threat = ""
        for name in config.get("threat") or []:
            threat = index.first(name)[:120]
            if threat:
                break
        policy = ""
        for name in config.get("policy") or []:
            policy = index.first(name)[:200]
            if policy:
                break

        out: list[GatewayEvidence] = []
        for name in present:
            raw_value = index.first(name)
            verdict = self._classify(raw_value) or GatewayVerdictType.UNKNOWN
            out.append(
                GatewayEvidence(
                    provider_id=self.provider_id,
                    provider_type=self.provider_type,
                    message_id=context.internet_message_id,
                    verdict=verdict,
                    category=category_for_header(name),
                    confidence=0.7 if decision.trusted else 0.0,
                    score=score,
                    threat_name=threat,
                    engine=self.config.display_name or self.provider_id,
                    policy=policy,
                    source=GatewayEvidenceSource.HEADER,
                    trusted=decision.trusted,
                    trust_state=decision.state,
                    trust_reason=decision.reason,
                    raw_reference=name,
                    normalized_detail={"value": raw_value[:200]},
                )
            )
        return out


def _hops_from_config(raw: Any, provider_id: str, direction: GatewayDirection) -> list[TrustedMailHop]:
    """Accept both the shorthand (a bare CIDR) and the full hop description."""
    hops: list[TrustedMailHop] = []
    for entry in raw or []:
        if isinstance(entry, str):
            value = entry.strip()
            if not value:
                continue
            looks_like_network = value[0].isdigit() or ":" in value
            hops.append(
                TrustedMailHop(
                    id=f"{provider_id}:{value}",
                    provider_id=provider_id,
                    hostname="" if looks_like_network else value,
                    ip_networks=[value] if looks_like_network else [],
                    direction=direction,
                )
            )
        elif isinstance(entry, dict):
            hops.append(
                TrustedMailHop(
                    id=str(entry.get("id") or f"{provider_id}:{entry.get('hostname', '')}"),
                    provider_id=provider_id,
                    type=str(entry.get("type", "gateway")),
                    hostname=str(entry.get("hostname", "")),
                    ip_networks=[str(n) for n in (entry.get("ip_networks") or [])],
                    expected_headers=[str(h) for h in (entry.get("expected_headers") or [])],
                    authserv_ids=[str(a) for a in (entry.get("authserv_ids") or [])],
                    position_in_chain=entry.get("position_in_chain"),
                    direction=direction,
                    enabled=bool(entry.get("enabled", True)),
                )
            )
    return hops


def config_from_mapping(data: dict[str, Any]) -> GatewayProviderConfig:
    """Build a provider configuration from a parsed YAML mapping."""
    provider_id = str(data.get("provider_id") or data.get("provider") or "generic")
    try:
        direction = GatewayDirection(str(data.get("direction", "inbound")).lower())
    except ValueError:
        direction = GatewayDirection.INBOUND
    settings = {
        key: value
        for key, value in data.items()
        if key not in {"provider", "provider_id", "display_name", "enabled", "direction", "trusted_hops"}
    }
    return GatewayProviderConfig(
        provider_id=provider_id,
        provider_type=str(data.get("provider", "generic")),
        display_name=str(data.get("display_name", "") or provider_id),
        enabled=bool(data.get("enabled", True)),
        direction=direction,
        trusted_hops=_hops_from_config(data.get("trusted_hops"), provider_id, direction),
        settings=settings,
    )


def load_profiles(directory: str | Path) -> list[GatewayProviderConfig]:
    """Load every ``*.yaml`` gateway profile in a directory."""
    path = Path(directory)
    out: list[GatewayProviderConfig] = []
    if not path.is_dir():
        return out
    for file in sorted(path.glob("*.yaml")):
        payload = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
        if isinstance(payload, dict):
            out.append(config_from_mapping(payload))
    return out


def build(config: GatewayProviderConfig) -> GenericHeaderGatewayProvider:
    return GenericHeaderGatewayProvider(config)
