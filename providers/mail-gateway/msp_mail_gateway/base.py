"""The ``MailGatewayProvider`` contract (ТЗ 1.0.2 §14).

Every integration with an upstream gateway — header parser, syslog receiver, vendor API — sits
behind this Protocol, so the platform core never names a vendor. No provider is required to
implement every capability: a header-only adapter is a complete, useful provider, and callers
ask :meth:`capabilities` instead of assuming.

The default implementations below all refuse rather than pretend. A provider that has not
implemented quarantine returns a plan that says so, instead of a result claiming success.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from msp_contracts import (
    GatewayActionPlan,
    GatewayActionResult,
    GatewayCapability,
    GatewayDirection,
    GatewayEvidence,
    GatewayMessageRef,
    MessageTrace,
    ProviderHealth,
    QuarantineStatus,
    TrustedMailHop,
)

from .trust import ChainVerification


@dataclass
class GatewayContext:
    """Everything a provider needs to judge one message's headers.

    Passing the verification in rather than letting each provider re-derive it keeps the trust
    decision in one place: a provider cannot accidentally trust its own headers.
    """

    verification: ChainVerification
    registered: bool = True
    internet_message_id: str = ""


@dataclass
class GatewayProviderConfig:
    """Configuration shared by every provider kind."""

    provider_id: str
    provider_type: str = "generic"
    display_name: str = ""
    enabled: bool = True
    direction: GatewayDirection = GatewayDirection.INBOUND
    trusted_hops: list[TrustedMailHop] = field(default_factory=list)
    settings: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class MailGatewayProvider(Protocol):
    """Read side is mandatory in 1.0.2; the write side stays optional and is not enabled."""

    provider_id: str

    def health(self) -> ProviderHealth: ...
    def capabilities(self) -> set[GatewayCapability]: ...
    def parse_message_headers(
        self, headers: list[tuple[str, str]], context: GatewayContext
    ) -> list[GatewayEvidence]: ...
    def get_message_trace(self, ref: GatewayMessageRef) -> MessageTrace | None: ...
    def get_verdict(self, ref: GatewayMessageRef) -> GatewayEvidence | None: ...
    def get_quarantine_status(self, ref: GatewayMessageRef) -> QuarantineStatus | None: ...
    def search_related(self, **criteria: Any) -> list[GatewayMessageRef]: ...
    def propose_quarantine(self, refs: list[GatewayMessageRef]) -> GatewayActionPlan: ...
    def execute_quarantine(
        self, refs: list[GatewayMessageRef], *, dry_run: bool = True
    ) -> GatewayActionResult: ...
    def release_message(self, ref: GatewayMessageRef, *, dry_run: bool = True) -> GatewayActionResult: ...
    def block_sender(self, sender: str, *, dry_run: bool = True) -> GatewayActionResult: ...


class BaseGatewayProvider:
    """Shared behaviour: capability refusal, read-only defaults, health reporting.

    Subclasses override only what they can actually do. Everything else refuses with a plan or
    result that names the missing capability, which is what the console renders.
    """

    provider_type = "generic"

    def __init__(self, config: GatewayProviderConfig) -> None:
        self.config = config
        self.provider_id = config.provider_id

    # -- introspection -------------------------------------------------------------------------
    def health(self) -> ProviderHealth:
        if not self.config.enabled:
            return ProviderHealth(provider_id=self.provider_id, status="disabled")
        return ProviderHealth(provider_id=self.provider_id, status="ok", mode=self.provider_type)

    def capabilities(self) -> set[GatewayCapability]:
        return set()

    def has(self, capability: GatewayCapability) -> bool:
        return capability in self.capabilities()

    # -- read ----------------------------------------------------------------------------------
    def parse_message_headers(
        self, headers: list[tuple[str, str]], context: GatewayContext
    ) -> list[GatewayEvidence]:
        return []

    def get_message_trace(self, ref: GatewayMessageRef) -> MessageTrace | None:
        return None

    def get_verdict(self, ref: GatewayMessageRef) -> GatewayEvidence | None:
        return None

    def get_quarantine_status(self, ref: GatewayMessageRef) -> QuarantineStatus | None:
        return None

    def search_related(self, **criteria: Any) -> list[GatewayMessageRef]:
        return []

    # -- write (read-only in 1.0.2, ТЗ 1.0.2 §30) ----------------------------------------------
    def _unsupported_plan(self, action: str, capability: GatewayCapability) -> GatewayActionPlan:
        return GatewayActionPlan(
            provider_id=self.provider_id,
            action=action,
            requires_capability=capability,
            capability_available=self.has(capability),
            blockers=[
                f"провайдер {self.provider_id} не реализует '{action}'"
                if not self.has(capability)
                else "изменение состояния шлюза отключено на этапе 1.0.2"
            ],
            summary=f"{action}: недоступно",
        )

    def _refused(self, action: str, reason: str) -> GatewayActionResult:
        return GatewayActionResult(
            provider_id=self.provider_id, action=action, executed=False, dry_run=True, errors=[reason]
        )

    def propose_quarantine(self, refs: list[GatewayMessageRef]) -> GatewayActionPlan:
        return self._unsupported_plan("quarantine", GatewayCapability.QUARANTINE_WRITE)

    def execute_quarantine(
        self, refs: list[GatewayMessageRef], *, dry_run: bool = True
    ) -> GatewayActionResult:
        return self._refused("quarantine", "действия над шлюзом на этапе 1.0.2 только read-only")

    def release_message(self, ref: GatewayMessageRef, *, dry_run: bool = True) -> GatewayActionResult:
        return self._refused("release", "действия над шлюзом на этапе 1.0.2 только read-only")

    def block_sender(self, sender: str, *, dry_run: bool = True) -> GatewayActionResult:
        return self._refused("block_sender", "действия над шлюзом на этапе 1.0.2 только read-only")
