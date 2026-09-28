"""On-premises EWS provider (ТЗ 7).

Deliberately incomplete: per ТЗ §51 the real Exchange edition/build, EWS configuration, service
accounts and mail-flow topology are not yet known, and inventing them would produce code that
looks finished and fails in production. What exists here is the boundary:

* capability discovery that reports what is actually reachable, instead of assuming;
* a conservative, documented set of blockers surfaced through ``health()`` and ``blockers()``;
* remediation that stays in dry-run and refuses to execute without an enabled, separate account.

Filling this in is a task of MSP 0.9 and requires the environment inventory from ТЗ §51.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import httpx
from msp_contracts import ProviderHealth, RemediationType

from .base import (
    CapabilityUnavailable,
    ExchangeCapability,
    ExchangeMessageRef,
    FetchedMessage,
    RemediationOutcome,
    RemediationRequest,
)

logger = logging.getLogger(__name__)

BLOCKERS: tuple[str, ...] = (
    "Exchange edition/version/build not provided (ТЗ 51)",
    "EWS endpoint URL and authentication model (NTLM/Kerberos/Basic over TLS) not provided",
    "Service account for mailbox intake not provisioned; ApplicationImpersonation scope undecided",
    "Internal PKI / TLS trust chain for the EWS endpoint not provided",
    "Mail-flow topology and Edge Transport presence unknown",
    "Outbound proxy / firewall rules for the worker egress not defined",
)


@dataclass
class EwsConfig:
    endpoint: str = ""
    username: str = ""
    password: str = ""
    auth: str = "ntlm"  # ntlm|kerberos|basic — must be confirmed against the real deployment
    verify_tls: bool = True
    ca_file: str | None = None
    timeout_seconds: float = 30.0
    impersonation_enabled: bool = False
    remediation_account_enabled: bool = False  # ТЗ 7.1 — off by default


@dataclass
class OnPremEwsExchangeProvider:
    """Adapter boundary for on-premises EWS. Not production-complete by design."""

    config: EwsConfig
    provider_id: str = "onprem_ews"
    _discovered: set[ExchangeCapability] = field(default_factory=set)

    def blockers(self) -> list[str]:
        out = list(BLOCKERS) if not self.config.endpoint else []
        if self.config.endpoint and not self.config.verify_tls:
            out.append("TLS verification disabled: not acceptable for production (ТЗ 44)")
        if self.config.remediation_account_enabled and not self.config.impersonation_enabled:
            out.append("remediation requires a scoped impersonation/RBAC role that is not configured")
        return out

    def health(self) -> ProviderHealth:
        if not self.config.endpoint:
            return ProviderHealth(
                provider_id=self.provider_id,
                status="not_configured",
                detail="EWS endpoint not configured; platform runs without Exchange integration",
            )
        try:
            with httpx.Client(
                timeout=self.config.timeout_seconds,
                verify=self.config.ca_file or self.config.verify_tls,
            ) as client:
                response = client.get(self.config.endpoint)
            # 401 means the endpoint is reachable but needs the negotiated auth we cannot assume.
            if response.status_code in {200, 401}:
                return ProviderHealth(
                    provider_id=self.provider_id,
                    status="degraded",
                    mode=self.config.auth,
                    detail="endpoint reachable; capability verification pending environment inventory",
                )
            return ProviderHealth(
                provider_id=self.provider_id,
                status="unavailable",
                detail=f"HTTP {response.status_code}",
            )
        except httpx.HTTPError as exc:
            return ProviderHealth(
                provider_id=self.provider_id, status="unavailable", detail=type(exc).__name__
            )

    def capabilities(self) -> set[ExchangeCapability]:
        """Only capabilities verified against the live server are reported (ТЗ 6.5)."""
        return set(self._discovered)

    def _require(self, capability: ExchangeCapability) -> None:
        if capability not in self._discovered:
            raise CapabilityUnavailable(
                capability,
                "not verified against this Exchange deployment; see docs/EXCHANGE_COMPATIBILITY.md",
            )

    def get_message(self, ref: ExchangeMessageRef) -> FetchedMessage:
        self._require(ExchangeCapability.GET_MESSAGE)
        raise NotImplementedError("EWS GetItem is implemented in MSP 0.9 with the verified environment")

    def get_message_headers(self, ref: ExchangeMessageRef) -> dict[str, str]:
        self._require(ExchangeCapability.GET_HEADERS)
        raise NotImplementedError("EWS header fetch is implemented in MSP 0.9")

    def get_attachments(self, ref: ExchangeMessageRef) -> list[tuple[str, bytes]]:
        self._require(ExchangeCapability.GET_ATTACHMENTS)
        raise NotImplementedError("EWS GetAttachment is implemented in MSP 0.9")

    def submit_report(self, ref: ExchangeMessageRef, reported_by: str, note: str = "") -> str:
        self._require(ExchangeCapability.SUBMIT_REPORT)
        raise NotImplementedError("use SecurityMailboxProvider for reporting until EWS is verified")

    def search_related_messages(
        self, *, sender: str = "", subject: str = "", message_id: str = "", limit: int = 100
    ) -> list[ExchangeMessageRef]:
        self._require(ExchangeCapability.SEARCH)
        raise NotImplementedError("EWS/eDiscovery search is implemented in MSP 0.9")

    def request_remediation(self, request: RemediationRequest) -> RemediationOutcome:
        """Never executes: remediation stays dry-run until the environment is accepted (ТЗ 20.2)."""
        outcome = RemediationOutcome(
            action=request.action,
            dry_run=True,
            affected_messages=len(request.targets),
            affected_mailboxes=sorted({t.mailbox for t in request.targets}),
            rollback_supported=request.action is RemediationType.QUARANTINE,
        )
        outcome.warnings.append("dry-run: EWS remediation is not enabled in this deployment")
        for blocker in self.blockers():
            outcome.warnings.append(f"blocker: {blocker}")
        if not request.dry_run:
            outcome.errors.append(
                "refusing to execute: remediation account disabled and environment not accepted"
            )
        return outcome
