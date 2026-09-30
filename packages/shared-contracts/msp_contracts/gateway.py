"""Vendor-neutral contracts for upstream mail gateways (ТЗ 1.0.2 §14-17, §22).

These are pure data types with no vendor in them. A Secure Email Gateway — Kaspersky Secure Mail
Gateway, FortiMail, Proofpoint, Mimecast, Cisco ESA, Exchange Online Protection, Rspamd — is an
*additional source of evidence*, never the final word. Three rules are encoded in the types
themselves rather than left to each adapter:

* ``CLEAN_OBSERVED`` is a distinct value from "safe". There is no SAFE verdict here, for the same
  reason :class:`~msp_contracts.enums.RiskLevel` has none: a gateway that found nothing has not
  proved anything. :meth:`GatewayVerdictType.lowers_risk` returns ``False`` for every value.
* Evidence carries ``trusted`` and ``trust_reason``. An adapter that cannot prove the message
  really traversed the gateway must leave ``trusted`` false, because any sender can write an
  "already scanned" header.
* A capability is something a deployment was *observed* to have, never something inferred from a
  product name or version.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .models import utcnow


class GatewayCapability(StrEnum):
    """What a gateway integration can actually do here (ТЗ 1.0.2 §15).

    Backend and UI probe these rather than branching on the product name.
    """

    HEADER_VERDICT = "HEADER_VERDICT"
    SYSLOG_EVENTS = "SYSLOG_EVENTS"
    MESSAGE_TRACE = "MESSAGE_TRACE"
    API_VERDICT = "API_VERDICT"
    QUARANTINE_READ = "QUARANTINE_READ"
    QUARANTINE_WRITE = "QUARANTINE_WRITE"
    RELEASE = "RELEASE"
    SENDER_BLOCK = "SENDER_BLOCK"
    IOC_BLOCK = "IOC_BLOCK"
    SEARCH = "SEARCH"
    CAMPAIGN_DATA = "CAMPAIGN_DATA"
    SANDBOX_RESULT = "SANDBOX_RESULT"
    AV_RESULT = "AV_RESULT"
    SPAM_RESULT = "SPAM_RESULT"
    PHISHING_RESULT = "PHISHING_RESULT"


#: Capabilities that change state in the gateway. They stay read-only in 1.0.2 (ТЗ 1.0.2 §30).
WRITE_CAPABILITIES: frozenset[GatewayCapability] = frozenset(
    {
        GatewayCapability.QUARANTINE_WRITE,
        GatewayCapability.RELEASE,
        GatewayCapability.SENDER_BLOCK,
        GatewayCapability.IOC_BLOCK,
    }
)


class GatewayVerdictType(StrEnum):
    """Normalised verdict across every vendor (ТЗ 1.0.2 §17).

    ``CLEAN_OBSERVED`` deliberately does not mean safe: it records that a gateway looked and
    reported nothing, which is an observation about the gateway, not about the message.
    """

    MALICIOUS = "MALICIOUS"
    PHISHING = "PHISHING"
    SPAM = "SPAM"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN_OBSERVED = "CLEAN_OBSERVED"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"

    @property
    def is_negative(self) -> bool:
        """True when the gateway reported something bad, which may raise our risk."""
        return self in _NEGATIVE_VERDICTS

    @property
    def lowers_risk(self) -> bool:
        """Always False.

        No gateway verdict may reduce the platform's own risk score. This is a method rather
        than a comment so that a future adapter cannot quietly assume otherwise.
        """
        return False


_NEGATIVE_VERDICTS = frozenset(
    {
        GatewayVerdictType.MALICIOUS,
        GatewayVerdictType.PHISHING,
        GatewayVerdictType.SPAM,
        GatewayVerdictType.SUSPICIOUS,
    }
)


class GatewayCategory(StrEnum):
    """Which engine inside the gateway produced the verdict."""

    ANTIVIRUS = "antivirus"
    ANTISPAM = "antispam"
    ANTIPHISHING = "antiphishing"
    SANDBOX = "sandbox"
    REPUTATION = "reputation"
    POLICY = "policy"
    DLP = "dlp"
    UNKNOWN = "unknown"


class GatewayEvidenceSource(StrEnum):
    HEADER = "header"
    SYSLOG = "syslog"
    API = "api"
    MANUAL = "manual"


class TrustState(StrEnum):
    """Why a piece of gateway evidence is or is not trusted (ТЗ 1.0.1 §4.3)."""

    TRUSTED = "trusted"
    #: The gateway is registered but the delivery chain does not show the message passing it.
    UNVERIFIED_CHAIN = "unverified_chain"
    #: Headers of a gateway the organisation does not run at all: likely forged.
    UNKNOWN_GATEWAY = "unknown_gateway"
    #: The header appeared at a position in the chain that the topology does not allow.
    TOPOLOGY_MISMATCH = "topology_mismatch"
    #: The source of a syslog/API event was not on the allowlist.
    UNTRUSTED_SOURCE = "untrusted_source"


class GatewayEvidence(BaseModel):
    """One normalised observation from one gateway (ТЗ 1.0.2 §16).

    ``raw_reference`` is a pointer (a header name, a syslog message id, an API request id), not
    the raw payload: storing whole vendor responses would duplicate message content under a
    different retention policy (ТЗ 1.0.2 §16, ТЗ 26.1).
    """

    model_config = ConfigDict(frozen=True)

    provider_id: str
    provider_type: str
    message_id: str = ""
    timestamp: datetime = Field(default_factory=utcnow)
    verdict: GatewayVerdictType = GatewayVerdictType.UNKNOWN
    category: GatewayCategory = GatewayCategory.UNKNOWN
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    score: float | None = None
    threat_name: str = ""
    engine: str = ""
    policy: str = ""
    source: GatewayEvidenceSource = GatewayEvidenceSource.HEADER
    trusted: bool = False
    trust_state: TrustState = TrustState.UNVERIFIED_CHAIN
    trust_reason: str = ""
    raw_reference: str = ""
    normalized_detail: dict[str, Any] = Field(default_factory=dict)

    @property
    def counts_as_signal(self) -> bool:
        """Only a trusted negative verdict may influence detection.

        An untrusted verdict is still recorded — a forged "already scanned" header is itself
        worth showing an analyst — but it never feeds the risk score as a gateway detection.
        """
        return self.trusted and self.verdict.is_negative


class GatewayMessageRef(BaseModel):
    """A message as the gateway knows it."""

    model_config = ConfigDict(frozen=True)

    provider_id: str
    gateway_message_id: str = ""
    queue_id: str = ""
    internet_message_id: str = ""
    sender: str = ""
    recipients: tuple[str, ...] = ()
    subject: str = ""
    timestamp: datetime | None = None


class MessageTraceEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    timestamp: datetime
    node: str = ""
    action: str = ""  # received|scanned|delivered|quarantined|rejected|deferred
    detail: str = ""


class MessageTrace(BaseModel):
    """Delivery path of one message through a gateway (ТЗ 1.0.2 §23)."""

    provider_id: str
    ref: GatewayMessageRef
    events: list[MessageTraceEvent] = Field(default_factory=list)
    final_action: str = ""
    complete: bool = False


class QuarantineState(StrEnum):
    NOT_QUARANTINED = "NOT_QUARANTINED"
    QUARANTINED = "QUARANTINED"
    RELEASED = "RELEASED"
    DELETED = "DELETED"
    UNKNOWN = "UNKNOWN"


class QuarantineStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider_id: str
    state: QuarantineState = QuarantineState.UNKNOWN
    quarantine_id: str = ""
    reason: str = ""
    quarantined_at: datetime | None = None
    releasable: bool = False


class GatewayActionPlan(BaseModel):
    """What an action *would* do. Produced by ``propose_*`` and shown before any execution."""

    provider_id: str
    action: str
    targets: list[GatewayMessageRef] = Field(default_factory=list)
    reversible: bool = False
    requires_capability: GatewayCapability | None = None
    capability_available: bool = False
    blockers: list[str] = Field(default_factory=list)
    summary: str = ""

    @property
    def executable(self) -> bool:
        return self.capability_available and not self.blockers


class GatewayActionResult(BaseModel):
    provider_id: str
    action: str
    executed: bool = False
    dry_run: bool = True
    affected: int = 0
    reversible: bool = False
    rollback_token: str | None = None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    performed_at: datetime = Field(default_factory=utcnow)


class GatewayState(StrEnum):
    """Whether this deployment has an upstream gateway at all (ТЗ 1.0.2 §31)."""

    NOT_PRESENT = "NOT_PRESENT"  # a valid configuration, not an error
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


class GatewayDirection(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BOTH = "both"


class ConflictKind(StrEnum):
    """Disagreements worth an analyst's attention (ТЗ 1.0.2 §28)."""

    GATEWAY_MALICIOUS_PLATFORM_LOW = "GATEWAY_MALICIOUS_PLATFORM_LOW"
    GATEWAY_CLEAN_PLATFORM_HIGH = "GATEWAY_CLEAN_PLATFORM_HIGH"
    GATEWAY_DISAGREEMENT = "GATEWAY_DISAGREEMENT"
    HEADER_API_MISMATCH = "HEADER_API_MISMATCH"


class ProviderConflict(BaseModel):
    """An explicit, visible disagreement between sources."""

    kind: ConflictKind
    summary: str
    providers: list[str] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=utcnow)


class TrustedMailHop(BaseModel):
    """A hop the organisation operates and can therefore believe (ТЗ 1.0.1 §4.3).

    Trust is proved per message: a header is believed only when the ``Received`` chain shows the
    message actually passing through one of these hops at an allowed position.
    """

    id: str = ""
    type: str = "gateway"  # gateway|exchange_edge|exchange_mailbox|relay
    hostname: str = ""
    ip_networks: list[str] = Field(default_factory=list)
    expected_headers: list[str] = Field(default_factory=list)
    authserv_ids: list[str] = Field(default_factory=list)
    #: Where this hop may appear, counted from the outside in. ``None`` means anywhere.
    position_in_chain: int | None = None
    provider_id: str = ""
    direction: GatewayDirection = GatewayDirection.INBOUND
    enabled: bool = True

    def networks(self) -> list[IPv4Network | IPv6Network]:
        out: list[IPv4Network | IPv6Network] = []
        for raw in self.ip_networks:
            try:
                out.append(ip_network(raw.strip(), strict=False))
            except ValueError:
                continue
        return out
