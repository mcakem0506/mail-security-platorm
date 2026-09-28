"""Exchange integration interface (ТЗ 7).

All Exchange access sits behind this Protocol. Two rules are structural, not optional:
* least privilege — the runtime service never uses Organization Management / Domain Admin, and
  intake, directory and remediation use separate accounts (ТЗ 7.1, 49.7);
* remediation is disabled by default and runs in dry-run until explicitly approved (ТЗ 20).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

from msp_contracts import ProviderHealth, RemediationType, utcnow


class ExchangeCapability(StrEnum):
    """Capabilities are discovered, never assumed (ТЗ 6.5, 51)."""

    GET_MESSAGE = "get_message"
    GET_HEADERS = "get_headers"
    GET_ATTACHMENTS = "get_attachments"
    SEARCH = "search"
    SUBMIT_REPORT = "submit_report"
    REMEDIATION = "remediation"
    SHADOW_FEED = "shadow_feed"


@dataclass
class ExchangeMessageRef:
    """Identifies a message without assuming a specific Exchange API."""

    mailbox: str
    message_id: str = ""  # RFC 5322 Message-ID
    item_id: str = ""  # EWS ItemId / provider-specific handle
    internet_message_id: str = ""
    received_at: datetime | None = None
    subject: str = ""
    sender: str = ""

    def key(self) -> str:
        return self.item_id or self.internet_message_id or self.message_id


@dataclass
class FetchedMessage:
    ref: ExchangeMessageRef
    raw_mime: bytes
    source: str = ""
    truncated: bool = False


@dataclass
class RemediationRequest:
    action: RemediationType
    targets: list[ExchangeMessageRef] = field(default_factory=list)
    reason: str = ""
    requested_by: str = ""
    approved_by: list[str] = field(default_factory=list)
    dry_run: bool = True
    sender: str = ""
    domain: str = ""


@dataclass
class RemediationOutcome:
    action: RemediationType
    dry_run: bool
    affected_messages: int = 0
    affected_mailboxes: list[str] = field(default_factory=list)
    executed: bool = False
    rollback_supported: bool = False
    rollback_token: str | None = None
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    performed_at: datetime = field(default_factory=utcnow)
    detail: dict[str, object] = field(default_factory=dict)


@runtime_checkable
class ExchangeProvider(Protocol):
    provider_id: str

    def health(self) -> ProviderHealth: ...
    def capabilities(self) -> set[ExchangeCapability]: ...
    def get_message(self, ref: ExchangeMessageRef) -> FetchedMessage: ...
    def get_message_headers(self, ref: ExchangeMessageRef) -> dict[str, str]: ...
    def get_attachments(self, ref: ExchangeMessageRef) -> list[tuple[str, bytes]]: ...
    def submit_report(self, ref: ExchangeMessageRef, reported_by: str, note: str = "") -> str: ...
    def search_related_messages(
        self, *, sender: str = "", subject: str = "", message_id: str = "", limit: int = 100
    ) -> list[ExchangeMessageRef]: ...
    def request_remediation(self, request: RemediationRequest) -> RemediationOutcome: ...


class CapabilityUnavailable(RuntimeError):
    """Raised when a capability is not available in the connected Exchange configuration."""

    def __init__(self, capability: ExchangeCapability, detail: str = "") -> None:
        super().__init__(
            f"capability '{capability.value}' unavailable: {detail}" if detail else capability.value
        )
        self.capability = capability
