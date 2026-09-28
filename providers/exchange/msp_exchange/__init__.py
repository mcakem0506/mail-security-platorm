"""Exchange integration providers (ТЗ 7)."""

from .base import (
    CapabilityUnavailable,
    ExchangeCapability,
    ExchangeMessageRef,
    ExchangeProvider,
    FetchedMessage,
    RemediationOutcome,
    RemediationRequest,
)
from .ews import BLOCKERS as EWS_BLOCKERS, EwsConfig, OnPremEwsExchangeProvider
from .mock import MockExchangeProvider
from .security_mailbox import (
    IngestedReport,
    SecurityMailboxConfig,
    SecurityMailboxProvider,
    extract_original_message,
)

__all__ = [
    "EWS_BLOCKERS",
    "CapabilityUnavailable",
    "EwsConfig",
    "ExchangeCapability",
    "ExchangeMessageRef",
    "ExchangeProvider",
    "FetchedMessage",
    "IngestedReport",
    "MockExchangeProvider",
    "OnPremEwsExchangeProvider",
    "RemediationOutcome",
    "RemediationRequest",
    "SecurityMailboxConfig",
    "SecurityMailboxProvider",
    "extract_original_message",
]
