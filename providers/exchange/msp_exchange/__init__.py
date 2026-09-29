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
from .ews import BLOCKERS as EWS_BLOCKERS
from .ews import (
    EwsAccessMode,
    EwsAuthMethod,
    EwsCapabilityReport,
    EwsConfig,
    MailboxOutOfScope,
    OnPremEwsExchangeProvider,
    mailbox_in_scope,
    probe_environment,
)
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
    "EwsAccessMode",
    "EwsAuthMethod",
    "EwsCapabilityReport",
    "EwsConfig",
    "ExchangeCapability",
    "ExchangeMessageRef",
    "ExchangeProvider",
    "FetchedMessage",
    "IngestedReport",
    "MailboxOutOfScope",
    "MockExchangeProvider",
    "OnPremEwsExchangeProvider",
    "RemediationOutcome",
    "RemediationRequest",
    "SecurityMailboxConfig",
    "SecurityMailboxProvider",
    "extract_original_message",
    "mailbox_in_scope",
    "probe_environment",
]
