"""Vendor-neutral integration with upstream mail gateways (ТЗ 1.0.2).

The platform runs with no gateway, with one, or with several. Nothing in the core names a vendor:
gateways are discovered from configuration, their capabilities are probed, and their verdicts are
evidence that can raise risk but never lower it.
"""

from .api_base import (
    ApiConfigurationError,
    ApiUnavailable,
    GatewayApiClient,
    GatewayApiConfig,
    build_url,
    validate_base_url,
)
from .base import (
    BaseGatewayProvider,
    GatewayContext,
    GatewayProviderConfig,
    MailGatewayProvider,
)
from .builtin import EopGatewayProvider, GenericAvGatewayProvider, SpamAssassinGatewayProvider
from .conflict import detect_conflicts, upstream_hard_signal
from .generic_header import (
    GenericHeaderGatewayProvider,
    config_from_mapping,
    load_profiles,
)
from .ksmg import KsmgGatewayProvider
from .received import ChainSummary, ReceivedHop, last_external_hop, parse_received, summarise
from .registry import PROVIDER_TYPES, GatewayAnalysis, GatewayRegistry, build_provider
from .skeletons import SKELETONS, ProviderSkeleton, skeleton_summary
from .syslog import (
    SyslogEvent,
    SyslogGatewayProvider,
    SyslogIngestor,
    SyslogIngestorConfig,
    SyslogListener,
    SyslogRejected,
    parse_syslog,
)
from .trust import (
    AuthResultsTrust,
    ChainVerification,
    HeaderTrustDecision,
    decide_header_trust,
    filter_authentication_results,
    verify_chain,
)

__all__ = [
    "PROVIDER_TYPES",
    "SKELETONS",
    "ApiConfigurationError",
    "ApiUnavailable",
    "AuthResultsTrust",
    "BaseGatewayProvider",
    "ChainSummary",
    "ChainVerification",
    "EopGatewayProvider",
    "GatewayAnalysis",
    "GatewayApiClient",
    "GatewayApiConfig",
    "GatewayContext",
    "GatewayProviderConfig",
    "GatewayRegistry",
    "GenericAvGatewayProvider",
    "GenericHeaderGatewayProvider",
    "HeaderTrustDecision",
    "KsmgGatewayProvider",
    "MailGatewayProvider",
    "ProviderSkeleton",
    "ReceivedHop",
    "SpamAssassinGatewayProvider",
    "SyslogEvent",
    "SyslogGatewayProvider",
    "SyslogIngestor",
    "SyslogIngestorConfig",
    "SyslogListener",
    "SyslogRejected",
    "build_provider",
    "build_url",
    "config_from_mapping",
    "decide_header_trust",
    "detect_conflicts",
    "filter_authentication_results",
    "last_external_hop",
    "load_profiles",
    "parse_received",
    "parse_syslog",
    "skeleton_summary",
    "summarise",
    "upstream_hard_signal",
    "validate_base_url",
    "verify_chain",
]
