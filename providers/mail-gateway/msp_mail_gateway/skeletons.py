"""Provider skeletons for gateways not yet available to test against (ТЗ 1.0.2 §36).

FortiMail, Proofpoint, Mimecast and Cisco ESA are in scope as *contracts* for 1.0.2: the header
shapes are publicly documented, so the header side is implemented and usable, while the API side
is declared and refused until there is a real environment to verify it against. Guessing at an
API and shipping it as working would be worse than refusing: an adapter that silently returns
nothing looks exactly like a gateway that found nothing.

Each skeleton therefore states three things:

* which headers it reads today (working, header-only);
* which capabilities its API *would* provide, as a contract to implement against;
* what is needed from the organisation before that API can be built — the integration guide is
  in ``docs/GENERIC_GATEWAY_INTEGRATION.md``.
"""

from __future__ import annotations

from dataclasses import dataclass

from msp_contracts import GatewayCapability

from .base import GatewayProviderConfig
from .generic_header import GenericHeaderGatewayProvider


@dataclass(frozen=True)
class ProviderSkeleton:
    """The declared contract for a gateway whose API is not implemented yet."""

    provider_type: str
    display_name: str
    #: Capabilities available right now, through header parsing alone.
    implemented: frozenset[GatewayCapability]
    #: Capabilities the vendor's API is expected to provide once implemented.
    planned: frozenset[GatewayCapability]
    #: What must be supplied before the API adapter can be written and verified.
    prerequisites: tuple[str, ...]
    #: Header configuration, in the same shape the generic provider consumes.
    header_profile: dict[str, object]

    def to_config(self, provider_id: str = "") -> GatewayProviderConfig:
        return GatewayProviderConfig(
            provider_id=provider_id or self.provider_type,
            provider_type="generic_header",
            display_name=self.display_name,
            settings=dict(self.header_profile),
        )

    def build(self, provider_id: str = "") -> GenericHeaderGatewayProvider:
        """A working, header-only provider for this vendor."""
        return GenericHeaderGatewayProvider(self.to_config(provider_id))


_HEADER_ONLY = frozenset({GatewayCapability.HEADER_VERDICT})
_TYPICAL_API = frozenset(
    {
        GatewayCapability.API_VERDICT,
        GatewayCapability.MESSAGE_TRACE,
        GatewayCapability.QUARANTINE_READ,
        GatewayCapability.SEARCH,
    }
)
_COMMON_PREREQUISITES = (
    "адрес API и версия продукта",
    "сервисная учётная запись только на чтение",
    "способ аутентификации и место хранения секрета",
    "тестовая среда для проверки адаптера",
)


SKELETONS: dict[str, ProviderSkeleton] = {
    "fortimail": ProviderSkeleton(
        provider_type="fortimail",
        display_name="Fortinet FortiMail",
        implemented=_HEADER_ONLY | {GatewayCapability.SPAM_RESULT, GatewayCapability.AV_RESULT},
        planned=_TYPICAL_API | {GatewayCapability.QUARANTINE_WRITE, GatewayCapability.RELEASE},
        prerequisites=_COMMON_PREREQUISITES,
        header_profile={
            "headers": {
                "verdict": ["X-FEAS-CLIENT-IP", "X-FE-Spam-Status", "X-FEAS-SPAM-STATUS", "X-Virus-Status"],
                "score": ["X-FE-Spam-Score", "X-FEAS-SPAM-SCORE"],
                "threat": ["X-FE-Virus-Name", "X-Virus-Name"],
                "policy": ["X-FE-Policy-ID"],
            }
        },
    ),
    "proofpoint": ProviderSkeleton(
        provider_type="proofpoint",
        display_name="Proofpoint Protection Server",
        implemented=_HEADER_ONLY | {GatewayCapability.SPAM_RESULT, GatewayCapability.PHISHING_RESULT},
        planned=_TYPICAL_API | {GatewayCapability.CAMPAIGN_DATA, GatewayCapability.SANDBOX_RESULT},
        prerequisites=_COMMON_PREREQUISITES,
        header_profile={
            "headers": {
                "verdict": ["X-Proofpoint-Spam-Details", "X-Proofpoint-Virus-Version"],
                "score": ["X-Proofpoint-Spam-Score"],
                "threat": ["X-Proofpoint-Threat"],
            },
            "verdict_map": {
                "SPAM": ["rule=spam", "rule=bulk"],
                "PHISHING": ["rule=phish"],
                "MALICIOUS": ["rule=malware", "rule=virus"],
                "CLEAN_OBSERVED": ["rule=notspam", "rule=clean"],
            },
        },
    ),
    "mimecast": ProviderSkeleton(
        provider_type="mimecast",
        display_name="Mimecast Email Security",
        implemented=_HEADER_ONLY | {GatewayCapability.SPAM_RESULT},
        planned=_TYPICAL_API | {GatewayCapability.RELEASE, GatewayCapability.SENDER_BLOCK},
        prerequisites=_COMMON_PREREQUISITES,
        header_profile={
            "headers": {
                "verdict": [
                    "X-Mimecast-Spam-Signature",
                    "X-Mimecast-Bulk-Signature",
                    "X-Mimecast-Impersonation-Protect",
                ],
                "score": ["X-Mimecast-Spam-Score"],
            },
            "verdict_map": {"SPAM": ["true", "yes"], "CLEAN_OBSERVED": ["false", "no"]},
        },
    ),
    "cisco_esa": ProviderSkeleton(
        provider_type="cisco_esa",
        display_name="Cisco Secure Email (ESA)",
        implemented=_HEADER_ONLY | {GatewayCapability.SPAM_RESULT, GatewayCapability.AV_RESULT},
        planned=_TYPICAL_API | {GatewayCapability.SANDBOX_RESULT},
        prerequisites=_COMMON_PREREQUISITES,
        header_profile={
            "headers": {
                "verdict": ["X-IronPort-Anti-Spam-Result", "X-IronPort-AV", "X-Amp-Result"],
                "score": ["X-IronPort-Reputation", "X-SBRS"],
                "threat": ["X-IronPort-Threat"],
            }
        },
    ),
}


def skeleton_summary() -> list[dict[str, object]]:
    """What the console shows under "gateways this platform can talk to"."""
    return [
        {
            "provider_type": skeleton.provider_type,
            "display_name": skeleton.display_name,
            "implemented": sorted(c.value for c in skeleton.implemented),
            "planned": sorted(c.value for c in skeleton.planned),
            "prerequisites": list(skeleton.prerequisites),
            "status": "header_only",
        }
        for skeleton in SKELETONS.values()
    ]
