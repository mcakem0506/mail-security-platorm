"""Threat Intelligence provider interface and privacy policy gate (ТЗ 13, 14.4)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from msp_contracts import IOCType, ProviderHealth, QuotaInfo, TIResult, TIStatus

_SENSITIVE_QUERY_KEYS = re.compile(
    r"(?i)(token|auth|key|secret|password|passwd|pwd|session|sid|jwt|bearer|code|otp|signature|sig|"
    r"email|mail|login|user|uid|account|claim|invite|unsubscribe|recipient|rcpt|hash|id)"
)
_EMAIL_IN_URL = re.compile(r"[\w.+\-]+@[\w\-]+\.[a-z]{2,}", re.IGNORECASE)


@runtime_checkable
class ThreatIntelligenceProvider(Protocol):
    """All external intelligence access goes through this interface (ТЗ 13.2)."""

    provider_id: str

    def lookup_file_hash(self, sha256: str) -> TIResult: ...
    def lookup_domain(self, domain: str) -> TIResult: ...
    def lookup_url(self, url: str) -> TIResult: ...
    def lookup_ip(self, ip: str) -> TIResult: ...
    def health(self) -> ProviderHealth: ...
    def quota(self) -> QuotaInfo: ...


@dataclass
class PrivacyPolicy:
    """What may leave the perimeter, per IOC type (ТЗ 2.4, 14.4).

    Defaults are deliberately restrictive: hashes and domains only. Full URLs frequently carry
    tokens and recipient identifiers, so sending them requires an explicit decision.
    """

    allow_hash: bool = True
    allow_domain: bool = True
    allow_ip: bool = True
    allow_url: bool = False
    allow_url_path: bool = False  # when URLs are allowed, send only scheme://host by default
    allow_sender_email: bool = False
    allow_file_upload: bool = False
    allow_internal_domains: bool = False  # never send corporate domains by default
    corporate_domains: tuple[str, ...] = ()
    blocked_domains: tuple[str, ...] = ()

    def _internal(self, value: str) -> bool:
        value = value.lower()
        return any(value == d or value.endswith("." + d) for d in map(str.lower, self.corporate_domains))

    def check(self, ioc_type: IOCType, value: str) -> tuple[bool, str]:
        """Return (allowed, reason). The reason is recorded for audit when blocked."""
        value = (value or "").strip()
        if not value:
            return False, "empty indicator"
        match ioc_type:
            case IOCType.SHA256:
                return (self.allow_hash, "" if self.allow_hash else "policy: file hash lookups disabled")
            case IOCType.DOMAIN:
                if not self.allow_domain:
                    return False, "policy: domain lookups disabled"
                if self._internal(value) and not self.allow_internal_domains:
                    return False, "policy: corporate domain must not be sent externally"
                if any(value.endswith(b) for b in self.blocked_domains):
                    return False, "policy: domain in blocked list"
                return True, ""
            case IOCType.IPV4 | IOCType.IPV6:
                return (self.allow_ip, "" if self.allow_ip else "policy: IP lookups disabled")
            case IOCType.URL:
                if not self.allow_url:
                    return False, "policy: URL lookups disabled"
                if _EMAIL_IN_URL.search(value):
                    return False, "policy: URL contains an email address"
                host = value.split("//", 1)[-1].split("/", 1)[0].split("@")[-1].split(":")[0]
                if self._internal(host) and not self.allow_internal_domains:
                    return False, "policy: URL points to a corporate domain"
                if "?" in value or "#" in value:
                    query = value.split("?", 1)[-1]
                    if _SENSITIVE_QUERY_KEYS.search(query):
                        return False, "policy: URL query contains potentially sensitive parameters"
                    if not self.allow_url_path:
                        return False, "policy: URL query parameters must not be sent"
                if not self.allow_url_path:
                    path = "/" + value.split("//", 1)[-1].partition("/")[2]
                    if path.strip("/"):
                        return False, "policy: URL path must not be sent"
                return True, ""
            case IOCType.EMAIL:
                if not self.allow_sender_email:
                    return False, "policy: sender address lookups disabled"
                if self._internal(value.rsplit("@", 1)[-1]):
                    return False, "policy: internal address must not be sent externally"
                return True, ""
        return False, f"policy: IOC type {ioc_type.value} not permitted"

    def sanitize_url(self, url: str) -> str:
        """Strip path/query when only the host may leave the perimeter."""
        if self.allow_url_path:
            return url
        scheme, _, rest = url.partition("://")
        host = rest.split("/", 1)[0]
        return f"{scheme}://{host}" if scheme else host


def policy_blocked(provider_id: str, ioc_type: IOCType, indicator: str, reason: str) -> TIResult:
    return TIResult(
        provider_id=provider_id,
        ioc_type=ioc_type,
        indicator=indicator,
        status=TIStatus.POLICY_BLOCKED,
        summary={"reason": reason},
    )


def unsupported(provider_id: str, ioc_type: IOCType, indicator: str) -> TIResult:
    return TIResult(
        provider_id=provider_id,
        ioc_type=ioc_type,
        indicator=indicator,
        status=TIStatus.NOT_SUPPORTED,
    )


@dataclass
class ProviderRegistry:
    providers: dict[str, ThreatIntelligenceProvider] = field(default_factory=dict)

    def register(self, provider: ThreatIntelligenceProvider) -> None:
        self.providers[provider.provider_id] = provider

    def get(self, provider_id: str) -> ThreatIntelligenceProvider | None:
        return self.providers.get(provider_id)

    def enabled(self) -> list[ThreatIntelligenceProvider]:
        out: list[ThreatIntelligenceProvider] = []
        for p in self.providers.values():
            health = p.health()
            if health.status not in {"disabled", "not_configured"}:
                out.append(p)
        return out
