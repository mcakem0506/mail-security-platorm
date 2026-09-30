"""Framework for gateway API adapters (ТЗ 1.0.2 §21).

Where a gateway does expose an API, the adapter for it gets base URL, authentication, timeouts,
retry, a circuit breaker, rate limiting, caching, TLS validation and proxy support from here, so
each vendor adapter contains only the vendor's request and response shapes.

Three prohibitions are enforced in code rather than documented:

* **no credential ever leaves this module.** :meth:`GatewayApiClient.describe` and every log line
  emit the credential *reference*, not its value, and :class:`GatewayApiConfig` reads the secret
  from a file — the same mechanism Docker secrets and Vault use (ТЗ 28).
* **``verify_tls=False`` is refused in production.** An API adapter carries verdicts that change
  what an analyst does; accepting any certificate would make it trivially spoofable.
* **no arbitrary URL.** Every request path is joined onto the configured base URL, and the result
  is re-validated against the allowed host and scheme before it is sent, so neither a
  configuration mistake nor a redirect can turn the adapter into an SSRF primitive.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from msp_contracts import ProviderHealth, utcnow

logger = logging.getLogger(__name__)

_ALLOWED_SCHEMES = frozenset({"https"})
#: Schemes that must never be reachable through a configured base URL.
_FORBIDDEN_SCHEMES = frozenset({"file", "ftp", "gopher", "data", "dict", "ldap"})


class ApiConfigurationError(ValueError):
    """Configuration that would be unsafe to use, refused at construction time."""


class ApiUnavailable(RuntimeError):
    """The API could not be reached, or the circuit breaker is open."""


@dataclass
class GatewayApiConfig:
    provider_id: str
    base_url: str = ""
    auth_scheme: str = "bearer"  # bearer|api_key_header|basic|none
    auth_header: str = "Authorization"
    #: Path to the secret. The value is read at start-up and never written anywhere else.
    credential_file: str | None = None
    credential: str = ""
    username: str = ""
    verify_tls: bool = True
    ca_file: str | None = None
    proxy: str | None = None
    timeout_seconds: float = 10.0
    max_retries: int = 2
    retry_backoff_seconds: float = 0.5
    rate_limit_per_minute: int = 120
    cache_ttl_seconds: int = 300
    failure_threshold: int = 5
    circuit_reset_seconds: float = 300.0
    #: Permit plain HTTP. Only ever for a lab; refused when ``environment`` is production.
    allow_insecure_transport: bool = False

    def resolved_credential(self) -> str:
        if self.credential_file:
            path = Path(self.credential_file)
            if path.is_file():
                return path.read_text(encoding="utf-8").strip()
            logger.error("gateway_api.credential_file_missing", extra={"provider": self.provider_id})
        return self.credential

    @property
    def credential_reference(self) -> str:
        """A safe description of where the credential came from — never its value."""
        if self.credential_file:
            return f"file:{self.credential_file}"
        return "inline" if self.credential else "none"


def validate_base_url(url: str, *, environment: str = "production", allow_insecure: bool = False) -> str:
    """Refuse a base URL that could not be used safely."""
    if not url:
        raise ApiConfigurationError("base URL is required")
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme in _FORBIDDEN_SCHEMES or not scheme:
        raise ApiConfigurationError(f"scheme '{scheme or 'none'}' is not permitted for a gateway API")
    if scheme not in _ALLOWED_SCHEMES:
        if scheme != "http":
            raise ApiConfigurationError(f"scheme '{scheme}' is not permitted for a gateway API")
        if environment == "production" or not allow_insecure:
            raise ApiConfigurationError(
                "a gateway API must be reached over HTTPS: its verdicts change analyst decisions"
            )
    if not parsed.hostname:
        raise ApiConfigurationError("base URL has no host")
    return url if url.endswith("/") else url + "/"


def build_url(base_url: str, path: str) -> str:
    """Join a relative path onto the base URL, refusing anything that escapes it.

    This is the SSRF gate: a path that carries its own scheme or host, or that climbs out of the
    base path, is rejected rather than normalised, because the caller may be passing through a
    value that originated in a message.
    """
    if "\n" in path or "\r" in path or "\x00" in path:
        raise ApiConfigurationError("request path contains control characters")
    parsed_path = urlparse(path)
    if parsed_path.scheme or parsed_path.netloc:
        raise ApiConfigurationError("request path must be relative to the configured base URL")
    candidate = urljoin(base_url, path.lstrip("/"))
    base = urlparse(base_url)
    target = urlparse(candidate)
    if target.scheme != base.scheme or target.netloc != base.netloc:
        raise ApiConfigurationError("request path would leave the configured host")
    if not target.path.startswith(base.path):
        raise ApiConfigurationError("request path would leave the configured base path")
    host = (target.hostname or "").lower()
    try:
        address = ip_address(host)
    except ValueError:
        address = None
    if address is not None and (address.is_loopback or address.is_link_local or address.is_reserved):
        raise ApiConfigurationError(f"gateway API host {host} is not a routable address")
    return candidate


@dataclass
class _RateLimiter:
    per_minute: int
    _events: deque[float] = field(default_factory=deque)

    def allow(self) -> bool:
        if self.per_minute <= 0:
            return True
        now = time.monotonic()
        while self._events and now - self._events[0] > 60:
            self._events.popleft()
        if len(self._events) >= self.per_minute:
            return False
        self._events.append(now)
        return True


@dataclass
class _CircuitBreaker:
    failure_threshold: int
    reset_after: float
    _failures: int = 0
    _opened_at: float | None = None

    @property
    def is_open(self) -> bool:
        if self._opened_at is None:
            return False
        if time.monotonic() - self._opened_at >= self.reset_after:
            # Half-open: let one request through to see whether the gateway recovered.
            self._opened_at = None
            self._failures = max(self.failure_threshold - 1, 0)
            return False
        return True

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.failure_threshold and self._opened_at is None:
            self._opened_at = time.monotonic()

    @property
    def state(self) -> str:
        return "open" if self.is_open else "closed"


@dataclass
class _CacheEntry:
    value: Any
    expires_at: float


class GatewayApiClient:
    """HTTP client with the whole §21 checklist applied before any vendor code runs."""

    def __init__(self, config: GatewayApiConfig, *, environment: str = "production") -> None:
        self.config = config
        self.environment = environment
        if environment == "production" and not config.verify_tls:
            raise ApiConfigurationError(
                "verify_tls=false is not permitted in production: the API carries security verdicts"
            )
        self.base_url = validate_base_url(
            config.base_url, environment=environment, allow_insecure=config.allow_insecure_transport
        )
        self._credential = config.resolved_credential()
        self._rate_limiter = _RateLimiter(config.rate_limit_per_minute)
        self._breaker = _CircuitBreaker(config.failure_threshold, config.circuit_reset_seconds)
        self._cache: dict[str, _CacheEntry] = {}
        self._client: Any = None
        self.last_error: str = ""
        self.requests = 0
        self.failures = 0

    # -- description ---------------------------------------------------------------------------
    def describe(self) -> dict[str, Any]:
        """Everything the console may show. Deliberately free of the credential value."""
        return {
            "provider_id": self.config.provider_id,
            "base_url": self.base_url,
            "auth_scheme": self.config.auth_scheme,
            "credential": self.config.credential_reference,
            "verify_tls": self.config.verify_tls,
            "proxy_configured": bool(self.config.proxy),
            "rate_limit_per_minute": self.config.rate_limit_per_minute,
            "circuit_state": self._breaker.state,
            "requests": self.requests,
            "failures": self.failures,
            "last_error": self.last_error,
        }

    def health(self) -> ProviderHealth:
        if self._breaker.is_open:
            return ProviderHealth(
                provider_id=self.config.provider_id,
                status="unavailable",
                detail="circuit breaker open after repeated failures",
                checked_at=utcnow(),
            )
        if not self._credential and self.config.auth_scheme != "none":
            return ProviderHealth(
                provider_id=self.config.provider_id,
                status="not_configured",
                detail=f"credential not available ({self.config.credential_reference})",
            )
        return ProviderHealth(
            provider_id=self.config.provider_id,
            status="degraded" if self.failures else "ok",
            mode=self.config.auth_scheme,
            detail=self.last_error or None,
        )

    # -- request -------------------------------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": "mail-security-platform"}
        if not self._credential:
            return headers
        match self.config.auth_scheme:
            case "bearer":
                headers[self.config.auth_header] = f"Bearer {self._credential}"
            case "api_key_header":
                headers[self.config.auth_header] = self._credential
            case "basic":
                import base64

                raw = f"{self.config.username}:{self._credential}".encode()
                headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
        return headers

    def _ensure_client(self) -> Any:
        if self._client is None:
            import httpx

            verify: Any = self.config.ca_file or self.config.verify_tls
            self._client = httpx.Client(
                timeout=self.config.timeout_seconds,
                verify=verify,
                proxy=self.config.proxy,
                # A redirect is how an SSRF gate is usually bypassed; the adapter follows none.
                follow_redirects=False,
            )
        return self._client

    def get_json(self, path: str, params: dict[str, Any] | None = None, *, cache: bool = True) -> Any:
        url = build_url(self.base_url, path)
        cache_key = f"{url}?{sorted((params or {}).items())}"
        if cache and self.config.cache_ttl_seconds > 0:
            entry = self._cache.get(cache_key)
            if entry is not None and entry.expires_at > time.monotonic():
                return entry.value
        if self._breaker.is_open:
            raise ApiUnavailable(f"{self.config.provider_id}: circuit breaker open")
        if not self._rate_limiter.allow():
            raise ApiUnavailable(f"{self.config.provider_id}: local rate limit reached")

        import httpx

        client = self._ensure_client()
        last: Exception | None = None
        for attempt in range(self.config.max_retries + 1):
            try:
                self.requests += 1
                response = client.get(url, params=params, headers=self._headers())
                if response.status_code >= 500:
                    raise ApiUnavailable(f"HTTP {response.status_code}")
                if response.status_code == 429:
                    raise ApiUnavailable("HTTP 429: gateway rate limit")
                response.raise_for_status()
                payload = response.json()
                self._breaker.record_success()
                self.last_error = ""
                if cache and self.config.cache_ttl_seconds > 0:
                    self._cache[cache_key] = _CacheEntry(
                        payload, time.monotonic() + self.config.cache_ttl_seconds
                    )
                return payload
            except (httpx.HTTPError, ApiUnavailable, ValueError) as exc:
                last = exc
                self.failures += 1
                # The exception text may echo the request; only the type is recorded.
                self.last_error = type(exc).__name__
                self._breaker.record_failure()
                logger.warning(
                    "gateway_api.request_failed",
                    extra={"provider": self.config.provider_id, "error": type(exc).__name__},
                )
                if attempt < self.config.max_retries:
                    time.sleep(self.config.retry_backoff_seconds * (2**attempt))
        raise ApiUnavailable(f"{self.config.provider_id}: {type(last).__name__}") from last

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            finally:
                self._client = None
