"""VirusTotal enrichment provider (ТЗ 14).

Explicit product decisions encoded here:
* VirusTotal is an *enrichment* provider, never the only AV or anti-phishing source;
* ``public`` is not a supported production mode — VT_MODE is disabled|mock|premium|private_scanning;
* file upload is DISABLED in v1 and requires a separate, explicit switch even with Premium;
* Private Scanning is a separate provider path and is never mixed with the normal upload flow;
* the API key is server-side only and is never logged or returned through the API;
* raw provider JSON is normalised before it leaves this module.
"""

from __future__ import annotations

import base64
import logging
import random
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
from msp_contracts import IOCType, ProviderHealth, QuotaInfo, TIResult, TIStatus, VTMode, utcnow

logger = logging.getLogger(__name__)

PROVIDER_ID = "virustotal"
_API_BASE = "https://www.virustotal.com/api/v3"
_MALICIOUS_THRESHOLD = 2  # a single noisy engine is not a verdict
_SUSPICIOUS_THRESHOLD = 1


class VirusTotalConfigError(ValueError):
    pass


@dataclass
class VirusTotalConfig:
    mode: VTMode = VTMode.DISABLED
    api_key: str | None = None
    base_url: str = _API_BASE
    timeout_seconds: float = 8.0
    per_minute_limit: int = 300  # Premium default; adjust to the actual contract
    per_day_limit: int = 50_000
    allow_file_upload: bool = False  # ТЗ 14.5 — must stay False unless explicitly enabled
    verify_tls: bool = True
    proxy: str | None = None

    def validate(self) -> None:
        if self.mode in {VTMode.PREMIUM, VTMode.PRIVATE_SCANNING} and not self.api_key:
            raise VirusTotalConfigError("VT_MODE requires VT_API_KEY to be configured")
        if self.allow_file_upload and self.mode is not VTMode.PRIVATE_SCANNING:
            raise VirusTotalConfigError(
                "file upload is only permitted through the Private Scanning provider path"
            )

    @property
    def enabled(self) -> bool:
        return self.mode is not VTMode.DISABLED


class _RateLimiter:
    """Token-bucket limiter shared across threads, with a backoff window after 429."""

    def __init__(self, per_minute: int, per_day: int) -> None:
        self.per_minute = max(1, per_minute)
        self.per_day = max(1, per_day)
        self._lock = threading.Lock()
        self._minute_window = 0.0
        self._minute_used = 0
        self._day_window = 0.0
        self._day_used = 0
        self._backoff_until = 0.0

    def acquire(self) -> tuple[bool, str]:
        now = time.monotonic()
        with self._lock:
            if now < self._backoff_until:
                return False, "provider backoff active"
            if now - self._minute_window >= 60:
                self._minute_window, self._minute_used = now, 0
            if now - self._day_window >= 86400:
                self._day_window, self._day_used = now, 0
            if self._minute_used >= self.per_minute:
                return False, "per-minute quota exhausted"
            if self._day_used >= self.per_day:
                return False, "daily quota exhausted"
            self._minute_used += 1
            self._day_used += 1
            return True, ""

    def penalise(self, seconds: float) -> None:
        with self._lock:
            self._backoff_until = time.monotonic() + seconds

    def snapshot(self) -> tuple[int, int, float]:
        with self._lock:
            return self._minute_used, self._day_used, self._backoff_until


def url_id(url: str) -> str:
    """VirusTotal URL identifier: unpadded base64url of the URL (API v3)."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _classify(stats: dict[str, int]) -> TIStatus:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    if malicious >= _MALICIOUS_THRESHOLD:
        return TIStatus.KNOWN_BAD
    if malicious + suspicious >= _SUSPICIOUS_THRESHOLD:
        return TIStatus.SUSPICIOUS
    if harmless + undetected > 0:
        # Explicitly NOT "safe": engines simply have nothing negative on record (ТЗ 13.3).
        return TIStatus.NO_NEGATIVE_REPUTATION
    return TIStatus.UNKNOWN


def _ts(value: object) -> datetime | None:
    if isinstance(value, int | float) and value > 0:
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    return None


def normalize_response(payload: dict, ioc_type: IOCType, indicator: str) -> TIResult:
    """Convert a raw VT v3 object into the platform's normalised result (ТЗ 42.9)."""
    attributes = (payload.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    status = _classify(stats)
    categories: list[str] = []
    for source_categories in (attributes.get("categories") or {}).values():
        if isinstance(source_categories, str):
            categories.append(source_categories[:64])
    label = (attributes.get("popular_threat_classification") or {}).get("suggested_threat_label")
    if isinstance(label, str) and label:
        categories.append(label[:64])

    first_seen = _ts(
        attributes.get("first_submission_date")
        or attributes.get("creation_date")
        or attributes.get("first_seen_itw_date")
    )
    last_seen = _ts(attributes.get("last_analysis_date") or attributes.get("last_modification_date"))
    summary: dict[str, object] = {
        "stats": {k: int(v) for k, v in stats.items() if isinstance(v, int | float)},
        "reputation": attributes.get("reputation"),
        "times_submitted": attributes.get("times_submitted"),
    }
    creation = _ts(attributes.get("creation_date"))
    if creation is not None:
        age_days = (utcnow() - creation).days
        summary["domain_age_days"] = age_days
        summary["recently_registered"] = age_days < 30
    if attributes.get("meaningful_name"):
        summary["meaningful_name"] = str(attributes["meaningful_name"])[:200]
    if attributes.get("type_description"):
        summary["file_type"] = str(attributes["type_description"])[:100]

    return TIResult(
        provider_id=PROVIDER_ID,
        ioc_type=ioc_type,
        indicator=indicator,
        status=status,
        malicious_count=int(stats.get("malicious", 0)) or None,
        suspicious_count=int(stats.get("suspicious", 0)) or None,
        total_count=sum(int(v) for v in stats.values() if isinstance(v, int | float)) or None,
        categories=sorted(set(categories))[:8],
        first_seen=first_seen,
        last_seen=last_seen,
        summary=summary,
    )


class VirusTotalProvider:
    """VirusTotal API v3 provider. Enrichment only; never a dependency of core analysis."""

    provider_id = PROVIDER_ID

    def __init__(self, config: VirusTotalConfig, client: httpx.Client | None = None) -> None:
        config.validate()
        self.config = config
        self._limiter = _RateLimiter(config.per_minute_limit, config.per_day_limit)
        self._client = client
        self._owns_client = client is None
        self._last_error: str | None = None

    # -- lifecycle
    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.config.base_url,
                timeout=self.config.timeout_seconds,
                verify=self.config.verify_tls,
                proxy=self.config.proxy,
                headers={"x-apikey": self.config.api_key or "", "accept": "application/json"},
            )
        return self._client

    def close(self) -> None:
        if self._client is not None and self._owns_client:
            self._client.close()
            self._client = None

    # -- interface
    def health(self) -> ProviderHealth:
        if self.config.mode is VTMode.DISABLED:
            return ProviderHealth(
                provider_id=self.provider_id,
                status="disabled",
                mode=self.config.mode.value,
                detail="VirusTotal not configured",
            )
        if self.config.mode is VTMode.MOCK:
            return ProviderHealth(provider_id=self.provider_id, status="ok", mode="mock")
        if not self.config.api_key:
            return ProviderHealth(
                provider_id=self.provider_id,
                status="not_configured",
                mode=self.config.mode.value,
                detail="VirusTotal not configured",
            )
        _, _, backoff = self._limiter.snapshot()
        if backoff > time.monotonic():
            return ProviderHealth(
                provider_id=self.provider_id,
                status="degraded",
                mode=self.config.mode.value,
                detail="rate limited",
            )
        return ProviderHealth(
            provider_id=self.provider_id,
            status="ok" if self._last_error is None else "degraded",
            mode=self.config.mode.value,
            detail=self._last_error,
        )

    def quota(self) -> QuotaInfo:
        minute_used, day_used, backoff = self._limiter.snapshot()
        return QuotaInfo(
            provider_id=self.provider_id,
            per_minute_limit=self.config.per_minute_limit,
            per_day_limit=self.config.per_day_limit,
            used_minute=minute_used,
            used_day=day_used,
            backoff_until=(utcnow() if backoff > time.monotonic() else None),
        )

    def lookup_file_hash(self, sha256: str) -> TIResult:
        return self._lookup(f"/files/{sha256}", IOCType.SHA256, sha256)

    def lookup_domain(self, domain: str) -> TIResult:
        return self._lookup(f"/domains/{domain}", IOCType.DOMAIN, domain)

    def lookup_url(self, url: str) -> TIResult:
        return self._lookup(f"/urls/{url_id(url)}", IOCType.URL, url)

    def lookup_ip(self, ip: str) -> TIResult:
        ioc_type = IOCType.IPV6 if ":" in ip else IOCType.IPV4
        return self._lookup(f"/ip_addresses/{ip}", ioc_type, ip)

    def submit_file(self, *_args: object, **_kwargs: object) -> TIResult:
        """File submission (ТЗ 14.5): disabled in v1, and Premium alone does not enable it."""
        raise PermissionError(
            "VirusTotal file upload is disabled. Enable it explicitly via the Private Scanning "
            "provider path after a privacy/DPA review."
        )

    # -- internals
    def _disabled_result(self, ioc_type: IOCType, indicator: str) -> TIResult:
        return TIResult(
            provider_id=self.provider_id,
            ioc_type=ioc_type,
            indicator=indicator,
            status=TIStatus.PROVIDER_UNAVAILABLE,
            error="VirusTotal not configured",
            summary={"mode": self.config.mode.value},
        )

    def _lookup(self, path: str, ioc_type: IOCType, indicator: str) -> TIResult:
        if (self.config.mode is VTMode.DISABLED or not self.config.api_key) and (
            self.config.mode is not VTMode.MOCK
        ):
            return self._disabled_result(ioc_type, indicator)
        if self.config.mode is VTMode.MOCK:
            return mock_result(ioc_type, indicator)

        allowed, reason = self._limiter.acquire()
        if not allowed:
            return TIResult(
                provider_id=self.provider_id,
                ioc_type=ioc_type,
                indicator=indicator,
                status=TIStatus.RATE_LIMITED,
                error=reason,
            )
        try:
            response = self._http().get(path)
        except httpx.TimeoutException:
            self._last_error = "timeout"
            return TIResult(
                provider_id=self.provider_id,
                ioc_type=ioc_type,
                indicator=indicator,
                status=TIStatus.PROVIDER_UNAVAILABLE,
                error="timeout",
            )
        except httpx.HTTPError as exc:
            self._last_error = type(exc).__name__
            return TIResult(
                provider_id=self.provider_id,
                ioc_type=ioc_type,
                indicator=indicator,
                status=TIStatus.PROVIDER_UNAVAILABLE,
                error=type(exc).__name__,
            )

        if response.status_code == 404:
            self._last_error = None
            return TIResult(
                provider_id=self.provider_id,
                ioc_type=ioc_type,
                indicator=indicator,
                status=TIStatus.UNKNOWN,
                summary={"reason": "indicator not present in VirusTotal"},
            )
        if response.status_code == 429:
            retry_after = float(response.headers.get("retry-after", 60) or 60)
            self._limiter.penalise(min(retry_after, 900))
            return TIResult(
                provider_id=self.provider_id,
                ioc_type=ioc_type,
                indicator=indicator,
                status=TIStatus.RATE_LIMITED,
                error="HTTP 429",
            )
        if response.status_code in {401, 403}:
            self._last_error = f"authentication failed (HTTP {response.status_code})"
            logger.error("virustotal.auth_failed", extra={"status": response.status_code})
            return TIResult(
                provider_id=self.provider_id,
                ioc_type=ioc_type,
                indicator=indicator,
                status=TIStatus.ERROR,
                error=f"HTTP {response.status_code}",
            )
        if response.status_code >= 500:
            self._limiter.penalise(30)
            return TIResult(
                provider_id=self.provider_id,
                ioc_type=ioc_type,
                indicator=indicator,
                status=TIStatus.PROVIDER_UNAVAILABLE,
                error=f"HTTP {response.status_code}",
            )
        if response.status_code != 200:
            return TIResult(
                provider_id=self.provider_id,
                ioc_type=ioc_type,
                indicator=indicator,
                status=TIStatus.ERROR,
                error=f"HTTP {response.status_code}",
            )
        try:
            payload = response.json()
        except ValueError:
            return TIResult(
                provider_id=self.provider_id,
                ioc_type=ioc_type,
                indicator=indicator,
                status=TIStatus.ERROR,
                error="invalid JSON",
            )
        self._last_error = None
        return normalize_response(payload, ioc_type, indicator)


# ---------------------------------------------------------------------------------------------
# Mock mode: deterministic, offline, no API key. Used for development, CI and demos (ТЗ 42.2).
# ---------------------------------------------------------------------------------------------
_MOCK_BAD_MARKERS = ("malware-test", "known-bad", "phish-test", "evil", "eicar")
_MOCK_SUSPICIOUS_MARKERS = ("suspicious-test", "lookalike", "newly-registered")


@dataclass
class MockVirusTotalProvider:
    """Offline stand-in with the same contract; never performs network access."""

    provider_id: str = PROVIDER_ID
    latency_ms: int = 0
    fail_rate: float = 0.0
    forced_status: TIStatus | None = None
    _rng: random.Random = field(default_factory=lambda: random.Random(20260927))

    def health(self) -> ProviderHealth:
        return ProviderHealth(provider_id=self.provider_id, status="ok", mode="mock")

    def quota(self) -> QuotaInfo:
        return QuotaInfo(provider_id=self.provider_id, per_minute_limit=None, per_day_limit=None)

    def _maybe_fail(self, ioc_type: IOCType, indicator: str) -> TIResult | None:
        # Deterministic pseudo-randomness for outage simulation only, never security.
        if self.fail_rate > 0 and self._rng.random() < self.fail_rate:  # nosec
            return TIResult(
                provider_id=self.provider_id,
                ioc_type=ioc_type,
                indicator=indicator,
                status=TIStatus.PROVIDER_UNAVAILABLE,
                error="simulated outage",
            )
        return None

    def _lookup(self, ioc_type: IOCType, indicator: str) -> TIResult:
        if self.latency_ms:
            time.sleep(self.latency_ms / 1000)
        failure = self._maybe_fail(ioc_type, indicator)
        if failure is not None:
            return failure
        if self.forced_status is not None:
            return TIResult(
                provider_id=self.provider_id,
                ioc_type=ioc_type,
                indicator=indicator,
                status=self.forced_status,
            )
        return mock_result(ioc_type, indicator)

    def lookup_file_hash(self, sha256: str) -> TIResult:
        return self._lookup(IOCType.SHA256, sha256)

    def lookup_domain(self, domain: str) -> TIResult:
        return self._lookup(IOCType.DOMAIN, domain)

    def lookup_url(self, url: str) -> TIResult:
        return self._lookup(IOCType.URL, url)

    def lookup_ip(self, ip: str) -> TIResult:
        return self._lookup(IOCType.IPV6 if ":" in ip else IOCType.IPV4, ip)

    def submit_file(self, *_args: object, **_kwargs: object) -> TIResult:
        raise PermissionError("file upload is disabled in mock mode")


def mock_result(ioc_type: IOCType, indicator: str) -> TIResult:
    """Deterministic verdict derived from the indicator itself, for tests and fixtures."""
    lowered = indicator.lower()
    if any(marker in lowered for marker in _MOCK_BAD_MARKERS):
        return TIResult(
            provider_id=PROVIDER_ID,
            ioc_type=ioc_type,
            indicator=indicator,
            status=TIStatus.KNOWN_BAD,
            malicious_count=42,
            total_count=70,
            categories=["phishing" if ioc_type is not IOCType.SHA256 else "trojan"],
            summary={"mode": "mock", "stats": {"malicious": 42, "harmless": 0, "undetected": 28}},
        )
    if any(marker in lowered for marker in _MOCK_SUSPICIOUS_MARKERS):
        return TIResult(
            provider_id=PROVIDER_ID,
            ioc_type=ioc_type,
            indicator=indicator,
            status=TIStatus.SUSPICIOUS,
            malicious_count=1,
            suspicious_count=3,
            total_count=70,
            summary={"mode": "mock", "recently_registered": True, "domain_age_days": 5},
        )
    return TIResult(
        provider_id=PROVIDER_ID,
        ioc_type=ioc_type,
        indicator=indicator,
        status=TIStatus.NO_NEGATIVE_REPUTATION,
        malicious_count=0,
        total_count=70,
        summary={"mode": "mock", "stats": {"malicious": 0, "harmless": 65, "undetected": 5}},
    )


def build_provider(config: VirusTotalConfig) -> VirusTotalProvider | MockVirusTotalProvider:
    if config.mode is VTMode.MOCK:
        return MockVirusTotalProvider()
    return VirusTotalProvider(config)
