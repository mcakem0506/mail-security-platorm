"""Threat Intelligence cache with verdict-aware TTL (ТЗ 13.4).

TTL depends on IOC type, verdict and data age. Malicious verdicts are cached longer but stay
re-checkable: every entry records when it was fetched and when it becomes stale, so the
maintenance worker can refresh them without waiting for a lookup to miss.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from msp_contracts import IOCType, TIResult, TIStatus, utcnow

# (status, ioc_type) -> TTL. Failure statuses use a short negative TTL so an outage does not
# freeze results, and are never cached as an answer about the indicator itself.
_TTL_SECONDS: dict[TIStatus, int] = {
    TIStatus.KNOWN_BAD: 7 * 24 * 3600,
    TIStatus.SUSPICIOUS: 24 * 3600,
    TIStatus.NO_NEGATIVE_REPUTATION: 12 * 3600,
    TIStatus.UNKNOWN: 6 * 3600,
    TIStatus.NOT_SUPPORTED: 30 * 24 * 3600,
    TIStatus.POLICY_BLOCKED: 3600,
    TIStatus.RATE_LIMITED: 300,
    TIStatus.PROVIDER_UNAVAILABLE: 120,
    TIStatus.ERROR: 120,
}
_TYPE_FACTOR: dict[IOCType, float] = {
    IOCType.SHA256: 4.0,  # file content never changes
    IOCType.DOMAIN: 1.0,
    IOCType.URL: 0.75,  # URLs are rotated quickly by attackers
    IOCType.IPV4: 0.75,
    IOCType.IPV6: 0.75,
    IOCType.EMAIL: 1.0,
    IOCType.CERT_FINGERPRINT: 4.0,
}
_MIN_TTL = 60
_MAX_TTL = 30 * 24 * 3600


def ttl_for(result: TIResult) -> int:
    base = _TTL_SECONDS.get(result.status, 3600)
    ttl = int(base * _TYPE_FACTOR.get(result.ioc_type, 1.0))
    # Fresh intelligence about a young indicator ages faster than long-established data.
    if result.status is TIStatus.KNOWN_BAD and result.first_seen is not None:
        age_days = (utcnow() - result.first_seen).days
        if age_days < 7:
            ttl = min(ttl, 24 * 3600)
    return max(_MIN_TTL, min(ttl, _MAX_TTL))


def cache_key(provider_id: str, ioc_type: IOCType, indicator: str) -> str:
    return f"msp:ti:{provider_id}:{ioc_type.value}:{indicator.lower()}"


class CacheBackend(Protocol):
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str, ttl_seconds: int) -> None: ...
    def delete(self, key: str) -> None: ...


@dataclass
class MemoryCacheBackend:
    """In-process backend for tests and single-process runs."""

    _data: dict[str, tuple[str, datetime]] | None = None

    def __post_init__(self) -> None:
        self._data = {}

    def get(self, key: str) -> str | None:
        assert self._data is not None
        item = self._data.get(key)
        if item is None:
            return None
        value, expires = item
        if utcnow() >= expires:
            del self._data[key]
            return None
        return value

    def set(self, key: str, value: str, ttl_seconds: int) -> None:
        assert self._data is not None
        self._data[key] = (value, utcnow() + timedelta(seconds=ttl_seconds))

    def delete(self, key: str) -> None:
        assert self._data is not None
        self._data.pop(key, None)


class RedisCacheBackend:
    """Redis backend. Redis is a cache only — never authoritative storage (ТЗ 32)."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def get(self, key: str) -> str | None:
        value = self._client.get(key)
        if value is None:
            return None
        return value.decode("utf-8") if isinstance(value, bytes) else str(value)

    def set(self, key: str, value: str, ttl_seconds: int) -> None:
        self._client.set(key, value, ex=ttl_seconds)

    def delete(self, key: str) -> None:
        self._client.delete(key)


class TICache:
    def __init__(self, backend: CacheBackend | None = None) -> None:
        self.backend = backend or MemoryCacheBackend()

    def get(self, provider_id: str, ioc_type: IOCType, indicator: str) -> TIResult | None:
        raw = self.backend.get(cache_key(provider_id, ioc_type, indicator))
        if raw is None:
            return None
        try:
            payload = json.loads(raw)
        except (ValueError, TypeError):
            return None
        try:
            result = TIResult.model_validate(payload)
        except Exception:  # noqa: BLE001 - a corrupt cache entry must not break analysis
            return None
        result.from_cache = True
        return result

    def put(self, result: TIResult) -> int:
        """Store a result; returns the TTL used. Transient failures are cached only briefly."""
        ttl = ttl_for(result)
        self.backend.set(
            cache_key(result.provider_id, result.ioc_type, result.indicator),
            result.model_dump_json(),
            ttl,
        )
        return ttl

    def invalidate(self, provider_id: str, ioc_type: IOCType, indicator: str) -> None:
        self.backend.delete(cache_key(provider_id, ioc_type, indicator))

    @staticmethod
    def is_recheck_due(result: TIResult, max_age_hours: int = 24) -> bool:
        """Whether a stored malicious verdict should be re-checked (ТЗ 13.4)."""
        if result.status is not TIStatus.KNOWN_BAD:
            return False
        fetched = result.fetched_at
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=UTC)
        return utcnow() - fetched > timedelta(hours=max_age_hours)


def age_seconds(result: TIResult) -> int:
    fetched = result.fetched_at
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=UTC)
    return max(0, int((utcnow() - fetched).total_seconds()))


def cache_age_label(result: TIResult) -> str:
    """Human-readable cache age for the Threat Intelligence view (ТЗ 22.4)."""
    seconds = age_seconds(result)
    if seconds < 60:
        return "только что"
    if seconds < 3600:
        return f"{seconds // 60} мин назад"
    if seconds < 86400:
        return f"{seconds // 3600} ч назад"
    return f"{seconds // 86400} дн назад"
