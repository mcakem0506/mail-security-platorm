"""Threat Intelligence Hub: the only path between analysers and external services (ТЗ 13).

Guarantees:
* every lookup passes the privacy gate before leaving the perimeter;
* the cache is consulted first, so repeated indicators cost nothing externally;
* one slow or broken provider cannot block the others or the analysis (per-provider timeout,
  circuit breaker and rate limiting);
* provider failure is reported as a status, never silently converted into a clean result.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from datetime import timedelta

from msp_contracts import (
    TI_FAILURE_STATUSES,
    IOCType,
    Indicator,
    ProviderHealth,
    TIResult,
    TIStatus,
    utcnow,
)

from .base import PrivacyPolicy, ThreatIntelligenceProvider, policy_blocked, unsupported
from .cache import TICache

logger = logging.getLogger(__name__)

_LOOKUP_BY_TYPE = {
    IOCType.SHA256: "lookup_file_hash",
    IOCType.DOMAIN: "lookup_domain",
    IOCType.URL: "lookup_url",
    IOCType.IPV4: "lookup_ip",
    IOCType.IPV6: "lookup_ip",
}


@dataclass
class CircuitBreaker:
    """Stops calling a provider that keeps failing, and probes it again later."""

    failure_threshold: int = 5
    reset_after: timedelta = timedelta(minutes=5)
    _failures: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _opened_at: dict[str, float] = field(default_factory=dict)

    def is_open(self, provider_id: str) -> bool:
        opened = self._opened_at.get(provider_id)
        if opened is None:
            return False
        if time.monotonic() - opened >= self.reset_after.total_seconds():
            # half-open: allow one probe
            del self._opened_at[provider_id]
            self._failures[provider_id] = self.failure_threshold - 1
            return False
        return True

    def record_success(self, provider_id: str) -> None:
        self._failures[provider_id] = 0
        self._opened_at.pop(provider_id, None)

    def record_failure(self, provider_id: str) -> None:
        self._failures[provider_id] += 1
        if self._failures[provider_id] >= self.failure_threshold:
            self._opened_at.setdefault(provider_id, time.monotonic())

    def state(self, provider_id: str) -> str:
        return "open" if self.is_open(provider_id) else "closed"


@dataclass
class HubStats:
    requested: int = 0
    served_from_cache: int = 0
    external_calls: int = 0
    policy_blocked: int = 0
    failures: int = 0
    timeouts: int = 0
    circuit_open: int = 0


class ThreatIntelligenceHub:
    def __init__(
        self,
        providers: list[ThreatIntelligenceProvider] | None = None,
        *,
        policy: PrivacyPolicy | None = None,
        cache: TICache | None = None,
        timeout_seconds: float = 6.0,
        max_workers: int = 8,
        max_indicators_per_type: int = 25,
        breaker: CircuitBreaker | None = None,
    ) -> None:
        self.providers = list(providers or [])
        self.policy = policy or PrivacyPolicy()
        self.cache = cache or TICache()
        self.timeout_seconds = timeout_seconds
        self.max_workers = max_workers
        self.max_indicators_per_type = max_indicators_per_type
        self.breaker = breaker or CircuitBreaker()
        self.stats = HubStats()

    @property
    def configured(self) -> bool:
        return any(p.health().status not in {"disabled", "not_configured"} for p in self.providers)

    def health(self) -> list[ProviderHealth]:
        out: list[ProviderHealth] = []
        for p in self.providers:
            try:
                health = p.health()
            except Exception as exc:  # noqa: BLE001 - health must never raise upward
                health = ProviderHealth(provider_id=p.provider_id, status="unavailable", detail=str(exc)[:200])
            if self.breaker.is_open(p.provider_id):
                health = ProviderHealth(
                    provider_id=p.provider_id,
                    status="degraded",
                    mode=health.mode,
                    detail="circuit breaker open after repeated failures",
                )
            out.append(health)
        return out

    # ---- single lookup ----------------------------------------------------------------------
    def lookup(
        self, provider: ThreatIntelligenceProvider, ioc_type: IOCType, indicator: str
    ) -> TIResult:
        self.stats.requested += 1
        method_name = _LOOKUP_BY_TYPE.get(ioc_type)
        if method_name is None or not hasattr(provider, method_name):
            return unsupported(provider.provider_id, ioc_type, indicator)

        allowed, reason = self.policy.check(ioc_type, indicator)
        if not allowed:
            self.stats.policy_blocked += 1
            logger.info(
                "ti.policy_blocked",
                extra={"provider": provider.provider_id, "ioc_type": ioc_type.value, "reason": reason},
            )
            return policy_blocked(provider.provider_id, ioc_type, indicator, reason)

        value = self.policy.sanitize_url(indicator) if ioc_type is IOCType.URL else indicator
        cached = self.cache.get(provider.provider_id, ioc_type, value)
        if cached is not None:
            self.stats.served_from_cache += 1
            return cached

        if self.breaker.is_open(provider.provider_id):
            self.stats.circuit_open += 1
            return TIResult(
                provider_id=provider.provider_id,
                ioc_type=ioc_type,
                indicator=value,
                status=TIStatus.PROVIDER_UNAVAILABLE,
                error="circuit breaker open",
            )

        started = time.monotonic()
        try:
            self.stats.external_calls += 1
            result: TIResult = getattr(provider, method_name)(value)
        except Exception as exc:  # noqa: BLE001 - a provider must never break analysis
            self.stats.failures += 1
            self.breaker.record_failure(provider.provider_id)
            logger.warning(
                "ti.provider_error",
                extra={"provider": provider.provider_id, "error": type(exc).__name__},
            )
            return TIResult(
                provider_id=provider.provider_id,
                ioc_type=ioc_type,
                indicator=value,
                status=TIStatus.ERROR,
                error=f"{type(exc).__name__}",
                latency_ms=int((time.monotonic() - started) * 1000),
            )
        result.latency_ms = int((time.monotonic() - started) * 1000)
        if result.status in TI_FAILURE_STATUSES:
            self.stats.failures += 1
            self.breaker.record_failure(provider.provider_id)
        else:
            self.breaker.record_success(provider.provider_id)
        self.cache.put(result)
        return result

    # ---- bulk enrichment --------------------------------------------------------------------
    def enrich(self, indicators: list[Indicator]) -> list[TIResult]:
        """Look up all indicators across all providers in parallel, bounded by a timeout.

        A provider that does not answer in time yields PROVIDER_UNAVAILABLE for its pending
        indicators; results already collected are kept.
        """
        active = [p for p in self.providers if p.health().status not in {"disabled", "not_configured"}]
        if not active or not indicators:
            return []

        selected = self._select(indicators)
        tasks: list[tuple[ThreatIntelligenceProvider, Indicator]] = [
            (p, ind) for p in active for ind in selected
        ]
        if not tasks:
            return []

        results: list[TIResult] = []
        deadline = time.monotonic() + self.timeout_seconds * 2
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(tasks))) as pool:
            futures = {
                pool.submit(self.lookup, provider, ind.ioc_type, ind.value): (provider, ind)
                for provider, ind in tasks
            }
            for future, (provider, ind) in futures.items():
                remaining = max(0.05, deadline - time.monotonic())
                try:
                    results.append(future.result(timeout=remaining))
                except FuturesTimeout:
                    self.stats.timeouts += 1
                    future.cancel()
                    self.breaker.record_failure(provider.provider_id)
                    results.append(
                        TIResult(
                            provider_id=provider.provider_id,
                            ioc_type=ind.ioc_type,
                            indicator=ind.value,
                            status=TIStatus.PROVIDER_UNAVAILABLE,
                            error="timeout",
                        )
                    )
                except Exception as exc:  # noqa: BLE001
                    self.stats.failures += 1
                    results.append(
                        TIResult(
                            provider_id=provider.provider_id,
                            ioc_type=ind.ioc_type,
                            indicator=ind.value,
                            status=TIStatus.ERROR,
                            error=type(exc).__name__,
                        )
                    )
        return results

    def _select(self, indicators: list[Indicator]) -> list[Indicator]:
        """Cap indicators per type so one message cannot exhaust provider quota."""
        by_type: dict[IOCType, list[Indicator]] = defaultdict(list)
        for ind in indicators:
            if ind.ioc_type in _LOOKUP_BY_TYPE:
                by_type[ind.ioc_type].append(ind)
        out: list[Indicator] = []
        for ioc_type, items in by_type.items():
            seen: set[str] = set()
            unique = [i for i in items if not (i.value in seen or seen.add(i.value))]
            out.extend(unique[: self.max_indicators_per_type])
        return out

    def recheck_candidates(self, results: list[TIResult], max_age_hours: int = 24) -> list[TIResult]:
        return [r for r in results if TICache.is_recheck_due(r, max_age_hours)]

    def summary(self) -> dict[str, object]:
        return {
            "configured": self.configured,
            "providers": [
                {"provider_id": h.provider_id, "status": h.status, "mode": h.mode, "detail": h.detail}
                for h in self.health()
            ],
            "stats": vars(self.stats),
            "checked_at": utcnow().isoformat(),
        }
