"""FastAPI dependencies: current actor, permissions, CSRF, rate limiting, providers."""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from msp_contracts import Role, VTMode
from msp_scanner import ClamAVScannerProvider, MalwareScannerProvider, MockScannerProvider
from msp_ti import PrivacyPolicy, RedisCacheBackend, ThreatIntelligenceHub, TICache
from msp_virustotal import VirusTotalConfig, build_provider
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .db.session import get_session
from .security.auth import (
    MemorySessionStore,
    RedisSessionStore,
    SessionData,
    SessionManager,
    verify_csrf,
)
from .security.rbac import Permission, has_permission

logger = logging.getLogger(__name__)

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@lru_cache(maxsize=1)
def _redis_client():  # type: ignore[no-untyped-def]
    settings = get_settings()
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=3)
        client.ping()
        return client
    except Exception as exc:  # noqa: BLE001 - fall back to in-process state
        logger.warning("redis.unavailable", extra={"error": type(exc).__name__})
        return None


@lru_cache(maxsize=1)
def get_session_manager() -> SessionManager:
    settings = get_settings()
    client = _redis_client()
    store = RedisSessionStore(client) if client is not None else MemorySessionStore()
    return SessionManager(
        store,
        settings.secret_key,
        ttl_minutes=settings.session_ttl_minutes,
        privileged_ttl_minutes=settings.privileged_session_ttl_minutes,
        idle_minutes=settings.session_idle_minutes,
    )


@lru_cache(maxsize=1)
def get_ti_hub() -> ThreatIntelligenceHub:
    settings = get_settings()
    providers = []
    if settings.vt_mode != "disabled":
        providers.append(
            build_provider(
                VirusTotalConfig(
                    mode=VTMode(settings.vt_mode),
                    api_key=settings.vt_api_key or None,
                    timeout_seconds=settings.vt_timeout_seconds,
                    per_minute_limit=settings.vt_per_minute_limit,
                    per_day_limit=settings.vt_per_day_limit,
                    allow_file_upload=settings.vt_allow_file_upload,
                )
            )
        )
    client = _redis_client()
    cache = TICache(RedisCacheBackend(client)) if client is not None else TICache()
    return ThreatIntelligenceHub(
        providers,
        policy=PrivacyPolicy(
            allow_hash=settings.ti_allow_hash,
            allow_domain=settings.ti_allow_domain,
            allow_ip=settings.ti_allow_ip,
            allow_url=settings.ti_allow_url,
            allow_url_path=settings.ti_allow_url_path,
            allow_sender_email=settings.ti_allow_sender_email,
            allow_internal_domains=settings.ti_allow_internal_domains,
            corporate_domains=settings.corporate_domain_list,
        ),
        cache=cache,
        timeout_seconds=settings.ti_timeout_seconds,
    )


@lru_cache(maxsize=1)
def get_scanner() -> MalwareScannerProvider:
    settings = get_settings()
    if settings.clamav_enabled:
        return ClamAVScannerProvider(
            host=settings.clamav_host,
            port=settings.clamav_port,
            unix_socket=settings.clamav_unix_socket,
            max_size=settings.clamav_max_size,
        )
    return MockScannerProvider()


def reset_provider_cache() -> None:
    """Drop cached providers so configuration changes take effect (and tests stay isolated)."""
    for factory in (get_ti_hub, get_scanner, get_session_manager, _redis_client):
        clear = getattr(factory, "cache_clear", None)
        if clear is not None:  # a test may have substituted a plain function
            clear()


# ---------------------------------------------------------------------------------------------
# Rate limiting (ТЗ 30)
# ---------------------------------------------------------------------------------------------
class SlidingWindowLimiter:
    """Per-key sliding window. Backed by Redis when available, in-process otherwise."""

    def __init__(self) -> None:
        self._local: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str, limit: int, window_seconds: int = 60) -> tuple[bool, int]:
        client = _redis_client()
        now = time.time()
        if client is not None:
            redis_key = f"msp:rl:{key}"
            try:
                pipe = client.pipeline()
                pipe.zremrangebyscore(redis_key, 0, now - window_seconds)
                pipe.zadd(redis_key, {f"{now}:{id(self)}": now})
                pipe.zcard(redis_key)
                pipe.expire(redis_key, window_seconds)
                count = int(pipe.execute()[2])
                return count <= limit, max(0, limit - count)
            except Exception as exc:  # noqa: BLE001 - never fail a request on limiter problems
                logger.warning("ratelimit.redis_error", extra={"error": type(exc).__name__})
        bucket = self._local[key]
        while bucket and bucket[0] < now - window_seconds:
            bucket.popleft()
        bucket.append(now)
        return len(bucket) <= limit, max(0, limit - len(bucket))


_limiter = SlidingWindowLimiter()


def reset_rate_limiter() -> None:
    """Clear in-process rate-limit state (used by tests and after a configuration reload)."""
    _limiter._local.clear()


def rate_limit(key: str, limit: int, window_seconds: int = 60) -> None:
    allowed, remaining = _limiter.check(key, limit, window_seconds)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Превышен лимит запросов. Повторите попытку позже.",
            headers={"Retry-After": str(window_seconds)},
        )


def client_ip(request: Request) -> str:
    # X-Forwarded-For is only trusted because nginx sets it; see infrastructure/nginx.
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else ""


# ---------------------------------------------------------------------------------------------
# Actor
# ---------------------------------------------------------------------------------------------
@dataclass
class Actor:
    session: SessionData

    @property
    def user_id(self) -> str:
        return self.session.user_id

    @property
    def email(self) -> str:
        return self.session.email

    @property
    def role(self) -> Role:
        return self.session.role

    @property
    def organization_id(self) -> str:
        return self.session.organization_id

    def can(self, permission: Permission) -> bool:
        return has_permission(self.role, permission)


def get_current_actor(
    request: Request, manager: Annotated[SessionManager, Depends(get_session_manager)]
) -> Actor:
    cookie = request.cookies.get(get_settings().cookie_name)
    session = manager.load(cookie)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Требуется аутентификация"
        )
    if request.method not in SAFE_METHODS:
        token = request.headers.get("x-csrf-token") or request.cookies.get(
            get_settings().csrf_cookie_name
        )
        if not verify_csrf(session, token):
            logger.warning("auth.csrf_failed", extra={"actor": session.email})
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="CSRF-токен недействителен"
            )
    manager.touch(session)
    request.state.actor_email = session.email
    request.state.actor_role = session.role.value
    return Actor(session=session)


def require_permission(permission: Permission):  # type: ignore[no-untyped-def]
    """Dependency factory enforcing a single permission."""

    def dependency(actor: Annotated[Actor, Depends(get_current_actor)]) -> Actor:
        if not actor.can(permission):
            logger.warning(
                "authz.denied", extra={"actor": actor.email, "permission": permission.value}
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Недостаточно прав для этой операции"
            )
        return actor

    return dependency


CurrentActor = Annotated[Actor, Depends(get_current_actor)]
DbSession = Annotated[Session, Depends(get_session)]
AppSettings = Annotated[Settings, Depends(get_settings)]
