"""Authentication: password hashing, sessions, CSRF and lockout (ТЗ 24).

Sessions are signed, short-lived tokens stored server-side in Redis (or in memory for the fast
test suite) so they can be revoked. The cookie is HttpOnly + SameSite=Strict + Secure, and every
state-changing request must carry a matching CSRF token (double-submit with a constant-time
comparison).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from argon2 import PasswordHasher
from argon2.exceptions import HashingError, InvalidHashError, VerificationError, VerifyMismatchError
from msp_contracts import Role

logger = logging.getLogger(__name__)

# Argon2id parameters: OWASP-recommended baseline for interactive logins.
_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2, hash_len=32, salt_len=16)

PRIVILEGED_ROLES = frozenset({Role.SECURITY_ADMIN, Role.PLATFORM_ADMIN})
SESSION_TOKEN_BYTES = 32
MIN_PASSWORD_LENGTH = 12


class AuthError(Exception):
    """Raised for any authentication failure; the message is safe to log, not to expose."""


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    try:
        return _hasher.hash(password)
    except HashingError as exc:  # pragma: no cover - argon2 internal failure
        raise AuthError("password hashing failed") from exc


def verify_password(password: str, stored_hash: str | None) -> bool:
    if not stored_hash:
        # Constant-ish work even without a hash, so timing does not reveal unknown accounts.
        _hasher.hash(secrets.token_urlsafe(16))
        return False
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


@dataclass
class SessionData:
    session_id: str
    user_id: str
    email: str
    role: Role
    organization_id: str
    csrf_token: str
    created_at: datetime
    expires_at: datetime
    last_seen_at: datetime
    mfa_verified: bool = False
    ip_address: str = ""
    user_agent: str = ""

    def to_json(self) -> str:
        return json.dumps(
            {
                "session_id": self.session_id,
                "user_id": self.user_id,
                "email": self.email,
                "role": self.role.value,
                "organization_id": self.organization_id,
                "csrf_token": self.csrf_token,
                "created_at": self.created_at.isoformat(),
                "expires_at": self.expires_at.isoformat(),
                "last_seen_at": self.last_seen_at.isoformat(),
                "mfa_verified": self.mfa_verified,
                "ip_address": self.ip_address,
                "user_agent": self.user_agent[:255],
            }
        )

    @classmethod
    def from_json(cls, raw: str) -> SessionData | None:
        try:
            data: dict[str, Any] = json.loads(raw)
            return cls(
                session_id=data["session_id"],
                user_id=data["user_id"],
                email=data["email"],
                role=Role(data["role"]),
                organization_id=data["organization_id"],
                csrf_token=data["csrf_token"],
                created_at=datetime.fromisoformat(data["created_at"]),
                expires_at=datetime.fromisoformat(data["expires_at"]),
                last_seen_at=datetime.fromisoformat(data["last_seen_at"]),
                mfa_verified=bool(data.get("mfa_verified", False)),
                ip_address=data.get("ip_address", ""),
                user_agent=data.get("user_agent", ""),
            )
        except (ValueError, KeyError, TypeError):
            return None

    @property
    def expired(self) -> bool:
        return datetime.now(UTC) >= self.expires_at

    def idle_expired(self, idle_minutes: int) -> bool:
        return datetime.now(UTC) - self.last_seen_at > timedelta(minutes=idle_minutes)


class SessionStore(Protocol):
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str, ttl_seconds: int) -> None: ...
    def delete(self, key: str) -> None: ...
    def scan_user(self, user_id: str) -> list[str]: ...


class MemorySessionStore:
    def __init__(self) -> None:
        self._data: dict[str, tuple[str, datetime]] = {}

    def get(self, key: str) -> str | None:
        item = self._data.get(key)
        if item is None:
            return None
        value, expires = item
        if datetime.now(UTC) >= expires:
            del self._data[key]
            return None
        return value

    def set(self, key: str, value: str, ttl_seconds: int) -> None:
        self._data[key] = (value, datetime.now(UTC) + timedelta(seconds=ttl_seconds))

    def delete(self, key: str) -> None:
        self._data.pop(key, None)

    def scan_user(self, user_id: str) -> list[str]:
        out = []
        for key, (value, _) in list(self._data.items()):
            session = SessionData.from_json(value)
            if session is not None and session.user_id == user_id:
                out.append(key)
        return out


class RedisSessionStore:
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

    def scan_user(self, user_id: str) -> list[str]:
        out: list[str] = []
        for key in self._client.scan_iter(match="msp:session:*", count=500):
            key_str = key.decode("utf-8") if isinstance(key, bytes) else str(key)
            raw = self.get(key_str)
            if raw is None:
                continue
            session = SessionData.from_json(raw)
            if session is not None and session.user_id == user_id:
                out.append(key_str)
        return out


def _session_key(session_id: str) -> str:
    return f"msp:session:{session_id}"


class SessionManager:
    def __init__(
        self,
        store: SessionStore,
        secret_key: str,
        *,
        ttl_minutes: int = 60,
        privileged_ttl_minutes: int = 30,
        idle_minutes: int = 20,
    ) -> None:
        self.store = store
        self._secret = secret_key.encode("utf-8")
        self.ttl_minutes = ttl_minutes
        self.privileged_ttl_minutes = privileged_ttl_minutes
        self.idle_minutes = idle_minutes

    def _sign(self, session_id: str) -> str:
        digest = hmac.new(self._secret, session_id.encode("ascii"), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def issue_cookie_value(self, session_id: str) -> str:
        return f"{session_id}.{self._sign(session_id)}"

    def parse_cookie_value(self, cookie: str | None) -> str | None:
        """Verify the HMAC before touching the store, so forged ids never hit Redis."""
        if not cookie or "." not in cookie:
            return None
        session_id, _, signature = cookie.partition(".")
        if not session_id or not signature:
            return None
        if not hmac.compare_digest(signature, self._sign(session_id)):
            logger.warning("auth.session_signature_mismatch")
            return None
        return session_id

    def create(
        self,
        *,
        user_id: str,
        email: str,
        role: Role,
        organization_id: str,
        mfa_verified: bool = False,
        ip_address: str = "",
        user_agent: str = "",
    ) -> SessionData:
        now = datetime.now(UTC)
        ttl = self.privileged_ttl_minutes if role in PRIVILEGED_ROLES else self.ttl_minutes
        session = SessionData(
            session_id=secrets.token_urlsafe(SESSION_TOKEN_BYTES),
            user_id=user_id,
            email=email,
            role=role,
            organization_id=organization_id,
            csrf_token=secrets.token_urlsafe(32),
            created_at=now,
            expires_at=now + timedelta(minutes=ttl),
            last_seen_at=now,
            mfa_verified=mfa_verified,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self.store.set(_session_key(session.session_id), session.to_json(), ttl * 60)
        return session

    def load(self, cookie: str | None) -> SessionData | None:
        session_id = self.parse_cookie_value(cookie)
        if session_id is None:
            return None
        raw = self.store.get(_session_key(session_id))
        if raw is None:
            return None
        session = SessionData.from_json(raw)
        if session is None or session.expired or session.idle_expired(self.idle_minutes):
            if session is not None:
                self.store.delete(_session_key(session_id))
            return None
        return session

    def touch(self, session: SessionData) -> None:
        session.last_seen_at = datetime.now(UTC)
        remaining = int((session.expires_at - session.last_seen_at).total_seconds())
        if remaining > 0:
            self.store.set(_session_key(session.session_id), session.to_json(), remaining)

    def revoke(self, session_id: str) -> None:
        self.store.delete(_session_key(session_id))

    def revoke_all_for_user(self, user_id: str) -> int:
        keys = self.store.scan_user(user_id)
        for key in keys:
            self.store.delete(key)
        return len(keys)


def verify_csrf(session: SessionData, provided: str | None) -> bool:
    return bool(provided) and hmac.compare_digest(session.csrf_token, provided or "")


@dataclass
class LockoutState:
    locked: bool
    remaining_attempts: int
    locked_until: datetime | None = None


def evaluate_lockout(
    failed_logins: int, locked_until: datetime | None, *, max_attempts: int, lockout_minutes: int
) -> LockoutState:
    now = datetime.now(UTC)
    if locked_until is not None:
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=UTC)
        if locked_until > now:
            return LockoutState(True, 0, locked_until)
    remaining = max(0, max_attempts - failed_logins)
    return LockoutState(False, remaining)


def next_lockout(failed_logins: int, *, max_attempts: int, lockout_minutes: int) -> datetime | None:
    if failed_logins < max_attempts:
        return None
    # Exponential backoff for repeated lockouts, capped at 24h.
    multiplier = min(2 ** max(0, (failed_logins - max_attempts) // max_attempts), 96)
    return datetime.now(UTC) + timedelta(minutes=min(lockout_minutes * multiplier, 24 * 60))
