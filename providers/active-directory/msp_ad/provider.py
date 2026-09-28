"""Active Directory integration — read-only (ТЗ 10, 49.8).

Only the attributes needed for identity protection are synchronised; no write operations exist
in this module at all, so a misconfiguration cannot lead to directory changes. Attributes that
are not required for detection (phone, address, photo, manager chain by default) are not read.
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from msp_contracts import ProviderHealth, utcnow

logger = logging.getLogger(__name__)

# Minimal attribute set (ТЗ 10). Extending this list is a privacy decision, not a technical one.
MINIMAL_ATTRIBUTES: tuple[str, ...] = (
    "objectGUID",
    "displayName",
    "mail",
    "proxyAddresses",
    "department",
    "userAccountControl",
)
OPTIONAL_ATTRIBUTES: tuple[str, ...] = ("title", "manager")

_UAC_ACCOUNTDISABLE = 0x0002


@dataclass
class DirectoryEntry:
    object_id: str
    display_name: str
    mail: str
    aliases: tuple[str, ...] = ()
    department: str = ""
    title: str = ""
    manager_dn: str = ""
    enabled: bool = True
    deleted: bool = False


@dataclass
class SyncResult:
    entries: list[DirectoryEntry] = field(default_factory=list)
    created: int = 0
    updated: int = 0
    disabled: int = 0
    deleted: int = 0
    errors: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None
    incremental: bool = False
    high_watermark: str | None = None  # uSNChanged / cookie for the next incremental run


@runtime_checkable
class DirectoryProvider(Protocol):
    provider_id: str

    def health(self) -> ProviderHealth: ...
    def sync(self, since: str | None = None) -> SyncResult: ...


@dataclass
class ActiveDirectoryConfig:
    server: str = ""
    port: int = 636
    use_ssl: bool = True
    bind_dn: str = ""
    bind_password: str = ""  # from the secret store only (ТЗ 28)
    base_dn: str = ""
    user_filter: str = "(&(objectCategory=person)(objectClass=user)(mail=*))"
    include_optional_attributes: bool = False
    page_size: int = 500
    timeout_seconds: float = 30.0
    ca_file: str | None = None
    verify_tls: bool = True


def _aliases_from_proxy(values: Any) -> tuple[str, ...]:
    out: list[str] = []
    for raw in values or ():
        text = str(raw)
        if ":" in text:
            scheme, _, address = text.partition(":")
            if scheme.lower() == "smtp" and "@" in address:
                out.append(address.lower())
        elif "@" in text:
            out.append(text.lower())
    return tuple(dict.fromkeys(out))


class ActiveDirectoryProvider:
    """LDAP read-only directory sync. Contains no modify/add/delete operations by design."""

    provider_id = "active_directory"

    def __init__(self, config: ActiveDirectoryConfig) -> None:
        self.config = config

    def _connect(self) -> Any:
        import ssl as ssl_module

        from ldap3 import ALL, Connection, Server, Tls

        cfg = self.config
        tls = None
        if cfg.use_ssl:
            tls = Tls(
                ca_certs_file=cfg.ca_file,
                validate=ssl_module.CERT_REQUIRED if cfg.verify_tls else ssl_module.CERT_NONE,
            )
        server = Server(
            cfg.server,
            port=cfg.port,
            use_ssl=cfg.use_ssl,
            tls=tls,
            get_info=ALL,
            connect_timeout=cfg.timeout_seconds,
        )
        return Connection(
            server,
            user=cfg.bind_dn,
            password=cfg.bind_password,
            auto_bind=True,
            read_only=True,  # hard guarantee: the connection itself rejects writes
            receive_timeout=cfg.timeout_seconds,
        )

    def health(self) -> ProviderHealth:
        if not self.config.server or not self.config.base_dn:
            return ProviderHealth(
                provider_id=self.provider_id,
                status="not_configured",
                detail="Active Directory not configured; protected identities are managed manually",
            )
        try:
            conn = self._connect()
            try:
                ok = bool(conn.bound)
            finally:
                conn.unbind()
            return ProviderHealth(
                provider_id=self.provider_id,
                status="ok" if ok else "degraded",
                mode="ldaps" if self.config.use_ssl else "ldap",
            )
        except Exception as exc:  # noqa: BLE001 - ldap3 raises a wide range of errors
            return ProviderHealth(
                provider_id=self.provider_id,
                status="unavailable",
                detail=type(exc).__name__,
                checked_at=utcnow(),
            )

    def sync(self, since: str | None = None) -> SyncResult:
        """Full or incremental (uSNChanged-based) sync of the minimal attribute set."""
        result = SyncResult(incremental=since is not None)
        if not self.config.server or not self.config.base_dn:
            result.errors.append("Active Directory not configured")
            result.finished_at = utcnow()
            return result

        attributes = list(MINIMAL_ATTRIBUTES)
        if self.config.include_optional_attributes:
            attributes.extend(OPTIONAL_ATTRIBUTES)
        search_filter = self.config.user_filter
        if since:
            search_filter = f"(&{search_filter}(uSNChanged>={since}))"

        high_watermark = int(since or 0)
        try:
            conn = self._connect()
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"bind failed: {type(exc).__name__}")
            result.finished_at = utcnow()
            return result
        try:
            entries = conn.extend.standard.paged_search(
                search_base=self.config.base_dn,
                search_filter=search_filter,
                attributes=[*attributes, "uSNChanged"],
                paged_size=self.config.page_size,
                generator=True,
            )
            for raw in entries:
                if raw.get("type") != "searchResEntry":
                    continue
                attrs = raw.get("attributes", {})
                mail = str(attrs.get("mail") or "").lower()
                if not mail:
                    continue
                uac = attrs.get("userAccountControl")
                enabled = True
                if isinstance(uac, int):
                    enabled = not bool(uac & _UAC_ACCOUNTDISABLE)
                usn = attrs.get("uSNChanged")
                if isinstance(usn, int):
                    high_watermark = max(high_watermark, usn)
                object_id = attrs.get("objectGUID")
                result.entries.append(
                    DirectoryEntry(
                        object_id=str(object_id or mail),
                        display_name=str(attrs.get("displayName") or "").strip(),
                        mail=mail,
                        aliases=tuple(
                            a for a in _aliases_from_proxy(attrs.get("proxyAddresses")) if a != mail
                        ),
                        department=str(attrs.get("department") or "").strip(),
                        title=str(attrs.get("title") or "").strip(),
                        manager_dn=str(attrs.get("manager") or "").strip(),
                        enabled=enabled,
                    )
                )
                if not enabled:
                    result.disabled += 1
        except Exception as exc:  # noqa: BLE001 - a directory outage must not break the platform
            result.errors.append(f"search failed: {type(exc).__name__}")
        finally:
            with contextlib.suppress(Exception):  # an unbind failure must not mask the result
                conn.unbind()
        result.high_watermark = str(high_watermark) if high_watermark else None
        result.finished_at = utcnow()
        return result


@dataclass
class MockDirectoryProvider:
    """Fixture-backed directory for development, CI and the pilot before AD is connected."""

    provider_id: str = "mock_directory"
    entries: list[DirectoryEntry] = field(default_factory=list)

    def health(self) -> ProviderHealth:
        return ProviderHealth(provider_id=self.provider_id, status="ok", mode="mock")

    def sync(self, since: str | None = None) -> SyncResult:
        return SyncResult(
            entries=list(self.entries),
            created=len(self.entries),
            disabled=sum(1 for e in self.entries if not e.enabled),
            finished_at=utcnow(),
            incremental=since is not None,
            high_watermark="mock",
        )
