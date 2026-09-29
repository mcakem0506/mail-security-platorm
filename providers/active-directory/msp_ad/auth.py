"""Active Directory authentication (ТЗ 24: приоритет корпоративного AD/LDAP).

Design notes for a product that must work in *any* organisation, not one fixed lab:

* nothing about the directory layout is assumed — the base DN is discovered from RootDSE when it
  is not configured, and the user is located by a configurable filter;
* the password never leaves this module: authentication is a bind as the user, so the platform
  neither stores nor forwards it;
* roles come from AD group membership through an explicit mapping, so access is managed where the
  organisation already manages it;
* a directory outage must not silently grant access — every failure mode is a denial, never a
  fallback to "allow".

MFA is out of scope here: the organisation states that authentication is AD-bound without MFA.
That is an accepted risk recorded in docs/SECURITY_MODEL.md, not a gap in this module.
"""

from __future__ import annotations

import logging
import re
import ssl
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)

# Attributes needed to authenticate and to decide the role. Deliberately minimal (ТЗ 10).
_AUTH_ATTRIBUTES = ("distinguishedName", "displayName", "mail", "memberOf", "userAccountControl")
_UAC_ACCOUNTDISABLE = 0x0002
_UAC_LOCKOUT = 0x0010
_UAC_PASSWORD_EXPIRED = 0x800000

# LDAP filter metacharacters (RFC 4515). User input is escaped before it reaches a filter.
_FILTER_ESCAPE = {"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\0": r"\00", "/": r"\2f"}


class AuthOutcome(StrEnum):
    SUCCESS = "success"
    INVALID_CREDENTIALS = "invalid_credentials"
    USER_NOT_FOUND = "user_not_found"
    ACCOUNT_DISABLED = "account_disabled"
    ACCOUNT_LOCKED = "account_locked"
    PASSWORD_EXPIRED = "password_expired"  # noqa: S105  # nosec
    NOT_AUTHORIZED = "not_authorized"
    DIRECTORY_UNAVAILABLE = "directory_unavailable"
    MISCONFIGURED = "misconfigured"


def escape_filter_value(value: str) -> str:
    """Escape a value before embedding it in an LDAP filter (prevents filter injection)."""
    return "".join(_FILTER_ESCAPE.get(char, char) for char in value or "")


@dataclass
class AdAuthConfig:
    server: str = ""
    port: int = 636
    use_ssl: bool = True
    start_tls: bool = False
    # Service account used only to find the user before binding as them. Optional: with
    # user_principal_template the platform can bind directly and skip the lookup entirely.
    bind_dn: str = ""
    bind_password: str = ""
    base_dn: str = ""  # discovered from RootDSE when empty
    user_filter: str = (
        "(&(objectCategory=person)(objectClass=user)"
        "(|(mail={login})(userPrincipalName={login})(sAMAccountName={login})))"
    )
    # e.g. "{login}@corp.example" — lets a user bind without a prior lookup.
    user_principal_template: str = ""
    # AD group DN (or CN) -> platform role. Checked in order; the first match wins, so the most
    # privileged group must come first.
    group_role_map: tuple[tuple[str, str], ...] = ()
    default_role: str = "employee"
    # When True, a user with no mapped group is refused instead of getting the default role.
    require_group_match: bool = False
    ca_file: str | None = None
    verify_tls: bool = True
    timeout_seconds: float = 10.0
    nested_groups: bool = True

    def validate(self) -> list[str]:
        """Return configuration problems rather than raising: health must stay reportable."""
        problems: list[str] = []
        if not self.server:
            problems.append("AD server is not configured")
        if not self.bind_dn and not self.user_principal_template:
            problems.append(
                "either a service account (bind_dn) or user_principal_template is required "
                "to locate or bind the user"
            )
        if "{login}" not in self.user_filter and not self.user_principal_template:
            problems.append("user_filter must contain the {login} placeholder")
        if self.use_ssl and not self.verify_tls:
            problems.append("TLS verification is disabled: acceptable only on a lab stand")
        if not self.use_ssl and not self.start_tls:
            problems.append(
                "LDAP without TLS transmits the password in clear text; enable use_ssl or start_tls"
            )
        return problems


@dataclass
class AuthResult:
    outcome: AuthOutcome
    email: str = ""
    display_name: str = ""
    distinguished_name: str = ""
    groups: tuple[str, ...] = ()
    role: str = ""
    detail: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def authenticated(self) -> bool:
        return self.outcome is AuthOutcome.SUCCESS


def _tls_object(config: AdAuthConfig):  # type: ignore[no-untyped-def]
    from ldap3 import Tls

    return Tls(
        ca_certs_file=config.ca_file,
        validate=ssl.CERT_REQUIRED if config.verify_tls else ssl.CERT_NONE,
        version=ssl.PROTOCOL_TLS_CLIENT,
    )


def _group_names(dn: str) -> set[str]:
    """Both the full DN and the bare CN, so a mapping can be written either way."""
    names = {dn.lower()}
    match = re.match(r"(?i)^cn=([^,]+)", dn.strip())
    if match:
        names.add(match.group(1).strip().lower())
    return names


class ActiveDirectoryAuthenticator:
    """Authenticates a user against Active Directory by binding as that user."""

    provider_id = "active_directory_auth"

    def __init__(self, config: AdAuthConfig) -> None:
        self.config = config
        self._base_dn_cache: str | None = config.base_dn or None

    # -- connections ---------------------------------------------------------------------------
    def _server(self):  # type: ignore[no-untyped-def]
        from ldap3 import ALL, Server

        return Server(
            self.config.server,
            port=self.config.port,
            use_ssl=self.config.use_ssl,
            tls=_tls_object(self.config) if (self.config.use_ssl or self.config.start_tls) else None,
            get_info=ALL,
            connect_timeout=self.config.timeout_seconds,
        )

    def _connect(self, user: str | None, password: str | None, *, read_only: bool = True):  # type: ignore[no-untyped-def]
        from ldap3 import SIMPLE, Connection

        connection = Connection(
            self._server(),
            user=user,
            password=password,
            authentication=SIMPLE if user else None,
            auto_bind=False,
            read_only=read_only,  # this module never writes to the directory (ТЗ 49.8)
            receive_timeout=self.config.timeout_seconds,
            raise_exceptions=False,
        )
        if self.config.start_tls and not self.config.use_ssl and not connection.start_tls():
            raise ConnectionError("STARTTLS failed; refusing to send credentials in clear text")
        return connection

    # -- discovery -----------------------------------------------------------------------------
    def discover_base_dn(self) -> str | None:
        """Read defaultNamingContext from RootDSE so the product works without manual setup."""
        if self._base_dn_cache:
            return self._base_dn_cache
        try:
            connection = self._connect(self.config.bind_dn or None, self.config.bind_password or None)
            if not connection.bind():
                logger.warning("ad_auth.rootdse_bind_failed")
                return None
            try:
                info = connection.server.info
                contexts = list(getattr(info, "naming_contexts", None) or [])
                default = getattr(info, "other", {}).get("defaultNamingContext") if info else None
                if isinstance(default, list):
                    default = default[0] if default else None
                self._base_dn_cache = str(default or (contexts[0] if contexts else "")) or None
            finally:
                connection.unbind()
        except Exception as exc:  # noqa: BLE001 - discovery must never raise upward
            logger.warning("ad_auth.discovery_failed", extra={"error": type(exc).__name__})
            return None
        if self._base_dn_cache:
            logger.info("ad_auth.base_dn_discovered", extra={"base_dn": self._base_dn_cache})
        return self._base_dn_cache

    # -- health --------------------------------------------------------------------------------
    def health(self) -> dict[str, Any]:
        problems = self.config.validate()
        if not self.config.server:
            return {"status": "not_configured", "detail": "AD authentication is not configured"}
        try:
            connection = self._connect(self.config.bind_dn or None, self.config.bind_password or None)
            bound = connection.bind()
            base_dn = self.discover_base_dn() if bound else None
            if bound:
                connection.unbind()
        except Exception as exc:  # noqa: BLE001
            return {"status": "unavailable", "detail": type(exc).__name__, "problems": problems}
        return {
            "status": "ok" if bound and not problems else "degraded" if bound else "unavailable",
            "detail": "; ".join(problems) if problems else None,
            "base_dn": base_dn or self.config.base_dn,
            "problems": problems,
        }

    # -- authentication ------------------------------------------------------------------------
    def authenticate(self, login: str, password: str) -> AuthResult:
        problems = self.config.validate()
        blocking = [p for p in problems if "acceptable only on a lab stand" not in p]
        if blocking:
            return AuthResult(AuthOutcome.MISCONFIGURED, detail="; ".join(blocking))
        if not login or not password:
            # An empty password would be an unauthenticated bind, which many servers accept.
            return AuthResult(AuthOutcome.INVALID_CREDENTIALS, detail="empty credentials")

        try:
            entry = self._find_user(login)
        except ConnectionError as exc:
            return AuthResult(AuthOutcome.DIRECTORY_UNAVAILABLE, detail=str(exc)[:200])
        except Exception as exc:  # noqa: BLE001
            logger.warning("ad_auth.lookup_failed", extra={"error": type(exc).__name__})
            return AuthResult(AuthOutcome.DIRECTORY_UNAVAILABLE, detail=type(exc).__name__)

        if entry is None:
            if not self.config.user_principal_template:
                return AuthResult(AuthOutcome.USER_NOT_FOUND)
            # Without a service account the user is bound directly and attributes are read after.
            bind_dn = self.config.user_principal_template.format(login=login)
            entry = {"distinguishedName": bind_dn, "mail": login, "displayName": "", "memberOf": []}
        else:
            account_state = self._account_state(entry)
            if account_state is not None:
                return AuthResult(account_state, email=str(entry.get("mail") or login))
            bind_dn = str(entry.get("distinguishedName") or "")
            if not bind_dn:
                return AuthResult(AuthOutcome.USER_NOT_FOUND, detail="entry has no distinguishedName")

        # The actual authentication: bind as the user with their own password.
        try:
            connection = self._connect(bind_dn, password)
            bound = connection.bind()
            result_code = getattr(connection.result, "get", lambda *_: None)("description")
            if bound:
                if not self.config.user_principal_template or entry.get("memberOf"):
                    connection.unbind()
                else:
                    entry = self._read_self(connection, bind_dn) or entry
                    connection.unbind()
        except Exception as exc:  # noqa: BLE001
            logger.warning("ad_auth.bind_error", extra={"error": type(exc).__name__})
            return AuthResult(AuthOutcome.DIRECTORY_UNAVAILABLE, detail=type(exc).__name__)

        if not bound:
            # AD returns "data 52e" for a wrong password and "data 533/701/775" for account state.
            detail = str(result_code or "")
            state = self._state_from_bind_error(str(connection.result))
            if state is not None:
                return AuthResult(state, email=str(entry.get("mail") or login))
            return AuthResult(AuthOutcome.INVALID_CREDENTIALS, detail=detail[:200])

        groups = tuple(str(g) for g in (entry.get("memberOf") or []))
        role = self.map_role(groups)
        if role is None:
            logger.info("ad_auth.no_group_match", extra={"actor": login})
            return AuthResult(
                AuthOutcome.NOT_AUTHORIZED,
                email=str(entry.get("mail") or login),
                groups=groups,
                detail="no AD group maps to a platform role",
            )

        return AuthResult(
            AuthOutcome.SUCCESS,
            email=str(entry.get("mail") or login).lower(),
            display_name=str(entry.get("displayName") or ""),
            distinguished_name=bind_dn,
            groups=groups,
            role=role,
            warnings=[p for p in problems if p not in blocking],
        )

    # -- internals -----------------------------------------------------------------------------
    def _find_user(self, login: str) -> dict[str, Any] | None:
        if not self.config.bind_dn:
            return None  # direct bind mode: nothing to look up beforehand
        base_dn = self.config.base_dn or self.discover_base_dn()
        if not base_dn:
            raise ConnectionError("cannot determine the AD base DN")

        connection = self._connect(self.config.bind_dn, self.config.bind_password)
        if not connection.bind():
            raise ConnectionError("service account bind failed")
        try:
            search_filter = self.config.user_filter.format(login=escape_filter_value(login))
            connection.search(
                search_base=base_dn,
                search_filter=search_filter,
                attributes=list(_AUTH_ATTRIBUTES),
                size_limit=2,
            )
            entries = list(connection.entries)
            if not entries:
                return None
            if len(entries) > 1:
                # An ambiguous login must not be resolved by guessing.
                logger.warning("ad_auth.ambiguous_login", extra={"matches": len(entries)})
                return None
            entry = entries[0]
            return {
                "distinguishedName": str(entry.entry_dn),
                "displayName": str(entry.displayName) if "displayName" in entry else "",
                "mail": str(entry.mail) if "mail" in entry else "",
                "memberOf": [str(g) for g in (entry.memberOf if "memberOf" in entry else [])],
                "userAccountControl": int(entry.userAccountControl.value)
                if "userAccountControl" in entry and entry.userAccountControl.value is not None
                else None,
            }
        finally:
            connection.unbind()

    def _read_self(self, connection, dn: str) -> dict[str, Any] | None:  # type: ignore[no-untyped-def]
        """Read the user's own attributes over their authenticated connection."""
        try:
            connection.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=list(_AUTH_ATTRIBUTES),
            )
            entries = list(connection.entries)
            if not entries:
                return None
            entry = entries[0]
            return {
                "distinguishedName": str(entry.entry_dn),
                "displayName": str(entry.displayName) if "displayName" in entry else "",
                "mail": str(entry.mail) if "mail" in entry else "",
                "memberOf": [str(g) for g in (entry.memberOf if "memberOf" in entry else [])],
            }
        except Exception:  # noqa: BLE001
            return None

    def _account_state(self, entry: dict[str, Any]) -> AuthOutcome | None:
        uac = entry.get("userAccountControl")
        if not isinstance(uac, int):
            return None
        if uac & _UAC_ACCOUNTDISABLE:
            return AuthOutcome.ACCOUNT_DISABLED
        if uac & _UAC_LOCKOUT:
            return AuthOutcome.ACCOUNT_LOCKED
        if uac & _UAC_PASSWORD_EXPIRED:
            return AuthOutcome.PASSWORD_EXPIRED
        return None

    @staticmethod
    def _state_from_bind_error(result: str) -> AuthOutcome | None:
        """Map Active Directory sub-error codes to a specific outcome."""
        lowered = (result or "").lower()
        if "data 533" in lowered:
            return AuthOutcome.ACCOUNT_DISABLED
        if "data 775" in lowered:
            return AuthOutcome.ACCOUNT_LOCKED
        if "data 532" in lowered or "data 773" in lowered:
            return AuthOutcome.PASSWORD_EXPIRED
        return None

    def map_role(self, group_dns: tuple[str, ...]) -> str | None:
        """Map AD group membership to a platform role. The first configured match wins."""
        member_names: set[str] = set()
        for dn in group_dns:
            member_names |= _group_names(dn)
        for group, role in self.config.group_role_map:
            if group.strip().lower() in member_names:
                return role
        if self.config.require_group_match:
            return None
        return self.config.default_role


def parse_group_role_map(raw: str) -> tuple[tuple[str, str], ...]:
    """Parse ``group=role`` pairs separated by ``;``.

    Example:
        CN=SOC Admins,OU=Groups,DC=corp,DC=example=security_admin;SOC Analysts=security_analyst
    """
    pairs: list[tuple[str, str]] = []
    for chunk in (raw or "").split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        # The group DN itself contains "=", so only the last separator splits group from role.
        group, _, role = chunk.rpartition("=")
        group, role = group.strip(), role.strip()
        if group and role:
            pairs.append((group, role))
    return tuple(pairs)
