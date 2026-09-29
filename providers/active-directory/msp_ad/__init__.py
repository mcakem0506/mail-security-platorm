"""Read-only Active Directory integration (ТЗ 10)."""

from .auth import (
    ActiveDirectoryAuthenticator,
    AdAuthConfig,
    AuthOutcome,
    AuthResult,
    escape_filter_value,
    parse_group_role_map,
)
from .provider import (
    MINIMAL_ATTRIBUTES,
    OPTIONAL_ATTRIBUTES,
    ActiveDirectoryConfig,
    ActiveDirectoryProvider,
    DirectoryEntry,
    DirectoryProvider,
    MockDirectoryProvider,
    SyncResult,
)

__all__ = [
    "MINIMAL_ATTRIBUTES",
    "OPTIONAL_ATTRIBUTES",
    "ActiveDirectoryAuthenticator",
    "ActiveDirectoryConfig",
    "ActiveDirectoryProvider",
    "AdAuthConfig",
    "AuthOutcome",
    "AuthResult",
    "DirectoryEntry",
    "DirectoryProvider",
    "MockDirectoryProvider",
    "SyncResult",
    "escape_filter_value",
    "parse_group_role_map",
]
