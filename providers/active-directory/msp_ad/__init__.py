"""Read-only Active Directory integration (ТЗ 10)."""

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
    "ActiveDirectoryConfig",
    "ActiveDirectoryProvider",
    "DirectoryEntry",
    "DirectoryProvider",
    "MockDirectoryProvider",
    "SyncResult",
]
