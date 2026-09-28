"""Authentication, authorization and audit."""

from .audit import AuditAction, record, redact
from .auth import (
    AuthError,
    MemorySessionStore,
    RedisSessionStore,
    SessionData,
    SessionManager,
    evaluate_lockout,
    hash_password,
    needs_rehash,
    next_lockout,
    verify_csrf,
    verify_password,
)
from .rbac import (
    ROLE_LABELS,
    ROLE_PERMISSIONS,
    Permission,
    can_access_job,
    can_approve,
    can_view_all_messages,
    has_permission,
    permissions_for,
    required_approvals,
)

__all__ = [
    "ROLE_LABELS",
    "ROLE_PERMISSIONS",
    "AuditAction",
    "AuthError",
    "MemorySessionStore",
    "Permission",
    "RedisSessionStore",
    "SessionData",
    "SessionManager",
    "can_access_job",
    "can_approve",
    "can_view_all_messages",
    "evaluate_lockout",
    "has_permission",
    "hash_password",
    "needs_rehash",
    "next_lockout",
    "permissions_for",
    "record",
    "redact",
    "required_approvals",
    "verify_csrf",
    "verify_password",
]
