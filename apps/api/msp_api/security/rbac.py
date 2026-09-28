"""Role-based access control and object-level authorization (ТЗ 23, 30).

Two separate concerns:
* permissions — what a role may do at all;
* object-level checks — whether *this* actor may touch *this* object. An employee may only ever
  see their own analyses, and platform administration is kept apart from message investigation.
"""

from __future__ import annotations

from enum import StrEnum

from msp_contracts import Role


class Permission(StrEnum):
    # employee scope
    ANALYZE_OWN_MESSAGE = "analyze:own"
    VIEW_OWN_RESULT = "view:own_result"
    REPORT_PHISHING = "report:phishing"

    # investigation scope
    VIEW_INVESTIGATIONS = "view:investigations"
    VIEW_MESSAGE_CONTENT = "view:message_content"
    DOWNLOAD_ATTACHMENT = "download:attachment"
    SEARCH_INDICATORS = "search:indicators"
    VIEW_CAMPAIGNS = "view:campaigns"
    VIEW_INCIDENTS = "view:incidents"
    MANAGE_INCIDENTS = "manage:incidents"
    CLASSIFY_MESSAGE = "classify:message"
    CREATE_EXCEPTION = "create:exception"
    PROPOSE_REMEDIATION = "propose:remediation"
    EXPORT_DATA = "export:data"

    # administration scope
    APPROVE_REMEDIATION = "approve:remediation"
    EXECUTE_REMEDIATION = "execute:remediation"
    MANAGE_POLICIES = "manage:policies"
    MANAGE_PROVIDERS = "manage:providers"
    MANAGE_PROTECTED_IDENTITIES = "manage:protected_identities"
    MANAGE_INTEGRATIONS = "manage:integrations"
    MANAGE_USERS = "manage:users"
    VIEW_AUDIT = "view:audit"

    # platform scope
    MANAGE_PLATFORM = "manage:platform"
    VIEW_SYSTEM_HEALTH = "view:system_health"


_EMPLOYEE: frozenset[Permission] = frozenset(
    {Permission.ANALYZE_OWN_MESSAGE, Permission.VIEW_OWN_RESULT, Permission.REPORT_PHISHING}
)
_VIEWER: frozenset[Permission] = _EMPLOYEE | {
    Permission.VIEW_INVESTIGATIONS,
    Permission.VIEW_MESSAGE_CONTENT,
    Permission.SEARCH_INDICATORS,
    Permission.VIEW_CAMPAIGNS,
    Permission.VIEW_INCIDENTS,
}
_ANALYST: frozenset[Permission] = _VIEWER | {
    Permission.MANAGE_INCIDENTS,
    Permission.CLASSIFY_MESSAGE,
    Permission.CREATE_EXCEPTION,
    Permission.PROPOSE_REMEDIATION,
    Permission.DOWNLOAD_ATTACHMENT,
    Permission.EXPORT_DATA,
}
_SECURITY_ADMIN: frozenset[Permission] = _ANALYST | {
    Permission.APPROVE_REMEDIATION,
    Permission.EXECUTE_REMEDIATION,
    Permission.MANAGE_POLICIES,
    Permission.MANAGE_PROVIDERS,
    Permission.MANAGE_PROTECTED_IDENTITIES,
    Permission.MANAGE_INTEGRATIONS,
    Permission.MANAGE_USERS,
    Permission.VIEW_AUDIT,
}
# Platform Admin runs the infrastructure and is deliberately NOT granted message content access
# by default (ТЗ 23). Granting it is a policy decision recorded in the audit trail.
_PLATFORM_ADMIN: frozenset[Permission] = frozenset(
    {
        Permission.MANAGE_PLATFORM,
        Permission.VIEW_SYSTEM_HEALTH,
        Permission.MANAGE_USERS,
        Permission.MANAGE_PROVIDERS,
        Permission.MANAGE_INTEGRATIONS,
        Permission.VIEW_AUDIT,
    }
)

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.EMPLOYEE: _EMPLOYEE,
    Role.SECURITY_VIEWER: _VIEWER,
    Role.SECURITY_ANALYST: _ANALYST,
    Role.SECURITY_ADMIN: _SECURITY_ADMIN,
    Role.PLATFORM_ADMIN: _PLATFORM_ADMIN,
}

ROLE_LABELS: dict[Role, str] = {
    Role.EMPLOYEE: "Сотрудник",
    Role.SECURITY_VIEWER: "Наблюдатель ИБ",
    Role.SECURITY_ANALYST: "Аналитик ИБ",
    Role.SECURITY_ADMIN: "Администратор ИБ",
    Role.PLATFORM_ADMIN: "Администратор платформы",
}


def permissions_for(role: Role) -> frozenset[Permission]:
    return ROLE_PERMISSIONS.get(role, frozenset())


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in permissions_for(role)


def can_view_all_messages(role: Role) -> bool:
    return has_permission(role, Permission.VIEW_INVESTIGATIONS)


def can_access_job(
    *, role: Role, actor_user_id: str, actor_mailbox: str, job_owner_id: str | None, job_mailbox: str
) -> bool:
    """Object-level check for an analysis job (ТЗ 40.6: no cross-user result access)."""
    if can_view_all_messages(role):
        return True
    if not has_permission(role, Permission.VIEW_OWN_RESULT):
        return False
    if job_owner_id and job_owner_id == actor_user_id:
        return True
    return bool(actor_mailbox) and actor_mailbox.lower() == (job_mailbox or "").lower()


def required_approvals(affected_mailboxes: int, threshold: int = 10) -> int:
    """Two-person approval for bulk operations (ТЗ 20.1)."""
    return 2 if affected_mailboxes > threshold else 1


def can_approve(
    *, role: Role, approver_id: str, proposer_id: str, existing_approvers: set[str]
) -> tuple[bool, str]:
    """Approval rules: admin only, never self-approval, never the same person twice."""
    if not has_permission(role, Permission.APPROVE_REMEDIATION):
        return False, "role is not permitted to approve remediation"
    if approver_id == proposer_id:
        return False, "the proposer cannot approve their own remediation request"
    if approver_id in existing_approvers:
        return False, "this approver has already decided on the request"
    return True, ""
