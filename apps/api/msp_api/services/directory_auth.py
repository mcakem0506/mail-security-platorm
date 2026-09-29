"""Bridge between Active Directory authentication and the platform's user records (ТЗ 24).

Users are provisioned just-in-time on first successful AD login: the organisation manages people
and their roles in AD, and the platform follows. A local password is never created for such an
account, so an AD-managed user cannot bypass the directory by logging in locally.
"""

from __future__ import annotations

import logging

from msp_ad import ActiveDirectoryAuthenticator, AdAuthConfig, AuthOutcome, AuthResult, parse_group_role_map
from msp_contracts import Role
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.base import utcnow
from ..db.models import MailboxIdentity, Organization, User

logger = logging.getLogger(__name__)

# Outcomes that must look identical to the user, so AD state is not disclosed by the login form.
_GENERIC_FAILURES = {
    AuthOutcome.INVALID_CREDENTIALS,
    AuthOutcome.USER_NOT_FOUND,
    AuthOutcome.ACCOUNT_DISABLED,
    AuthOutcome.ACCOUNT_LOCKED,
    AuthOutcome.PASSWORD_EXPIRED,
    AuthOutcome.NOT_AUTHORIZED,
}


def build_authenticator(settings: Settings) -> ActiveDirectoryAuthenticator:
    return ActiveDirectoryAuthenticator(
        AdAuthConfig(
            server=settings.ad_server,
            port=settings.ad_port,
            use_ssl=settings.ad_use_ssl,
            start_tls=settings.ad_start_tls,
            bind_dn=settings.ad_bind_dn,
            bind_password=settings.ad_bind_password,
            base_dn=settings.ad_base_dn,
            user_filter=settings.ad_user_filter,
            user_principal_template=settings.ad_user_principal_template,
            group_role_map=parse_group_role_map(settings.ad_group_role_map),
            default_role=settings.ad_default_role,
            require_group_match=settings.ad_require_group_match,
            ca_file=settings.ad_ca_file,
            verify_tls=settings.ad_verify_tls,
            timeout_seconds=settings.ad_timeout_seconds,
        )
    )


def _role_from_result(result: AuthResult) -> Role:
    try:
        return Role(result.role)
    except ValueError:
        logger.warning("directory_auth.unknown_role", extra={"role": result.role})
        return Role.EMPLOYEE


def provision_user(session: Session, settings: Settings, result: AuthResult) -> User | None:
    """Create or update the local record for an AD-authenticated user."""
    organization = session.execute(select(Organization)).scalars().first()
    if organization is None:
        logger.error("directory_auth.no_organization")
        return None

    email = (result.email or "").lower()
    if not email:
        logger.warning("directory_auth.entry_without_mail", extra={"dn": result.distinguished_name})
        return None

    role = _role_from_result(result)
    user = session.execute(select(User).where(func.lower(User.email) == email)).scalar_one_or_none()

    if user is None:
        user = User(
            organization_id=organization.id,
            email=email,
            display_name=result.display_name or email.split("@")[0],
            role=role,
            auth_source="ldap",
            # No local password: this account can only authenticate through the directory.
            password_hash=None,
            is_active=True,
        )
        session.add(user)
        session.flush()
        logger.info("directory_auth.user_provisioned", extra={"actor": email, "role": role.value})
    else:
        user.display_name = result.display_name or user.display_name
        # The directory is authoritative for the role while the account is AD-managed.
        if user.auth_source == "ldap" and user.role != role:
            logger.info(
                "directory_auth.role_changed",
                extra={"actor": email, "from": user.role.value, "to": role.value},
            )
            user.role = role
        user.is_active = True

    user.last_login_at = utcnow()
    user.failed_logins = 0
    user.locked_until = None

    existing_mailbox = session.execute(
        select(MailboxIdentity).where(
            MailboxIdentity.organization_id == organization.id,
            func.lower(MailboxIdentity.address) == email,
        )
    ).scalar_one_or_none()
    if existing_mailbox is None:
        session.add(
            MailboxIdentity(
                organization_id=organization.id,
                user_id=user.id,
                address=email,
                display_name=user.display_name,
                last_synced_at=utcnow(),
            )
        )
    elif existing_mailbox.user_id is None:
        existing_mailbox.user_id = user.id

    return user


def authenticate(
    session: Session, settings: Settings, login: str, password: str
) -> tuple[User | None, AuthOutcome, str]:
    """Authenticate against AD and return the local user record.

    Returns ``(user, outcome, detail)``. The caller decides what to show; all ordinary failures
    are reported to the user with one generic message so AD account state is not disclosed.
    """
    authenticator = build_authenticator(settings)
    result = authenticator.authenticate(login, password)

    if result.outcome is not AuthOutcome.SUCCESS:
        if result.outcome not in _GENERIC_FAILURES:
            logger.warning(
                "directory_auth.failed",
                extra={"outcome": result.outcome.value, "detail": result.detail[:200]},
            )
        return None, result.outcome, result.detail

    for warning in result.warnings:
        logger.warning("directory_auth.configuration_warning", extra={"detail": warning})

    user = provision_user(session, settings, result)
    if user is None:
        return None, AuthOutcome.MISCONFIGURED, "cannot provision the user locally"
    return user, AuthOutcome.SUCCESS, ""


def is_directory_managed(user: User | None) -> bool:
    """An AD-managed account must not fall back to local password authentication."""
    return user is not None and user.auth_source == "ldap"
