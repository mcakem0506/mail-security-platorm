"""Authentication endpoints (ТЗ 24)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request, Response, status
from msp_ad import AuthOutcome
from sqlalchemy import func, select

from ..config import get_settings
from ..db.base import utcnow
from ..db.models import User
from ..deps import AppSettings, CurrentActor, DbSession, client_ip, get_session_manager, rate_limit
from ..schemas import ChangePasswordRequest, LoginRequest, LoginResponse, MeResponse
from ..security.audit import AuditAction, record
from ..security.auth import (
    evaluate_lockout,
    hash_password,
    needs_rehash,
    next_lockout,
    verify_password,
)
from ..security.rbac import PRIVILEGED_ROLES_LABEL, ROLE_LABELS, permissions_for
from ..services.directory_auth import authenticate as directory_authenticate
from ..services.directory_auth import is_directory_managed

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

_GENERIC_ERROR = "Неверный адрес электронной почты или пароль"


def _set_session_cookies(response: Response, settings, cookie_value: str, csrf_token: str, ttl: int) -> None:  # type: ignore[no-untyped-def]
    response.set_cookie(
        settings.cookie_name,
        cookie_value,
        max_age=ttl,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        domain=settings.cookie_domain,
        path="/",
    )
    # Double-submit CSRF token: readable by the SPA, compared in constant time server-side.
    response.set_cookie(
        settings.csrf_cookie_name,
        csrf_token,
        max_age=ttl,
        httponly=False,
        secure=settings.cookie_secure,
        samesite="strict",
        domain=settings.cookie_domain,
        path="/",
    )


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    session: DbSession,
    settings: AppSettings,
) -> LoginResponse:
    ip = client_ip(request)
    rate_limit(f"login:{ip}", settings.rate_limit_login_per_minute)
    rate_limit(f"login-user:{payload.email.lower()}", settings.rate_limit_login_per_minute)

    user = session.execute(
        select(User).where(func.lower(User.email) == payload.email.lower())
    ).scalar_one_or_none()

    lockout = evaluate_lockout(
        user.failed_logins if user else 0,
        user.locked_until if user else None,
        max_attempts=settings.max_failed_logins,
        lockout_minutes=settings.lockout_minutes,
    )
    if user is not None and lockout.locked:
        record(
            session,
            action=AuditAction.LOGIN_FAILED,
            actor_email=payload.email,
            organization_id=user.organization_id,
            outcome="locked",
            detail={"reason": "account locked"},
            ip_address=ip,
            user_agent=request.headers.get("user-agent", ""),
            request_id=getattr(request.state, "request_id", ""),
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Учётная запись временно заблокирована из-за неудачных попыток входа",
        )

    directory_outcome: str | None = None
    if settings.auth_backend == "ldap" and not (user is not None and user.auth_source == "local"):
        # The directory is authoritative. A locally-created account (the bootstrap administrator,
        # an emergency account) keeps working, so a directory outage cannot lock everyone out.
        user, outcome, detail = directory_authenticate(session, settings, payload.email, payload.password)
        directory_outcome = outcome.value
        password_ok = outcome is AuthOutcome.SUCCESS
        if outcome is AuthOutcome.DIRECTORY_UNAVAILABLE:
            record(
                session,
                action=AuditAction.LOGIN_FAILED,
                actor_email=payload.email,
                outcome="directory_unavailable",
                detail={"reason": detail[:200]},
                ip_address=ip,
                user_agent=request.headers.get("user-agent", ""),
                request_id=getattr(request.state, "request_id", ""),
            )
            session.commit()
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Служба каталогов недоступна. Повторите попытку позже.",
            )
    elif settings.auth_backend == "ldap" and user is not None and user.auth_source == "local":
        # Break-glass: a local account signing in while the directory is authoritative. It is
        # allowed — otherwise a directory outage would lock the security team out of their own
        # console — but it is never silent.
        password_ok = verify_password(payload.password, user.password_hash)
        directory_outcome = "local_account_used_while_directory_is_authoritative"
        expected = settings.emergency_local_account_list
        if password_ok:
            logger.warning(
                "auth.emergency_local_login",
                extra={
                    "declared_emergency_account": (not expected) or user.email.lower() in expected,
                },
            )
    elif is_directory_managed(user):
        # An AD-managed account must never fall back to a local password.
        password_ok = False
        directory_outcome = "local_login_refused_for_directory_account"
    else:
        password_ok = verify_password(payload.password, user.password_hash if user else None)

    if user is None or not password_ok or not user.is_active:
        if user is not None:
            user.failed_logins += 1
            user.locked_until = next_lockout(
                user.failed_logins,
                max_attempts=settings.max_failed_logins,
                lockout_minutes=settings.lockout_minutes,
            )
        record(
            session,
            action=AuditAction.LOGIN_FAILED,
            actor_email=payload.email,
            organization_id=user.organization_id if user else None,
            outcome="failure",
            detail={
                "reason": directory_outcome or ("invalid credentials" if user else "unknown user"),
                "backend": settings.auth_backend,
            },
            ip_address=ip,
            user_agent=request.headers.get("user-agent", ""),
            request_id=getattr(request.state, "request_id", ""),
        )
        session.commit()
        # One generic message for all failure modes: no account enumeration.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_GENERIC_ERROR)

    if settings.require_mfa_for_privileged and user.role in PRIVILEGED_ROLES_LABEL and not user.mfa_enabled:
        logger.warning("auth.privileged_without_mfa", extra={"actor": user.email})

    # Only a locally-managed account keeps a password hash. A directory password must never be
    # written into the platform, even as a hash: the directory stays the only place it lives.
    if not is_directory_managed(user) and user.password_hash and needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)

    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = utcnow()

    manager = get_session_manager()
    sess = manager.create(
        user_id=user.id,
        email=user.email,
        role=user.role,
        organization_id=user.organization_id,
        mfa_verified=user.mfa_enabled,
        ip_address=ip,
        user_agent=request.headers.get("user-agent", "")[:255],
    )
    ttl = int((sess.expires_at - sess.created_at).total_seconds())
    _set_session_cookies(
        response, settings, manager.issue_cookie_value(sess.session_id), sess.csrf_token, ttl
    )

    record(
        session,
        action=AuditAction.LOGIN,
        actor_id=user.id,
        actor_email=user.email,
        actor_role=user.role.value,
        organization_id=user.organization_id,
        object_type="user",
        object_id=user.id,
        ip_address=ip,
        user_agent=request.headers.get("user-agent", ""),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return LoginResponse(
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        role_label=ROLE_LABELS.get(user.role, user.role.value),
        permissions=sorted(p.value for p in permissions_for(user.role)),
        csrf_token=sess.csrf_token,
        expires_at=sess.expires_at,
        must_change_password=user.must_change_password,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request, response: Response, actor: CurrentActor, session: DbSession, settings: AppSettings
) -> Response:
    get_session_manager().revoke(actor.session.session_id)
    response.delete_cookie(settings.cookie_name, path="/", domain=settings.cookie_domain)
    response.delete_cookie(settings.csrf_cookie_name, path="/", domain=settings.cookie_domain)
    record(
        session,
        action=AuditAction.LOGOUT,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=MeResponse)
def me(actor: CurrentActor) -> MeResponse:
    return MeResponse(
        user_id=actor.user_id,
        email=actor.email,
        display_name=actor.session.email.split("@")[0],
        role=actor.role,
        role_label=ROLE_LABELS.get(actor.role, actor.role.value),
        permissions=sorted(p.value for p in permissions_for(actor.role)),
        organization_id=actor.organization_id,
        csrf_token=actor.session.csrf_token,
    )


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    actor: CurrentActor,
    session: DbSession,
) -> Response:
    user = session.get(User, actor.user_id)
    if is_directory_managed(user):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Пароль этой учётной записи управляется службой каталогов организации",
        )
    if user is None or not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Текущий пароль неверен")
    if payload.new_password == payload.current_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Новый пароль должен отличаться от текущего"
        )
    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = False
    # Changing a password invalidates every other session for that user.
    revoked = get_session_manager().revoke_all_for_user(user.id)
    record(
        session,
        action=AuditAction.PASSWORD_CHANGED,
        actor_id=user.id,
        actor_email=user.email,
        actor_role=user.role.value,
        organization_id=user.organization_id,
        object_type="user",
        object_id=user.id,
        detail={"sessions_revoked": revoked},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/config")
def public_config() -> dict[str, object]:
    """Non-sensitive configuration for the SPA and the add-in (never contains secrets)."""
    return get_settings().public_config()
