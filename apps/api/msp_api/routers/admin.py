"""Administration: protected identities, exceptions, policies, providers, audit (ТЗ 22.5, 25)."""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import desc, func, select

from ..db.base import utcnow
from ..db.models import (
    AuditEvent,
    DetectionException,
    Policy,
    PolicyVersion,
    ProtectedIdentity,
    ProviderConfig,
    User,
)
from ..deps import Actor, AppSettings, DbSession, client_ip, get_scanner, get_ti_hub, require_permission
from ..schemas import (
    AuditEventOut,
    ExceptionCreateRequest,
    ExceptionOut,
    PaginatedResponse,
    PolicyOut,
    PolicyUpdateRequest,
    ProtectedIdentityOut,
    ProtectedIdentityRequest,
    ProviderHealthOut,
)
from ..security.audit import AuditAction, record
from ..security.rbac import Permission
from ..services.analysis import reload_ruleset

logger = logging.getLogger(__name__)
router = APIRouter(tags=["administration"])

IdentityAdmin = Annotated[Actor, Depends(require_permission(Permission.MANAGE_PROTECTED_IDENTITIES))]
PolicyAdmin = Annotated[Actor, Depends(require_permission(Permission.MANAGE_POLICIES))]
ProviderAdmin = Annotated[Actor, Depends(require_permission(Permission.MANAGE_PROVIDERS))]
ExceptionCreator = Annotated[Actor, Depends(require_permission(Permission.CREATE_EXCEPTION))]
AuditViewer = Annotated[Actor, Depends(require_permission(Permission.VIEW_AUDIT))]


# ---------------------------------------------------------------------------------------------
# Protected identities
# ---------------------------------------------------------------------------------------------
@router.get("/protected-identities", response_model=list[ProtectedIdentityOut])
def list_protected_identities(actor: IdentityAdmin, session: DbSession) -> list[ProtectedIdentityOut]:
    rows = (
        session.execute(
            select(ProtectedIdentity).where(ProtectedIdentity.organization_id == actor.organization_id)
        )
        .scalars()
        .all()
    )
    return [_identity_out(row) for row in rows]


def _identity_out(row: ProtectedIdentity) -> ProtectedIdentityOut:
    return ProtectedIdentityOut(
        identity_id=row.id,
        display_name=row.display_name,
        email=row.email,
        categories=list(row.categories or []),
        aliases=list(row.aliases or []),
        name_variants=list(row.name_variants or []),
        approved_delegates=list(row.approved_delegates or []),
        approved_external_systems=list(row.approved_external_systems or []),
        department=row.department,
        title=row.title,
        enabled=row.enabled,
        created_at=row.created_at,
        risk_class=row.risk_class,
        vip=row.vip,
        source=row.source,
    )


@router.post("/protected-identities", response_model=ProtectedIdentityOut, status_code=201)
def create_protected_identity(
    payload: ProtectedIdentityRequest, request: Request, actor: IdentityAdmin, session: DbSession
) -> ProtectedIdentityOut:
    row = ProtectedIdentity(
        organization_id=actor.organization_id,
        display_name=payload.display_name,
        email=str(payload.email).lower(),
        categories=payload.categories,
        aliases=[a.lower() for a in payload.aliases],
        name_variants=payload.name_variants,
        approved_delegates=[d.lower() for d in payload.approved_delegates],
        approved_external_systems=[s.lower() for s in payload.approved_external_systems],
        department=payload.department,
        title=payload.title,
        enabled=payload.enabled,
        created_by=actor.email,
    )
    session.add(row)
    session.flush()
    record(
        session,
        action=AuditAction.PROTECTED_IDENTITY_CHANGED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="protected_identity",
        object_id=row.id,
        detail={"operation": "create", "email": row.email, "categories": row.categories},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return _identity_out(row)


@router.delete("/protected-identities/{identity_id}", status_code=204)
def delete_protected_identity(
    identity_id: str, request: Request, actor: IdentityAdmin, session: DbSession
) -> Response:
    row = session.get(ProtectedIdentity, identity_id)
    if row is None or row.organization_id != actor.organization_id:
        raise HTTPException(status_code=404, detail="Идентичность не найдена")
    row.enabled = False
    record(
        session,
        action=AuditAction.PROTECTED_IDENTITY_CHANGED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="protected_identity",
        object_id=row.id,
        detail={"operation": "disable", "email": row.email},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return Response(status_code=204)


# ---------------------------------------------------------------------------------------------
# Exceptions (ТЗ 15.3)
# ---------------------------------------------------------------------------------------------
@router.get("/exceptions", response_model=list[ExceptionOut])
def list_exceptions(
    actor: ExceptionCreator, session: DbSession, include_inactive: bool = False
) -> list[ExceptionOut]:
    query = select(DetectionException).where(DetectionException.organization_id == actor.organization_id)
    if not include_inactive:
        query = query.where(DetectionException.revoked_at.is_(None))
    rows = session.execute(query.order_by(desc(DetectionException.created_at))).scalars().all()
    now = utcnow()
    return [
        ExceptionOut(
            exception_id=r.id,
            exception_type=r.exception_type,
            value=r.value,
            rule_id=r.rule_id,
            owner_email=r.owner_email,
            reason=r.reason,
            expires_at=r.expires_at,
            revoked_at=r.revoked_at,
            hit_count=r.hit_count,
            created_at=r.created_at,
            active=r.revoked_at is None and (r.expires_at is None or r.expires_at > now),
        )
        for r in rows
    ]


@router.post("/exceptions", response_model=ExceptionOut, status_code=201)
def create_exception(
    payload: ExceptionCreateRequest, request: Request, actor: ExceptionCreator, session: DbSession
) -> ExceptionOut:
    """Every exception carries an owner, reason, expiry and audit entry (ТЗ 15.3, 43.6)."""
    row = DetectionException(
        organization_id=actor.organization_id,
        exception_type=payload.exception_type,
        value=payload.value.lower(),
        rule_id=payload.rule_id,
        owner_id=actor.user_id,
        owner_email=actor.email,
        reason=payload.reason,
        expires_at=payload.expires_at,
    )
    session.add(row)
    session.flush()
    record(
        session,
        action=AuditAction.EXCEPTION_CREATED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="detection_exception",
        object_id=row.id,
        detail={
            "type": row.exception_type.value,
            "value": row.value,
            "rule_id": row.rule_id,
            "reason": row.reason,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        },
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return ExceptionOut(
        exception_id=row.id,
        exception_type=row.exception_type,
        value=row.value,
        rule_id=row.rule_id,
        owner_email=row.owner_email,
        reason=row.reason,
        expires_at=row.expires_at,
        revoked_at=None,
        hit_count=0,
        created_at=row.created_at,
        active=True,
    )


@router.delete("/exceptions/{exception_id}", status_code=204)
def revoke_exception(
    exception_id: str, request: Request, actor: ExceptionCreator, session: DbSession
) -> Response:
    row = session.get(DetectionException, exception_id)
    if row is None or row.organization_id != actor.organization_id:
        raise HTTPException(status_code=404, detail="Исключение не найдено")
    row.revoked_at = utcnow()
    row.revoked_by = actor.email
    record(
        session,
        action=AuditAction.EXCEPTION_REVOKED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="detection_exception",
        object_id=row.id,
        detail={"value": row.value, "type": row.exception_type.value},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return Response(status_code=204)


# ---------------------------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------------------------
@router.get("/policies", response_model=list[PolicyOut])
def list_policies(actor: PolicyAdmin, session: DbSession) -> list[PolicyOut]:
    rows = (
        session.execute(select(Policy).where(Policy.organization_id == actor.organization_id)).scalars().all()
    )
    return [
        PolicyOut(
            key=r.key, value=r.value, version=r.version, updated_by=r.updated_by, updated_at=r.updated_at
        )
        for r in rows
    ]


@router.put("/policies/{key}", response_model=PolicyOut)
def update_policy(
    key: str, payload: PolicyUpdateRequest, request: Request, actor: PolicyAdmin, session: DbSession
) -> PolicyOut:
    """Policy changes are versioned, so an earlier state can always be reconstructed (ТЗ 15.2)."""
    row = session.execute(
        select(Policy).where(Policy.organization_id == actor.organization_id, Policy.key == key)
    ).scalar_one_or_none()
    if row is None:
        row = Policy(organization_id=actor.organization_id, key=key[:64], value=payload.value, version=1)
        session.add(row)
        session.flush()
    else:
        row.version += 1
        row.value = payload.value
    row.updated_by = actor.email
    session.add(
        PolicyVersion(
            policy_id=row.id,
            version=row.version,
            value=payload.value,
            changed_by=actor.email,
            change_reason=payload.reason,
        )
    )
    record(
        session,
        action=AuditAction.POLICY_CHANGED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="policy",
        object_id=row.key,
        detail={"version": row.version, "reason": payload.reason},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return PolicyOut(
        key=row.key,
        value=row.value,
        version=row.version,
        updated_by=row.updated_by,
        updated_at=row.updated_at,
    )


@router.post("/rules/reload")
def reload_rules(request: Request, actor: PolicyAdmin, session: DbSession) -> dict[str, Any]:
    ruleset = reload_ruleset()
    record(
        session,
        action=AuditAction.RULE_CHANGED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="ruleset",
        object_id="default",
        detail={"rule_count": len(ruleset.rules)},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return {"rule_count": len(ruleset.rules), "fingerprint": ruleset.version_fingerprint[:2000]}


@router.get("/rules")
def list_rules(actor: PolicyAdmin) -> list[dict[str, Any]]:
    from ..services.analysis import get_ruleset

    return [
        {
            "id": r.id,
            "version": r.version,
            "name": r.name,
            "category": r.category,
            "severity": r.severity.value,
            "confidence": r.confidence,
            "enabled": r.enabled,
            "hard": r.hard,
            "internal": r.internal,
            "weight": r.effective_weight,
        }
        for r in get_ruleset().rules
    ]


# ---------------------------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------------------------
@router.get("/providers", response_model=list[ProviderHealthOut])
def list_providers(actor: ProviderAdmin, settings: AppSettings) -> list[ProviderHealthOut]:
    """Provider status. API keys are never returned (ТЗ 28, 42.3)."""
    out: list[ProviderHealthOut] = []
    hub = get_ti_hub()
    for health in hub.health():
        provider = hub.providers[0] if hub.providers else None
        quota = None
        if provider is not None and hasattr(provider, "quota"):
            q = provider.quota()
            quota = {
                "per_minute_limit": q.per_minute_limit,
                "per_day_limit": q.per_day_limit,
                "used_minute": q.used_minute,
                "used_day": q.used_day,
            }
        out.append(
            ProviderHealthOut(
                provider_id=health.provider_id,
                kind="threat_intel",
                status=health.status,
                mode=health.mode,
                detail=health.detail,
                quota=quota,
            )
        )
    if not hub.providers:
        out.append(
            ProviderHealthOut(
                provider_id="virustotal",
                kind="threat_intel",
                status="disabled",
                mode=None,
                detail="VirusTotal not configured",
            )
        )
    scanner_health = get_scanner().health()
    out.append(
        ProviderHealthOut(
            provider_id=scanner_health.provider_id,
            kind="malware_scanner",
            status=scanner_health.status,
            mode=scanner_health.mode,
            detail=scanner_health.detail,
        )
    )
    return out


@router.put("/providers/{provider_id}")
def update_provider(
    provider_id: str,
    payload: dict[str, Any],
    request: Request,
    actor: ProviderAdmin,
    session: DbSession,
) -> dict[str, Any]:
    """Update non-secret provider configuration. Secrets stay in the secret store (ТЗ 28)."""
    forbidden = {"api_key", "apikey", "password", "secret", "token"}
    supplied = {k.lower() for k in payload}
    if supplied & forbidden:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Секреты нельзя задавать через API. Используйте хранилище секретов "
                "(Docker secrets / Vault) и переменную *_FILE."
            ),
        )
    row = session.execute(
        select(ProviderConfig).where(
            ProviderConfig.organization_id == actor.organization_id,
            ProviderConfig.provider_id == provider_id,
        )
    ).scalar_one_or_none()
    if row is None:
        row = ProviderConfig(organization_id=actor.organization_id, provider_id=provider_id[:64], settings={})
        session.add(row)
        session.flush()
    row.enabled = bool(payload.get("enabled", row.enabled))
    row.mode = str(payload.get("mode", row.mode))[:32]
    row.settings = {k: v for k, v in payload.items() if k not in {"enabled", "mode"}}
    row.updated_by = actor.email
    record(
        session,
        action=AuditAction.TI_CONFIG_CHANGED,
        actor_id=actor.user_id,
        actor_email=actor.email,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type="provider_config",
        object_id=provider_id,
        detail={"enabled": row.enabled, "mode": row.mode},
        ip_address=client_ip(request),
        request_id=getattr(request.state, "request_id", ""),
    )
    session.commit()
    return {"provider_id": provider_id, "enabled": row.enabled, "mode": row.mode}


# ---------------------------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------------------------
@router.get("/audit", response_model=PaginatedResponse)
def list_audit(
    actor: AuditViewer,
    session: DbSession,
    action_filter: str | None = Query(default=None, alias="action", max_length=64),
    actor_email: str | None = Query(default=None, max_length=320),
    object_type: str | None = Query(default=None, max_length=64),
    object_id: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> PaginatedResponse:
    query = select(AuditEvent).where(AuditEvent.organization_id == actor.organization_id)
    if action_filter:
        query = query.where(AuditEvent.action == action_filter)
    if actor_email:
        query = query.where(func.lower(AuditEvent.actor_email) == actor_email.lower())
    if object_type:
        query = query.where(AuditEvent.object_type == object_type)
    if object_id:
        query = query.where(AuditEvent.object_id == object_id)
    total = session.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    rows = (
        session.execute(query.order_by(desc(AuditEvent.created_at)).limit(limit).offset(offset))
        .scalars()
        .all()
    )
    return PaginatedResponse(
        total=int(total),
        limit=limit,
        offset=offset,
        items=[
            AuditEventOut(
                event_id=r.id,
                action=r.action,
                actor_email=r.actor_email,
                actor_role=r.actor_role,
                object_type=r.object_type,
                object_id=r.object_id,
                outcome=r.outcome,
                detail=r.detail,
                ip_address=r.ip_address,
                request_id=r.request_id,
                created_at=r.created_at,
            )
            for r in rows
        ],
    )


@router.get("/users")
def list_users(
    actor: Annotated[Actor, Depends(require_permission(Permission.MANAGE_USERS))], session: DbSession
) -> list[dict[str, Any]]:
    rows = (
        session.execute(
            select(User).where(User.organization_id == actor.organization_id).order_by(User.email)
        )
        .scalars()
        .all()
    )
    return [
        {
            "user_id": u.id,
            "email": u.email,
            "display_name": u.display_name,
            "role": u.role.value,
            "is_active": u.is_active,
            "mfa_enabled": u.mfa_enabled,
            "auth_source": u.auth_source,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            "locked": bool(u.locked_until and u.locked_until > utcnow()),
        }
        for u in rows
    ]
