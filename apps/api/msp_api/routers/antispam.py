"""API анти-спама, аутентификации и репутации (ТЗ 1.2 §33–§35).

Две аудитории, как и у транспорта:

* **человек в консоли** — сессия, роль и право на каждое действие; каждое изменяющее действие пишет
  своё событие аудита (запрос и одобрение провайдера, генерация и активация ключа, переходы политики);
* **узел шлюза** — общий секрет: присылает результаты сканера, забирает назначенную сканеру
  конфигурацию и сообщает состояние.

Ни одна точка не включает принуждение: такого параметра в API нет.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from msp_antispam.policy import SpamThresholds
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from ..db.models import Organization
from ..db.models_antispam import DkimKeyRecord, ReputationProviderRecord, SpamPolicyRecord
from ..deps import Actor, AppSettings, DbSession, client_ip, require_permission
from ..security.audit import AuditAction, record
from ..security.rbac import Permission
from ..services import antispam
from ..services.dns_lookup import txt_records
from ..services.storage import build_storage
from .transport import NodeAuth, ShadowAuth

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/gateway", tags=["antispam"])
agent_router = APIRouter(prefix="/gateway-agent", tags=["antispam agent"])

SpamReader = Annotated[Actor, Depends(require_permission(Permission.VIEW_SPAM))]
PolicyEditor = Annotated[Actor, Depends(require_permission(Permission.EDIT_SPAM_POLICY))]
PolicyApprover = Annotated[Actor, Depends(require_permission(Permission.APPROVE_SPAM_POLICY))]
PolicySimulator = Annotated[Actor, Depends(require_permission(Permission.SIMULATE_SPAM_POLICY))]
AuthReader = Annotated[Actor, Depends(require_permission(Permission.VIEW_AUTH))]
ConflictReviewer = Annotated[Actor, Depends(require_permission(Permission.REVIEW_AUTH_CONFLICT))]
ReputationReader = Annotated[Actor, Depends(require_permission(Permission.VIEW_REPUTATION))]
ProviderManager = Annotated[Actor, Depends(require_permission(Permission.MANAGE_REPUTATION_PROVIDER))]
DkimReader = Annotated[Actor, Depends(require_permission(Permission.VIEW_DKIM))]
DkimGenerator = Annotated[Actor, Depends(require_permission(Permission.GENERATE_DKIM_KEY))]
DkimActivator = Annotated[Actor, Depends(require_permission(Permission.ACTIVATE_DKIM_KEY))]
DkimRetirer = Annotated[Actor, Depends(require_permission(Permission.RETIRE_DKIM_KEY))]
Reviewer = Annotated[Actor, Depends(require_permission(Permission.REVIEW_REAL_FLOW))]


def _audit(
    session: DbSession,
    actor: Actor,
    request: Request,
    action: str,
    object_type: str,
    object_id: str,
    detail: dict[str, Any] | None = None,
    outcome: str = "success",
) -> None:
    record(
        session,
        action=action,
        actor_email=actor.email,
        actor_id=actor.user_id,
        actor_role=actor.role.value,
        organization_id=actor.organization_id,
        object_type=object_type,
        object_id=object_id,
        outcome=outcome,
        detail=detail or {},
        ip_address=client_ip(request),
    )


def _bad(error: antispam.AntispamError) -> HTTPException:
    return HTTPException(status.HTTP_409_CONFLICT, str(error))


# ---------------------------------------------------------------------------------------------
# Спам: обзор, письма, правила
# ---------------------------------------------------------------------------------------------
@router.get("/spam/summary")
def spam_summary(
    session: DbSession, actor: SpamReader, hours: Annotated[int, Query(ge=1, le=720)] = 24
) -> dict[str, Any]:
    return antispam.summary(session, actor.organization_id, hours=hours)


@router.get("/spam/messages")
def spam_messages(
    session: DbSession,
    actor: SpamReader,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    spam_class: str | None = None,
    suggested_action: str | None = None,
    direction: str | None = None,
) -> dict[str, Any]:
    rows = antispam.list_scans(
        session,
        actor.organization_id,
        limit=limit,
        spam_class=spam_class,
        suggested_action=suggested_action,
        direction=direction,
    )
    return {"items": [antispam.scan_view(r) for r in rows]}


@router.get("/spam/messages/{message_id}")
def spam_message(
    message_id: str, session: DbSession, actor: SpamReader, settings: AppSettings
) -> dict[str, Any]:
    row = antispam.get_scan(session, actor.organization_id, message_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "результат сканирования не найден")
    # Копия письма могла появиться уже после записи сканера: дополняем разбор по заголовкам.
    if antispam.enrich_scan(session, settings, build_storage(settings), row):
        session.commit()
    return antispam.scan_view(row, full=True)


@router.get("/spam/rules")
def spam_rules(actor: SpamReader) -> dict[str, Any]:
    del actor
    return antispam.rules_view()


@router.get("/spam/validation")
def spam_validation(
    session: DbSession, actor: SpamReader, hours: Annotated[int, Query(ge=1, le=2160)] = 168
) -> dict[str, Any]:
    metrics = antispam.validation_metrics(session, actor.organization_id, hours=hours)
    return {
        "metrics": metrics.__dict__,
        "reject_safety": antispam.reject_safety(session, actor.organization_id),
    }


class ReviewRequest(BaseModel):
    verdict: str = Field(pattern="^(HAM|SPAM|BULK)$")
    selection: str
    note: str = Field(default="", max_length=500)


@router.get("/spam/review-queue")
def spam_review_queue(
    session: DbSession, actor: SpamReader, selection: str, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> dict[str, Any]:
    try:
        items = antispam.review_queue(session, actor.organization_id, selection, limit=limit)
    except antispam.AntispamError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return {"selection": selection, "items": items}


@router.post("/spam/messages/{scan_id}/review", status_code=status.HTTP_201_CREATED)
def spam_review(
    scan_id: str, body: ReviewRequest, session: DbSession, actor: Reviewer, request: Request
) -> dict[str, Any]:
    try:
        review = antispam.record_review(
            session,
            actor.organization_id,
            scan_id,
            verdict=body.verdict,
            selection=body.selection,
            actor_email=actor.email,
            note=body.note,
        )
    except antispam.AntispamError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.SPAM_REVIEW_RECORDED,
        "spam_scan",
        scan_id,
        {"verdict": body.verdict, "selection": body.selection},
    )
    session.commit()
    return {"id": review.id, "verdict": review.verdict, "selection": review.selection}


# ---------------------------------------------------------------------------------------------
# Провайдеры репутации
# ---------------------------------------------------------------------------------------------
@router.get("/spam/providers")
def spam_providers(session: DbSession, actor: ReputationReader) -> dict[str, Any]:
    return {
        "items": [
            antispam.provider_public_view(r) for r in antispam.providers(session, actor.organization_id)
        ]
    }


class ProviderCreate(BaseModel):
    id: str
    provider_name: str = Field(max_length=128)
    type: str = "DNSBL"
    license_mode: str = "PUBLIC_NONCOMMERCIAL"
    query_types: list[str] = Field(default_factory=list)
    privacy_class: str = "EXTERNAL_DNS"
    zone: str | None = None
    zone_secret_file: str | None = None
    return_codes: list[str] = Field(default_factory=lambda: ["127.0.0.2"])


def _provider_or_404(session: DbSession, actor: Actor, slug: str) -> ReputationProviderRecord:
    row = session.execute(
        select(ReputationProviderRecord).where(
            ReputationProviderRecord.organization_id == actor.organization_id,
            ReputationProviderRecord.slug == slug,
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "провайдер не найден")
    return row


@router.post("/spam/providers", status_code=status.HTTP_201_CREATED)
def spam_provider_create(
    body: ProviderCreate, session: DbSession, actor: ProviderManager, request: Request
) -> dict[str, Any]:
    try:
        row = antispam.create_provider(
            session, actor.organization_id, body.model_dump(), actor_email=actor.email
        )
    except antispam.AntispamError as exc:
        raise _bad(exc) from exc
    _audit(session, actor, request, AuditAction.SPAM_PROVIDER_CREATED, "reputation_provider", row.slug)
    session.commit()
    return antispam.provider_public_view(row)


class ActivationRequest(BaseModel):
    usage_scope: str = Field(default="", max_length=256)
    expires_at: datetime | None = None


@router.post("/spam/providers/{slug}/request-activation")
def spam_provider_request(
    slug: str, body: ActivationRequest, session: DbSession, actor: ProviderManager, request: Request
) -> dict[str, Any]:
    row = _provider_or_404(session, actor, slug)
    try:
        antispam.request_provider_activation(
            row, actor_email=actor.email, usage_scope=body.usage_scope, expires_at=body.expires_at
        )
    except antispam.AntispamError as exc:
        raise _bad(exc) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.SPAM_PROVIDER_ACTIVATION_REQUESTED,
        "reputation_provider",
        slug,
        {"usage_scope": row.usage_scope, "expires_at": row.expires_at},
    )
    session.commit()
    return antispam.provider_public_view(row)


@router.post("/spam/providers/{slug}/approve")
def spam_provider_approve(
    slug: str, session: DbSession, actor: ProviderManager, request: Request
) -> dict[str, Any]:
    row = _provider_or_404(session, actor, slug)
    try:
        antispam.approve_provider(row, actor_email=actor.email)
    except antispam.AntispamError as exc:
        _audit(
            session,
            actor,
            request,
            AuditAction.SPAM_PROVIDER_APPROVED,
            "reputation_provider",
            slug,
            {"reason": str(exc)},
            outcome="denied",
        )
        session.commit()
        raise _bad(exc) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.SPAM_PROVIDER_APPROVED,
        "reputation_provider",
        slug,
        {"requested_by": row.requested_by, "usage_scope": row.usage_scope},
    )
    session.commit()
    return antispam.provider_public_view(row)


@router.post("/spam/providers/{slug}/reject")
def spam_provider_reject(
    slug: str, session: DbSession, actor: ProviderManager, request: Request
) -> dict[str, Any]:
    row = _provider_or_404(session, actor, slug)
    try:
        antispam.reject_provider(row, actor_email=actor.email)
    except antispam.AntispamError as exc:
        raise _bad(exc) from exc
    _audit(session, actor, request, AuditAction.SPAM_PROVIDER_REJECTED, "reputation_provider", slug)
    session.commit()
    return antispam.provider_public_view(row)


@router.post("/spam/providers/{slug}/suspend")
def spam_provider_suspend(
    slug: str, session: DbSession, actor: ProviderManager, request: Request
) -> dict[str, Any]:
    row = _provider_or_404(session, actor, slug)
    antispam.suspend_provider(row)
    _audit(session, actor, request, AuditAction.SPAM_PROVIDER_SUSPENDED, "reputation_provider", slug)
    session.commit()
    return antispam.provider_public_view(row)


# ---------------------------------------------------------------------------------------------
# Аутентификация и репутация
# ---------------------------------------------------------------------------------------------
@router.get("/auth/distribution")
def auth_distribution(
    session: DbSession, actor: AuthReader, hours: Annotated[int, Query(ge=1, le=720)] = 24
) -> dict[str, Any]:
    return antispam.auth_distribution(session, actor.organization_id, hours=hours)


@router.get("/auth/conflicts")
def auth_conflicts(
    session: DbSession,
    actor: AuthReader,
    disposition: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    return {
        "items": antispam.conflicts_list(session, actor.organization_id, disposition=disposition, limit=limit)
    }


class ConflictDispositionRequest(BaseModel):
    disposition: str = Field(pattern="^(OPEN|EXPECTED|REAL_PROBLEM|FALSE_ALARM)$")


@router.put("/auth/conflicts/{conflict_id}")
def auth_conflict_review(
    conflict_id: str,
    body: ConflictDispositionRequest,
    session: DbSession,
    actor: ConflictReviewer,
    request: Request,
) -> dict[str, Any]:
    try:
        row = antispam.review_conflict(
            session, actor.organization_id, conflict_id, body.disposition, actor_email=actor.email
        )
    except antispam.AntispamError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.SPAM_AUTH_CONFLICT_DISPOSITION,
        "auth_conflict",
        conflict_id,
        {"disposition": body.disposition},
    )
    session.commit()
    return {"id": row.id, "disposition": row.disposition.value, "reviewed_by": row.reviewed_by}


@router.get("/auth/{message_id}")
def auth_of_message(
    message_id: str, session: DbSession, actor: AuthReader, settings: AppSettings
) -> dict[str, Any]:
    row = antispam.get_scan(session, actor.organization_id, message_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "результат сканирования не найден")
    if antispam.enrich_scan(session, settings, build_storage(settings), row):
        session.commit()
    return {
        "message_id": row.internet_message_id,
        "direction": row.direction,
        "auth": row.auth,
        "helo": row.helo,
        "missing_evidence": row.missing_evidence,
    }


@router.get("/reputation/ip/{ip}")
def reputation_ip(ip: str, session: DbSession, actor: ReputationReader) -> dict[str, Any]:
    return antispam.ip_reputation_view(session, actor.organization_id, ip)


@router.get("/reputation/domain/{domain}")
def reputation_domain(domain: str, session: DbSession, actor: ReputationReader) -> dict[str, Any]:
    return antispam.domain_reputation_view(session, actor.organization_id, domain)


# ---------------------------------------------------------------------------------------------
# Политики и симулятор
# ---------------------------------------------------------------------------------------------
class PolicyBody(BaseModel):
    # Неизвестные поля (в том числе enforcement_enabled) отвергаются, а не молча игнорируются.
    model_config = ConfigDict(extra="forbid")

    thresholds: dict[str, float] | None = None
    mode: str | None = None
    enabled_modules: list[str] | None = None
    rbl_provider_ids: list[str] | None = None
    bayes_enabled: bool | None = None
    greylisting_enabled: bool | None = None
    note: str = Field(default="", max_length=500)

    def as_body(self) -> dict[str, Any]:
        return {k: v for k, v in self.model_dump(exclude={"note"}).items() if v is not None}


def _policy_or_404(session: DbSession, actor: Actor, policy_id: str) -> SpamPolicyRecord:
    row = session.get(SpamPolicyRecord, policy_id)
    if row is None or row.organization_id != actor.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "политика не найдена")
    return row


@router.get("/spam/policies")
def spam_policies(session: DbSession, actor: SpamReader) -> dict[str, Any]:
    active = antispam.active_policy(session, actor.organization_id)
    return {
        "items": [antispam.policy_view(r) for r in antispam.list_policies(session, actor.organization_id)],
        "active_version": active.version if active.state.value == "ACTIVE_SHADOW" else None,
        "enforcement_enabled": False,
    }


@router.post("/spam/policies", status_code=status.HTTP_201_CREATED)
def spam_policy_create(
    body: PolicyBody, session: DbSession, actor: PolicyEditor, request: Request
) -> dict[str, Any]:
    payload = body.as_body()
    if "thresholds" in payload:
        payload["thresholds"] = {**SpamThresholds().model_dump(), **payload["thresholds"]}
    try:
        row = antispam.create_policy(
            session, actor.organization_id, payload, actor_email=actor.email, note=body.note
        )
    except antispam.AntispamError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.SPAM_POLICY_CREATED,
        "spam_policy",
        row.id,
        {"version": row.version},
    )
    session.commit()
    return antispam.policy_view(row)


@router.put("/spam/policies/{policy_id}")
def spam_policy_edit(
    policy_id: str, body: PolicyBody, session: DbSession, actor: PolicyEditor, request: Request
) -> dict[str, Any]:
    row = _policy_or_404(session, actor, policy_id)
    payload = body.as_body()
    if "thresholds" in payload:
        current = (row.body or {}).get("thresholds") or SpamThresholds().model_dump()
        payload["thresholds"] = {**current, **payload["thresholds"]}
    try:
        antispam.edit_policy(session, row, payload, actor_email=actor.email)
    except antispam.AntispamError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.SPAM_POLICY_CHANGED,
        "spam_policy",
        row.id,
        {"version": row.version},
    )
    session.commit()
    return antispam.policy_view(row)


@router.post("/spam/policies/{policy_id}/simulate")
def spam_policy_simulate(
    policy_id: str,
    session: DbSession,
    actor: PolicySimulator,
    request: Request,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> dict[str, Any]:
    row = _policy_or_404(session, actor, policy_id)
    result = antispam.simulate_policy(session, row, organization_id=actor.organization_id, limit=limit)
    _audit(
        session,
        actor,
        request,
        AuditAction.SPAM_POLICY_SIMULATED,
        "spam_policy",
        row.id,
        {"evaluated": result["evaluated"], "changed": result["changed"]},
    )
    session.commit()
    return result


class TransitionRequest(BaseModel):
    target: str


@router.post("/spam/policies/{policy_id}/transition")
def spam_policy_transition(
    policy_id: str, body: TransitionRequest, session: DbSession, actor: PolicyEditor, request: Request
) -> dict[str, Any]:
    row = _policy_or_404(session, actor, policy_id)
    # Одобрение кандидата — отдельное право и другой человек (четыре глаза).
    if body.target == "APPROVED" and Permission.APPROVE_SPAM_POLICY not in _perms(actor):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "нет права одобрять политику")
    try:
        antispam.transition_policy(session, row, body.target, actor_email=actor.email)
    except antispam.AntispamError as exc:
        _audit(
            session,
            actor,
            request,
            AuditAction.SPAM_POLICY_TRANSITION,
            "spam_policy",
            row.id,
            {"target": body.target, "reason": str(exc)},
            outcome="denied",
        )
        session.commit()
        raise _bad(exc) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.SPAM_POLICY_TRANSITION,
        "spam_policy",
        row.id,
        {"target": body.target, "version": row.version},
    )
    session.commit()
    return antispam.policy_view(row)


@router.post("/spam/policies/{policy_id}/activate-shadow")
def spam_policy_activate_shadow(
    policy_id: str, session: DbSession, actor: PolicyApprover, request: Request
) -> dict[str, Any]:
    row = _policy_or_404(session, actor, policy_id)
    try:
        antispam.transition_policy(session, row, "ACTIVE_SHADOW", actor_email=actor.email)
    except antispam.AntispamError as exc:
        raise _bad(exc) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.SPAM_POLICY_TRANSITION,
        "spam_policy",
        row.id,
        {"target": "ACTIVE_SHADOW", "version": row.version},
    )
    session.commit()
    return antispam.policy_view(row)


def _perms(actor: Actor) -> frozenset[Permission]:
    from ..security.rbac import ROLE_PERMISSIONS

    return ROLE_PERMISSIONS.get(actor.role, frozenset())


# ---------------------------------------------------------------------------------------------
# Ключи подписи DKIM
# ---------------------------------------------------------------------------------------------
class DkimKeyCreate(BaseModel):
    domain: str = Field(max_length=253)
    selector: str = Field(max_length=63)


@router.get("/dkim/keys")
def dkim_keys(session: DbSession, actor: DkimReader) -> dict[str, Any]:
    return {
        "items": [
            antispam.dkim_public_view(k) for k in antispam.dkim_keys_list(session, actor.organization_id)
        ]
    }


def _key_or_404(session: DbSession, actor: Actor, key_id: str) -> DkimKeyRecord:
    row = session.get(DkimKeyRecord, key_id)
    if row is None or row.organization_id != actor.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "ключ не найден")
    return row


@router.post("/dkim/keys", status_code=status.HTTP_201_CREATED)
def dkim_key_generate(
    body: DkimKeyCreate,
    session: DbSession,
    actor: DkimGenerator,
    request: Request,
    response: Response,
    settings: AppSettings,
) -> dict[str, Any]:
    """Генерация. Закрытая часть возвращается ОДИН раз и нигде не сохраняется: её нужно сразу положить в
    хранилище секретов узла. В рабочей установке рекомендуется генерировать ключ на узле и регистрировать
    в панели только открытую запись."""
    try:
        row, pem = antispam.generate_dkim_key(
            session,
            actor.organization_id,
            body.domain,
            body.selector,
            actor_email=actor.email,
            trusted_domains=set(settings.antispam_signing_domain_set),
        )
    except antispam.AntispamError as exc:
        raise _bad(exc) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.SPAM_DKIM_KEY_GENERATED,
        "dkim_key",
        row.id,
        {"domain": row.domain, "selector": row.selector},
    )
    session.commit()
    response.headers["Cache-Control"] = "no-store"
    return {
        **antispam.dkim_public_view(row),
        "private_key_pem": pem.decode("ascii"),
        "private_key_returned_once": True,
    }


@router.post("/dkim/keys/{key_id}/verify-dns")
def dkim_key_verify_dns(
    key_id: str, session: DbSession, actor: DkimGenerator, request: Request, settings: AppSettings
) -> dict[str, Any]:
    row = _key_or_404(session, actor, key_id)
    resolvers = tuple(r.strip() for r in settings.antispam_dns_resolvers.split(",") if r.strip())
    records, error = txt_records(
        f"{row.selector}._domainkey.{row.domain}",
        nameservers=resolvers,
        timeout=settings.antispam_dns_timeout_seconds,
    )
    try:
        antispam.verify_dkim_dns(row, records, dns_error=error)
    except antispam.AntispamError as exc:
        raise _bad(exc) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.SPAM_DKIM_KEY_DNS_CHECKED,
        "dkim_key",
        row.id,
        {"status": row.status.value, "problems": row.failure},
    )
    session.commit()
    return antispam.dkim_public_view(row)


@router.post("/dkim/keys/{key_id}/activate")
def dkim_key_activate(
    key_id: str, session: DbSession, actor: DkimActivator, request: Request, settings: AppSettings
) -> dict[str, Any]:
    row = _key_or_404(session, actor, key_id)
    try:
        antispam.activate_dkim_key(
            row, actor_email=actor.email, trusted_domains=set(settings.antispam_signing_domain_set)
        )
    except antispam.AntispamError as exc:
        _audit(
            session,
            actor,
            request,
            AuditAction.SPAM_DKIM_KEY_ACTIVATED,
            "dkim_key",
            row.id,
            {"reason": str(exc)},
            outcome="denied",
        )
        session.commit()
        raise _bad(exc) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.SPAM_DKIM_KEY_ACTIVATED,
        "dkim_key",
        row.id,
        {"domain": row.domain, "selector": row.selector, "generated_by": row.generated_by},
    )
    session.commit()
    return antispam.dkim_public_view(row)


@router.post("/dkim/keys/{key_id}/retire")
def dkim_key_retire(key_id: str, session: DbSession, actor: DkimRetirer, request: Request) -> dict[str, Any]:
    row = _key_or_404(session, actor, key_id)
    before = row.status.value
    try:
        antispam.retire_dkim_key(row)
    except antispam.AntispamError as exc:
        raise _bad(exc) from exc
    action = (
        AuditAction.SPAM_DKIM_KEY_RETIRING
        if row.status.value == "RETIRING"
        else AuditAction.SPAM_DKIM_KEY_RETIRED
    )
    _audit(session, actor, request, action, "dkim_key", row.id, {"from": before, "to": row.status.value})
    session.commit()
    return antispam.dkim_public_view(row)


# ---------------------------------------------------------------------------------------------
# Bayes
# ---------------------------------------------------------------------------------------------
class BayesSampleRequest(BaseModel):
    message_id: str = Field(max_length=998)
    label: str = Field(pattern="^(HAM|SPAM)$")
    source: str


@router.get("/spam/bayes")
def bayes_status(session: DbSession, actor: SpamReader) -> dict[str, Any]:
    return antispam.bayes_status(session, actor.organization_id)


@router.post("/spam/bayes/samples", status_code=status.HTTP_201_CREATED)
def bayes_learn(
    body: BayesSampleRequest, session: DbSession, actor: ConflictReviewer, request: Request
) -> dict[str, Any]:
    try:
        row = antispam.add_bayes_sample(
            session,
            actor.organization_id,
            message_id=body.message_id,
            label=body.label,
            source=body.source,
            actor_email=actor.email,
        )
    except antispam.AntispamError as exc:
        _audit(
            session,
            actor,
            request,
            AuditAction.SPAM_BAYES_LEARNED,
            "bayes_sample",
            body.message_id,
            {"reason": str(exc), "source": body.source},
            outcome="denied",
        )
        session.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    _audit(
        session,
        actor,
        request,
        AuditAction.SPAM_BAYES_LEARNED,
        "bayes_sample",
        row.id,
        {"label": body.label, "source": body.source},
    )
    session.commit()
    return antispam.bayes_status(session, actor.organization_id)


@router.delete("/spam/bayes/samples/{message_id}")
def bayes_unlearn(
    message_id: str, session: DbSession, actor: ConflictReviewer, request: Request
) -> dict[str, Any]:
    try:
        row = antispam.unlearn_bayes_sample(session, actor.organization_id, message_id)
    except antispam.AntispamError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    _audit(session, actor, request, AuditAction.SPAM_BAYES_UNLEARNED, "bayes_sample", row.id)
    session.commit()
    return antispam.bayes_status(session, actor.organization_id)


# ---------------------------------------------------------------------------------------------
# Точки для узлов
# ---------------------------------------------------------------------------------------------
def _organization(session: DbSession) -> Organization:
    org = session.execute(select(Organization)).scalars().first()
    if org is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "организация не настроена")
    return org


class ScansRequest(BaseModel):
    node_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    #: Элементы проверяются по одному: плохая запись не должна отбрасывать всю пачку.
    scans: list[Any] = Field(max_length=antispam.MAX_SCANS_PER_BATCH)


@agent_router.post("/spam-scans")
def agent_spam_scans(
    body: ScansRequest, session: DbSession, _auth: ShadowAuth, settings: AppSettings
) -> dict[str, Any]:
    org = _organization(session)
    outcome = antispam.ingest_scans(
        session,
        settings,
        organization_id=org.id,
        node_id=body.node_id,
        scans=list(body.scans),
        storage=build_storage(settings),
    )
    session.commit()
    return {"accepted": outcome.accepted, "duplicate": outcome.duplicate, "rejected": outcome.rejected}


@agent_router.get("/rspamd-config")
def agent_rspamd_config(session: DbSession, _auth: NodeAuth) -> dict[str, Any]:
    """Что панель назначает сканеру. Сети подписи, адреса DNS и секреты определяет узел."""
    org = _organization(session)
    return antispam.node_overlay(session, org.id)


class RspamdStatus(BaseModel):
    node_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    state: dict[str, Any]


@agent_router.post("/rspamd-status")
def agent_rspamd_status(body: RspamdStatus, session: DbSession, _auth: NodeAuth) -> dict[str, Any]:
    org = _organization(session)
    antispam.remember_node_state(session, org.id, body.node_id, body.state)
    session.commit()
    return {"ok": True}
