"""Анти-спам, аутентификация и репутация: приём результатов сканера и управление (ТЗ 1.2 §6–§35).

Что делает этот модуль и чего не делает:

* принимает записи самого сканера (не заголовки писем), нормализует их и хранит как свидетельства;
* ничего не исполняет над почтой: ``applied_action`` всегда ``OBSERVE_ONLY``;
* не хранит секретов: ни закрытых ключей подписи, ни секретных зон провайдеров;
* разделяет класс спама и вердикт безопасности: они лежат в разных полях и считаются разно.
"""

from __future__ import annotations

import hashlib
import logging
import random
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email import message_from_bytes
from typing import Any

from msp_antispam import bayes as bayes_mod
from msp_antispam import dkim_keys, reputation, validation
from msp_antispam.analysis import AntispamAnalysis, analyze
from msp_antispam.auth import domain_of
from msp_antispam.authres import parse_authentication_results
from msp_antispam.conflicts import compare
from msp_antispam.mapping import default_mapping
from msp_antispam.model import RspamdEvidence
from msp_antispam.policy import (
    CandidateState,
    PolicyError,
    SimulationInput,
    SpamPolicy,
    simulate,
)
from msp_antispam.providers import ReputationProvider
from msp_antispam.rates import AnomalyKind, anomaly
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.models import Organization
from ..db.models_antispam import (
    AuthConflictRecord,
    BayesSample,
    ConflictDisposition,
    DkimKeyRecord,
    DkimKeyStatus,
    DomainReputationRecord,
    ProviderApprovalState,
    ReputationProviderRecord,
    SourceIpReputationRecord,
    SpamPolicyRecord,
    SpamPolicyState,
    SpamReview,
    SpamScan,
)
from ..db.models_transport import TransportMessage
from .storage import ObjectStorage

logger = logging.getLogger(__name__)

MAX_SCANS_PER_BATCH = 200
MAX_KNOWN_SET = 200


def now() -> datetime:
    return datetime.now(UTC)


class AntispamError(Exception):
    """Нарушение правила предметной области (четыре глаза, лицензия, порядок состояний)."""


# ---------------------------------------------------------------------------------------------
# Политика
# ---------------------------------------------------------------------------------------------
def _policy_from_record(record: SpamPolicyRecord) -> SpamPolicy:
    body = dict(record.body or {})
    body.update(
        {
            "version": record.version,
            "state": record.state.value,
            "edited_by": record.edited_by,
            "approved_by": record.approved_by,
        }
    )
    return SpamPolicy.model_validate(body)


def active_policy(session: Session, organization_id: str) -> SpamPolicy:
    """Действующая политика: кандидат ACTIVE_SHADOW, иначе значения по умолчанию.

    Политика на этапе 1.2 влияет только на то, как MSP классифицирует и что ПРЕДЛАГАЕТ; поток почты
    она не меняет ни в одном состоянии.
    """
    record = (
        session.execute(
            select(SpamPolicyRecord)
            .where(
                SpamPolicyRecord.organization_id == organization_id,
                SpamPolicyRecord.state == SpamPolicyState.ACTIVE_SHADOW,
            )
            .order_by(SpamPolicyRecord.version.desc())
        )
        .scalars()
        .first()
    )
    if record is None:
        return SpamPolicy(organization_id=organization_id)
    return _policy_from_record(record)


def list_policies(session: Session, organization_id: str) -> list[SpamPolicyRecord]:
    return list(
        session.execute(
            select(SpamPolicyRecord)
            .where(SpamPolicyRecord.organization_id == organization_id)
            .order_by(SpamPolicyRecord.version.desc())
        ).scalars()
    )


def _next_policy_version(session: Session, organization_id: str) -> int:
    top = session.execute(
        select(func.max(SpamPolicyRecord.version)).where(SpamPolicyRecord.organization_id == organization_id)
    ).scalar_one()
    return int(top or 0) + 1


def create_policy(
    session: Session, organization_id: str, body: dict[str, Any], *, actor_email: str, note: str = ""
) -> SpamPolicyRecord:
    """Новый кандидат в состоянии DRAFT. Включить принуждение через него нельзя."""
    try:
        policy = SpamPolicy.model_validate(
            {
                **body,
                "organization_id": organization_id,
                "state": "DRAFT",
                "edited_by": actor_email,
                "approved_by": "",
            }
        )
    except (PolicyError, ValueError) as exc:
        raise AntispamError(_first_error(exc)) from exc
    record = SpamPolicyRecord(
        organization_id=organization_id,
        version=_next_policy_version(session, organization_id),
        state=SpamPolicyState.DRAFT,
        body=_policy_body(policy),
        edited_by=actor_email,
        note=note[:500],
    )
    session.add(record)
    session.flush()
    return record


def _policy_body(policy: SpamPolicy) -> dict[str, Any]:
    body = policy.model_dump(mode="json")
    for key in ("version", "state", "edited_by", "approved_by"):
        body.pop(key, None)
    return body


def _first_error(exc: Exception) -> str:
    errors = getattr(exc, "errors", None)
    if callable(errors):
        try:
            first = errors()[0]
            return str(first.get("msg", exc))[:300]
        except (IndexError, KeyError, TypeError):
            return str(exc)[:300]
    return str(exc)[:300]


def edit_policy(
    session: Session, record: SpamPolicyRecord, body: dict[str, Any], *, actor_email: str
) -> SpamPolicyRecord:
    if record.state not in (SpamPolicyState.DRAFT, SpamPolicyState.SHADOW):
        raise AntispamError("правка допустима только для кандидата в состоянии DRAFT или SHADOW")
    try:
        policy = SpamPolicy.model_validate(
            {
                **_policy_from_record(record).model_dump(),
                **body,
                "state": record.state.value,
                "edited_by": actor_email,
                "approved_by": "",
            }
        )
    except (PolicyError, ValueError) as exc:
        raise AntispamError(_first_error(exc)) from exc
    record.body = _policy_body(policy)
    record.edited_by = actor_email
    return record


def transition_policy(
    session: Session, record: SpamPolicyRecord, target: str, *, actor_email: str
) -> SpamPolicyRecord:
    try:
        wanted = CandidateState(target)
    except ValueError as exc:
        raise AntispamError("такого состояния нет; состояния ACTIVE_ENFORCING не существует") from exc
    try:
        updated = _policy_from_record(record).transition(wanted, actor=actor_email)
    except (PolicyError, ValueError) as exc:
        raise AntispamError(_first_error(exc)) from exc
    if wanted is CandidateState.ACTIVE_SHADOW:
        # Действующим может быть один кандидат: прежний возвращается в APPROVED.
        for other in list_policies(session, record.organization_id):
            if other.id != record.id and other.state is SpamPolicyState.ACTIVE_SHADOW:
                other.state = SpamPolicyState.APPROVED
    record.state = SpamPolicyState(updated.state.value)
    record.approved_by = updated.approved_by
    return record


# ---------------------------------------------------------------------------------------------
# Провайдеры репутации
# ---------------------------------------------------------------------------------------------
def providers(session: Session, organization_id: str) -> list[ReputationProviderRecord]:
    return list(
        session.execute(
            select(ReputationProviderRecord)
            .where(ReputationProviderRecord.organization_id == organization_id)
            .order_by(ReputationProviderRecord.slug)
        ).scalars()
    )


def provider_definition(record: ReputationProviderRecord) -> ReputationProvider:
    """Определение с учётом одобрения: включённость и допуск берутся из записи, а не из JSON."""
    data = dict(record.definition or {})
    data["id"] = record.slug
    data["enabled"] = bool(record.enabled and record.approval_state is ProviderApprovalState.APPROVED)
    if record.approval_state is ProviderApprovalState.APPROVED:
        data["approval"] = {
            "license_approved": True,
            "approved_by": record.approved_by or None,
            "approved_at": record.approved_at,
            "usage_scope": record.usage_scope,
            "expires_at": record.expires_at,
        }
    else:
        data["approval"] = {"license_approved": False}
    return ReputationProvider.model_validate(data)


def create_provider(
    session: Session, organization_id: str, definition: dict[str, Any], *, actor_email: str
) -> ReputationProviderRecord:
    """Заведение провайдера. Всегда выключен и без допуска: включить его можно только отдельным действием."""
    data = {k: v for k, v in definition.items() if k not in ("enabled", "approval")}
    data["enabled"] = False
    try:
        provider = ReputationProvider.model_validate(data)
    except ValueError as exc:
        raise AntispamError(_first_error(exc)) from exc
    existing = session.execute(
        select(ReputationProviderRecord).where(
            ReputationProviderRecord.organization_id == organization_id,
            ReputationProviderRecord.slug == provider.id,
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise AntispamError("провайдер с таким идентификатором уже есть")
    stored = provider.model_dump(mode="json", exclude={"approval", "enabled", "id"})
    record = ReputationProviderRecord(
        organization_id=organization_id,
        slug=provider.id,
        definition=stored,
        enabled=False,
        approval_state=ProviderApprovalState.DRAFT,
        requested_by=actor_email,
    )
    session.add(record)
    session.flush()
    return record


def request_provider_activation(
    record: ReputationProviderRecord, *, actor_email: str, usage_scope: str, expires_at: datetime | None
) -> ReputationProviderRecord:
    """Первый человек запрашивает включение. Область применения лицензии обязательна."""
    if record.approval_state not in (
        ProviderApprovalState.DRAFT,
        ProviderApprovalState.REJECTED,
        ProviderApprovalState.SUSPENDED,
    ):
        raise AntispamError("запрос включения возможен из состояний DRAFT, REJECTED, SUSPENDED")
    mode = (record.definition or {}).get("license_mode", "PUBLIC_NONCOMMERCIAL")
    if mode in ("PUBLIC_NONCOMMERCIAL", "COMMERCIAL_LICENSED") and not usage_scope.strip():
        raise AntispamError("для внешнего списка нужна область применения лицензии (usage_scope)")
    record.requested_by = actor_email
    record.usage_scope = usage_scope.strip()[:256]
    record.expires_at = expires_at
    record.approval_state = ProviderApprovalState.PENDING_APPROVAL
    return record


def approve_provider(record: ReputationProviderRecord, *, actor_email: str) -> ReputationProviderRecord:
    """Второй человек одобряет. Тот, кто запросил, одобрить не может (четыре глаза, ТЗ 1.2 §34)."""
    if record.approval_state is not ProviderApprovalState.PENDING_APPROVAL:
        raise AntispamError("одобрять нечего: запроса на включение нет")
    if actor_email == record.requested_by:
        raise AntispamError("одобряет другой человек: запросивший включение не может его же одобрить")
    record.approval_state = ProviderApprovalState.APPROVED
    record.approved_by = actor_email
    record.approved_at = now()
    record.enabled = True
    return record


def reject_provider(record: ReputationProviderRecord, *, actor_email: str) -> ReputationProviderRecord:
    if record.approval_state is not ProviderApprovalState.PENDING_APPROVAL:
        raise AntispamError("отклонять нечего")
    record.approval_state = ProviderApprovalState.REJECTED
    record.enabled = False
    return record


def suspend_provider(record: ReputationProviderRecord) -> ReputationProviderRecord:
    record.approval_state = ProviderApprovalState.SUSPENDED
    record.enabled = False
    return record


def provider_public_view(record: ReputationProviderRecord) -> dict[str, Any]:
    """Что показывается в консоли. Секретной зоны здесь нет по построению."""
    definition = provider_definition(record)
    view = definition.public_view()
    view.update(
        {
            "approval_state": record.approval_state.value,
            "requested_by": record.requested_by,
            "approved_by": record.approved_by,
            "approved_at": record.approved_at,
            "usage_scope": record.usage_scope,
            "expires_at": record.expires_at,
            "last_error": record.last_error,
            "status": definition.effective_status().value,
        }
    )
    return view


def secret_provider_ids(session: Session, organization_id: str) -> list[str]:
    return [
        r.slug for r in providers(session, organization_id) if (r.definition or {}).get("zone_secret_file")
    ]


# ---------------------------------------------------------------------------------------------
# Приём результатов сканера
# ---------------------------------------------------------------------------------------------
@dataclass
class IngestOutcome:
    accepted: int = 0
    duplicate: int = 0
    rejected: int = 0


def _headers_of(raw: bytes) -> dict[str, list[str]]:
    message = message_from_bytes(raw)
    out: dict[str, list[str]] = {}
    for name, value in message.items():
        out.setdefault(name.lower(), []).append(str(value))
    return out


def _find_transport_message(
    session: Session, organization_id: str, message_id: str, queue_id: str
) -> TransportMessage | None:
    if not message_id:
        return None
    rows = (
        session.execute(
            select(TransportMessage)
            .where(
                TransportMessage.organization_id == organization_id,
                TransportMessage.internet_message_id.in_([message_id, f"<{message_id}>"]),
            )
            .order_by(TransportMessage.created_at.desc())
        )
        .scalars()
        .all()
    )
    for row in rows:
        if not queue_id or row.queue_id == queue_id:
            return row
    return rows[0] if rows else None


def _load_raw(storage: ObjectStorage | None, message: TransportMessage | None) -> bytes | None:
    if storage is None or message is None or not message.raw_storage_key:
        return None
    try:
        return storage.get(message.raw_storage_key)
    except Exception as exc:  # noqa: BLE001 - недоступное хранилище не мешает принять результат сканера
        logger.warning("antispam.raw_unavailable", extra={"error": type(exc).__name__})
        return None


def _clip_set(values: list[Any], new: str) -> tuple[list[Any], bool]:
    if new in values:
        return values, False
    if len(values) >= MAX_KNOWN_SET:
        return values, True
    return [*values, new], True


def _update_reputation(
    session: Session, org_id: str, ip: str, sender: str, domain: str, authenticated: bool, at: datetime
) -> None:
    if ip:
        row = session.execute(
            select(SourceIpReputationRecord).where(
                SourceIpReputationRecord.organization_id == org_id, SourceIpReputationRecord.ip == ip
            )
        ).scalar_one_or_none()
        known = (
            SourceIpReputationRecord(
                organization_id=org_id,
                ip=ip,
                first_seen=at,
                last_seen=at,
                message_count=0.0,
                threat_count=0.0,
                spam_count=0.0,
                legitimate_count=0.0,
                distinct_senders=0,
                distinct_domains=0,
                known_senders=[],
                known_domains=[],
            )
            if row is None
            else row
        )
        if row is None:
            session.add(known)
        model = reputation.observe_ip(
            reputation.SourceIpReputation(
                ip,
                known.first_seen,
                known.last_seen,
                known.message_count,
                known.threat_count,
                known.spam_count,
                known.legitimate_count,
                known.distinct_senders,
                known.distinct_domains,
                reputation.Analyst(known.analyst_confirmed) if known.analyst_confirmed else None,
            ),
            ip,
            reputation.Outcome.UNKNOWN,
            new_sender=bool(sender) and sender not in (known.known_senders or []),
            new_domain=bool(domain) and domain not in (known.known_domains or []),
            now=at,
        )
        known.message_count, known.threat_count = model.message_count, model.threat_count
        known.spam_count, known.legitimate_count = model.spam_count, model.legitimate_count
        known.distinct_senders, known.distinct_domains = model.distinct_senders, model.distinct_domains
        known.last_seen = at
        if sender:
            known.known_senders, _ = _clip_set(list(known.known_senders or []), sender)
        if domain:
            known.known_domains, _ = _clip_set(list(known.known_domains or []), domain)
    if domain:
        drow = session.execute(
            select(DomainReputationRecord).where(
                DomainReputationRecord.organization_id == org_id, DomainReputationRecord.domain == domain
            )
        ).scalar_one_or_none()
        dknown = (
            DomainReputationRecord(
                organization_id=org_id,
                domain=domain,
                first_seen=at,
                last_seen=at,
                message_count=0.0,
                threat_count=0.0,
                spam_count=0.0,
                legitimate_count=0.0,
                auth_pass_count=0.0,
            )
            if drow is None
            else drow
        )
        if drow is None:
            session.add(dknown)
        dmodel = reputation.observe_domain(
            reputation.DomainReputation(
                domain,
                dknown.first_seen,
                dknown.last_seen,
                dknown.message_count,
                dknown.threat_count,
                dknown.spam_count,
                dknown.legitimate_count,
                dknown.auth_pass_count,
                reputation.Analyst(dknown.analyst_confirmed) if dknown.analyst_confirmed else None,
            ),
            domain,
            reputation.Outcome.UNKNOWN,
            authenticated=authenticated,
            now=at,
        )
        dknown.message_count, dknown.auth_pass_count = dmodel.message_count, dmodel.auth_pass_count
        dknown.last_seen = at


def ingest_scans(
    session: Session,
    settings: Settings,
    *,
    organization_id: str,
    node_id: str,
    scans: list[dict[str, Any]],
    storage: ObjectStorage | None = None,
) -> IngestOutcome:
    """Принять записи сканера. Повторная доставка той же записи безвредна."""
    outcome = IngestOutcome()
    policy = active_policy(session, organization_id)
    org = session.get(Organization, organization_id)
    protected = tuple(org.corporate_domains or ()) if org else settings.corporate_domain_list
    secret_ids = secret_provider_ids(session, organization_id)
    mapping_version = default_mapping().version
    for record in scans[:MAX_SCANS_PER_BATCH]:
        if not isinstance(record, dict):
            outcome.rejected += 1
            continue
        try:
            first = analyze(record, policy, protected_domains=protected, secret_provider_ids=secret_ids)
            evidence = first.evidence
        except Exception as exc:  # noqa: BLE001 - одна плохая запись не должна останавливать остальные
            logger.warning("antispam.scan_unparsed", extra={"error": type(exc).__name__})
            outcome.rejected += 1
            continue
        if evidence is None or not evidence.message_id:
            outcome.rejected += 1
            continue
        transport_message = _find_transport_message(
            session, organization_id, evidence.message_id, evidence.transport_message_id
        )
        raw = _load_raw(storage, transport_message)
        headers = _headers_of(raw) if raw else {}
        received = headers.get("received", [])
        analysis = analyze(
            record,
            policy,
            headers=headers,
            received_headers=received,
            protected_domains=protected,
            secret_provider_ids=secret_ids,
            peername_lookup=True,
        )
        row = _store_scan(
            session,
            organization_id,
            node_id,
            evidence,
            analysis,
            record,
            transport_message,
            headers,
            mapping_version,
        )
        if row is None:
            outcome.duplicate += 1
            continue
        outcome.accepted += 1
        _record_conflicts(session, organization_id, row, analysis, headers, evidence)
        sender = domain_of(evidence.envelope_from)
        _update_reputation(
            session,
            organization_id,
            evidence.client_ip,
            evidence.envelope_from,
            analysis.auth.dmarc.from_domain or sender,
            analysis.auth.dmarc.result.value == "PASS",
            row.received_at,
        )
        row.details = {**(row.details or {}), **_rate_details(session, organization_id, row, record)}
    return outcome


def _store_scan(
    session: Session,
    organization_id: str,
    node_id: str,
    evidence: RspamdEvidence,
    analysis: AntispamAnalysis,
    record: dict[str, Any],
    transport_message: TransportMessage | None,
    headers: dict[str, list[str]],
    mapping_version: str,
) -> SpamScan | None:
    sender_domain = analysis.auth.dmarc.from_domain if analysis.auth else domain_of(evidence.envelope_from)
    row = SpamScan(
        organization_id=organization_id,
        node_id=node_id,
        queue_id=evidence.transport_message_id,
        internet_message_id=evidence.message_id,
        transport_message_id=transport_message.id if transport_message else None,
        direction=evidence.direction.value,
        score=evidence.score,
        required_score=evidence.required_score,
        suggested_action=evidence.suggested_action.value,
        applied_action=analysis.applied_action.value,
        spam_class=analysis.spam_class.value,
        symbols=[s.model_dump(mode="json") for s in evidence.symbols],
        groups=list(evidence.groups),
        auth=analysis.auth.model_dump(mode="json") if analysis.auth else {},
        helo=analysis.helo.model_dump(mode="json") if analysis.helo else {},
        signals=[
            {"code": s.code, "kind": s.kind, "risk_effect": s.risk_effect, "symbol": s.symbol}
            for s in (analysis.signals.signals if analysis.signals else [])
        ],
        unmapped_symbols=list(analysis.signals.unmapped if analysis.signals else []),
        missing_evidence=list(analysis.missing_evidence),
        scan_time_ms=evidence.scan_time_ms,
        rspamd_version=evidence.rspamd_version,
        rspamd_config_version=evidence.config_version,
        symbol_mapping_version=mapping_version,
        client_ip=evidence.client_ip,
        sender_domain=(sender_domain or "")[:255],
        details={
            "recipient_count": len(record.get("rcpt") or []) if isinstance(record.get("rcpt"), list) else 0,
            "bulk": analysis.bulk.reasons,
            "forged_scanner_headers": sorted(
                {h for h in headers if h.startswith("x-spamd-") or h in ("x-spam-status", "x-rspamd-score")}
            ),
            "classification_reasons": analysis.classification.reasons,
        },
        received_at=evidence.created_at,
    )
    try:
        with session.begin_nested():
            session.add(row)
            session.flush()
    except IntegrityError:
        return None
    return row


def _record_conflicts(
    session: Session,
    organization_id: str,
    row: SpamScan,
    analysis: AntispamAnalysis,
    headers: dict[str, list[str]],
    evidence: RspamdEvidence,
) -> None:
    if analysis.auth is None:
        return
    for raw in headers.get("authentication-results", []):
        parsed = parse_authentication_results(raw)
        if parsed is None:
            continue
        report = compare(parsed, analysis.auth, msp_client_ip=evidence.client_ip)
        for conflict in report.conflicts:
            session.add(
                AuthConflictRecord(
                    organization_id=organization_id,
                    scan_id=row.id,
                    kind=conflict.kind.value,
                    upstream_value=conflict.upstream_value[:64],
                    msp_value=conflict.msp_value[:64],
                    note=conflict.note[:500],
                )
            )


def _rate_details(
    session: Session, organization_id: str, row: SpamScan, record: dict[str, Any]
) -> dict[str, Any]:
    """Аномалии частоты: только свидетельства (ТЗ 1.2 §18, §32)."""
    since = row.received_at - timedelta(hours=1)
    anomalies: list[dict[str, Any]] = []
    if row.client_ip:
        senders = session.execute(
            select(func.count(func.distinct(SpamScan.sender_domain))).where(
                SpamScan.organization_id == organization_id,
                SpamScan.client_ip == row.client_ip,
                SpamScan.received_at >= since,
            )
        ).scalar_one()
        found = anomaly(AnomalyKind.SENDERS_PER_IP, float(senders), [], floor=25)
        if found:
            anomalies.append(
                {
                    "kind": found.kind.value,
                    "observed": found.observed,
                    "severity": found.severity.value,
                    "action": found.action,
                }
            )
    if row.sender_domain:
        volume = session.execute(
            select(func.count()).where(
                SpamScan.organization_id == organization_id,
                SpamScan.sender_domain == row.sender_domain,
                SpamScan.received_at >= since,
            )
        ).scalar_one()
        found = anomaly(AnomalyKind.DOMAIN_VOLUME_SPIKE, float(volume), [], floor=200)
        if found:
            anomalies.append(
                {
                    "kind": found.kind.value,
                    "observed": found.observed,
                    "severity": found.severity.value,
                    "action": found.action,
                }
            )
    recipients = len(record.get("rcpt") or []) if isinstance(record.get("rcpt"), list) else 0
    found = anomaly(AnomalyKind.BURST_TO_MANY_RECIPIENTS, float(recipients), [], floor=50)
    if found:
        anomalies.append(
            {
                "kind": found.kind.value,
                "observed": found.observed,
                "severity": found.severity.value,
                "action": found.action,
            }
        )
    if row.direction == "OUTBOUND" and recipients:
        out = anomaly(AnomalyKind.OUTBOUND_ACCOUNT_ANOMALY, float(recipients), [], floor=100)
        if out:
            anomalies.append(
                {
                    "kind": out.kind.value,
                    "observed": out.observed,
                    "severity": out.severity.value,
                    "action": out.action,
                }
            )
    return {"rate_anomalies": anomalies}


# ---------------------------------------------------------------------------------------------
# Представления
# ---------------------------------------------------------------------------------------------
def scan_view(row: SpamScan, *, full: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": row.id,
        "message_id": row.internet_message_id,
        "queue_id": row.queue_id,
        "node_id": row.node_id,
        "direction": row.direction,
        "score": row.score,
        "required_score": row.required_score,
        "suggested_action": row.suggested_action,
        "applied_action": row.applied_action,
        "spam_class": row.spam_class,
        "security_verdict": row.security_verdict,
        "client_ip": row.client_ip,
        "sender_domain": row.sender_domain,
        "spf": (row.auth or {}).get("spf", {}).get("result"),
        "dkim": (row.auth or {}).get("dkim", {}).get("result"),
        "dmarc": (row.auth or {}).get("dmarc", {}).get("result"),
        "arc": (row.auth or {}).get("arc", {}).get("result"),
        "received_at": row.received_at,
        "missing_evidence": row.missing_evidence,
    }
    if full:
        out.update(
            {
                "symbols": row.symbols,
                "groups": row.groups,
                "auth": row.auth,
                "helo": row.helo,
                "signals": row.signals,
                "unmapped_symbols": row.unmapped_symbols,
                "scan_time_ms": row.scan_time_ms,
                "rspamd_version": row.rspamd_version,
                "rspamd_config_version": row.rspamd_config_version,
                "symbol_mapping_version": row.symbol_mapping_version,
                "details": row.details,
                "transport_message_id": row.transport_message_id,
            }
        )
    return out


def get_scan(session: Session, organization_id: str, identifier: str) -> SpamScan | None:
    row = session.get(SpamScan, identifier)
    if row is not None and row.organization_id == organization_id:
        return row
    return (
        session.execute(
            select(SpamScan)
            .where(
                SpamScan.organization_id == organization_id,
                SpamScan.internet_message_id.in_([identifier, identifier.strip("<>")]),
            )
            .order_by(SpamScan.received_at.desc())
        )
        .scalars()
        .first()
    )


def list_scans(
    session: Session,
    organization_id: str,
    *,
    limit: int = 50,
    spam_class: str | None = None,
    suggested_action: str | None = None,
    direction: str | None = None,
) -> list[SpamScan]:
    query = select(SpamScan).where(SpamScan.organization_id == organization_id)
    if spam_class:
        query = query.where(SpamScan.spam_class == spam_class)
    if suggested_action:
        query = query.where(SpamScan.suggested_action == suggested_action)
    if direction:
        query = query.where(SpamScan.direction == direction)
    return list(session.execute(query.order_by(SpamScan.received_at.desc()).limit(min(limit, 500))).scalars())


def summary(session: Session, organization_id: str, *, hours: int = 24) -> dict[str, Any]:
    since = now() - timedelta(hours=hours)
    rows = list(
        session.execute(
            select(SpamScan)
            .where(SpamScan.organization_id == organization_id, SpamScan.received_at >= since)
            .limit(20000)
        ).scalars()
    )
    classes = Counter(r.spam_class for r in rows)
    actions = Counter(r.suggested_action for r in rows)
    symbols: Counter[str] = Counter()
    rbl_hits = 0
    histogram = Counter()
    for r in rows:
        for s in r.symbols or []:
            name = str(s.get("name", ""))
            if name.startswith("MSP_RBL_"):
                rbl_hits += 1
            elif float(s.get("score", 0) or 0) != 0:
                symbols[name] += 1
        histogram[_bucket(r.score)] += 1
    nodes = _scanner_health(session, organization_id)
    metrics = validation_metrics(session, organization_id, hours=hours)
    return {
        "window_hours": hours,
        "analyzed": len(rows),
        "spam_classes": dict(classes),
        "suggested_actions": dict(actions),
        "score_histogram": dict(sorted(histogram.items(), key=lambda kv: float(kv[0].split("..")[0]))),
        "top_symbols": symbols.most_common(15),
        "rbl_hits": rbl_hits,
        "applied_action": "OBSERVE_ONLY",
        "enforcement_enabled": False,
        "false_positive_metrics": {
            "spam_fp_per_1000": metrics.spam_fp_per_1000,
            "reviewed": metrics.reviewed,
            "spam_fn": metrics.spam_fn,
        },
        "health": nodes,
    }


def _bucket(score: float) -> str:
    low = int(score // 2) * 2 if score >= 0 else int(-((-score) // 2 + 1)) * 2
    return f"{low}..{low + 2}"


def _scanner_health(session: Session, organization_id: str) -> list[dict[str, Any]]:
    from ..db.models_transport import TransportNode

    out = []
    for node in session.execute(
        select(TransportNode).where(TransportNode.organization_id == organization_id)
    ).scalars():
        state = (node.details or {}).get("rspamd") or {}
        out.append({"node_id": node.node_id, "rspamd": state or None})
    return out


def rules_view() -> dict[str, Any]:
    mapping = default_mapping()
    return {
        "symbol_mapping_version": mapping.version,
        "entries": [
            {"symbol": e.symbol, "signal": e.signal, "kind": e.kind, "risk_effect": e.risk_effect}
            for e in mapping.entries
        ],
        "note": (
            "Неизвестные символы сохраняются как свидетельство и не влияют на риск, "
            "пока не добавлены в отображение."
        ),
    }


def auth_distribution(session: Session, organization_id: str, *, hours: int = 24) -> dict[str, Any]:
    since = now() - timedelta(hours=hours)
    rows = list(
        session.execute(
            select(SpamScan)
            .where(SpamScan.organization_id == organization_id, SpamScan.received_at >= since)
            .limit(20000)
        ).scalars()
    )
    dist: dict[str, Counter[str]] = {m: Counter() for m in ("spf", "dkim", "dmarc", "arc")}
    failing: Counter[str] = Counter()
    temp = 0
    misaligned = 0
    for r in rows:
        auth = r.auth or {}
        for method in dist:
            dist[method][str((auth.get(method) or {}).get("result", "NONE"))] += 1
        if (auth.get("dmarc") or {}).get("result") == "FAIL" and r.sender_domain:
            failing[r.sender_domain] += 1
        if auth.get("incomplete_reasons"):
            temp += 1
        dmarc = auth.get("dmarc") or {}
        if dmarc.get("spf_aligned") is False and dmarc.get("dkim_aligned") is False:
            misaligned += 1
    conflicts = session.execute(
        select(func.count())
        .select_from(AuthConflictRecord)
        .where(AuthConflictRecord.organization_id == organization_id, AuthConflictRecord.created_at >= since)
    ).scalar_one()
    return {
        "window_hours": hours,
        "analyzed": len(rows),
        "distributions": {k: dict(v) for k, v in dist.items()},
        "top_failing_domains": failing.most_common(10),
        "incomplete": temp,
        "alignment_failures": misaligned,
        "conflicts": int(conflicts),
    }


def conflicts_list(
    session: Session, organization_id: str, *, disposition: str | None = None, limit: int = 100
) -> list[dict[str, Any]]:
    query = select(AuthConflictRecord).where(AuthConflictRecord.organization_id == organization_id)
    if disposition:
        query = query.where(AuthConflictRecord.disposition == ConflictDisposition(disposition))
    rows = session.execute(
        query.order_by(AuthConflictRecord.created_at.desc()).limit(min(limit, 500))
    ).scalars()
    return [
        {
            "id": c.id,
            "scan_id": c.scan_id,
            "kind": c.kind,
            "upstream_value": c.upstream_value,
            "msp_value": c.msp_value,
            "note": c.note,
            "disposition": c.disposition.value,
            "reviewed_by": c.reviewed_by,
            "reviewed_at": c.reviewed_at,
            "created_at": c.created_at,
        }
        for c in rows
    ]


def review_conflict(
    session: Session, organization_id: str, conflict_id: str, disposition: str, *, actor_email: str
) -> AuthConflictRecord:
    row = session.get(AuthConflictRecord, conflict_id)
    if row is None or row.organization_id != organization_id:
        raise AntispamError("конфликт не найден")
    try:
        row.disposition = ConflictDisposition(disposition)
    except ValueError as exc:
        raise AntispamError("допустимые решения: EXPECTED, REAL_PROBLEM, FALSE_ALARM, OPEN") from exc
    row.reviewed_by = actor_email
    row.reviewed_at = now()
    return row


def ip_reputation_view(session: Session, organization_id: str, ip: str) -> dict[str, Any]:
    row = session.execute(
        select(SourceIpReputationRecord).where(
            SourceIpReputationRecord.organization_id == organization_id, SourceIpReputationRecord.ip == ip
        )
    ).scalar_one_or_none()
    if row is None:
        view = reputation.view_ip(None, now())
        return {
            "ip": ip,
            "known": False,
            "tier": view.tier.value,
            "score": view.score,
            "explanations": view.explanations,
        }
    model = reputation.SourceIpReputation(
        row.ip,
        row.first_seen,
        row.last_seen,
        row.message_count,
        row.threat_count,
        row.spam_count,
        row.legitimate_count,
        row.distinct_senders,
        row.distinct_domains,
        reputation.Analyst(row.analyst_confirmed) if row.analyst_confirmed else None,
    )
    view = reputation.view_ip(model, now())
    return {
        "ip": ip,
        "known": True,
        "first_seen": row.first_seen,
        "last_seen": row.last_seen,
        "message_count": round(model.decayed(now()).message_count, 2),
        "distinct_senders": row.distinct_senders,
        "distinct_domains": row.distinct_domains,
        "analyst_confirmed": row.analyst_confirmed,
        "tier": view.tier.value,
        "score": view.score,
        "explanations": view.explanations,
        "suppresses_hard_signals": view.suppresses_hard_signals,
    }


def domain_reputation_view(session: Session, organization_id: str, domain: str) -> dict[str, Any]:
    domain = domain.lower().strip(".")
    row = session.execute(
        select(DomainReputationRecord).where(
            DomainReputationRecord.organization_id == organization_id, DomainReputationRecord.domain == domain
        )
    ).scalar_one_or_none()
    if row is None:
        view = reputation.view_domain(None, now())
        return {
            "domain": domain,
            "known": False,
            "tier": view.tier.value,
            "score": view.score,
            "explanations": view.explanations,
        }
    model = reputation.DomainReputation(
        row.domain,
        row.first_seen,
        row.last_seen,
        row.message_count,
        row.threat_count,
        row.spam_count,
        row.legitimate_count,
        row.auth_pass_count,
        reputation.Analyst(row.analyst_confirmed) if row.analyst_confirmed else None,
    )
    view = reputation.view_domain(model, now())
    return {
        "domain": domain,
        "known": True,
        "first_seen": row.first_seen,
        "last_seen": row.last_seen,
        "message_count": round(model.decayed(now()).message_count, 2),
        "authentication_pass_rate": model.authentication_pass_rate,
        "analyst_confirmed": row.analyst_confirmed,
        "tier": view.tier.value,
        "score": view.score,
        "explanations": view.explanations,
        "suppresses_hard_signals": view.suppresses_hard_signals,
    }


# ---------------------------------------------------------------------------------------------
# Симулятор
# ---------------------------------------------------------------------------------------------
def simulate_policy(
    session: Session, record: SpamPolicyRecord, *, organization_id: str, limit: int = 200, hours: int = 168
) -> dict[str, Any]:
    """Применить кандидата к уже принятым письмам. Поток почты не затрагивается."""
    candidate = _policy_from_record(record)
    since = now() - timedelta(hours=hours)
    rows = list(
        session.execute(
            select(SpamScan)
            .where(SpamScan.organization_id == organization_id, SpamScan.received_at >= since)
            .order_by(SpamScan.received_at.desc())
            .limit(min(limit, 1000))
        ).scalars()
    )
    results = []
    changed = 0
    for row in rows:
        sample = SimulationInput(
            score=row.score,
            symbols=tuple(str(s.get("name")) for s in (row.symbols or [])),
            auth_summary={
                "spf": str((row.auth or {}).get("spf", {}).get("result", "NONE")),
                "dkim": str((row.auth or {}).get("dkim", {}).get("result", "NONE")),
                "dmarc": str((row.auth or {}).get("dmarc", {}).get("result", "NONE")),
            },
            reputation_listed=any(str(s.get("name", "")).startswith("MSP_RBL_") for s in (row.symbols or [])),
            current_suggested_action=_action(row.suggested_action),
            msp_spam_class=_spam_class(row.spam_class),
            msp_security_verdict=row.security_verdict or "UNKNOWN",
        )
        result = simulate(candidate, sample)
        changed += 1 if result.changed_vs_current else 0
        results.append(
            {
                "scan_id": row.id,
                "message_id": row.internet_message_id,
                "score": row.score,
                "current_spam_class": row.spam_class,
                "candidate_spam_class": result.candidate_spam_class.value,
                "current_suggested_action": row.suggested_action,
                "hypothetical_action": result.hypothetical_action.value,
                "changed": result.changed_vs_current,
                "security_verdict": row.security_verdict,
                "applied_action": result.applied_action.value,
            }
        )
    return {
        "policy_version": record.version,
        "state": record.state.value,
        "evaluated": len(results),
        "changed": changed,
        "applied_action": "OBSERVE_ONLY",
        "enforcement_enabled": False,
        "items": results,
    }


def _action(value: str):  # type: ignore[no-untyped-def]
    from msp_antispam.model import SuggestedAction

    try:
        return SuggestedAction(value)
    except ValueError:
        return SuggestedAction.UNKNOWN


def _spam_class(value: str):  # type: ignore[no-untyped-def]
    from msp_antispam.model import SpamClass

    try:
        return SpamClass(value)
    except ValueError:
        return SpamClass.UNKNOWN


def policy_view(record: SpamPolicyRecord) -> dict[str, Any]:
    body = dict(record.body or {})
    return {
        "id": record.id,
        "version": record.version,
        "state": record.state.value,
        "edited_by": record.edited_by,
        "approved_by": record.approved_by,
        "note": record.note,
        "created_at": record.created_at,
        "thresholds": body.get("thresholds"),
        "mode": body.get("mode"),
        "enabled_modules": body.get("enabled_modules"),
        "rbl_provider_ids": body.get("rbl_provider_ids"),
        "bayes_enabled": body.get("bayes_enabled"),
        "greylisting_enabled": body.get("greylisting_enabled"),
        "enforcement_enabled": False,
    }


# ---------------------------------------------------------------------------------------------
# Ключи подписи DKIM
# ---------------------------------------------------------------------------------------------
def dkim_keys_list(session: Session, organization_id: str) -> list[DkimKeyRecord]:
    return list(
        session.execute(
            select(DkimKeyRecord)
            .where(DkimKeyRecord.organization_id == organization_id)
            .order_by(DkimKeyRecord.created_at.desc())
        ).scalars()
    )


def _to_model(record: DkimKeyRecord) -> dkim_keys.DkimSigningKey:
    return dkim_keys.DkimSigningKey(
        domain=record.domain,
        selector=record.selector,
        algorithm=record.algorithm,
        public_record=record.public_record,
        private_key_ref=record.private_key_ref,
        created_at=record.created_at,
        status=dkim_keys.KeyStatus(record.status.value),
        activate_at=record.activate_at,
        retire_at=record.retire_at,
        generated_by=record.generated_by,
        activated_by=record.activated_by,
        failure=record.failure,
    )


def _apply(record: DkimKeyRecord, model: dkim_keys.DkimSigningKey) -> None:
    record.status = DkimKeyStatus(model.status.value)
    record.activate_at, record.retire_at = model.activate_at, model.retire_at
    record.activated_by, record.failure = model.activated_by, model.failure


def generate_dkim_key(
    session: Session,
    organization_id: str,
    domain: str,
    selector: str,
    *,
    actor_email: str,
    trusted_domains: set[str],
) -> tuple[DkimKeyRecord, bytes]:
    """Новый ключ. Закрытая часть возвращается один раз и в базу не попадает (её сразу кладут в секреты)."""
    if domain.lower() not in trusted_domains:
        raise AntispamError("подпись разрешена только для лабораторного или пилотного домена")
    try:
        key, pem = dkim_keys.generate(domain, selector, generated_by=actor_email)
    except dkim_keys.KeyError_ as exc:
        raise AntispamError(str(exc)) from exc
    record = DkimKeyRecord(
        organization_id=organization_id,
        domain=key.domain,
        selector=key.selector,
        algorithm=key.algorithm,
        public_record=key.public_record,
        private_key_ref=key.private_key_ref,
        status=DkimKeyStatus.DNS_PENDING,
        generated_by=actor_email,
    )
    try:
        with session.begin_nested():
            session.add(record)
            session.flush()
    except IntegrityError as exc:
        raise AntispamError("ключ с таким селектором для этого домена уже есть") from exc
    return record, pem


def verify_dkim_dns(
    record: DkimKeyRecord, txt_records: list[str] | None, *, dns_error: bool = False
) -> DkimKeyRecord:
    try:
        model = dkim_keys.verify_dns(_to_model(record), txt_records, dns_error=dns_error)
    except dkim_keys.KeyError_ as exc:
        raise AntispamError(str(exc)) from exc
    _apply(record, model)
    return record


def activate_dkim_key(record: DkimKeyRecord, *, actor_email: str, trusted_domains: set[str]) -> DkimKeyRecord:
    try:
        model = dkim_keys.activate(_to_model(record), approver=actor_email, trusted_domains=trusted_domains)
    except dkim_keys.KeyError_ as exc:
        raise AntispamError(str(exc)) from exc
    _apply(record, model)
    return record


def retire_dkim_key(record: DkimKeyRecord, *, force_begin: bool = True) -> DkimKeyRecord:
    try:
        model = _to_model(record)
        if model.status is dkim_keys.KeyStatus.ACTIVE and force_begin:
            model = dkim_keys.begin_retirement(model)
        elif model.status is dkim_keys.KeyStatus.RETIRING:
            model = dkim_keys.retire(model)
        else:
            raise dkim_keys.KeyError_("вывести из работы можно действующий или выводимый ключ")
    except dkim_keys.KeyError_ as exc:
        raise AntispamError(str(exc)) from exc
    _apply(record, model)
    return record


def dkim_public_view(record: DkimKeyRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "domain": record.domain,
        "selector": record.selector,
        "algorithm": record.algorithm,
        "dns_name": f"{record.selector}._domainkey.{record.domain}",
        "public_record": record.public_record,
        "status": record.status.value,
        "created_at": record.created_at,
        "activate_at": record.activate_at,
        "retire_at": record.retire_at,
        "generated_by": record.generated_by,
        "activated_by": record.activated_by,
        "failure": record.failure,
        # Ссылка на секрет показывается, само значение недоступно нигде.
        "private_key_ref": record.private_key_ref,
    }


# ---------------------------------------------------------------------------------------------
# Bayes
# ---------------------------------------------------------------------------------------------
def bayes_status(session: Session, organization_id: str) -> dict[str, Any]:
    rows = session.execute(
        select(BayesSample.label, func.count())
        .where(BayesSample.organization_id == organization_id, BayesSample.unlearned_at.is_(None))
        .group_by(BayesSample.label)
    ).all()
    counts = {label: int(count) for label, count in rows}
    ham, spam = counts.get("HAM", 0), counts.get("SPAM", 0)
    ok, reason = bayes_mod.can_enable(ham, spam, autolearn=False)
    return {
        "state": bayes_mod.state(ham, spam).value,
        "approved_ham": ham,
        "approved_spam": spam,
        "minimum_per_class": bayes_mod.MIN_APPROVED_PER_CLASS,
        "can_enable": ok,
        "reason": reason,
        "autolearn": False,
    }


def add_bayes_sample(
    session: Session, organization_id: str, *, message_id: str, label: str, source: str, actor_email: str
) -> BayesSample:
    try:
        sample = bayes_mod.LearnSample(
            message_id=message_id,
            label=bayes_mod.Label(label),
            source=bayes_mod.Source(source),
            confirmed_by=actor_email,
        )
    except ValueError as exc:
        raise AntispamError("неизвестная метка или источник") from exc
    try:
        bayes_mod.check_learn(sample)
    except bayes_mod.LearnRefused as exc:
        raise AntispamError(str(exc)) from exc
    existing = session.execute(
        select(BayesSample).where(
            BayesSample.organization_id == organization_id, BayesSample.internet_message_id == message_id
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise AntispamError("это письмо уже в обучающей выборке")
    row = BayesSample(
        organization_id=organization_id,
        internet_message_id=message_id,
        label=label,
        source=source,
        confirmed_by=actor_email,
    )
    session.add(row)
    session.flush()
    return row


def unlearn_bayes_sample(session: Session, organization_id: str, message_id: str) -> BayesSample:
    row = session.execute(
        select(BayesSample).where(
            BayesSample.organization_id == organization_id, BayesSample.internet_message_id == message_id
        )
    ).scalar_one_or_none()
    if row is None:
        raise AntispamError("такого примера нет")
    row.unlearned_at = now()
    return row


# ---------------------------------------------------------------------------------------------
# Просмотр и метрики качества
# ---------------------------------------------------------------------------------------------
def review_queue(
    session: Session, organization_id: str, selection: str, *, limit: int = 50, hours: int = 168
) -> list[dict[str, Any]]:
    try:
        chosen = validation.Selection(selection)
    except ValueError as exc:
        raise AntispamError("неизвестная выборка") from exc
    since = now() - timedelta(hours=hours)
    reviewed = select(SpamReview.scan_id).where(SpamReview.organization_id == organization_id)
    base = select(SpamScan).where(
        SpamScan.organization_id == organization_id,
        SpamScan.received_at >= since,
        SpamScan.id.not_in(reviewed),
    )
    rows = list(session.execute(base.order_by(SpamScan.received_at.desc()).limit(5000)).scalars())
    picked: list[SpamScan]
    if chosen is validation.Selection.SUGGESTED_REJECT:
        picked = [r for r in rows if r.suggested_action in ("REJECT", "SOFT_REJECT")]
    elif chosen is validation.Selection.DMARC_REJECT_FAILURE:
        picked = [r for r in rows if (r.auth or {}).get("dmarc", {}).get("suggested_disposition") == "REJECT"]
    elif chosen is validation.Selection.RBL_LISTED:
        picked = [
            r for r in rows if any(str(s.get("name", "")).startswith("MSP_RBL_") for s in (r.symbols or []))
        ]
    elif chosen is validation.Selection.HIGH_SCORE:
        picked = [r for r in rows if r.spam_class in ("SPAM", "HIGH_CONFIDENCE_SPAM")]
    elif chosen is validation.Selection.AUTH_CONFLICT:
        with_conflict = set(
            session.execute(
                select(AuthConflictRecord.scan_id).where(
                    AuthConflictRecord.organization_id == organization_id
                )
            ).scalars()
        )
        picked = [r for r in rows if r.id in with_conflict]
    else:
        low = [r for r in rows if r.spam_class in ("NOT_SPAM", "UNKNOWN") and r.score < 4]
        # Случайная, но воспроизводимая выборка: одна и та же очередь при повторном открытии.
        picked = random.Random(hashlib.sha256(f"{organization_id}:{len(low)}".encode()).hexdigest()).sample(
            low, min(limit, len(low))
        )
    return [scan_view(r) | {"selection": chosen.value} for r in picked[:limit]]


def record_review(
    session: Session,
    organization_id: str,
    scan_id: str,
    *,
    verdict: str,
    selection: str,
    actor_email: str,
    note: str = "",
) -> SpamReview:
    scan = session.get(SpamScan, scan_id)
    if scan is None or scan.organization_id != organization_id:
        raise AntispamError("письмо не найдено")
    try:
        validation.Verdict(verdict)
        validation.Selection(selection)
    except ValueError as exc:
        raise AntispamError("неверный вердикт или выборка") from exc
    existing = session.execute(select(SpamReview).where(SpamReview.scan_id == scan_id)).scalar_one_or_none()
    if existing is not None:
        existing.verdict, existing.selection, existing.reviewed_by, existing.reviewed_at, existing.note = (
            verdict,
            selection,
            actor_email,
            now(),
            note[:500],
        )
        return existing
    review = SpamReview(
        organization_id=organization_id,
        scan_id=scan_id,
        verdict=verdict,
        selection=selection,
        reviewed_by=actor_email,
        reviewed_at=now(),
        note=note[:500],
    )
    session.add(review)
    session.flush()
    # Решение человека — единственное место, где история репутации узнаёт исход (ТЗ 1.2 §17).
    _apply_outcome(session, organization_id, scan, verdict)
    return review


def _apply_outcome(session: Session, organization_id: str, scan: SpamScan, verdict: str) -> None:
    ip_row = session.execute(
        select(SourceIpReputationRecord).where(
            SourceIpReputationRecord.organization_id == organization_id,
            SourceIpReputationRecord.ip == scan.client_ip,
        )
    ).scalar_one_or_none()
    dom_row = session.execute(
        select(DomainReputationRecord).where(
            DomainReputationRecord.organization_id == organization_id,
            DomainReputationRecord.domain == scan.sender_domain,
        )
    ).scalar_one_or_none()
    for row in (ip_row, dom_row):
        if row is None:
            continue
        if verdict == "SPAM":
            row.spam_count += 1
        elif verdict == "HAM":
            row.legitimate_count += 1


def validation_metrics(
    session: Session, organization_id: str, *, hours: int = 168
) -> validation.ValidationMetrics:
    since = now() - timedelta(hours=hours)
    scanned = session.execute(
        select(func.count())
        .select_from(SpamScan)
        .where(SpamScan.organization_id == organization_id, SpamScan.received_at >= since)
    ).scalar_one()
    reviews = session.execute(
        select(SpamReview, SpamScan)
        .join(SpamScan, SpamScan.id == SpamReview.scan_id)
        .where(SpamReview.organization_id == organization_id, SpamReview.reviewed_at >= since)
    ).all()
    items = [
        validation.ReviewedScan(
            selection=validation.Selection(review.selection),
            verdict=validation.Verdict(review.verdict),
            score=scan.score,
            spam_class=scan.spam_class,
            suggested_action=scan.suggested_action,
            symbols=tuple(str(s.get("name")) for s in (scan.symbols or [])),
        )
        for review, scan in reviews
    ]
    return validation.compute(int(scanned), items)


def reject_safety(session: Session, organization_id: str) -> dict[str, Any]:
    metrics = validation_metrics(session, organization_id)
    gate = validation.reject_safety(metrics)
    return {
        "ready_for_discussion": gate.ready,
        "reasons": list(gate.reasons),
        "enforcement_enabled": False,
        "metrics": metrics.__dict__,
    }


# ---------------------------------------------------------------------------------------------
# Конфигурация сканера для узла
# ---------------------------------------------------------------------------------------------
def node_overlay(session: Session, organization_id: str, *, now_: datetime | None = None) -> dict[str, Any]:
    """Что панель назначает сканеру. Сети подписи, адреса DNS и секреты узел берёт из своей локальной
    конфигурации: панель не вправе расширить, кого подписывать, и не видит секретов."""
    moment = now_ or now()
    policy = active_policy(session, organization_id)
    out_providers: list[dict[str, Any]] = []
    for record in providers(session, organization_id):
        definition = provider_definition(record)
        if definition.is_usable(moment):
            data = definition.model_dump(mode="json")
            out_providers.append(data)
    keys = [
        k
        for k in dkim_keys_list(session, organization_id)
        if k.status in (DkimKeyStatus.ACTIVE, DkimKeyStatus.RETIRING)
    ]
    signing = [
        {"domain": k.domain, "selector": k.selector, "private_key_file": k.private_key_ref} for k in keys
    ]
    body = {
        "thresholds": {
            "greylist": policy.thresholds.suspected,
            "add_header": policy.thresholds.spam,
            "reject": policy.thresholds.suggest_reject,
        },
        "providers": out_providers,
        "signing_domains": signing,
        "bayes_enabled": policy.bayes_enabled,
        "greylisting": policy.greylisting_enabled,
        "policy_version": policy.version,
        "symbol_mapping_version": default_mapping().version,
    }
    body["checksum"] = hashlib.sha256(repr(sorted(body.items(), key=lambda kv: kv[0])).encode()).hexdigest()
    return body


def remember_node_state(session: Session, organization_id: str, node_id: str, state: dict[str, Any]) -> None:
    from .transport import get_or_create_node

    node = get_or_create_node(session, organization_id, node_id)
    allowed = {
        key: state.get(key)
        for key in (
            "up",
            "version",
            "config_version",
            "config_checksum",
            "redis_up",
            "scans_received",
            "scans_dropped",
            "scan_errors",
            "last_apply",
            "dkim_missing_keys",
        )
    }
    details = dict(node.details or {})
    details["rspamd"] = {**allowed, "reported_at": now().isoformat()}
    node.details = details
    node.last_heartbeat_at = node.last_heartbeat_at or now()


# ---------------------------------------------------------------------------------------------
# Связь с движком обнаружения (ТЗ 1.2 §26)
# ---------------------------------------------------------------------------------------------
def findings_for(session: Session, organization_id: str, message_id: str, *, expected: bool) -> Any:
    """Нормализованные свидетельства сканера для движка обнаружения.

    В движок попадают только сигналы, помеченные в отображении как влияющие на риск; неизвестные
    символы, класс спама и чистые результаты проверок туда не идут. ``expected`` — письмо прошло
    через шлюз с включённым сканером, и отсутствие записи сканера становится недостающим свидетельством.
    """
    from msp_detection.antispam import AntispamFindings

    mid = (message_id or "").strip().strip("<>")
    if not mid:
        return AntispamFindings(expected=expected) if expected else None
    row = (
        session.execute(
            select(SpamScan)
            .where(
                SpamScan.organization_id == organization_id,
                SpamScan.internet_message_id.in_([mid, f"<{mid}>"]),
            )
            .order_by(SpamScan.received_at.desc())
        )
        .scalars()
        .first()
    )
    if row is None:
        return AntispamFindings(expected=expected) if expected else None
    conflict = session.execute(
        select(func.count())
        .select_from(AuthConflictRecord)
        .where(
            AuthConflictRecord.scan_id == row.id,
            AuthConflictRecord.disposition != ConflictDisposition.FALSE_ALARM,
        )
    ).scalar_one()
    hostile = False
    if row.client_ip:
        ip_row = session.execute(
            select(SourceIpReputationRecord.analyst_confirmed).where(
                SourceIpReputationRecord.organization_id == organization_id,
                SourceIpReputationRecord.ip == row.client_ip,
            )
        ).scalar_one_or_none()
        hostile = ip_row == "MALICIOUS"
    return AntispamFindings(
        scan_present=True,
        expected=expected,
        risk_signals=[s["code"] for s in (row.signals or []) if s.get("risk_effect") == "INCREASE"],
        auth_conflict=bool(conflict),
        source_confirmed_hostile=hostile,
        mapping_version=row.symbol_mapping_version,
    )


def record_security_verdict(session: Session, organization_id: str, message_id: str, verdict: str) -> None:
    """Записать вердикт безопасности рядом с классом спама. Это вторая ось: класс он не меняет."""
    mid = (message_id or "").strip().strip("<>")
    if not mid:
        return
    for row in session.execute(
        select(SpamScan).where(
            SpamScan.organization_id == organization_id, SpamScan.internet_message_id.in_([mid, f"<{mid}>"])
        )
    ).scalars():
        row.security_verdict = verdict[:32]
