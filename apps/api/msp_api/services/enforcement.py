"""Принуждение MSP 1.3: контроли, политика, решения, исключения, выключатель, инциденты.

Служба не анализирует письма (ТЗ §13) и не исполняет решения: она управляет жизненным циклом контролей,
собирает подписанную политику для узлов и принимает от узлов журнал решений. Исполняет решение сам узел
по проверенной локальной копии политики.

Инварианты, которые проверяют тесты:

* общего флага принуждения нет, у каждого контроля своё состояние и своя готовность;
* контроль, заблокированный пробелом, не включается ни при каких запросах (409);
* включение канарейки и пилота — двое: инициатор и согласующий разные, у согласующего есть право;
* опубликованная политика неизменяема, правка — новая версия; откат возвращает прежнюю версию;
* общий выключатель включается одним человеком и мгновенно, снимается вторым.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from msp_enforcement.canary import CanaryScope
from msp_enforcement.engine import EnforcementInput, MalwareEvidence, Runtime, Switches, decide
from msp_enforcement.exceptions import EnforcementException
from msp_enforcement.model import (
    ACTIVE_STATES,
    DEFAULT_FAIL_MODE,
    TRANSITIONS,
    ControlState,
    ControlType,
    ExceptionScope,
    Readiness,
)
from msp_enforcement.policy import (
    ControlPolicy,
    EnforcementPolicy,
    PolicyError,
    PolicyStatus,
    sign_policy,
)
from msp_enforcement.readiness import (
    ReadinessInput,
    ReadinessReport,
    assess,
    blocking_gaps,
    build_reject_safety,
    restricted_reasons,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.base import utcnow
from ..db.models import DetectionGapRecord
from ..db.models_antispam import ProviderApprovalState, ReputationProviderRecord, SpamReview, SpamScan
from ..db.models_enforcement import (
    EmergencyIncidentRecord,
    EnforcementControlRecord,
    EnforcementDecisionRecord,
    EnforcementExceptionRecord,
    EnforcementPolicyRecord,
    EnforcementSwitchRecord,
    IncidentState,
    PolicyReleaseState,
    QuarantineItemRecord,
    QuarantineState,
)
from ..db.models_transport import TransportNode, TransportNodeRole

CONTROL_ORDER: tuple[ControlType, ...] = tuple(ControlType)

DEFAULT_THRESHOLDS: dict[ControlType, dict[str, float]] = {
    ControlType.SPAM_REJECT: {"reject_score": 15.0},
    ControlType.MALWARE_REJECT: {"min_confidence": 0.95},
    ControlType.PHISHING_REJECT: {"reject_score": 15.0},
}

#: Подтверждения, которые вправе давать человек с правом канарейки (с фиксацией ревизии и записью в аудите).
ATTESTATIONS = (
    "control_tests_green",
    "rspamd_failopen_tested",
    "no_secret_leakage_tested",
    "timeout_semantics_tested",
    "malware_high_confidence_only",
    "sync_path_approved",
    "outbound_acceptance",
    "provider_healthy",
)


class EnforcementError(Exception):
    def __init__(self, message: str, status: int = 400, *, detail: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.detail = detail


def now() -> datetime:
    return utcnow()


# ---------------------------------------------------------------------------------------------
# Контроли
# ---------------------------------------------------------------------------------------------
def ensure_controls(session: Session, organization_id: str) -> list[EnforcementControlRecord]:
    rows = {
        r.control_type: r
        for r in session.execute(
            select(EnforcementControlRecord).where(
                EnforcementControlRecord.organization_id == organization_id
            )
        ).scalars()
    }
    for kind in CONTROL_ORDER:
        if kind.value not in rows:
            row = EnforcementControlRecord(
                organization_id=organization_id,
                control_type=kind.value,
                state=ControlState.SHADOW.value,
                fail_mode=DEFAULT_FAIL_MODE[kind].value,
                thresholds=dict(DEFAULT_THRESHOLDS.get(kind, {})),
            )
            session.add(row)
            rows[kind.value] = row
    session.flush()
    return [rows[k.value] for k in CONTROL_ORDER]


def get_control(session: Session, organization_id: str, control_id: str) -> EnforcementControlRecord:
    ensure_controls(session, organization_id)
    row = session.get(EnforcementControlRecord, control_id)
    if row is None:
        # Допустимо обращение и по имени контроля.
        row = session.execute(
            select(EnforcementControlRecord).where(
                EnforcementControlRecord.organization_id == organization_id,
                EnforcementControlRecord.control_type == control_id,
            )
        ).scalar_one_or_none()
    if row is None or row.organization_id != organization_id:
        raise EnforcementError("контроль не найден", 404)
    return row


def gap_statuses(session: Session, organization_id: str) -> dict[str, str]:
    return {
        r.gap_id: r.status.value if hasattr(r.status, "value") else str(r.status)
        for r in session.execute(
            select(DetectionGapRecord).where(DetectionGapRecord.organization_id == organization_id)
        ).scalars()
    }


def _node_roles(session: Session, organization_id: str) -> dict[str, str]:
    return {
        n.node_id: n.role.value
        for n in session.execute(
            select(TransportNode).where(TransportNode.organization_id == organization_id)
        ).scalars()
    }


def reject_evidence(
    session: Session, settings: Settings, organization_id: str, control: ControlType
) -> tuple[Any, bool]:
    """Выборка просмотренных кандидатов на отказ по контролю: (отчёт, выборка реального потока)."""
    roles = _node_roles(session, organization_id)
    correct = fp = 0
    real_reviewed = 0
    if control is ControlType.SPAM_REJECT:
        rows = session.execute(
            select(SpamReview, SpamScan)
            .join(SpamScan, SpamScan.id == SpamReview.scan_id)
            .where(SpamReview.organization_id == organization_id, SpamScan.suggested_action == "REJECT")
        ).all()
        for review, scan in rows:
            if review.verdict == "SPAM":
                correct += 1
            else:
                fp += 1
            if roles.get(scan.node_id, TransportNodeRole.LAB.value) != TransportNodeRole.LAB.value:
                real_reviewed += 1
    drows = session.execute(
        select(EnforcementDecisionRecord).where(
            EnforcementDecisionRecord.organization_id == organization_id,
            EnforcementDecisionRecord.control_type == control.value,
            EnforcementDecisionRecord.suggested_action == "REJECT",
            EnforcementDecisionRecord.review_outcome != "",
        )
    ).scalars()
    critical = 0
    for d in drows:
        if d.review_outcome == "CORRECT":
            correct += 1
        else:
            fp += 1
            critical += 1 if d.review_critical else 0
        if roles.get(d.node_id, TransportNodeRole.LAB.value) != TransportNodeRole.LAB.value:
            real_reviewed += 1
    reviewed = correct + fp
    report = build_reject_safety(
        reviewed=reviewed,
        confirmed_correct=correct,
        confirmed_fp=fp,
        critical_fp=critical,
        sample_window="all",
        min_reviewed=settings.enforcement_min_reviewed,
        max_fp_upper=settings.enforcement_max_fp_rate,
        systemic_unresolved=_open_incident(session, organization_id, control) is not None,
    )
    return report, real_reviewed >= settings.enforcement_min_reviewed


def _open_incident(
    session: Session, organization_id: str, control: ControlType
) -> EmergencyIncidentRecord | None:
    return (
        session.execute(
            select(EmergencyIncidentRecord).where(
                EmergencyIncidentRecord.organization_id == organization_id,
                EmergencyIncidentRecord.control_type == control.value,
                EmergencyIncidentRecord.state != IncidentState.CLOSED,
            )
        )
        .scalars()
        .first()
    )


def _effective_actions_clean(session: Session, organization_id: str) -> bool:
    nodes = (
        session.execute(select(TransportNode).where(TransportNode.organization_id == organization_id))
        .scalars()
        .all()
    )
    reported = [
        (n.details or {}).get("rspamd", {}).get("effective_actions")
        for n in nodes
        if (n.details or {}).get("rspamd")
    ]
    reported = [r for r in reported if isinstance(r, dict)]
    # Нет отчёта хотя бы от одного узла со сканером — аудит не подтверждён, а не «чисто».
    return bool(reported) and all(r.get("clean") is True for r in reported)


def _quarantine_ready(session: Session, settings: Settings, organization_id: str) -> tuple[bool, bool]:
    backend = len((settings.quarantine_encryption_key or "").strip()) >= 32
    released = session.execute(
        select(func.count())
        .select_from(QuarantineItemRecord)
        .where(
            QuarantineItemRecord.organization_id == organization_id,
            QuarantineItemRecord.state == QuarantineState.RELEASED,
            QuarantineItemRecord.delivered_count >= 1,
        )
    ).scalar_one()
    return backend, bool(released)


def readiness_input(
    session: Session, settings: Settings, organization_id: str, control: EnforcementControlRecord
) -> ReadinessInput:
    kind = ControlType(control.control_type)
    safety, real = reject_evidence(session, settings, organization_id, kind)
    att = {k: bool((v or {}).get("value")) for k, v in (control.attestations or {}).items()}
    approved_provider = (
        session.execute(
            select(func.count())
            .select_from(ReputationProviderRecord)
            .where(
                ReputationProviderRecord.organization_id == organization_id,
                ReputationProviderRecord.approval_state == ProviderApprovalState.APPROVED,
                ReputationProviderRecord.enabled.is_(True),
            )
        ).scalar_one()
        > 0
    )
    backend, release_tested = _quarantine_ready(session, settings, organization_id)
    return ReadinessInput(
        gaps=gap_statuses(session, organization_id),
        reject_safety=safety,
        min_reviewed=settings.enforcement_min_reviewed,
        max_fp_upper=settings.enforcement_max_fp_rate,
        real_evidence=real,
        lab_mode=settings.enforcement_lab_mode,
        thresholds_versioned=True,
        control_tests_green=att.get("control_tests_green", False),
        rspamd_failopen_tested=att.get("rspamd_failopen_tested", False),
        effective_actions_clean=_effective_actions_clean(session, organization_id),
        systemic_fp_unresolved=_open_incident(session, organization_id, kind) is not None,
        license_approved=approved_provider,
        provider_healthy=att.get("provider_healthy", False),
        no_secret_leakage_tested=att.get("no_secret_leakage_tested", False),
        timeout_semantics_tested=att.get("timeout_semantics_tested", False),
        malware_high_confidence_only=att.get("malware_high_confidence_only", False),
        sync_path_approved=att.get("sync_path_approved", False),
        quarantine_backend_healthy=backend,
        release_tested=release_tested,
        outbound_acceptance=att.get("outbound_acceptance", False),
    )


def refresh_readiness(
    session: Session, settings: Settings, organization_id: str, control: EnforcementControlRecord
) -> ReadinessReport:
    report = assess(
        ControlType(control.control_type), readiness_input(session, settings, organization_id, control)
    )
    control.readiness_status = report.status.value
    control.readiness_reasons = [*report.reasons, *report.warnings]
    control.eligibility = {"can_canary": report.can_canary, "can_pilot": report.can_pilot}
    return report


def control_view(
    session: Session, settings: Settings, organization_id: str, control: EnforcementControlRecord
) -> dict[str, Any]:
    report = refresh_readiness(session, settings, organization_id, control)
    kind = ControlType(control.control_type)
    return {
        "id": control.id,
        "organization_id": control.organization_id,
        "type": control.control_type,
        "state": control.state,
        "policy_version": control.policy_version,
        "eligibility": control.eligibility,
        "readiness_status": report.status.value,
        "readiness_reasons": list(report.reasons),
        "readiness_warnings": list(report.warnings),
        "blocking_gaps": list(blocking_gaps(kind, gap_statuses(session, organization_id))),
        "canary_scope": control.canary_scope,
        "fail_mode": control.fail_mode,
        "thresholds": control.thresholds,
        "activated_at": control.activated_at.isoformat() if control.activated_at else None,
        "activated_by": control.activated_by,
        "approved_by": control.approved_by,
        "paused_at": control.paused_at.isoformat() if control.paused_at else None,
        "rollback_version": control.rollback_version,
        "pending_request": control.pending_request or None,
        "attestations": {
            k: {"value": v.get("value"), "by": v.get("by"), "at": v.get("at"), "ref": v.get("ref")}
            for k, v in (control.attestations or {}).items()
        },
    }


def attest(control: EnforcementControlRecord, *, name: str, value: bool, actor_email: str, ref: str) -> None:
    if name not in ATTESTATIONS:
        raise EnforcementError("неизвестное подтверждение", 422)
    if not ref.strip():
        raise EnforcementError("нужна ссылка на ревизию или отчёт, подтверждающие проверку", 422)
    items = dict(control.attestations or {})
    items[name] = {"value": bool(value), "by": actor_email, "at": now().isoformat(), "ref": ref[:200]}
    control.attestations = items


# ---------------------------------------------------------------------------------------------
# Политика
# ---------------------------------------------------------------------------------------------
def _signing_key(settings: Settings) -> bytes:
    key = (settings.enforcement_policy_signing_key or "").encode()
    if len(key) < 32:
        raise EnforcementError("ключ подписи политики принуждения не настроен", 503)
    return key


def _next_version(session: Session, organization_id: str) -> str:
    count = session.execute(
        select(func.count())
        .select_from(EnforcementPolicyRecord)
        .where(EnforcementPolicyRecord.organization_id == organization_id)
    ).scalar_one()
    return f"v{int(count) + 1}"


def _active_exceptions(session: Session, organization_id: str) -> list[EnforcementException]:
    rows = session.execute(
        select(EnforcementExceptionRecord).where(
            EnforcementExceptionRecord.organization_id == organization_id,
            EnforcementExceptionRecord.revoked_at.is_(None),
            EnforcementExceptionRecord.expires_at > now(),
        )
    ).scalars()
    out: list[EnforcementException] = []
    for r in rows:
        out.append(
            EnforcementException(
                id=r.id,
                scope=ExceptionScope(r.scope),
                control=ControlType(r.control_type) if r.control_type else None,
                value=r.value,
                reason=r.reason,
                owner=r.owner,
                approved_by=r.approved_by,
                created_at=_aware(r.created_at),
                expires_at=_aware(r.expires_at),
                max_uses=r.max_uses,
            )
        )
    return out


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def build_policy(
    session: Session,
    settings: Settings,
    organization_id: str,
    *,
    owner: str,
    reviewer: str = "",
    rollback_target: str = "",
    groups: Mapping[str, Iterable[str]] | None = None,
    notes: str = "",
) -> EnforcementPolicy:
    controls = []
    for row in ensure_controls(session, organization_id):
        scope = CanaryScope.model_validate(row.canary_scope or {})
        controls.append(
            ControlPolicy(
                control_type=ControlType(row.control_type),
                state=ControlState(row.state),
                thresholds=dict(row.thresholds or {}),
                canary_scope=scope,
                fail_mode=None,
            )
        )
    started = now()
    return EnforcementPolicy(
        version=_next_version(session, organization_id),
        organization_id=organization_id,
        controls=tuple(controls),
        gaps=gap_statuses(session, organization_id),
        groups={k: tuple(v) for k, v in (groups or {}).items()},
        exceptions=tuple(_active_exceptions(session, organization_id)),
        valid_from=started,
        valid_until=started + timedelta(days=settings.enforcement_policy_valid_days),
        owner=owner,
        reviewer=reviewer,
        rollback_target=rollback_target,
        notes=notes[:500],
    )


def publish(
    session: Session,
    settings: Settings,
    organization_id: str,
    *,
    owner: str,
    reviewer: str = "",
    rollback_target: str = "",
    justification: str = "",
    groups: Mapping[str, Iterable[str]] | None = None,
) -> EnforcementPolicyRecord:
    key = _signing_key(settings)
    previous_groups = groups
    if previous_groups is None:
        current = current_policy(session, organization_id)
        previous_groups = (current.body or {}).get("groups", {}) if current else {}
    try:
        policy = build_policy(
            session,
            settings,
            organization_id,
            owner=owner,
            reviewer=reviewer,
            rollback_target=rollback_target,
            groups=previous_groups,
            notes=justification,
        )
        bundle = sign_policy(policy, key)
    except (PolicyError, ValueError) as exc:
        raise EnforcementError(f"политика не принята: {exc.__class__.__name__}", 422) from exc
    for old in session.execute(
        select(EnforcementPolicyRecord).where(
            EnforcementPolicyRecord.organization_id == organization_id,
            EnforcementPolicyRecord.is_current.is_(True),
        )
    ).scalars():
        old.is_current = False
        old.state = PolicyReleaseState.SUPERSEDED
    record = EnforcementPolicyRecord(
        organization_id=organization_id,
        version=policy.version,
        state=PolicyReleaseState.PUBLISHED,
        body=json.loads(policy.canonical()),
        checksum=bundle.checksum,
        bundle=bundle.model_dump(mode="json"),
        owner=owner,
        reviewer=reviewer,
        rollback_target=rollback_target,
        justification=justification[:1000],
        valid_from=policy.valid_from,
        valid_until=policy.valid_until,
        published_at=now(),
        is_current=True,
    )
    session.add(record)
    for row in ensure_controls(session, organization_id):
        row.policy_version = policy.version
    session.flush()
    return record


def current_policy(session: Session, organization_id: str) -> EnforcementPolicyRecord | None:
    return (
        session.execute(
            select(EnforcementPolicyRecord).where(
                EnforcementPolicyRecord.organization_id == organization_id,
                EnforcementPolicyRecord.is_current.is_(True),
            )
        )
        .scalars()
        .first()
    )


def ensure_baseline(
    session: Session, settings: Settings, organization_id: str
) -> EnforcementPolicyRecord | None:
    """Первая политика: все контроли в наблюдении. Без ключа подписи политики нет — узел остаётся в безопасном режиме."""
    existing = current_policy(session, organization_id)
    if existing is not None:
        return existing
    try:
        return publish(session, settings, organization_id, owner="system", justification="исходная политика")
    except EnforcementError:
        return None


def policy_view(record: EnforcementPolicyRecord, *, with_body: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": record.id,
        "version": record.version,
        "state": record.state.value,
        "checksum": record.checksum,
        "owner": record.owner,
        "reviewer": record.reviewer,
        "rollback_target": record.rollback_target,
        "justification": record.justification,
        "published_at": record.published_at.isoformat() if record.published_at else None,
        "valid_until": record.valid_until.isoformat() if record.valid_until else None,
        "current": record.is_current,
    }
    if with_body:
        out["body"] = record.body
    return out


def node_policy_payload(session: Session, settings: Settings, organization_id: str) -> dict[str, Any]:
    """Ответ узлу: подписанный пакет текущей политики и общий выключатель (быстрое поле)."""
    record = ensure_baseline(session, settings, organization_id)
    switch = switch_row(session, organization_id)
    return {
        "bundle": record.bundle if record else None,
        "policy_version": record.version if record else "",
        "checksum": record.checksum if record else "",
        "kill_switch": bool(switch.kill_switch),
        "server_time": now().isoformat(),
    }


# ---------------------------------------------------------------------------------------------
# Жизненный цикл: канарейка и пилот (четыре глаза)
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Activation:
    control: EnforcementControlRecord
    policy: EnforcementPolicyRecord | None
    pending: bool


def request_activation(
    session: Session,
    settings: Settings,
    organization_id: str,
    control: EnforcementControlRecord,
    *,
    target: ControlState,
    scope: Mapping[str, Any],
    thresholds: Mapping[str, float] | None,
    justification: str,
    rollback_version: str,
    actor_email: str,
) -> tuple[EnforcementControlRecord, ReadinessReport]:
    """Первый человек просит включить. Контроль не меняется, пока не согласует второй."""
    if target not in (ControlState.CANARY, ControlState.PILOT):
        raise EnforcementError("включение возможно только в CANARY или PILOT", 422)
    kind = ControlType(control.control_type)
    report = refresh_readiness(session, settings, organization_id, control)
    blocked = blocking_gaps(kind, gap_statuses(session, organization_id))
    if blocked or report.status is Readiness.BLOCKED_BY_GAP:
        raise EnforcementError(
            "контроль заблокирован известным пробелом",
            409,
            detail={"readiness": report.status.value, "reasons": list(report.reasons)},
        )
    if target not in TRANSITIONS[ControlState(control.state)]:
        raise EnforcementError(f"переход {control.state} → {target.value} недопустим", 409)
    if target is ControlState.CANARY and not report.can_canary:
        raise EnforcementError(
            "контроль не готов к канарейке",
            409,
            detail={"readiness": report.status.value, "reasons": list(report.reasons)},
        )
    if target is ControlState.PILOT and not report.can_pilot:
        raise EnforcementError(
            "контроль не готов к пилоту",
            409,
            detail={"readiness": report.status.value, "reasons": list(report.reasons)},
        )
    if _open_incident(session, organization_id, kind) is not None:
        raise EnforcementError("по контролю есть незакрытый инцидент ложного срабатывания", 409)
    if len((justification or "").strip()) < 10:
        raise EnforcementError("нужно обоснование не короче 10 символов", 422)
    try:
        parsed_scope = CanaryScope.model_validate(dict(scope))
    except ValueError as exc:
        raise EnforcementError("область канарейки задана неверно", 422) from exc
    if parsed_scope.is_empty():
        raise EnforcementError("область канарейки не может быть пустой: глобального включения нет", 422)
    current = ensure_baseline(session, settings, organization_id)
    rollback = (rollback_version or (current.version if current else "")).strip()
    if not rollback:
        raise EnforcementError("нужна цель отката", 422)
    control.pending_request = {
        "target": target.value,
        "scope": parsed_scope.model_dump(mode="json"),
        "thresholds": dict(thresholds or control.thresholds or {}),
        "justification": justification.strip(),
        "rollback_version": rollback,
        "requested_by": actor_email,
        "requested_at": now().isoformat(),
        "readiness": {
            "status": report.status.value,
            "reasons": list(report.reasons),
            "warnings": list(report.warnings),
        },
    }
    session.flush()
    return control, report


def approve_activation(
    session: Session,
    settings: Settings,
    organization_id: str,
    control: EnforcementControlRecord,
    *,
    actor_email: str,
) -> EnforcementPolicyRecord:
    request = dict(control.pending_request or {})
    if not request:
        raise EnforcementError("нет ожидающего запроса на включение", 409)
    if request["requested_by"] == actor_email:
        raise EnforcementError(
            "согласовать должен другой человек: автор запроса не может согласовать сам", 403
        )
    target = ControlState(request["target"])
    # Состояние могло измениться после запроса: готовность проверяется заново.
    report = refresh_readiness(session, settings, organization_id, control)
    kind = ControlType(control.control_type)
    if (
        blocking_gaps(kind, gap_statuses(session, organization_id))
        or report.status is Readiness.BLOCKED_BY_GAP
    ):
        raise EnforcementError(
            "контроль заблокирован известным пробелом",
            409,
            detail={"readiness": report.status.value, "reasons": list(report.reasons)},
        )
    if (target is ControlState.CANARY and not report.can_canary) or (
        target is ControlState.PILOT and not report.can_pilot
    ):
        raise EnforcementError(
            "контроль больше не готов",
            409,
            detail={"readiness": report.status.value, "reasons": list(report.reasons)},
        )
    if _open_incident(session, organization_id, kind) is not None:
        raise EnforcementError("по контролю есть незакрытый инцидент ложного срабатывания", 409)
    _signing_key(settings)  # без ключа подписи включать нечего: узел не получит политику
    control.state = target.value
    control.canary_scope = request["scope"]
    control.thresholds = request["thresholds"]
    control.justification = request["justification"][:1000]
    control.rollback_version = request["rollback_version"]
    control.activated_by = request["requested_by"]
    control.approved_by = actor_email
    control.activated_at = now()
    control.paused_at = None
    control.pending_request = {}
    record = publish(
        session,
        settings,
        organization_id,
        owner=request["requested_by"],
        reviewer=actor_email,
        rollback_target=request["rollback_version"],
        justification=request["justification"],
    )
    session.flush()
    return record


def cancel_request(control: EnforcementControlRecord) -> None:
    if not control.pending_request:
        raise EnforcementError("нет ожидающего запроса", 409)
    control.pending_request = {}


def pause(
    session: Session,
    settings: Settings,
    organization_id: str,
    control: EnforcementControlRecord,
    *,
    actor_email: str,
    reason: str,
) -> EnforcementPolicyRecord:
    if ControlState(control.state) is ControlState.PAUSED:
        raise EnforcementError("контроль уже приостановлен", 409)
    if ControlState.PAUSED not in TRANSITIONS[ControlState(control.state)]:
        raise EnforcementError(f"из состояния {control.state} приостановить нельзя", 409)
    _signing_key(settings)
    control.state = ControlState.PAUSED.value
    control.paused_at = now()
    record = publish(
        session, settings, organization_id, owner=actor_email, justification=f"пауза: {reason}"[:500]
    )
    return record


def rollback(
    session: Session,
    settings: Settings,
    organization_id: str,
    control: EnforcementControlRecord,
    *,
    actor_email: str,
    to_version: str = "",
) -> EnforcementPolicyRecord:
    """Вернуть политику к прежней версии: узлы получают ту же контрольную сумму, что и раньше (ТЗ §76)."""
    target_version = (to_version or control.rollback_version or "").strip()
    if not target_version or target_version == "SHADOW":
        _signing_key(settings)
        control.state = ControlState.ROLLED_BACK.value
        control.canary_scope = {}
        control.rollback_version = ""
        return publish(
            session, settings, organization_id, owner=actor_email, justification="откат контроля в наблюдение"
        )
    target = session.execute(
        select(EnforcementPolicyRecord).where(
            EnforcementPolicyRecord.organization_id == organization_id,
            EnforcementPolicyRecord.version == target_version,
        )
    ).scalar_one_or_none()
    if target is None:
        raise EnforcementError("версия для отката не найдена", 404)
    if target.valid_until is not None and _aware(target.valid_until) <= now():
        raise EnforcementError(
            "срок действия версии для отката истёк: опубликуйте её копию новой версией", 409
        )
    for row in session.execute(
        select(EnforcementPolicyRecord).where(
            EnforcementPolicyRecord.organization_id == organization_id,
            EnforcementPolicyRecord.is_current.is_(True),
        )
    ).scalars():
        row.is_current = False
        row.state = PolicyReleaseState.SUPERSEDED
    target.is_current = True
    target.state = PolicyReleaseState.PUBLISHED
    # Состояния контролей приводятся к откатываемой версии, а откатываемый контроль помечается явно.
    by_type = {c["control_type"]: c for c in (target.body or {}).get("controls", [])}
    for crow in ensure_controls(session, organization_id):
        spec = by_type.get(crow.control_type)
        if spec:
            crow.state = spec["state"]
            crow.canary_scope = spec.get("canary_scope") or {}
            crow.thresholds = spec.get("thresholds") or {}
        crow.policy_version = target.version
    control.state = ControlState.ROLLED_BACK.value
    control.rollback_version = ""
    session.flush()
    return target


# ---------------------------------------------------------------------------------------------
# Общий выключатель
# ---------------------------------------------------------------------------------------------
def switch_row(session: Session, organization_id: str) -> EnforcementSwitchRecord:
    row = session.execute(
        select(EnforcementSwitchRecord).where(EnforcementSwitchRecord.organization_id == organization_id)
    ).scalar_one_or_none()
    if row is None:
        row = EnforcementSwitchRecord(organization_id=organization_id)
        session.add(row)
        session.flush()
    return row


def activate_kill_switch(
    session: Session, organization_id: str, *, actor_email: str, reason: str
) -> EnforcementSwitchRecord:
    """Один человек, без согласования: каждая лишняя секунда — это отказанные письма (ТЗ §19)."""
    row = switch_row(session, organization_id)
    if row.kill_switch:
        return row
    row.kill_switch = True
    row.reason = (reason or "без указания причины")[:1000]
    row.activated_by = actor_email
    row.activated_at = now()
    row.activation_count += 1
    row.clear_requested_by = ""
    row.clear_requested_at = None
    return row


def clear_kill_switch(
    session: Session, organization_id: str, *, actor_email: str
) -> tuple[EnforcementSwitchRecord, bool]:
    """Снять может второй человек. Возвращает (строка, снят ли выключатель)."""
    row = switch_row(session, organization_id)
    if not row.kill_switch:
        raise EnforcementError("общий выключатель не активен", 409)
    if not row.clear_requested_by:
        row.clear_requested_by = actor_email
        row.clear_requested_at = now()
        return row, False
    if row.clear_requested_by == actor_email:
        raise EnforcementError("снять выключатель должен другой человек: запрос уже подан вами", 403)
    row.kill_switch = False
    row.cleared_by = actor_email
    row.cleared_at = now()
    return row, True


# ---------------------------------------------------------------------------------------------
# Решения
# ---------------------------------------------------------------------------------------------
def ingest_decisions(
    session: Session, organization_id: str, node_id: str, items: Iterable[Mapping[str, Any]]
) -> dict[str, int]:
    accepted = duplicate = rejected = 0
    for raw in items:
        try:
            control = ControlType(str(raw["control_type"]))
            decided_at = datetime.fromisoformat(str(raw["decided_at"]))
        except (KeyError, ValueError):
            rejected += 1
            continue
        tmid = str(raw.get("transport_message_id", ""))[:64]
        exists = session.execute(
            select(func.count())
            .select_from(EnforcementDecisionRecord)
            .where(
                EnforcementDecisionRecord.organization_id == organization_id,
                EnforcementDecisionRecord.node_id == node_id,
                EnforcementDecisionRecord.transport_message_id == tmid,
                EnforcementDecisionRecord.control_type == control.value,
                EnforcementDecisionRecord.decided_at == decided_at,
            )
        ).scalar_one()
        if exists:
            duplicate += 1
            continue
        session.add(
            EnforcementDecisionRecord(
                organization_id=organization_id,
                node_id=node_id,
                transport_message_id=tmid,
                internet_message_id=str(raw.get("internet_message_id", ""))[:998],
                control_type=control.value,
                decision=str(raw.get("decision", "NO_DECISION"))[:16],
                smtp_action=str(raw.get("smtp_action", ""))[:200],
                suggested_action=str(raw.get("suggested_action", ""))[:24],
                applied_action=str(raw.get("applied_action", "OBSERVE_ONLY"))[:24],
                reason_codes=list(raw.get("reason_codes") or [])[:50],
                evidence_ids=list(raw.get("evidence_ids") or [])[:50],
                policy_version=str(raw.get("policy_version", ""))[:64],
                policy_checksum=str(raw.get("policy_checksum", ""))[:64],
                engine_versions=dict(raw.get("engine_versions") or {}),
                fail_mode_applied=str(raw.get("fail_mode_applied") or "")[:16],
                latency_ms=float(raw.get("latency_ms") or 0.0),
                recipient_count=int(raw.get("recipient_count") or 1),
                previous_attempt=str(raw.get("previous_attempt", ""))[:64],
                sender_domain=str(raw.get("sender_domain", ""))[:255],
                client_ip=str(raw.get("client_ip", ""))[:64],
                decided_at=decided_at,
            )
        )
        accepted += 1
    session.flush()
    return {"accepted": accepted, "duplicate": duplicate, "rejected": rejected}


def decision_view(row: EnforcementDecisionRecord) -> dict[str, Any]:
    return {
        "id": row.id,
        "node_id": row.node_id,
        "transport_message_id": row.transport_message_id,
        "internet_message_id": row.internet_message_id,
        "control_type": row.control_type,
        "decision": row.decision,
        "smtp_action": row.smtp_action,
        "suggested_action": row.suggested_action,
        "applied_action": row.applied_action,
        "reason_codes": row.reason_codes,
        "evidence_ids": row.evidence_ids,
        "policy_version": row.policy_version,
        "policy_checksum": row.policy_checksum,
        "engine_versions": row.engine_versions,
        "fail_mode_applied": row.fail_mode_applied or None,
        "latency_ms": row.latency_ms,
        "recipient_count": row.recipient_count,
        "previous_attempt": row.previous_attempt,
        "sender_domain": row.sender_domain,
        "client_ip": row.client_ip,
        "review_outcome": row.review_outcome or None,
        "review_critical": row.review_critical,
        "decided_at": row.decided_at.isoformat(),
    }


def list_decisions(
    session: Session,
    organization_id: str,
    *,
    control: str | None = None,
    applied: str | None = None,
    policy_version: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[EnforcementDecisionRecord]:
    stmt = select(EnforcementDecisionRecord).where(
        EnforcementDecisionRecord.organization_id == organization_id
    )
    if control:
        stmt = stmt.where(EnforcementDecisionRecord.control_type == control)
    if applied:
        stmt = stmt.where(EnforcementDecisionRecord.applied_action == applied)
    if policy_version:
        stmt = stmt.where(EnforcementDecisionRecord.policy_version == policy_version)
    stmt = stmt.order_by(EnforcementDecisionRecord.decided_at.desc()).limit(min(limit, 200)).offset(offset)
    return list(session.execute(stmt).scalars())


def review_decision(
    session: Session,
    settings: Settings,
    organization_id: str,
    decision_id: str,
    *,
    outcome: str,
    critical: bool,
    actor_email: str,
) -> tuple[EnforcementDecisionRecord, EmergencyIncidentRecord | None]:
    row = session.get(EnforcementDecisionRecord, decision_id)
    if row is None or row.organization_id != organization_id:
        raise EnforcementError("решение не найдено", 404)
    if outcome not in ("CORRECT", "FALSE_POSITIVE"):
        raise EnforcementError("исход: CORRECT или FALSE_POSITIVE", 422)
    row.review_outcome = outcome
    row.review_critical = bool(critical and outcome == "FALSE_POSITIVE")
    row.reviewed_by = actor_email
    row.reviewed_at = now()
    incident = None
    if row.review_critical:
        # Критическое ложное срабатывание: контроль останавливается сразу, а по нему открывается инцидент (ТЗ §37).
        incident = open_incident(
            session,
            settings,
            organization_id,
            control=ControlType(row.control_type),
            opened_by=actor_email,
            title=f"критическое ложное срабатывание: {row.control_type}",
            policy_version=row.policy_version,
            impacted=[row.transport_message_id],
            pause_control=True,
        )
    return row, incident


# ---------------------------------------------------------------------------------------------
# Аварийный сценарий ложного срабатывания
# ---------------------------------------------------------------------------------------------
def open_incident(
    session: Session,
    settings: Settings,
    organization_id: str,
    *,
    control: ControlType,
    opened_by: str,
    title: str,
    policy_version: str = "",
    impacted: list[str] | None = None,
    pause_control: bool = True,
) -> EmergencyIncidentRecord:
    existing = _open_incident(session, organization_id, control)
    if existing is not None:
        return existing
    incident = EmergencyIncidentRecord(
        organization_id=organization_id,
        control_type=control.value,
        policy_version=policy_version,
        title=title[:300],
        opened_by=opened_by,
        impacted=list(impacted or []),
    )
    session.add(incident)
    if pause_control:
        row = get_control(session, organization_id, control.value)
        if ControlState(row.state) in ACTIVE_STATES:
            try:
                pause(
                    session,
                    settings,
                    organization_id,
                    row,
                    actor_email=opened_by,
                    reason=f"инцидент: {title}",
                )
            except EnforcementError:
                # Без ключа подписи пауза недоступна; остаётся общий выключатель — он не требует подписи.
                activate_kill_switch(
                    session, organization_id, actor_email=opened_by, reason=f"инцидент: {title}"
                )
    session.flush()
    return incident


def advance_incident(
    incident: EmergencyIncidentRecord,
    *,
    to: IncidentState,
    actor_email: str,
    root_cause: str = "",
    regression_case: str = "",
    released: int = 0,
) -> EmergencyIncidentRecord:
    order = [
        IncidentState.OPEN,
        IncidentState.CONTAINED,
        IncidentState.ROOT_CAUSE_FOUND,
        IncidentState.REGRESSION_ADDED,
        IncidentState.CLOSED,
    ]
    if order.index(to) != order.index(incident.state) + 1:
        raise EnforcementError("этапы инцидента пропускать нельзя", 409)
    if to is IncidentState.ROOT_CAUSE_FOUND:
        if len(root_cause.strip()) < 20:
            raise EnforcementError("нужно описание причины не короче 20 символов", 422)
        incident.root_cause = root_cause.strip()
    if to is IncidentState.REGRESSION_ADDED:
        if not regression_case.strip():
            raise EnforcementError("нужна ссылка на регрессионный случай", 422)
        incident.regression_case = regression_case.strip()[:300]
    if to is IncidentState.CLOSED:
        incident.closed_by = actor_email
        incident.closed_at = now()
    if released:
        incident.released_count += released
    incident.state = to
    return incident


def incident_view(row: EmergencyIncidentRecord) -> dict[str, Any]:
    return {
        "id": row.id,
        "control_type": row.control_type,
        "policy_version": row.policy_version,
        "state": row.state.value,
        "title": row.title,
        "opened_by": row.opened_by,
        "impacted": row.impacted,
        "released_count": row.released_count,
        "root_cause": row.root_cause,
        "regression_case": row.regression_case,
        "closed_by": row.closed_by,
        "closed_at": row.closed_at.isoformat() if row.closed_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


# ---------------------------------------------------------------------------------------------
# Исключения
# ---------------------------------------------------------------------------------------------
def create_exception(
    session: Session,
    organization_id: str,
    *,
    scope: str,
    control: str | None,
    value: str,
    reason: str,
    owner: str,
    expires_at: datetime,
    max_uses: int | None,
) -> EnforcementExceptionRecord:
    try:
        model = EnforcementException(
            id="pending",
            scope=ExceptionScope(scope),
            control=ControlType(control) if control else None,
            value=value,
            reason=reason,
            owner=owner,
            created_at=now(),
            expires_at=expires_at,
            max_uses=max_uses,
        )
    except ValueError as exc:
        raise EnforcementError(f"исключение не принято: {exc}", 422) from exc
    row = EnforcementExceptionRecord(
        organization_id=organization_id,
        scope=model.scope.value,
        control_type=model.control.value if model.control else "",
        value=model.value,
        reason=model.reason,
        owner=owner,
        expires_at=expires_at,
        max_uses=max_uses,
        approved_by="" if model.needs_four_eyes() else owner,
    )
    session.add(row)
    session.flush()
    return row


def approve_exception(row: EnforcementExceptionRecord, *, actor_email: str) -> None:
    if row.revoked_at is not None:
        raise EnforcementError("исключение отозвано", 409)
    if row.approved_by and row.approved_by != row.owner:
        raise EnforcementError("исключение уже согласовано", 409)
    if actor_email == row.owner:
        raise EnforcementError("согласовать должен другой человек", 403)
    row.approved_by = actor_email


def exception_view(row: EnforcementExceptionRecord) -> dict[str, Any]:
    needs = row.scope == ExceptionScope.CONTROL.value or (
        bool(row.control_type) and ControlType(row.control_type) in _sensitive()
    )
    approved = (not needs) or (bool(row.approved_by) and row.approved_by != row.owner)
    active = (
        approved
        and row.revoked_at is None
        and _aware(row.expires_at) > now()
        and (row.max_uses is None or row.uses < row.max_uses)
    )
    return {
        "id": row.id,
        "scope": row.scope,
        "control": row.control_type or None,
        "value": row.value,
        "reason": row.reason,
        "owner": row.owner,
        "approved_by": row.approved_by or None,
        "needs_four_eyes": needs,
        "approved": approved,
        "expires_at": row.expires_at.isoformat(),
        "max_uses": row.max_uses,
        "uses": row.uses,
        "revoked": row.revoked_at is not None,
        "active": active,
    }


def _sensitive() -> frozenset[ControlType]:
    from msp_enforcement.model import SENSITIVE_CONTROLS

    return SENSITIVE_CONTROLS


# ---------------------------------------------------------------------------------------------
# Симулятор и воспроизведение
# ---------------------------------------------------------------------------------------------
def input_from_scan(scan: SpamScan) -> EnforcementInput:
    src = (scan.details or {}).get("source_record") or {}
    rcpt = src.get("rcpt") or []
    recipients = tuple(str(r) for r in rcpt) if isinstance(rcpt, list) else ()
    auth = scan.auth or {}
    dmarc = auth.get("dmarc") or {}
    signal_codes = tuple(s.get("code") for s in (scan.signals or []) if s.get("risk_effect") == "INCREASE")
    listed = tuple(code for code in signal_codes if code == "REPUTATION_LISTED")
    return EnforcementInput(
        transport_message_id=scan.queue_id or "",
        message_id=scan.internet_message_id or "",
        sender=str(src.get("from") or ""),
        recipients=recipients,
        source_ip=scan.client_ip or "",
        direction=scan.direction,
        trusted_evidence=True,
        spam_score=scan.score,
        spam_class=scan.spam_class,
        suggested_action=scan.suggested_action,
        reason_codes=tuple(c for c in signal_codes if c),
        evidence_ids=(scan.id,),
        rbl_listed=listed,
        dmarc_result=str(dmarc.get("result") or "NONE"),
        dmarc_policy=str(
            (dmarc.get("policy") or {}).get("p")
            if isinstance(dmarc.get("policy"), dict)
            else dmarc.get("policy") or "NONE"
        ).upper(),
        risk_verdict=scan.security_verdict or "UNKNOWN",
        malware=MalwareEvidence(),
    )


def _policy_for_simulation(
    session: Session,
    settings: Settings,
    organization_id: str,
    control: EnforcementControlRecord,
    inp: EnforcementInput,
    *,
    as_state: ControlState,
) -> EnforcementPolicy:
    """Текущая политика, в которой выбранный контроль гипотетически включён для этого письма."""
    base = build_policy(session, settings, organization_id, owner="simulator")
    scope = CanaryScope(recipients=tuple(inp.recipients) or ("simulated@invalid",))
    controls = tuple(
        ControlPolicy(
            control_type=c.control_type, state=as_state, thresholds=c.thresholds, canary_scope=scope
        )
        if c.control_type.value == control.control_type
        else c
        for c in base.controls
    )
    return base.model_copy(update={"controls": controls})


def simulate(
    session: Session,
    settings: Settings,
    organization_id: str,
    control: EnforcementControlRecord,
    *,
    scan_id: str,
) -> dict[str, Any]:
    scan = session.get(SpamScan, scan_id)
    if scan is None or scan.organization_id != organization_id:
        raise EnforcementError("письмо не найдено", 404)
    inp = input_from_scan(scan)
    kind = ControlType(control.control_type)
    gaps = gap_statuses(session, organization_id)
    report = refresh_readiness(session, settings, organization_id, control)
    live = decide_with_current(session, organization_id, inp)
    hypo_policy = _policy_for_simulation(
        session, settings, organization_id, control, inp, as_state=ControlState.CANARY
    )
    hypo = decide(inp, Runtime(policy=hypo_policy, status=PolicyStatus.FRESH, now=now(), switches=Switches()))
    mine = next((d for d in hypo.decisions if d.control_type is kind), None)
    live_mine = next((d for d in live.decisions if d.control_type is kind), None) if live else None
    return {
        "control": control.control_type,
        "readiness": report.status.value,
        "gap_blockers": list(blocking_gaps(kind, gaps)),
        "restricted_reasons": sorted(restricted_reasons(gaps)),
        "exception": next((c for c in (mine.reason_codes if mine else ()) if c == "EXCEPTION"), None),
        "suggested_action": (mine.suggested_action if mine else "") or scan.suggested_action,
        "current_applied_action": live_mine.applied_action.value if live_mine else "OBSERVE_ONLY",
        "hypothetical_applied_action": mine.applied_action.value if mine else "OBSERVE_ONLY",
        "hypothetical_decision": mine.decision.value if mine else "NO_DECISION",
        "reason_codes": list(mine.reason_codes) if mine else [],
        "note": "Гипотеза: письмо не изменено, решение не отправлялось на узел.",
    }


def decide_with_current(session: Session, organization_id: str, inp: EnforcementInput) -> Any:
    record = current_policy(session, organization_id)
    if record is None:
        return None
    policy = EnforcementPolicy.model_validate(record.body)
    switch = switch_row(session, organization_id)
    return decide(
        inp,
        Runtime(
            policy=policy,
            status=PolicyStatus.FRESH,
            now=now(),
            switches=Switches(kill_switch=switch.kill_switch),
        ),
    )


def replay(
    session: Session,
    settings: Settings,
    organization_id: str,
    control: EnforcementControlRecord,
    *,
    hours: int = 168,
    limit: int = 2000,
    thresholds: Mapping[str, float] | None = None,
) -> dict[str, Any]:
    """Что сделала бы политика с уже принятой почтой. Письма не меняются, решения не отправляются (ТЗ §43)."""
    since = now() - timedelta(hours=hours)
    kind = ControlType(control.control_type)
    scans = (
        session.execute(
            select(SpamScan)
            .where(SpamScan.organization_id == organization_id, SpamScan.received_at >= since)
            .order_by(SpamScan.received_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    reviews = {
        r.scan_id: r.verdict
        for r in session.execute(
            select(SpamReview).where(SpamReview.organization_id == organization_id)
        ).scalars()
    }
    base = build_policy(session, settings, organization_id, owner="replay")
    th = dict(thresholds or control.thresholds or DEFAULT_THRESHOLDS.get(kind, {}))
    controls = tuple(
        ControlPolicy(
            control_type=kind,
            state=ControlState.CANARY,
            thresholds=th,
            canary_scope=CanaryScope(percentage=100.0, salt="replay"),
        )
        if c.control_type is kind
        else c
        for c in base.controls
    )
    policy = base.model_copy(update={"controls": controls})
    counts: Counter[str] = Counter()
    tp = fp = fn = tn = 0
    for scan in scans:
        inp = input_from_scan(scan)
        # Область воспроизведения — вся принятая почта: получателей, которых в записи нет, подменяем условным.
        inp = inp.model_copy(update={"recipients": inp.recipients or ("replay@invalid",)})
        out = decide(inp, Runtime(policy=policy, status=PolicyStatus.FRESH, now=now()))
        mine = next((d for d in out.decisions if d.control_type is kind), None)
        decision = mine.decision.value if mine else "NO_DECISION"
        counts[decision] += 1
        verdict = reviews.get(scan.id)
        would_reject = decision in ("REJECT", "QUARANTINE", "HOLD", "TEMPFAIL")
        if verdict is not None:
            bad = verdict == "SPAM"
            if would_reject and bad:
                tp += 1
            elif would_reject and not bad:
                fp += 1
            elif not would_reject and bad:
                fn += 1
            else:
                tn += 1
    judged_pos = tp + fp
    return {
        "control": control.control_type,
        "window_hours": hours,
        "evaluated": len(scans),
        "decisions": dict(counts),
        "labelled": tp + fp + fn + tn,
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "fp_rate": round(fp / judged_pos, 4) if judged_pos else None,
        "thresholds": th,
        "note": "Воспроизведение без действий: письма не менялись, решения на узлы не отправлялись.",
    }


# ---------------------------------------------------------------------------------------------
# Безопасность и метрики
# ---------------------------------------------------------------------------------------------
def safety_summary(session: Session, settings: Settings, organization_id: str) -> dict[str, Any]:
    controls = ensure_controls(session, organization_id)
    out = []
    for row in controls:
        kind = ControlType(row.control_type)
        report, real = reject_evidence(session, settings, organization_id, kind)
        out.append(
            {
                "control": row.control_type,
                "state": row.state,
                "reject_safety": report.model_dump(mode="json"),
                "real_flow_sample": real,
                "canary_scope": row.canary_scope,
            }
        )
    current = current_policy(session, organization_id)
    nodes = (
        session.execute(select(TransportNode).where(TransportNode.organization_id == organization_id))
        .scalars()
        .all()
    )
    drift = []
    for n in nodes:
        enf = (n.details or {}).get("enforcement") or {}
        if not enf:
            continue
        drift.append(
            {
                "node_id": n.node_id,
                "policy_checksum": enf.get("policy_checksum"),
                "policy_status": enf.get("policy_status"),
                "in_sync": bool(current and enf.get("policy_checksum") == current.checksum),
                "local_bypass": bool(enf.get("local_bypass")),
                "reported_at": enf.get("reported_at"),
            }
        )
    exceptions = [
        exception_view(r)
        for r in session.execute(
            select(EnforcementExceptionRecord).where(
                EnforcementExceptionRecord.organization_id == organization_id
            )
        ).scalars()
    ]
    return {
        "controls": out,
        "policy": policy_view(current) if current else None,
        "nodes": drift,
        "active_exceptions": [e for e in exceptions if e["active"]],
        "kill_switch": switch_row(session, organization_id).kill_switch,
        "emergency_bypass_nodes": [d["node_id"] for d in drift if d["local_bypass"]],
        "global_production_mx_cutover": False,
        "warning": "MSP 1.3 IS NOT APPROVED FOR GLOBAL PRODUCTION MX CUTOVER.",
    }


def metrics_snapshot(session: Session, organization_id: str) -> dict[str, Any]:
    """Счётчики для консоли и экспорта: решения по контролям и действиям, ошибки, тайм-ауты, ложные срабатывания."""
    rows = session.execute(
        select(
            EnforcementDecisionRecord.control_type,
            EnforcementDecisionRecord.decision,
            EnforcementDecisionRecord.applied_action,
            func.count(),
        )
        .where(EnforcementDecisionRecord.organization_id == organization_id)
        .group_by(
            EnforcementDecisionRecord.control_type,
            EnforcementDecisionRecord.decision,
            EnforcementDecisionRecord.applied_action,
        )
    ).all()
    per: dict[str, dict[str, Any]] = {}
    for control, decision, applied, count in rows:
        item = per.setdefault(control, {"evaluated": 0, "applied": 0, "bypassed": 0, "by_decision": {}})
        item["evaluated"] += count
        item["by_decision"][decision] = item["by_decision"].get(decision, 0) + count
        if applied in ("SMTP_REJECT", "SMTP_TEMPFAIL", "QUARANTINED", "HELD"):
            item["applied"] += count
        if applied.startswith("BYPASS") or applied == "SAFE_MODE":
            item["bypassed"] += count
    timeouts = session.execute(
        select(EnforcementDecisionRecord.control_type, func.count())
        .where(
            EnforcementDecisionRecord.organization_id == organization_id,
            EnforcementDecisionRecord.fail_mode_applied != "",
        )
        .group_by(EnforcementDecisionRecord.control_type)
    ).all()
    for control, count in timeouts:
        per.setdefault(control, {"evaluated": 0, "applied": 0, "bypassed": 0, "by_decision": {}})[
            "timeouts"
        ] = count
    fp = session.execute(
        select(EnforcementDecisionRecord.control_type, func.count())
        .where(
            EnforcementDecisionRecord.organization_id == organization_id,
            EnforcementDecisionRecord.review_outcome == "FALSE_POSITIVE",
        )
        .group_by(EnforcementDecisionRecord.control_type)
    ).all()
    for control, count in fp:
        per.setdefault(control, {"evaluated": 0, "applied": 0, "bypassed": 0, "by_decision": {}})[
            "false_positive"
        ] = count
    latencies = [
        r[0]
        for r in session.execute(
            select(EnforcementDecisionRecord.latency_ms)
            .where(EnforcementDecisionRecord.organization_id == organization_id)
            .order_by(EnforcementDecisionRecord.decided_at.desc())
            .limit(1000)
        ).all()
    ]
    latencies.sort()
    p95 = latencies[int(len(latencies) * 0.95) - 1] if len(latencies) >= 20 else None
    switch = switch_row(session, organization_id)
    return {
        "per_control": per,
        "latency_ms_p95": p95,
        "latency_samples": len(latencies),
        "kill_switch": switch.kill_switch,
        "kill_switch_count": switch.activation_count,
    }


def note_node_state(session: Session, organization_id: str, node_id: str, state: Mapping[str, Any]) -> bool:
    """Сохранить состояние принуждения на узле. ``True`` — локальный обход включился (событие аудита)."""
    from .transport import get_or_create_node

    node = get_or_create_node(session, organization_id, node_id)
    details = dict(node.details or {})
    previous = bool((details.get("enforcement") or {}).get("local_bypass"))
    current = bool(state.get("local_bypass"))
    details["enforcement"] = {
        "policy_checksum": str(state.get("policy_checksum", ""))[:64],
        "policy_version": str(state.get("policy_version", ""))[:64],
        "policy_status": str(state.get("policy_status", ""))[:16],
        "local_bypass": current,
        "kill_switch_seen": bool(state.get("kill_switch_seen")),
        "decisions_total": int(state.get("decisions_total") or 0),
        "errors_total": int(state.get("errors_total") or 0),
        "timeouts_total": int(state.get("timeouts_total") or 0),
        "reported_at": now().isoformat(),
    }
    node.details = details
    return current and not previous


# ---------------------------------------------------------------------------------------------
# Послеочередной шлюз: полный анализ MSP до решения о карантине (ТЗ 1.3 §11, §12, §31)
# ---------------------------------------------------------------------------------------------
def gate_analyze(
    session: Session,
    settings: Settings,
    storage: Any,
    organization_id: str,
    *,
    node_id: str,
    queue_id: str,
    message_id: str,
    direction: str,
    raw: bytes,
    client_address: str = "",
) -> dict[str, Any]:
    """Синхронный полный анализ принятого письма. Письмо уже в очереди Postfix: сбой здесь не теряет почту."""
    import hashlib

    from msp_contracts import IntakeSource

    from ..db.models import AnalysisResult
    from ..db.models_transport import TransportMessage
    from .intake import begin_intake
    from .transport_analysis import analyze_transport_message

    digest = hashlib.sha256(raw).hexdigest()
    key = f"gate:{node_id}:{digest}"
    message = session.execute(
        select(TransportMessage).where(
            TransportMessage.organization_id == organization_id, TransportMessage.idempotency_key == key
        )
    ).scalar_one_or_none()
    if message is None:
        message = TransportMessage(
            organization_id=organization_id,
            node_id=node_id,
            idempotency_key=key,
            direction=direction if direction in ("INBOUND", "OUTBOUND") else "UNKNOWN",
            queue_id=queue_id[:40],
            internet_message_id=message_id[:998],
            content_sha256=digest,
            size_bytes=len(raw),
            client_address=client_address[:64],
        )
        session.add(message)
        session.flush()
        outcome = begin_intake(
            session,
            settings,
            organization_id=organization_id,
            source=IntakeSource.SHADOW,
            source_id=f"gateway:{node_id}",
            mailbox_uid=key[:64],
            raw=raw,
            internet_message_id=message_id,
            content_sha256=digest,
            storage=storage,
        )
        message.raw_storage_key = outcome.record.raw_storage_key
    status, job_id = analyze_transport_message(session, settings, message.id, storage)
    result = (
        session.execute(select(AnalysisResult).where(AnalysisResult.job_id == job_id)).scalar_one_or_none()
        if job_id
        else None
    )
    if result is None:
        return {"risk_verdict": "UNKNOWN", "analysis": status, "transport_message_id": message.id}
    facts = result.facts or {}
    codes = [
        str(r.get("id") or r.get("code") or r) if isinstance(r, dict) else str(r)
        for r in (result.reasons or [])
    ]
    return {
        "risk_verdict": result.classification.value,
        "risk_score": result.score,
        "reasons": codes[:12],
        "encrypted_unscannable": bool(
            facts.get("attachment_encrypted_archive")
            or facts.get("limit_archive_encrypted_unscannable")
            or result.scan_completeness == "UNSCANNABLE"
        ),
        "malware_detected": bool(facts.get("av_detection")),
        "scan_completeness": result.scan_completeness,
        "analysis": status,
        "transport_message_id": message.id,
        "job_id": job_id,
    }
