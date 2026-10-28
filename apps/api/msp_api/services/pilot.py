"""Пилот реального потока: метрики, гейты фаз, решения, остановки (MSP 1.3P, ТЗ §4, §13, §21, §24, §28, §29).

Модуль ничего не включает и не выключает. Он читает то, что уже измерили этапы 1.0.4–1.3 (набор валидации,
журнал решений
принуждения, готовность контролей, узлы), и отвечает на один вопрос: достаточно ли доказательств для
следующей фазы. Всё,
что можно проверить программно, проверяется; всё, что проверяется только в среде организации (резервный
ключ, отказ узла,
согласование маршрута), приходит как подтверждение со ссылкой на документ и по умолчанию остаётся
``NOT_TESTED``.

Правила, которые нельзя ослабить настройкой:

* при нуле реальных писем итог — ``NOT_READY``, какими бы зелёными ни были остальные проверки;
* отсутствие знаменателя — ``None``, а не 0 и не «пройдено»;
* лабораторная и реальная выборки не смешиваются; письма из ящика безопасности — смещённая выборка и в
  реальный поток
  не засчитываются;
* ``DMARC_REJECT`` блокируется пробелом GAP-006 и в список контролей решения попасть не может;
* решение вступает в силу только после подтверждения людьми нужных ролей, каждый под своей учётной записью;
* открытая остановка закрывает все фазы до разбора причины и нового решения.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from msp_contracts import RiskLevel, ValidationSource
from msp_enforcement import pilot_stats
from msp_enforcement.model import ControlType
from msp_enforcement.readiness import RESOLVED, assess
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.base import utcnow
from ..db.models import ValidationMessage
from ..db.models_antispam import SpamScan
from ..db.models_enforcement import EnforcementDecisionRecord, EnforcementSwitchRecord
from ..db.models_pilot import (
    PilotAttestationRecord,
    PilotDecisionOutcome,
    PilotDecisionState,
    PilotPhase,
    PilotPhaseDecisionRecord,
    PilotStopRecord,
)
from ..db.models_transport import TransportNode, TransportNodeRole
from . import enforcement
from .gateway_readiness import Check

logger = logging.getLogger(__name__)

#: Письма из этих источников дают представительную выборку реального потока (ТЗ 1.3P §10).
REAL_SHADOW_SOURCES = frozenset(
    {ValidationSource.JOURNAL_COPY, ValidationSource.EWS_READONLY, ValidationSource.GATEWAY_EVIDENCE}
)
#: Ящик безопасности — это «подозрительное, что переслали люди»: смещённая выборка, в реальный поток не идёт.
BIASED_SOURCES = frozenset({ValidationSource.SECURITY_MAILBOX})
IMPORTED_SOURCES = frozenset({ValidationSource.ANALYST_UPLOAD})

#: Контроли, которые могут войти в решение о пилоте. ``DMARC_REJECT`` не входит, пока открыт GAP-006
#: (проверяется отдельно).
PILOT_CONTROLS = tuple(ControlType)

#: Роли, чьё подтверждение нужно решению. Идентичность берётся из сессии: одна учётная запись — одна роль.
ROLE_MAIL_ADMIN = "MAIL_ADMIN"
ROLE_SECURITY_OWNER = "SECURITY_OWNER"
ROLE_BUSINESS_OWNER = "BUSINESS_OWNER"
ALL_ROLES = (ROLE_MAIL_ADMIN, ROLE_SECURITY_OWNER, ROLE_BUSINESS_OWNER)

ATTESTATION_STATUSES = ("PASS", "FAIL", "NOT_TESTED", "BLOCKED_EXTERNAL")

NODE_FRESH_MINUTES = 10


class PilotError(Exception):
    def __init__(self, message: str, status: int = 400, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.detail = detail


# ---------------------------------------------------------------------------------------------
# Каталог подтверждений
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Attest:
    key: str
    title: str
    #: Фаза, вход в которую требует подтверждения.
    phase: PilotPhase


def _a(key: str, title: str, phase: PilotPhase) -> tuple[str, Attest]:
    return key, Attest(key, title, phase)


ATTESTATIONS: dict[str, Attest] = dict(
    [
        # P0 — вход в P1: организационная готовность (ТЗ §14).
        _a(
            "data_approval",
            "Утверждены правомерность доступа к переписке и границы использования",
            PilotPhase.P1,
        ),
        _a("scope_approved", "Утверждены владелец, сроки, источник почты и пилотные ящики", PilotPhase.P1),
        _a("mailflow_plan", "Зафиксированы топология Exchange/SEG и пилотная область", PilotPhase.P1),
        _a("exchange_inventory", "Выполнена инвентаризация Exchange и SEG (только чтение)", PilotPhase.P1),
        _a(
            "roles_assigned",
            "Назначены почтовый администратор, ИБ, оператор, ревьюеры, бизнес-владелец",
            PilotPhase.P1,
        ),
        _a(
            "service_account_minimal",
            "Права служебных учётных записей минимальны (выгрузка прав)",
            PilotPhase.P1,
        ),
        _a("secrets_clean", "Проверка секретов: в репозитории и журналах секретов нет", PilotPhase.P1),
        _a("retention_approved", "Утверждены сроки хранения и удаления писем", PilotPhase.P1),
        _a("monitoring_alerts_tested", "Проверены мониторинг, тревоги и контакты", PilotPhase.P1),
        # P1 — вход в P2: smoke в целевой инфраструктуре (ТЗ §15).
        _a(
            "p1_journal_smoke",
            "Журнальный отчёт → оригинал → надёжный приём → анализ → подтверждение",
            PilotPhase.P2,
        ),
        _a(
            "p1_tls_verified",
            "TLS к Exchange проверен по цепочке и имени, исключений verify=false нет",
            PilotPhase.P2,
        ),
        _a("p1_open_relay_tests", "Проверка открытого ретранслятора на всех SMTP-слушателях", PilotPhase.P2),
        _a(
            "p1_outage_recovery",
            "Отказ EWS/журнала/воркера и восстановление без потери необработанного",
            PilotPhase.P2,
        ),
        _a(
            "p1_backup_restore_test", "Резервная копия и восстановление БД на тестовом объекте", PilotPhase.P2
        ),
        _a(
            "production_mx_unchanged",
            "Основной MX, поток Exchange и штатный SEG не изменялись",
            PilotPhase.P2,
        ),
        # P3/P4 — вход в P4: ограниченный SMTP-канареечный маршрут (ТЗ §9, §18, §23).
        _a(
            "route_change_approval",
            "Отдельное согласование изменения маршрута для пилотного домена",
            PilotPhase.P4,
        ),
        _a(
            "quarantine_key_restore",
            "Ключ карантина: резервная копия и восстановление на тестовом письме",
            PilotPhase.P4,
        ),
        _a(
            "two_node_independent_queues",
            "Два узла с независимыми очередями, адресами и томами",
            PilotPhase.P4,
        ),
        _a(
            "two_node_failover",
            "Потеря одного узла: доставка и восстановление очереди проверены",
            PilotPhase.P4,
        ),
        _a("policy_ttl_safe_mode_real", "Безопасный режим по сроку политики проверен на узле", PilotPhase.P4),
        _a("kill_switch_real", "Аварийный выключатель проверен на обоих узлах", PilotPhase.P4),
        _a("local_bypass_real", "Локальный обход без панели проверен на обоих узлах", PilotPhase.P4),
        _a(
            "policy_rollback_real",
            "Откат политики и контрольная сумма проверены на обоих узлах",
            PilotPhase.P4,
        ),
        _a(
            "receive_connector_restricted",
            "Receive Connector Exchange ограничен адресами узлов, TLS проверен",
            PilotPhase.P4,
        ),
        _a(
            "mixed_recipient_scope_tested",
            "Письмо с несколькими получателями в разных областях безопасно",
            PilotPhase.P4,
        ),
        _a(
            "policy_signing_risk_accept",
            "Асимметричная подпись политики либо принятие риска для изолированного пилота",
            PilotPhase.P4,
        ),
        _a("oncall_assigned", "Назначены дежурный, бизнес-владелец и окно с быстрым откатом", PilotPhase.P4),
        # P5 — итоговая приёмка (ТЗ §19, §28).
        _a("linux_load_profile", "Повторяемая нагрузка на целевой Linux-инфраструктуре", PilotPhase.P5),
        _a("source_cross_check", "Сверка Exchange, SEG и MSP по числу писем", PilotPhase.P5),
        _a("ci_main_green", "CI и проверки безопасности основной ветки зелёные", PilotPhase.P5),
        _a(
            "data_retention_executed",
            "Удаление и удержание данных пилота выполнены по политике",
            PilotPhase.P5,
        ),
        _a(
            "acceptance_signed", "Итоговый документ приёмки подготовлен и подписан владельцами", PilotPhase.P5
        ),
    ]
)

_PHASE_ORDER = [PilotPhase.P1, PilotPhase.P2, PilotPhase.P3, PilotPhase.P4, PilotPhase.P5]


# ---------------------------------------------------------------------------------------------
# Подтверждения
# ---------------------------------------------------------------------------------------------
def record_attestation(
    session: Session,
    organization_id: str,
    *,
    key: str,
    status: str,
    evidence_ref: str,
    note: str,
    actor_email: str,
) -> PilotAttestationRecord:
    if key not in ATTESTATIONS:
        raise PilotError("неизвестное подтверждение", 404)
    if status not in ATTESTATION_STATUSES:
        raise PilotError("недопустимый статус подтверждения", 422)
    ref = (evidence_ref or "").strip()
    if status == "PASS" and not ref:
        # «Проверено» без ссылки на документ — то же самое, что не проверено.
        raise PilotError("PASS требует ссылки на доказательство", 422)
    row = PilotAttestationRecord(
        organization_id=organization_id,
        attestation_key=key,
        status=status,
        evidence_ref=ref[:500],
        note=(note or "")[:1000],
        recorded_by=actor_email,
        recorded_at=utcnow(),
    )
    session.add(row)
    session.flush()
    return row


def latest_attestations(session: Session, organization_id: str) -> dict[str, PilotAttestationRecord]:
    rows = (
        session.execute(
            select(PilotAttestationRecord)
            .where(PilotAttestationRecord.organization_id == organization_id)
            .order_by(PilotAttestationRecord.recorded_at.asc(), PilotAttestationRecord.created_at.asc())
        )
        .scalars()
        .all()
    )
    latest: dict[str, PilotAttestationRecord] = {}
    for row in rows:
        latest[row.attestation_key] = row
    return latest


def attestation_view(row: PilotAttestationRecord | None, spec: Attest) -> dict[str, Any]:
    return {
        "key": spec.key,
        "title": spec.title,
        "phase": spec.phase.value,
        "status": row.status if row is not None else "NOT_TESTED",
        "evidence_ref": row.evidence_ref if row is not None else "",
        "recorded_by": row.recorded_by if row is not None else "",
        "recorded_at": row.recorded_at.isoformat() if row is not None else None,
    }


def attestation_check(latest: dict[str, PilotAttestationRecord], key: str) -> Check:
    spec = ATTESTATIONS[key]
    row = latest.get(key)
    if row is None or row.status in ("NOT_TESTED", "BLOCKED_EXTERNAL"):
        return Check(
            key=f"att:{key}",
            title=spec.title,
            required=True,
            passed=None,
            value=row.status if row is not None else "NOT_TESTED",
            expected="PASS со ссылкой на доказательство",
            detail="Проверяется в среде организации; платформа сама это подтвердить не может.",
        )
    return Check(
        key=f"att:{key}",
        title=spec.title,
        required=True,
        passed=row.status == "PASS" and bool(row.evidence_ref),
        value=row.status,
        expected="PASS со ссылкой на доказательство",
        detail=row.evidence_ref,
    )


# ---------------------------------------------------------------------------------------------
# Метрики
# ---------------------------------------------------------------------------------------------
def _roles(session: Session, organization_id: str) -> dict[str, str]:
    return {
        n.node_id: n.role.value
        for n in session.execute(
            select(TransportNode).where(TransportNode.organization_id == organization_id)
        ).scalars()
    }


def _is_real(roles: dict[str, str], node_id: str) -> bool:
    """Неизвестный узел считается лабораторным: реальным поток объявляет только зарегистрированный боевой."""
    return roles.get(node_id, TransportNodeRole.LAB.value) != TransportNodeRole.LAB.value


def _sample(session: Session, organization_id: str) -> dict[str, Any]:
    rows = session.execute(
        select(ValidationMessage).where(ValidationMessage.organization_id == organization_id)
    ).scalars()
    real: list[ValidationMessage] = []
    counts = {"biased_real": 0, "imported": 0, "drill": 0}
    by_source: dict[str, int] = {}
    for row in rows:
        if row.expected_classification is not None:
            # Заранее известный ответ — учения, а не реальный поток.
            counts["drill"] += 1
        elif row.source in REAL_SHADOW_SOURCES:
            real.append(row)
            by_source[row.source.value] = by_source.get(row.source.value, 0) + 1
        elif row.source in BIASED_SOURCES:
            counts["biased_real"] += 1
        elif row.source in IMPORTED_SOURCES:
            counts["imported"] += 1
    unique = len(real)
    reviewed = sum(1 for r in real if r.analyst_classification is not None)
    unknown = sum(1 for r in real if r.production_verdict in (None, RiskLevel.UNKNOWN))
    unscannable = sum(1 for r in real if r.unscannable_reasons)
    delays = [
        (r.created_at - r.received_at).total_seconds()
        for r in real
        if r.created_at is not None and r.received_at is not None
    ]
    return {
        "real_unique": unique,
        "real_reviewed": reviewed,
        "real_by_source": by_source,
        "biased_real_security_mailbox": counts["biased_real"],
        "imported_analyst_upload": counts["imported"],
        "drills": counts["drill"],
        "unknown_per_1000": pilot_stats.per_1000(unknown, unique),
        "unscannable_per_1000": pilot_stats.per_1000(unscannable, unique),
        "ingest_delay_p95_seconds": pilot_stats.percentile(delays, 0.95),
    }


def _control_rejects(
    session: Session, organization_id: str, roles: dict[str, str], control: ControlType
) -> dict[str, Any]:
    """Кандидаты на отказ и их просмотр — только реальный поток, по одному на письмо."""
    candidates = {
        k: n
        for k, n in enforcement.reject_candidates(session, organization_id, control).items()
        if _is_real(roles, n)
    }
    reviewed = {
        k: v
        for k, v in enforcement.reviewed_rejects(session, organization_id, control).items()
        if _is_real(roles, v.node_id)
    }
    fp = sum(1 for v in reviewed.values() if not v.correct)
    critical = sum(1 for v in reviewed.values() if not v.correct and v.critical)
    return {
        "candidates": len(candidates | {k: v.node_id for k, v in reviewed.items()}),
        "reviewed": len(reviewed),
        "confirmed_fp": fp,
        "critical_fp": critical,
    }


def _applied(session: Session, organization_id: str, roles: dict[str, str]) -> dict[str, Any]:
    rows = [
        d
        for d in session.execute(
            select(EnforcementDecisionRecord).where(
                EnforcementDecisionRecord.organization_id == organization_id
            )
        ).scalars()
        if _is_real(roles, d.node_id)
    ]
    rejects = [d for d in rows if d.applied_action == "SMTP_REJECT"]
    tempfails = [d for d in rows if d.applied_action == "SMTP_TEMPFAIL"]
    quarantines = [d for d in rows if d.applied_action in ("QUARANTINED", "HELD")]
    latencies = [float(d.latency_ms) for d in rows if d.latency_ms]
    return {
        "applied_rejects": len(rejects),
        "applied_rejects_reviewed": sum(1 for d in rejects if d.review_outcome),
        "applied_tempfails": len(tempfails),
        "applied_tempfails_reviewed": sum(1 for d in tempfails if d.review_outcome),
        "applied_quarantines": len(quarantines),
        "applied_quarantines_reviewed": sum(1 for d in quarantines if d.review_outcome),
        "decision_latency_p95_ms": pilot_stats.percentile(latencies, 0.95),
        "decision_latency_p99_ms": pilot_stats.percentile(latencies, 0.99),
    }


def _coverage(reviewed: int, total: int) -> float | None:
    return None if total == 0 else round(reviewed / total, 4)


def metrics(session: Session, settings: Settings, organization_id: str) -> dict[str, Any]:
    roles = _roles(session, organization_id)
    sample = _sample(session, organization_id)
    controls: dict[str, Any] = {}
    for kind in (ControlType.SPAM_REJECT, ControlType.RBL_REJECT, ControlType.MALWARE_REJECT):
        data = _control_rejects(session, organization_id, roles, kind)
        data["statistics"] = pilot_stats.evaluate_reject_statistics(
            data["confirmed_fp"],
            data["reviewed"],
            max_upper=settings.enforcement_max_fp_rate,
            min_reviewed=max(settings.enforcement_min_reviewed, 1),
        )
        controls[kind.value] = data
    applied = _applied(session, organization_id, roles)
    lab_scans = sum(
        1
        for s in session.execute(
            select(SpamScan).where(SpamScan.organization_id == organization_id)
        ).scalars()
        if not _is_real(roles, s.node_id)
    )
    applied["applied_rejects_review_coverage"] = _coverage(
        applied["applied_rejects_reviewed"], applied["applied_rejects"]
    )
    applied["applied_quarantines_review_coverage"] = _coverage(
        applied["applied_quarantines_reviewed"], applied["applied_quarantines"]
    )
    critical = sum(c["critical_fp"] for c in controls.values())
    return {
        "generated_at": utcnow().isoformat(),
        "data_classes": {
            "real": "REAL_FLOW_SHADOW и боевые узлы",
            "synthetic": "лабораторные узлы и учения; в реальную выборку не входят",
            "imported": "файлы аналитика и ящик безопасности; смещённая выборка",
        },
        "sample": sample,
        "synthetic_lab_scans": lab_scans,
        "controls": controls,
        "applied": applied,
        "critical_fp": critical,
        "targets": {
            "real_unique": pilot_stats.MIN_REAL_UNIQUE,
            "reviewed_real": pilot_stats.MIN_REVIEWED_REAL,
            "reviewed_reject_candidates": pilot_stats.MIN_REVIEWED_REJECT_CANDIDATES,
        },
        "unavailable": ["postfix_queue_depth", "smtp_delivery_delay_p95"],
    }


# ---------------------------------------------------------------------------------------------
# Факты о платформе
# ---------------------------------------------------------------------------------------------
def _nodes(session: Session, organization_id: str) -> list[dict[str, Any]]:
    current = enforcement.current_policy(session, organization_id)
    horizon = utcnow() - timedelta(minutes=NODE_FRESH_MINUTES)
    out: list[dict[str, Any]] = []
    for n in session.execute(
        select(TransportNode).where(TransportNode.organization_id == organization_id)
    ).scalars():
        if n.role is TransportNodeRole.LAB:
            continue
        state = (n.details or {}).get("enforcement") or {}
        reported = state.get("reported_at")
        fresh = False
        if reported:
            try:
                fresh = datetime.fromisoformat(str(reported)) >= horizon
            except ValueError:
                fresh = False
        out.append(
            {
                "node_id": n.node_id,
                "role": n.role.value,
                "reported_recently": fresh,
                "policy_in_sync": bool(current and state.get("policy_checksum") == current.checksum),
                "local_bypass": bool(state.get("local_bypass")),
            }
        )
    return out


def list_stops(session: Session, organization_id: str) -> list[PilotStopRecord]:
    return list(
        session.execute(
            select(PilotStopRecord)
            .where(PilotStopRecord.organization_id == organization_id)
            .order_by(PilotStopRecord.opened_at.asc())
        ).scalars()
    )


def list_decisions(session: Session, organization_id: str) -> list[PilotPhaseDecisionRecord]:
    return list(
        session.execute(
            select(PilotPhaseDecisionRecord)
            .where(PilotPhaseDecisionRecord.organization_id == organization_id)
            .order_by(PilotPhaseDecisionRecord.created_at.asc())
        ).scalars()
    )


def _aware(value: datetime) -> datetime:
    from datetime import UTC

    return value if value.tzinfo else value.replace(tzinfo=UTC)


def effective_go(
    session: Session, organization_id: str, phase: PilotPhase
) -> PilotPhaseDecisionRecord | None:
    """Действующее решение GO по фазе: подтверждённое и не закрытое остановкой."""
    stops = list_stops(session, organization_id)
    if any(s.state == "OPEN" for s in stops):
        return None
    last_resolved = max((_aware(s.resolved_at) for s in stops if s.resolved_at), default=None)
    found: PilotPhaseDecisionRecord | None = None
    for d in list_decisions(session, organization_id):
        if d.phase != phase.value or d.outcome != PilotDecisionOutcome.GO.value:
            continue
        if d.state != PilotDecisionState.EFFECTIVE.value or d.effective_at is None:
            continue
        if last_resolved is not None and _aware(d.effective_at) < last_resolved:
            continue
        found = d
    return found


# ---------------------------------------------------------------------------------------------
# Контроли
# ---------------------------------------------------------------------------------------------
def control_rows(session: Session, settings: Settings, organization_id: str) -> list[dict[str, Any]]:
    """Готовность каждого контроля отдельно, по реальной выборке (ТЗ §17)."""
    roles = _roles(session, organization_id)
    out = []
    for row in enforcement.ensure_controls(session, organization_id):
        kind = ControlType(row.control_type)
        data = _control_rejects(session, organization_id, roles, kind)
        stats = pilot_stats.evaluate_reject_statistics(
            data["confirmed_fp"],
            data["reviewed"],
            max_upper=settings.enforcement_max_fp_rate,
            min_reviewed=max(settings.enforcement_min_reviewed, 1),
        )
        base = enforcement.readiness_input(session, settings, organization_id, row)
        correct = data["reviewed"] - data["confirmed_fp"]
        from msp_enforcement.readiness import build_reject_safety

        safety = build_reject_safety(
            reviewed=data["reviewed"],
            confirmed_correct=correct,
            confirmed_fp=data["confirmed_fp"],
            critical_fp=data["critical_fp"],
            sample_window="real-only",
            min_reviewed=settings.enforcement_min_reviewed,
            max_fp_upper=settings.enforcement_max_fp_rate,
            systemic_unresolved=base.systemic_fp_unresolved,
        )
        # Пилотная готовность считается только по реальной выборке и без лабораторного допуска (ТЗ §17, §83).
        report = assess(
            kind,
            base.model_copy(
                update={
                    "reject_safety": safety,
                    "real_evidence": data["reviewed"] >= settings.enforcement_min_reviewed,
                    "lab_mode": False,
                }
            ),
        )
        out.append(
            {
                "control": row.control_type,
                "state": row.state,
                "pilot_readiness": report.status.value,
                "can_canary_on_real": report.can_canary,
                "reasons": list(report.reasons),
                "warnings": list(report.warnings),
                "real_reviewed_rejects": data["reviewed"],
                "real_confirmed_fp": data["confirmed_fp"],
                "statistics": stats,
                "blocked_by_gap": report.status.value == "BLOCKED_BY_GAP",
            }
        )
    return out


# ---------------------------------------------------------------------------------------------
# Гейты фаз
# ---------------------------------------------------------------------------------------------
def _check(key: str, title: str, passed: bool | None, value: Any, expected: Any, detail: str = "") -> Check:
    return Check(
        key=key, title=title, required=True, passed=passed, value=value, expected=expected, detail=detail
    )


def platform_facts(session: Session, settings: Settings, organization_id: str) -> dict[str, Any]:
    nodes = _nodes(session, organization_id)
    ready_nodes = [n for n in nodes if n["reported_recently"] and n["policy_in_sync"]]
    switch = session.execute(
        select(EnforcementSwitchRecord).where(EnforcementSwitchRecord.organization_id == organization_id)
    ).scalar_one_or_none()
    controls = enforcement.ensure_controls(session, organization_id)
    active = [c.control_type for c in controls if c.state in ("CANARY", "PILOT")]
    gaps = enforcement.gap_statuses(session, organization_id)
    return {
        "shared_token_allowed": bool(settings.gateway_shared_token_allowed),
        "quarantine_key_configured": len((settings.quarantine_encryption_key or "").strip()) >= 32,
        "nodes": nodes,
        "nodes_ready": len(ready_nodes),
        "kill_switch_active": bool(switch and switch.kill_switch),
        "controls_enforcing": active,
        "gaps": gaps,
        "dmarc_blocked": gaps.get("GAP-006") != RESOLVED,
        "open_stops": [s.id for s in list_stops(session, organization_id) if s.state == "OPEN"],
    }


def _sample_checks(m: dict[str, Any]) -> list[Check]:
    s = m["sample"]
    reject_reviewed = max((c["reviewed"] for c in m["controls"].values()), default=0)
    return [
        _check(
            "sample:real_unique",
            "Уникальных реальных писем",
            s["real_unique"] >= pilot_stats.MIN_REAL_UNIQUE,
            s["real_unique"],
            f">= {pilot_stats.MIN_REAL_UNIQUE}",
        ),
        _check(
            "sample:reviewed_real",
            "Просмотрено реальных писем",
            s["real_reviewed"] >= pilot_stats.MIN_REVIEWED_REAL,
            s["real_reviewed"],
            f">= {pilot_stats.MIN_REVIEWED_REAL}",
        ),
        _check(
            "sample:reject_candidates",
            "Просмотрено реальных кандидатов на отказ (по одному контролю)",
            reject_reviewed >= pilot_stats.MIN_REVIEWED_REJECT_CANDIDATES,
            reject_reviewed,
            f">= {pilot_stats.MIN_REVIEWED_REJECT_CANDIDATES}",
        ),
        _check(
            "sample:critical_fp",
            "Критических ложных срабатываний нет",
            m["critical_fp"] == 0,
            m["critical_fp"],
            0,
        ),
    ]


def gate(
    session: Session,
    settings: Settings,
    organization_id: str,
    phase: PilotPhase,
    *,
    controls: Iterable[str] = (),
) -> dict[str, Any]:
    """Можно ли принять решение GO по фазе. Каждое условие — отдельная запись с фактом и ожиданием."""
    latest = latest_attestations(session, organization_id)
    facts = platform_facts(session, settings, organization_id)
    checks: list[Check] = []

    checks.append(
        _check("no_open_stop", "Открытых остановок нет", not facts["open_stops"], len(facts["open_stops"]), 0)
    )
    index = _PHASE_ORDER.index(phase)
    if index > 0:
        previous = _PHASE_ORDER[index - 1]
        checks.append(
            _check(
                "previous_phase_go",
                f"Действует решение GO по {previous.value}",
                effective_go(session, organization_id, previous) is not None,
                previous.value,
                "EFFECTIVE GO",
            )
        )
    # Пока не принято GO на P4, ни один контроль не должен действовать на почту (ТЗ 1.3P §21, DoD).
    if phase is not PilotPhase.P5 and phase is not PilotPhase.P4:
        checks.append(
            _check(
                "no_enforcement_before_p4",
                "Ни один контроль не действует на почту до решения по P4",
                not facts["controls_enforcing"],
                facts["controls_enforcing"],
                [],
            )
        )

    for key, spec in ATTESTATIONS.items():
        if spec.phase is phase:
            checks.append(attestation_check(latest, key))

    if phase is PilotPhase.P3:
        m = metrics(session, settings, organization_id)
        checks.extend(_sample_checks(m))
    if phase is PilotPhase.P4:
        m = metrics(session, settings, organization_id)
        checks.extend(_sample_checks(m))
        checks.extend(_p4_checks(session, settings, organization_id, facts, controls))
    if phase is PilotPhase.P5:
        m = metrics(session, settings, organization_id)
        applied = m["applied"]
        checks.append(
            _check(
                "applied_rejects_reviewed",
                "Все применённые отказы просмотрены",
                applied["applied_rejects"] > 0 and applied["applied_rejects_review_coverage"] == 1.0,
                applied["applied_rejects_review_coverage"],
                1.0,
                "Если отказы не применялись, покрытие не определено (null): доказательства канарейки нет.",
            )
        )
        checks.append(
            _check(
                "applied_quarantines_reviewed",
                "Все применённые карантинные действия просмотрены",
                applied["applied_quarantines"] > 0 and applied["applied_quarantines_review_coverage"] == 1.0,
                applied["applied_quarantines_review_coverage"],
                1.0,
            )
        )
        checks.append(
            _check("critical_fp", "Критических ложных нет", m["critical_fp"] == 0, m["critical_fp"], 0)
        )

    blocking = [c for c in checks if c.required and c.passed is not True]
    return {
        "phase": phase.value,
        "go_possible": not blocking,
        "checks": [c.as_dict() for c in checks],
        "blocking": [c.key for c in blocking],
        "required_roles": list(required_roles(phase)),
    }


def required_roles(phase: PilotPhase) -> tuple[str, ...]:
    """Вход в P4 подтверждает ещё и владелец бизнес-риска (ТЗ §4)."""
    if phase is PilotPhase.P4:
        return ALL_ROLES
    return (ROLE_MAIL_ADMIN, ROLE_SECURITY_OWNER)


def _p4_checks(
    session: Session, settings: Settings, organization_id: str, facts: dict[str, Any], controls: Iterable[str]
) -> list[Check]:
    selected = list(dict.fromkeys(controls))
    rows = {r["control"]: r for r in control_rows(session, settings, organization_id)}
    checks = [
        _check(
            "shared_token_disabled",
            "Общий токен шлюза отключён (MSP_GATEWAY_SHARED_TOKEN_ALLOWED=false)",
            not facts["shared_token_allowed"],
            facts["shared_token_allowed"],
            False,
        ),
        _check(
            "quarantine_key_configured",
            "Ключ шифрования карантина задан",
            facts["quarantine_key_configured"],
            facts["quarantine_key_configured"],
            True,
        ),
        _check(
            "two_nodes_in_sync",
            "Не менее двух боевых узлов сообщают состояние, политика совпадает",
            facts["nodes_ready"] >= 2,
            facts["nodes_ready"],
            ">= 2",
            "Независимость очередей подтверждается отдельно (two_node_independent_queues).",
        ),
        _check(
            "controls_selected",
            "Выбран минимальный список контролей",
            0 < len(selected) <= 2,
            selected,
            "1–2 контроля",
        ),
    ]
    for name in selected:
        row = rows.get(name)
        if row is None:
            checks.append(_check(f"control:{name}", f"Контроль {name} существует", False, None, "существует"))
            continue
        if row["blocked_by_gap"]:
            checks.append(
                _check(
                    f"control:{name}",
                    f"{name} не заблокирован пробелом",
                    False,
                    "BLOCKED_BY_GAP",
                    "не заблокирован",
                )
            )
            continue
        stat = row["statistics"]["status"]
        checks.append(
            _check(
                f"control:{name}:readiness",
                f"{name}: готовность по реальной выборке",
                row["can_canary_on_real"],
                row["pilot_readiness"],
                "READY / READY_WITH_WARNINGS по реальной выборке",
                "; ".join(row["reasons"]),
            )
        )
        if name != ControlType.QUARANTINE.value and name != ControlType.OUTBOUND_BLOCK.value:
            checks.append(
                _check(
                    f"control:{name}:statistics",
                    f"{name}: верхняя граница ложных",
                    stat in (pilot_stats.STAT_PASS, pilot_stats.STAT_RISK_ACCEPT_REQUIRED),
                    stat,
                    "PASS либо RISK_ACCEPT_REQUIRED с письменным принятием риска",
                )
            )
    return checks


# ---------------------------------------------------------------------------------------------
# Решения
# ---------------------------------------------------------------------------------------------
def parse_phase(value: str) -> PilotPhase:
    try:
        return PilotPhase(value)
    except ValueError as exc:
        raise PilotError("неизвестная фаза", 404) from exc


def propose_decision(
    session: Session,
    settings: Settings,
    organization_id: str,
    *,
    phase: str,
    outcome: str,
    reasons: list[str],
    controls: list[str],
    risk_accept: str,
    actor_email: str,
) -> PilotPhaseDecisionRecord:
    target = parse_phase(phase)
    if target is PilotPhase.P0:
        raise PilotError("P0 — исходное состояние; решение принимается на вход в P1", 422)
    try:
        result = PilotDecisionOutcome(outcome)
    except ValueError as exc:
        raise PilotError("исход — GO или NO_GO", 422) from exc
    if not [r for r in reasons if r.strip()]:
        raise PilotError("причины обязательны", 422)
    names = list(dict.fromkeys(controls))
    for name in names:
        try:
            ControlType(name)
        except ValueError as exc:
            raise PilotError(f"неизвестный контроль {name}", 422) from exc
    if target not in (PilotPhase.P4, PilotPhase.P5) and names:
        raise PilotError("список контролей задаётся только решением по P4", 422)

    snapshot: dict[str, Any] = {}
    risk = (risk_accept or "").strip()
    if result is PilotDecisionOutcome.GO:
        g = gate(session, settings, organization_id, target, controls=names)
        snapshot = g
        if not g["go_possible"]:
            raise PilotError("условия фазы не выполнены", 409, {"blocking": g["blocking"], "gate": g})
        if target is PilotPhase.P4:
            _guard_controls_for_p4(session, settings, organization_id, names, risk)
    # Новое предложение закрывает прежние неподтверждённые по этой фазе.
    for old in list_decisions(session, organization_id):
        if old.phase == target.value and old.state == PilotDecisionState.PROPOSED.value:
            old.state = PilotDecisionState.SUPERSEDED.value
    row = PilotPhaseDecisionRecord(
        organization_id=organization_id,
        phase=target.value,
        outcome=result.value,
        # NO_GO действует сразу: остановить и отказать можно без согласования, расширять — только с ним.
        state=PilotDecisionState.EFFECTIVE.value
        if result is PilotDecisionOutcome.NO_GO
        else PilotDecisionState.PROPOSED.value,
        reasons=[r.strip() for r in reasons if r.strip()],
        proposed_by=actor_email,
        approvals=[],
        gate_snapshot={"controls": names, **snapshot},
        risk_accept=risk,
        effective_at=utcnow() if result is PilotDecisionOutcome.NO_GO else None,
    )
    session.add(row)
    session.flush()
    return row


def _guard_controls_for_p4(
    session: Session, settings: Settings, organization_id: str, names: list[str], risk_accept: str
) -> None:
    rows = {r["control"]: r for r in control_rows(session, settings, organization_id)}
    for name in names:
        row = rows[name]
        if row["blocked_by_gap"]:
            raise PilotError(
                f"{name} заблокирован открытым пробелом", 409, {"control": name, "reason": "BLOCKED_BY_GAP"}
            )
        if row["statistics"]["status"] == pilot_stats.STAT_RISK_ACCEPT_REQUIRED and not risk_accept:
            raise PilotError(
                f"{name}: верхняя граница ложных выше порога, нужно письменное принятие риска",
                409,
                {"control": name, "statistics": row["statistics"]},
            )


def approve_decision(
    session: Session,
    settings: Settings,
    organization_id: str,
    *,
    decision_id: str,
    role: str,
    actor_email: str,
) -> PilotPhaseDecisionRecord:
    row = session.get(PilotPhaseDecisionRecord, decision_id)
    if row is None or row.organization_id != organization_id:
        raise PilotError("решение не найдено", 404)
    if row.state != PilotDecisionState.PROPOSED.value:
        raise PilotError("решение уже не ожидает подтверждений", 409)
    target = parse_phase(row.phase)
    roles = required_roles(target)
    if role not in roles:
        raise PilotError("роль не требуется для этого решения", 422, {"required_roles": list(roles)})
    if actor_email == row.proposed_by:
        raise PilotError("автор решения не может подтверждать его сам", 409)
    approvals = list(row.approvals or [])
    if any(a["email"] == actor_email for a in approvals):
        raise PilotError("один человек не может закрывать две роли", 409)
    if any(a["role"] == role for a in approvals):
        raise PilotError("эта роль уже подтверждена", 409)
    # К моменту подтверждения условия могли измениться: решение не должно опираться на устаревший снимок.
    g = gate(
        session, settings, organization_id, target, controls=(row.gate_snapshot or {}).get("controls", [])
    )
    if not g["go_possible"]:
        raise PilotError("условия фазы больше не выполнены", 409, {"blocking": g["blocking"]})
    approvals.append({"role": role, "email": actor_email, "at": utcnow().isoformat()})
    row.approvals = approvals
    if {a["role"] for a in approvals} >= set(roles):
        for old in list_decisions(session, organization_id):
            if (
                old.id != row.id
                and old.phase == row.phase
                and old.state == PilotDecisionState.EFFECTIVE.value
            ):
                old.state = PilotDecisionState.SUPERSEDED.value
        row.state = PilotDecisionState.EFFECTIVE.value
        row.effective_at = utcnow()
    session.flush()
    return row


def decision_view(row: PilotPhaseDecisionRecord) -> dict[str, Any]:
    return {
        "id": row.id,
        "phase": row.phase,
        "outcome": row.outcome,
        "state": row.state,
        "reasons": list(row.reasons or []),
        "proposed_by": row.proposed_by,
        "approvals": list(row.approvals or []),
        "required_roles": list(required_roles(parse_phase(row.phase))),
        "controls": list((row.gate_snapshot or {}).get("controls", [])),
        "risk_accept": row.risk_accept,
        "effective_at": row.effective_at.isoformat() if row.effective_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


# ---------------------------------------------------------------------------------------------
# Остановки
# ---------------------------------------------------------------------------------------------
STOP_REASONS = frozenset(
    {
        "CRITICAL_FALSE_POSITIVE",
        "UNCONTROLLED_REJECT",
        "OPEN_RELAY",
        "ACCEPTED_MAIL_LOST",
        "CREDENTIAL_COMPROMISE",
        "INVALID_POLICY",
        "QUARANTINE_RELEASE_ERROR",
        "QUARANTINE_KEY_LOST",
        "BLOCKED_CONTROL_ACTIVE",
        "CONTROL_PLANE_UNAVAILABLE",
        "OTHER",
    }
)


def open_stop(
    session: Session,
    organization_id: str,
    *,
    reason_code: str,
    description: str,
    control_type: str,
    actor_email: str,
) -> PilotStopRecord:
    if reason_code not in STOP_REASONS:
        raise PilotError("неизвестная причина остановки", 422, {"allowed": sorted(STOP_REASONS)})
    if control_type:
        try:
            ControlType(control_type)
        except ValueError as exc:
            raise PilotError("неизвестный контроль", 422) from exc
    row = PilotStopRecord(
        organization_id=organization_id,
        reason_code=reason_code,
        description=(description or "")[:2000],
        control_type=control_type,
        opened_by=actor_email,
        opened_at=utcnow(),
        state="OPEN",
    )
    session.add(row)
    session.flush()
    return row


def resolve_stop(
    session: Session,
    organization_id: str,
    *,
    stop_id: str,
    rca_ref: str,
    regression_ref: str,
    actor_email: str,
) -> PilotStopRecord:
    row = session.get(PilotStopRecord, stop_id)
    if row is None or row.organization_id != organization_id:
        raise PilotError("остановка не найдена", 404)
    if row.state != "OPEN":
        raise PilotError("остановка уже закрыта", 409)
    if not rca_ref.strip() or not regression_ref.strip():
        # Возобновление без разбора причины и регрессионного случая — то же, что игнорировать остановку.
        raise PilotError("для закрытия нужны разбор причины и регрессионный случай", 422)
    if actor_email == row.opened_by:
        raise PilotError("остановку закрывает другой человек", 409)
    row.state = "RESOLVED"
    row.resolved_by = actor_email
    row.resolved_at = utcnow()
    row.rca_ref = rca_ref.strip()[:500]
    row.regression_ref = regression_ref.strip()[:500]
    session.flush()
    return row


def stop_view(row: PilotStopRecord) -> dict[str, Any]:
    return {
        "id": row.id,
        "reason_code": row.reason_code,
        "description": row.description,
        "control_type": row.control_type,
        "state": row.state,
        "opened_by": row.opened_by,
        "opened_at": row.opened_at.isoformat() if row.opened_at else None,
        "resolved_by": row.resolved_by,
        "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
        "rca_ref": row.rca_ref,
        "regression_ref": row.regression_ref,
        # Платформа не переключает SMTP-контроли отсюда: используются защищённые точки этапа 1.3.
        "next_actions": [
            "пауза проблемного контроля: POST /api/v1/enforcement/controls/{id}/pause",
            "при неизвестной области: аварийный выключатель POST /api/v1/enforcement/kill-switch",
            "при недоступной панели: локальный обход на узле (docs/ENFORCEMENT_KILL_SWITCH.md)",
        ],
    }


# ---------------------------------------------------------------------------------------------
# Критерии §28 и итоговое решение §29
# ---------------------------------------------------------------------------------------------
def _crit(number: int, title: str, status: str, evidence: str = "") -> dict[str, Any]:
    return {"n": number, "title": title, "status": status, "evidence": evidence}


def _from_attestations(latest: dict[str, PilotAttestationRecord], keys: list[str]) -> tuple[str, str]:
    rows = [latest.get(k) for k in keys]
    if any(r is not None and r.status == "FAIL" for r in rows):
        return "FAIL", ""
    if all(r is not None and r.status == "PASS" and r.evidence_ref for r in rows):
        return "PASS", "; ".join(r.evidence_ref for r in rows if r is not None)
    return "NOT_TESTED", ""


def criteria(session: Session, settings: Settings, organization_id: str) -> list[dict[str, Any]]:
    latest = latest_attestations(session, organization_id)
    facts = platform_facts(session, settings, organization_id)
    m = metrics(session, settings, organization_id)
    sample = m["sample"]
    applied = m["applied"]
    rows = {r["control"]: r for r in control_rows(session, settings, organization_id)}
    spam_stats = m["controls"][ControlType.SPAM_REJECT.value]["statistics"]
    out: list[dict[str, Any]] = []

    s, e = _from_attestations(latest, ["data_approval", "scope_approved", "exchange_inventory"])
    out.append(_crit(1, "Утверждённые scope/privacy/ownership и инвентаризация", s, e))
    s2, e2 = _from_attestations(latest, ["production_mx_unchanged"])
    out.append(
        _crit(
            2,
            "Реальные письма поступают без смены основного MX",
            "PASS"
            if sample["real_unique"] > 0 and s2 == "PASS"
            else ("FAIL" if s2 == "FAIL" else "NOT_TESTED"),
            e2,
        )
    )
    s3, e3 = _from_attestations(latest, ["p1_journal_smoke", "p1_outage_recovery"])
    out.append(_crit(3, "Надёжный и идемпотентный приём, происхождение источника, дедупликация", s3, e3))
    s4, e4 = _from_attestations(latest, ["secrets_clean"])
    out.append(_crit(4, "Нет тел писем и секретов в журналах и выгрузке", s4, e4))
    ok5 = (
        sample["real_unique"] >= pilot_stats.MIN_REAL_UNIQUE
        and sample["real_reviewed"] >= pilot_stats.MIN_REVIEWED_REAL
        and max((c["reviewed"] for c in m["controls"].values()), default=0)
        >= pilot_stats.MIN_REVIEWED_REJECT_CANDIDATES
    )
    out.append(
        _crit(
            5,
            "1000+ уникальных реальных, 200+ просмотренных, 100+ просмотренных кандидатов на отказ",
            "PASS" if ok5 else ("NOT_TESTED" if sample["real_unique"] == 0 else "FAIL"),
            f"real={sample['real_unique']} reviewed={sample['real_reviewed']}",
        )
    )
    cov_r, cov_q = applied["applied_rejects_review_coverage"], applied["applied_quarantines_review_coverage"]
    if cov_r is None and cov_q is None:
        c6 = "NOT_TESTED"
    else:
        c6 = "PASS" if all(v in (None, 1.0) for v in (cov_r, cov_q)) else "FAIL"
    out.append(_crit(6, "100% просмотр применённых отказов и карантина", c6))
    out.append(
        _crit(
            7,
            "0 подтверждённых критических ложных",
            "NOT_TESTED"
            if sum(c["reviewed"] for c in m["controls"].values()) == 0
            else ("PASS" if m["critical_fp"] == 0 else "FAIL"),
        )
    )
    stat = spam_stats["status"]
    out.append(
        _crit(
            8,
            "Доля ложных и граница Вильсона рассчитаны с размером выборки",
            "NOT_TESTED" if stat == pilot_stats.STAT_NO_DATA else "PASS",
            (
                f"n={spam_stats['sample_size']} obs={spam_stats['observed_fp_rate']} "
                f"upper={spam_stats['wilson_upper_95']}"
            ),
        )
    )
    out.append(
        _crit(
            9,
            "Статистические ограничения не скрыты; граница ниже порога либо принятие риска",
            {"PASS": "PASS", pilot_stats.STAT_RISK_ACCEPT_REQUIRED: "PASS_WITH_WARNING"}.get(
                stat, "NOT_TESTED"
            )
            if stat in (pilot_stats.STAT_PASS, pilot_stats.STAT_RISK_ACCEPT_REQUIRED)
            else ("NOT_TESTED" if stat == pilot_stats.STAT_NO_DATA else "FAIL"),
        )
    )
    gaps = facts["gaps"]
    out.append(
        _crit(
            10,
            "Статусы GAP-001–006 с реальными доказательствами; GAP-006 блокирует DMARC_REJECT",
            "PASS_WITH_WARNING"
            if facts["dmarc_blocked"] and rows[ControlType.DMARC_REJECT.value]["blocked_by_gap"]
            else "NOT_TESTED",
            ", ".join(f"{k}={v}" for k, v in sorted(gaps.items())),
        )
    )
    canary_real = any(
        d.applied_action in ("SMTP_REJECT", "QUARANTINED", "HELD")
        for d in _real_decisions(session, organization_id)
    )
    out.append(
        _crit(
            11,
            "SPAM_REJECT и QUARANTINE: реальный canary или NOT_TESTED_REAL",
            "PASS" if canary_real else "NOT_TESTED",
        )
    )
    out.append(
        _crit(
            12,
            "Непроверенные RBL/MALWARE/PHISHING/TEMPFAIL_ABUSE/OUTBOUND не считаются готовыми",
            "PASS" if not (set(facts["controls_enforcing"]) - {"SPAM_REJECT", "QUARANTINE"}) else "FAIL",
            ", ".join(facts["controls_enforcing"]),
        )
    )
    out.append(
        _crit(13, "Общий токен шлюза отключён", "PASS" if not facts["shared_token_allowed"] else "FAIL")
    )
    s14, e14 = _from_attestations(latest, ["quarantine_key_restore"])
    out.append(
        _crit(
            14,
            "Восстановление ключа карантина доказано",
            # Подтверждение восстановления без заданного ключа противоречиво; без подтверждения — не проверено.
            s14 if facts["quarantine_key_configured"] or s14 == "NOT_TESTED" else "FAIL",
            e14,
        )
    )
    s15, e15 = _from_attestations(latest, ["p1_open_relay_tests"])
    lost = any(
        s.reason_code in ("OPEN_RELAY", "ACCEPTED_MAIL_LOST") for s in list_stops(session, organization_id)
    )
    out.append(
        _crit(
            15, "Нет открытого ретранслятора, петель, потерянных принятых писем", "FAIL" if lost else s15, e15
        )
    )
    s16, e16 = _from_attestations(latest, ["two_node_independent_queues", "two_node_failover"])
    out.append(_crit(16, "Сценарии отказа двух узлов и очередей", s16, e16))
    s17, e17 = _from_attestations(
        latest, ["policy_ttl_safe_mode_real", "kill_switch_real", "local_bypass_real", "policy_rollback_real"]
    )
    out.append(_crit(17, "Безопасный режим по сроку, выключатель, обход, откат проверены на узлах", s17, e17))
    s18, e18 = _from_attestations(latest, ["linux_load_profile"])
    out.append(_crit(18, "Нагрузка повторяема на целевой Linux-инфраструктуре", s18, e18))
    s19, e19 = _from_attestations(latest, ["ci_main_green"])
    out.append(_crit(19, "CI и проверки безопасности зелёные; нестабильные тесты разобраны", s19, e19))
    s20, e20 = _from_attestations(latest, ["route_change_approval"])
    out.append(_crit(20, "Отдельное согласование маршрута и подтверждённый откат", s20, e20))
    out.append(
        _crit(
            21,
            "Нет автоматического изменения MX и глобального отказа",
            "PASS",
            "платформа не меняет DNS; общего флага принуждения нет",
        )
    )
    s22, e22 = _from_attestations(latest, ["data_retention_executed"])
    out.append(_crit(22, "Данные пилота удаляются/удерживаются по политике", s22, e22))
    s23, e23 = _from_attestations(latest, ["acceptance_signed"])
    out.append(_crit(23, "Итоговый MSP_1_3P_ACCEPTANCE.md с владельцами подготовлен", s23, e23))
    return out


def _real_decisions(session: Session, organization_id: str) -> list[EnforcementDecisionRecord]:
    roles = _roles(session, organization_id)
    return [
        d
        for d in session.execute(
            select(EnforcementDecisionRecord).where(
                EnforcementDecisionRecord.organization_id == organization_id
            )
        ).scalars()
        if _is_real(roles, d.node_id)
    ]


def overall_decision(session: Session, settings: Settings, organization_id: str) -> dict[str, Any]:
    """Итог по §29. Его нельзя назначить вручную вопреки этим данным."""
    crit = criteria(session, settings, organization_id)
    facts = platform_facts(session, settings, organization_id)
    m = metrics(session, settings, organization_id)
    sample = m["sample"]
    reasons: list[str] = []
    hard = False
    if sample["real_unique"] == 0:
        hard = True
        reasons.append("REAL_MESSAGES_ZERO")
    if facts["open_stops"]:
        hard = True
        reasons.append("OPEN_STOP")
    if m["critical_fp"] > 0:
        hard = True
        reasons.append("CRITICAL_FP")
    if facts["controls_enforcing"] and effective_go(session, organization_id, PilotPhase.P4) is None:
        hard = True
        reasons.append("ENFORCEMENT_ACTIVE_WITHOUT_P4_GO")
    status_by_number = {c["n"]: c["status"] for c in crit}
    # Потерянная почта и открытый ретранслятор делают итог неготовым всегда. Включённый общий токен — только когда
    # контроли уже действуют на почту: на фазе сбора он остаётся замечанием критерия 13 и блокирует вход в P4.
    if status_by_number.get(15) == "FAIL":
        hard = True
        reasons.append("OPEN_RELAY_OR_LOST_MAIL")
    if status_by_number.get(13) == "FAIL" and facts["controls_enforcing"]:
        hard = True
        reasons.append("SHARED_TOKEN_ALLOWED_WHILE_ENFORCING")
    if hard:
        decision = "NOT_READY"
    elif all(c["status"] in ("PASS", "PASS_WITH_WARNING") for c in crit):
        decision = "READY_FOR_MSP_1_4"
    else:
        decision = "READY_WITH_WARNINGS"
        reasons.extend(
            f"CRITERION_{c['n']}_{c['status']}"
            for c in crit
            if c["status"] not in ("PASS", "PASS_WITH_WARNING")
        )
    return {
        "decision": decision,
        "reasons": reasons,
        "criteria": crit,
        "manual_override_allowed": False,
        "note": "Результат не разрешает глобальный переход основного MX.",
    }


def readiness(session: Session, settings: Settings, organization_id: str) -> dict[str, Any]:
    facts = platform_facts(session, settings, organization_id)
    phases = []
    for phase in _PHASE_ORDER:
        decision = effective_go(session, organization_id, phase)
        g = gate(session, settings, organization_id, phase)
        phases.append(
            {
                "phase": phase.value,
                "go_possible": g["go_possible"],
                "blocking": g["blocking"],
                "decision": decision_view(decision) if decision else None,
            }
        )
    final = overall_decision(session, settings, organization_id)
    attested = latest_attestations(session, organization_id)
    return {
        "decision": final["decision"],
        "decision_reasons": final["reasons"],
        "stopped": bool(facts["open_stops"]),
        "phases": phases,
        "controls": control_rows(session, settings, organization_id),
        "platform": {k: v for k, v in facts.items() if k != "nodes"},
        "nodes": facts["nodes"],
        "attestations": [attestation_view(attested.get(k), s) for k, s in ATTESTATIONS.items()],
        "global_production_mx_cutover": False,
        "warning": "MSP 1.3P НЕ РАЗРЕШАЕТ ГЛОБАЛЬНОЕ ПЕРЕКЛЮЧЕНИЕ PRODUCTION MX.",
    }


#: Поля, которые не должны попадать в выгрузку доказательств ни при каких условиях (ТЗ §27).
FORBIDDEN_EXPORT_KEYS = frozenset({"subject", "body", "raw", "text", "recipients", "sender", "email_body"})


def evidence_export(session: Session, settings: Settings, organization_id: str) -> dict[str, Any]:
    """Агрегированные доказательства без тел писем и персональных данных."""
    final = overall_decision(session, settings, organization_id)
    decisions = [decision_view(d) for d in list_decisions(session, organization_id)]
    # Адреса участников решений — рабочие учётные записи; в выгрузку идут только роли и время.
    for d in decisions:
        d["approvals"] = [{"role": a["role"], "at": a["at"]} for a in d["approvals"]]
        d.pop("proposed_by", None)
    return {
        "generated_at": utcnow().isoformat(),
        "decision": final["decision"],
        "criteria": final["criteria"],
        "metrics": metrics(session, settings, organization_id),
        "controls": control_rows(session, settings, organization_id),
        "decisions": decisions,
        "stops": [
            {k: v for k, v in stop_view(s).items() if k not in ("opened_by", "resolved_by", "description")}
            for s in list_stops(session, organization_id)
        ],
        "contains_message_bodies": False,
    }
