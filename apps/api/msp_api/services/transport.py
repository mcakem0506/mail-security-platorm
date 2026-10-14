"""Управление транспортом почты: конфигурация, справочник, узлы (ТЗ 1.1 §37–§42).

Панель решает, *что* должно работать, и хранит историю решений; узел проверяет и применяет
сам (см. ``msp_gateway.apply``). Поэтому проверка здесь и проверка на узле используют один и
тот же код (``verify_bundle``): конфигурация, которую панель считает допустимой, а узел
отвергает, была бы худшим исходом — оператор нажал «применить» и увидел, что ничего не
произошло.

Принципы, из которых следуют решения ниже:

* **Ничего не применяется непроверенным.** Версия становится ``VALIDATED`` только после разбора
  модели, сборки пакета и узловой проверки пакета; применить можно только ``VALIDATED``.
* **Откат — это возврат прежнего пакета, а не его пересборка.** Пакеты хранятся готовыми:
  сегодняшний код из сегодняшнего справочника собрал бы другое.
* **Справочник не заменяется пустым или резко сократившимся** (``msp_gateway.recipients``), а
  отказ записывается так же подробно, как успех.
* **Состояние узла не выдумывается.** Нет сигнала — ``DOWN`` с причиной, а не последнее хорошее.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from msp_gateway.bundle import BundleError, verify_bundle
from msp_gateway.recipients import (
    RecipientEntry,
    RecipientSourceError,
    Snapshot,
    UpdateRefused,
    load_csv,
    load_json,
    merge,
    validate_update,
)
from msp_gateway.render import Recipient, manifest_bytes, render
from msp_gateway.spec import GatewaySpec
from msp_gateway.state import RecipientFreshness, classify_freshness
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.models_transport import (
    AcceptedRecipient,
    MailTransportEvent,
    RecipientSyncRun,
    RecipientSyncStatus,
    TransportCertificate,
    TransportConfigStatus,
    TransportConfigVersion,
    TransportMessage,
    TransportNode,
    TransportNodeRole,
)

logger = logging.getLogger(__name__)

#: Типы событий, которые панель принимает от узла. Остальное отбрасывается и считается.
ACCEPTED_EVENT_TYPES = frozenset(
    {
        "heartbeat",
        "pressure",
        "recipient_freshness",
        "config_applied",
        "drift",
        "probe",
        "certificate",
        "drain",
        "flush_done",
    }
)
MAX_EVENT_BYTES = 8192
MAX_EVENTS_PER_BATCH = 500
NOT_FOR_PRODUCTION = "MSP 1.1 IS NOT APPROVED FOR PRODUCTION MX CUTOVER"


def now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------------------------
# Проверка доступа узла
# ---------------------------------------------------------------------------------------------
def node_token_valid(settings: Settings, presented: str) -> bool | None:
    """``None`` — токен на панели не задан (приёмные точки закрыты); иначе результат сравнения."""
    expected = settings.gateway_ingest_token
    if not expected or len(expected) < 32:
        return None
    return hmac.compare_digest(expected.encode(), (presented or "").encode())


# ---------------------------------------------------------------------------------------------
# Конфигурация
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ValidationOutcome:
    ok: bool
    errors: list[str]
    spec: GatewaySpec | None = None


def validate_spec(raw: dict[str, Any]) -> ValidationOutcome:
    """Разобрать описание. Сообщения не содержат введённых значений: только место и причину."""
    try:
        spec = GatewaySpec.model_validate(raw)
    except ValidationError as error:
        messages = []
        for item in error.errors(include_input=False, include_url=False):
            where = ".".join(str(part) for part in item["loc"])
            messages.append(f"{where}: {item['msg']}" if where else str(item["msg"]))
        return ValidationOutcome(False, messages[:50])
    except ValueError as error:
        return ValidationOutcome(False, [type(error).__name__ + ": описание не разобрано"])
    return ValidationOutcome(True, [], spec)


def accepted_recipients(session: Session, organization_id: str) -> list[AcceptedRecipient]:
    return list(
        session.execute(
            select(AcceptedRecipient)
            .where(AcceptedRecipient.organization_id == organization_id, AcceptedRecipient.active.is_(True))
            .order_by(AcceptedRecipient.address)
        )
        .scalars()
        .all()
    )


def _entries(rows: Iterable[AcceptedRecipient]) -> list[RecipientEntry]:
    return [RecipientEntry(r.address, aliases=tuple(r.aliases or ())) for r in rows]


def last_accepted_sync(session: Session, organization_id: str) -> RecipientSyncRun | None:
    return session.execute(
        select(RecipientSyncRun)
        .where(
            RecipientSyncRun.organization_id == organization_id,
            RecipientSyncRun.status == RecipientSyncStatus.ACCEPTED,
        )
        .order_by(RecipientSyncRun.started_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def _recipients_meta(session: Session, organization_id: str) -> dict[str, object] | None:
    run = last_accepted_sync(session, organization_id)
    if run is None:
        return None
    generated = run.source_generated_at or run.started_at
    return {
        "generated_at": generated.isoformat(),
        "recipient_count": run.recipient_count,
        "checksum": run.checksum,
        "source": run.source,
    }


def build_bundle(
    session: Session, organization_id: str, spec: GatewaySpec, version: int
) -> tuple[dict[str, str], dict[str, Any], str]:
    """Собрать пакет и пропустить его через ту же проверку, что выполнит узел."""
    rows = accepted_recipients(session, organization_id)
    recipients = [Recipient(r.address, tuple(r.aliases or ())) for r in rows]
    config = render(
        spec, recipients, version=version, recipients_meta=_recipients_meta(session, organization_id)
    )
    verify_bundle(config.files, config.manifest)  # BundleError — наверх: пакет, который узел не примет
    files = {name: content.decode("utf-8") for name, content in config.files.items()}
    manifest = json.loads(manifest_bytes(config))
    recipients_checksum = hashlib.sha256(files["relay_recipients"].encode()).hexdigest()
    return files, manifest, recipients_checksum


def _next_version(session: Session, organization_id: str) -> int:
    top = session.execute(
        select(func.max(TransportConfigVersion.version)).where(
            TransportConfigVersion.organization_id == organization_id
        )
    ).scalar_one()
    return int(top or 0) + 1


def create_version(
    session: Session, *, organization_id: str, raw_spec: dict[str, Any], actor_email: str, note: str = ""
) -> TransportConfigVersion:
    """Создать версию: DRAFT при ошибке (с причинами), VALIDATED при успехе."""
    outcome = validate_spec(raw_spec)
    version = _next_version(session, organization_id)
    row = TransportConfigVersion(
        organization_id=organization_id,
        version=version,
        spec=outcome.spec.model_dump(mode="json") if outcome.spec else {},
        created_by=actor_email,
        note=note[:500],
        validation_errors=list(outcome.errors),
    )
    if outcome.ok and outcome.spec is not None:
        try:
            files, manifest, recipients_checksum = build_bundle(
                session, organization_id, outcome.spec, version
            )
        except BundleError as error:
            row.status = TransportConfigStatus.DRAFT
            row.validation_errors = [f"пакет не прошёл проверку узла: {error}"]
        else:
            row.status = TransportConfigStatus.VALIDATED
            row.bundle = {"files": files, "manifest": manifest}
            row.checksum = str(manifest["checksum"])
            row.recipients_checksum = recipients_checksum
    else:
        row.status = TransportConfigStatus.DRAFT
    session.add(row)
    session.flush()
    return row


class ConfigStateError(Exception):
    """Версию нельзя перевести в запрошенное состояние."""


def active_version(session: Session, organization_id: str) -> TransportConfigVersion | None:
    return session.execute(
        select(TransportConfigVersion).where(
            TransportConfigVersion.organization_id == organization_id,
            TransportConfigVersion.status == TransportConfigStatus.ACTIVE,
        )
    ).scalar_one_or_none()


def get_version(session: Session, organization_id: str, version: int) -> TransportConfigVersion | None:
    return session.execute(
        select(TransportConfigVersion).where(
            TransportConfigVersion.organization_id == organization_id,
            TransportConfigVersion.version == version,
        )
    ).scalar_one_or_none()


def activate(session: Session, row: TransportConfigVersion, *, actor_email: str) -> TransportConfigVersion:
    if row.status is not TransportConfigStatus.VALIDATED:
        raise ConfigStateError("применить можно только проверенную версию")
    _recheck_bundle(row)
    current = active_version(session, row.organization_id)
    if current is not None:
        current.status = TransportConfigStatus.SUPERSEDED
    row.status = TransportConfigStatus.ACTIVE
    row.activated_by = actor_email
    row.activated_at = now()
    session.flush()
    return row


def rollback(session: Session, row: TransportConfigVersion, *, actor_email: str) -> TransportConfigVersion:
    """Вернуть прежнюю версию. Возвращается сохранённый пакет, но проверка узла выполняется заново."""
    if row.status not in {TransportConfigStatus.SUPERSEDED, TransportConfigStatus.ROLLED_BACK}:
        raise ConfigStateError("откатиться можно только на ранее применявшуюся версию")
    if not row.bundle:
        raise ConfigStateError("у версии нет сохранённого пакета")
    _recheck_bundle(row)
    current = active_version(session, row.organization_id)
    if current is not None:
        current.status = TransportConfigStatus.ROLLED_BACK
    row.status = TransportConfigStatus.ACTIVE
    row.activated_by = actor_email
    row.activated_at = now()
    session.flush()
    return row


def _recheck_bundle(row: TransportConfigVersion) -> None:
    """Правила узла могли ужесточиться с момента сборки: пакет проверяется ещё раз перед применением."""
    files = {name: text.encode("utf-8") for name, text in (row.bundle.get("files") or {}).items()}
    try:
        verify_bundle(files, row.bundle.get("manifest") or {})
    except BundleError as error:
        raise ConfigStateError(f"пакет не прошёл проверку узла: {error}") from error


# ---------------------------------------------------------------------------------------------
# Справочник получателей
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class SyncResult:
    run: RecipientSyncRun
    activated_version: int | None = None


def sync_recipients(
    session: Session,
    *,
    organization_id: str,
    text: str,
    fmt: str,
    source: str,
    actor_email: str,
    source_generated_at: datetime | None = None,
    confirm_shrink: bool = False,
) -> SyncResult:
    """Принять новый справочник или отказать, не тронув действующий."""
    started = now()
    run = RecipientSyncRun(
        organization_id=organization_id,
        status=RecipientSyncStatus.FAILED,
        source=source[:64],
        requested_by=actor_email,
        started_at=started,
        source_generated_at=source_generated_at,
    )
    session.add(run)
    previous_rows = accepted_recipients(session, organization_id)
    run.previous_count = len(previous_rows)
    try:
        loaded = load_csv(text) if fmt == "csv" else load_json(text)
    except RecipientSourceError as error:
        run.reason = str(error)[:500]
        session.flush()
        return SyncResult(run)

    merged, conflicts = merge(loaded.entries)
    run.rejected_count = loaded.rejected_count
    run.conflict_count = len(conflicts)
    snapshot = Snapshot(merged, generated_at=source_generated_at or started, source=source)
    run.recipient_count = snapshot.count
    run.checksum = snapshot.checksum
    previous_run = last_accepted_sync(session, organization_id)
    previous = None
    if previous_run is not None:
        previous = Snapshot(
            tuple(_entries(previous_rows)),
            generated_at=previous_run.source_generated_at or previous_run.started_at,
        )
    try:
        validate_update(snapshot, previous, confirm_shrink=confirm_shrink)
    except UpdateRefused as error:
        run.status = RecipientSyncStatus.REFUSED
        run.reason = str(error)[:500]
        session.flush()
        return SyncResult(run)

    _apply_entries(session, organization_id, merged, source)
    run.status = RecipientSyncStatus.ACCEPTED
    session.flush()
    return SyncResult(
        run, _reissue_active(session, organization_id, actor_email, "обновление справочника получателей")
    )


def _apply_entries(
    session: Session, organization_id: str, entries: Iterable[RecipientEntry], source: str
) -> None:
    existing = {
        r.address: r
        for r in session.execute(
            select(AcceptedRecipient).where(AcceptedRecipient.organization_id == organization_id)
        ).scalars()
    }
    seen: set[str] = set()
    for entry in entries:
        seen.add(entry.address)
        row = existing.get(entry.address)
        if row is None:
            session.add(
                AcceptedRecipient(
                    organization_id=organization_id,
                    address=entry.address,
                    kind=entry.kind.value,
                    aliases=list(entry.aliases),
                    source=source[:64],
                )
            )
        else:
            row.kind, row.aliases, row.source, row.active = (
                entry.kind.value,
                list(entry.aliases),
                source[:64],
                True,
            )
    for address, row in existing.items():
        if address not in seen:
            row.active = False  # адрес не удаляется: нужен для истории и разбора «почему отказали»
    session.flush()


def _reissue_active(session: Session, organization_id: str, actor_email: str, note: str) -> int | None:
    """Пересобрать действующую конфигурацию с новым справочником и применить её.

    Справочник входит в пакет, поэтому его обновление — это новая версия. Она получается из той же
    топологии, что и действующая; если сборка не проходит проверку, действующая версия остаётся.
    """
    current = active_version(session, organization_id)
    if current is None:
        return None
    version = create_version(
        session, organization_id=organization_id, raw_spec=current.spec, actor_email=actor_email, note=note
    )
    if version.status is not TransportConfigStatus.VALIDATED:
        logger.warning("transport.reissue_failed", extra={"version": version.version})
        return None
    activate(session, version, actor_email=actor_email)
    return version.version


def recipients_status(session: Session, organization_id: str, settings: Settings) -> dict[str, Any]:
    run = last_accepted_sync(session, organization_id)
    last = session.execute(
        select(RecipientSyncRun)
        .where(RecipientSyncRun.organization_id == organization_id)
        .order_by(RecipientSyncRun.started_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    generated = (run.source_generated_at or run.started_at) if run else None
    age = None if generated is None else max(0.0, (now() - generated).total_seconds())
    freshness = classify_freshness(
        age_seconds=age,
        fresh_seconds=float(settings.gateway_recipients_fresh_seconds),
        grace_seconds=float(settings.gateway_recipients_grace_seconds),
    )
    total = session.execute(
        select(func.count())
        .select_from(AcceptedRecipient)
        .where(AcceptedRecipient.organization_id == organization_id, AcceptedRecipient.active.is_(True))
    ).scalar_one()
    return {
        "freshness": freshness.value,
        "age_seconds": age,
        "generated_at": generated,
        "recipient_count": int(total),
        "last_sync": None
        if last is None
        else {
            "status": last.status.value,
            "reason": last.reason,
            "recipient_count": last.recipient_count,
            "previous_count": last.previous_count,
            "rejected_count": last.rejected_count,
            "conflict_count": last.conflict_count,
            "started_at": last.started_at,
        },
        "closed": freshness is RecipientFreshness.STALE_HARD,
    }


# ---------------------------------------------------------------------------------------------
# Узлы и события
# ---------------------------------------------------------------------------------------------
def node_state(node: TransportNode, settings: Settings) -> str:
    if node.last_heartbeat_at is None:
        return "UNKNOWN"
    if now() - node.last_heartbeat_at > timedelta(seconds=settings.gateway_node_stale_seconds):
        return "DOWN"
    return "DRAINING" if node.pressure_state == "DRAINING" else "UP"


def get_or_create_node(
    session: Session, organization_id: str, node_id: str, role: str = "LAB"
) -> TransportNode:
    node = session.execute(
        select(TransportNode).where(
            TransportNode.organization_id == organization_id, TransportNode.node_id == node_id
        )
    ).scalar_one_or_none()
    if node is None:
        node = TransportNode(
            organization_id=organization_id,
            node_id=node_id,
            name=f"node-{node_id[:8]}",
            role=TransportNodeRole(role) if role in TransportNodeRole.__members__ else TransportNodeRole.LAB,
        )
        # Узел обращается к панели из нескольких процессов сразу (агент, синхронизация, сборщик),
        # и первые запросы приходят одновременно: проигравший гонку берёт уже созданную запись.
        try:
            with session.begin_nested():
                session.add(node)
        except IntegrityError:
            node = session.execute(
                select(TransportNode).where(
                    TransportNode.organization_id == organization_id, TransportNode.node_id == node_id
                )
            ).scalar_one()
    return node


def _clean_event_data(data: object) -> dict[str, Any]:
    """Оставить в данных события только скаляры ограниченной длины: панель не копит чужие структуры."""
    if not isinstance(data, dict):
        return {}
    clean: dict[str, Any] = {}
    for key, value in list(data.items())[:32]:
        if not isinstance(key, str) or len(key) > 64:
            continue
        if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
            clean[key] = value
        elif isinstance(value, str):
            clean[key] = value[:500]
    return clean


@dataclass
class IngestResult:
    accepted: int = 0
    rejected: int = 0


def ingest_events(
    session: Session, *, organization_id: str, node_id: str, events: list[object], role: str = "LAB"
) -> IngestResult:
    result = IngestResult()
    node = get_or_create_node(session, organization_id, node_id, role)
    for raw in events[:MAX_EVENTS_PER_BATCH]:
        if not isinstance(raw, dict) or len(json.dumps(raw, default=str)) > MAX_EVENT_BYTES:
            result.rejected += 1
            continue
        kind = raw.get("type")
        if kind not in ACCEPTED_EVENT_TYPES:
            result.rejected += 1
            continue
        data = _clean_event_data({k: v for k, v in raw.items() if k not in {"type", "at", "node_id"}})
        occurred = _parse_time(raw.get("at"))
        session.add(
            MailTransportEvent(
                organization_id=organization_id,
                node_id=node_id,
                event_type=kind,
                occurred_at=occurred,
                data=data,
            )
        )
        if kind == "heartbeat":
            node.last_heartbeat_at = max(filter(None, [node.last_heartbeat_at, occurred]))
            node.oldest_message_seconds = _number(data.get("oldest_message_seconds"), 0.0)
            node.exchange_ok = _tristate(data.get("exchange_ok"))
            node.open_relay_safe = _tristate(data.get("open_relay_safe"))
            node.config_drift = _tristate(data.get("config_drift"))
            node.collector_report_age = _optional_number(data.get("collector_report_age"))
            node.shadow_pending_seconds = _optional_number(data.get("shadow_pending_seconds"))
            node.config_version = str(data.get("config_version", ""))[:64]
            node.queue_messages = int(_number(data.get("queue_messages"), 0.0))
            node.pressure_state = str(data.get("pressure", "UNKNOWN"))[:16]
            node.unparsed_log_lines = int(_number(data.get("unparsed_log_lines"), 0.0))
        elif kind == "pressure":
            node.pressure_state = str(data.get("state", node.pressure_state))[:16]
        elif kind == "probe":
            _remember_probe(node, data, occurred)
        elif kind == "drift":
            node.config_drift = _tristate(data.get("drifting"))
        elif kind == "certificate":
            _remember_certificate(session, organization_id, node_id, data)
        elif kind == "config_applied":
            node.details = {
                **node.details,
                "last_apply": {k: data.get(k) for k in ("outcome", "version", "stage") if k in data}
                | {"at": occurred.isoformat()},
            }
        elif kind == "flush_done":
            node.flush_requested = False
        result.accepted += 1
    session.flush()
    return result


def _tristate(value: object) -> bool | None:
    """``True``/``False`` из события; всё остальное (в том числе ``None``) — «не известно»."""
    return value if isinstance(value, bool) else None


def _number(value: object, default: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    return float(value) if 0 <= value < 1e12 else default


def _optional_number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if 0 <= value < 1e12 else None


def _remember_probe(node: TransportNode, data: dict[str, Any], occurred: datetime) -> None:
    """Последний итог каждой пробы узла: ключ — вид пробы и цель. Число ключей ограничено."""
    probes = dict(node.details.get("probes") or {})
    key = f"{data.get('probe', '')}:{data.get('target', '')}"[:80]
    probes[key] = {
        "ok": _tristate(data.get("ok")),
        "failed_layer": str(data.get("failed_layer", ""))[:16],
        "state": str(data.get("state", ""))[:24],
        "detail": str(data.get("detail", ""))[:200],
        "at": occurred.isoformat(),
    }
    if len(probes) > 20:
        for old in sorted(probes, key=lambda k: probes[k]["at"])[: len(probes) - 20]:
            del probes[old]
    node.details = {**node.details, "probes": probes}


def _remember_certificate(session: Session, organization_id: str, node_id: str, data: dict[str, Any]) -> None:
    usage, fingerprint = str(data.get("usage", "")), str(data.get("fingerprint", ""))
    if not usage or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
        return
    record_certificate(
        session,
        organization_id=organization_id,
        node_id=node_id,
        usage=usage,
        subject=str(data.get("subject", "")),
        issuer=str(data.get("issuer", "")),
        not_before=_parse_optional_time(data.get("not_before")),
        not_after=_parse_optional_time(data.get("not_after")),
        fingerprint=fingerprint,
    )


def _parse_optional_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _parse_time(value: object) -> datetime:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return now()
        parsed = parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        # Часы узла не должны уводить события в будущее: оно скрыло бы настоящую тишину узла.
        return min(parsed, now())
    return now()


def record_certificate(
    session: Session,
    *,
    organization_id: str,
    node_id: str,
    usage: str,
    subject: str,
    issuer: str,
    not_before: datetime | None,
    not_after: datetime | None,
    fingerprint: str,
) -> TransportCertificate:
    row = session.execute(
        select(TransportCertificate).where(
            TransportCertificate.organization_id == organization_id,
            TransportCertificate.node_id == node_id,
            TransportCertificate.fingerprint == fingerprint,
        )
    ).scalar_one_or_none()
    if row is None:
        row = TransportCertificate(
            organization_id=organization_id, node_id=node_id, usage=usage[:32], fingerprint=fingerprint[:128]
        )
        session.add(row)
    row.subject, row.issuer = subject[:500], issuer[:500]
    row.not_before, row.not_after = not_before, not_after
    session.flush()
    return row


def tls_status(session: Session, organization_id: str, *, warn_days: int = 30) -> list[dict[str, Any]]:
    rows = (
        session.execute(
            select(TransportCertificate)
            .where(TransportCertificate.organization_id == organization_id)
            .order_by(TransportCertificate.not_after)
        )
        .scalars()
        .all()
    )
    result = []
    for row in rows:
        days = None if row.not_after is None else (row.not_after - now()).total_seconds() / 86400
        state = (
            "UNKNOWN" if days is None else "EXPIRED" if days < 0 else "EXPIRING" if days < warn_days else "OK"
        )
        result.append(
            {
                "node_id": row.node_id,
                "usage": row.usage,
                "subject": row.subject,
                "issuer": row.issuer,
                "not_after": row.not_after,
                "days_left": days,
                "state": state,
                "fingerprint": row.fingerprint,
            }
        )
    return result


def queue_summary(session: Session, organization_id: str, settings: Settings) -> dict[str, Any]:
    nodes = list(
        session.execute(
            select(TransportNode).where(TransportNode.organization_id == organization_id)
        ).scalars()
    )
    states = [node_state(n, settings) for n in nodes]
    return {
        "nodes_total": len(nodes),
        "nodes_up": sum(1 for s in states if s in {"UP", "DRAINING"}),
        "nodes_down": sum(1 for s in states if s in {"DOWN", "UNKNOWN"}),
        "queue_messages": sum(n.queue_messages for n in nodes),
        "pressure": _worst_pressure(n.pressure_state for n in nodes),
        "oldest_message_seconds": max((n.oldest_message_seconds for n in nodes), default=0.0),
        "unanalysed_copies": session.execute(
            select(func.count())
            .select_from(TransportMessage)
            .where(
                TransportMessage.organization_id == organization_id,
                TransportMessage.state.in_({"COLLECTED", "ANALYSIS_QUEUED"}),
            )
        ).scalar_one(),
        "deployment_note": NOT_FOR_PRODUCTION,
    }


_PRESSURE_ORDER = ("CRITICAL", "PRESSURE", "DRAINING", "NORMAL", "UNKNOWN")


def _worst_pressure(values: Iterable[str]) -> str:
    present = set(values)
    for name in _PRESSURE_ORDER:
        if name in present:
            return name
    return "UNKNOWN"
