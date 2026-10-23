"""Внутренний карантин (MSP 1.3, ТЗ §32–§36, §58, §63).

Исходное письмо неизменяемо: оно хранится зашифрованным (AES-256-GCM, ключ из хранилища секретов) под отдельным
префиксом хранилища объектов, и ни одна другая точка API не отдаёт его. В базе — ссылка, контрольная сумма и
безопасные для списка поля. Просмотр письма — безопасный предпросмотр без активного содержимого.

Выпуск письма: запрос → согласование, если нужно → одноразовая ссылка выпуска (в базе только её хэш, срок короткий) →
доверенная повторная подача узлом → подтверждение. Повтор ссылки не принимается. Выпущенное письмо второй раз в
карантин по тому же решению не попадает: узел получает ответ «уже выпущено» (ТЗ §35) и не полагается на заголовки.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import UTC, datetime, timedelta
from email import policy as email_policy
from email.parser import BytesParser
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.base import utcnow
from ..db.models_enforcement import QuarantineItemRecord, QuarantineState
from .enforcement import EnforcementError
from .storage import ObjectStorage, build_key

MAX_SIZE = 50 * 1024 * 1024
#: Причины, при которых выпуск требует второго человека.
APPROVAL_PREFIXES = ("MALWARE", "RISK_MALICIOUS", "PHISHING")
_URL = re.compile(r"https?://", re.IGNORECASE)


def now() -> datetime:
    return utcnow()


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _key_bytes(settings: Settings) -> bytes:
    raw = (settings.quarantine_encryption_key or "").encode()
    if len(raw) < 32:
        raise EnforcementError("ключ шифрования карантина не настроен", 503)
    return hashlib.sha256(raw).digest()


def encrypt(settings: Settings, plain: bytes, *, aad: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(_key_bytes(settings)).encrypt(nonce, plain, aad)


def decrypt(settings: Settings, blob: bytes, *, aad: bytes) -> bytes:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        return AESGCM(_key_bytes(settings)).decrypt(blob[:12], blob[12:], aad)
    except InvalidTag as exc:
        raise EnforcementError("письмо в карантине повреждено или подменено", 500) from exc


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def store(
    session: Session,
    settings: Settings,
    storage: ObjectStorage,
    organization_id: str,
    *,
    node_id: str,
    transport_message_id: str,
    internet_message_id: str,
    decision_ref: str,
    sender: str,
    recipients: list[str],
    subject: str,
    reason_codes: list[str],
    policy_version: str,
    raw: bytes,
    original_route: str,
) -> tuple[QuarantineItemRecord, bool]:
    """Положить письмо в карантин. ``(запись, уже_выпущено)``: выпущенное письмо повторно не карантинится."""
    if not raw or len(raw) > MAX_SIZE:
        raise EnforcementError("размер письма вне допустимых пределов", 413)
    existing = session.execute(
        select(QuarantineItemRecord).where(
            QuarantineItemRecord.organization_id == organization_id,
            QuarantineItemRecord.transport_message_id == transport_message_id,
            QuarantineItemRecord.decision_ref == decision_ref,
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing, existing.state in (QuarantineState.RELEASED, QuarantineState.RELEASE_PENDING)
    # Выпущенное ранее письмо с тем же Message-ID не должно вернуться в карантин (петля выпуска).
    if internet_message_id:
        released = (
            session.execute(
                select(QuarantineItemRecord).where(
                    QuarantineItemRecord.organization_id == organization_id,
                    QuarantineItemRecord.internet_message_id == internet_message_id,
                    QuarantineItemRecord.state == QuarantineState.RELEASED,
                )
            )
            .scalars()
            .first()
        )
        if released is not None:
            return released, True
    digest = hashlib.sha256(raw).hexdigest()
    item = QuarantineItemRecord(
        organization_id=organization_id,
        node_id=node_id,
        transport_message_id=transport_message_id[:64],
        internet_message_id=internet_message_id[:998],
        decision_ref=decision_ref[:64],
        content_sha256=digest,
        size_bytes=len(raw),
        sender=sender[:320],
        recipients=list(recipients)[:100],
        subject_safe=_safe_subject(subject),
        reason_codes=list(reason_codes)[:30],
        policy_version=policy_version[:64],
        quarantined_at=now(),
        expires_at=now() + timedelta(days=settings.quarantine_retention_days),
        original_route=original_route[:255],
    )
    session.add(item)
    session.flush()
    blob = encrypt(settings, raw, aad=item.id.encode())
    key = build_key(
        "quarantine", hashlib.sha256(blob).hexdigest(), organization_id=organization_id, extension="enc"
    )
    storage.put(key, blob, "application/octet-stream")
    item.content_object_ref = key
    return item, False


def _safe_subject(subject: str) -> str:
    # В списке тема без активного содержимого: ссылки обезврежены, управляющие символы убраны.
    cleaned = "".join(ch for ch in subject if ch.isprintable())[:300]
    return _URL.sub("hxxp://", cleaned)


def item_view(row: QuarantineItemRecord) -> dict[str, Any]:
    return {
        "id": row.id,
        "node_id": row.node_id,
        "transport_message_id": row.transport_message_id,
        "internet_message_id": row.internet_message_id,
        "sender": row.sender,
        "recipients": row.recipients,
        "subject": row.subject_safe,
        "reason_codes": row.reason_codes,
        "policy_version": row.policy_version,
        "state": row.state.value,
        "quarantined_at": row.quarantined_at.isoformat(),
        "expires_at": row.expires_at.isoformat(),
        "size_bytes": row.size_bytes,
        "sha256": row.content_sha256,
        "original_route": row.original_route,
        "release_requested_by": row.release_requested_by or None,
        "release_approved_by": row.release_approved_by or None,
        "released_by": row.released_by or None,
        "released_at": row.released_at.isoformat() if row.released_at else None,
        "delivered_count": row.delivered_count,
        "needs_approval": needs_approval(row),
        "decision_ref": row.decision_ref,
    }


def needs_approval(row: QuarantineItemRecord) -> bool:
    return any(str(c).startswith(APPROVAL_PREFIXES) for c in (row.reason_codes or []))


def list_items(
    session: Session,
    organization_id: str,
    *,
    state: str | None = None,
    q: str = "",
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[QuarantineItemRecord], int]:
    stmt = select(QuarantineItemRecord).where(QuarantineItemRecord.organization_id == organization_id)
    if state:
        try:
            stmt = stmt.where(QuarantineItemRecord.state == QuarantineState(state))
        except ValueError as exc:
            raise EnforcementError("неизвестное состояние", 422) from exc
    if q:
        like = f"%{q.strip()[:100]}%"
        stmt = stmt.where(
            QuarantineItemRecord.sender.ilike(like)
            | QuarantineItemRecord.subject_safe.ilike(like)
            | QuarantineItemRecord.internet_message_id.ilike(like)
        )
    total = session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = session.execute(
        stmt.order_by(QuarantineItemRecord.quarantined_at.desc()).limit(min(limit, 200)).offset(offset)
    ).scalars()
    return list(rows), int(total)


def get_item(session: Session, organization_id: str, item_id: str) -> QuarantineItemRecord:
    row = session.get(QuarantineItemRecord, item_id)
    if row is None or row.organization_id != organization_id:
        raise EnforcementError("письмо в карантине не найдено", 404)
    return row


def _raw(settings: Settings, storage: ObjectStorage, row: QuarantineItemRecord) -> bytes:
    if row.state in (QuarantineState.DELETED, QuarantineState.EXPIRED) or not row.content_object_ref:
        raise EnforcementError("содержимое удалено", 410)
    raw = decrypt(settings, storage.get(row.content_object_ref), aad=row.id.encode())
    if hashlib.sha256(raw).hexdigest() != row.content_sha256:
        raise EnforcementError("контрольная сумма письма не совпала", 500)
    return raw


def preview(settings: Settings, storage: ObjectStorage, row: QuarantineItemRecord) -> dict[str, Any]:
    """Безопасный предпросмотр: выбранные заголовки и обрезанный текст; HTML и вложения не отдаются."""
    raw = _raw(settings, storage, row)
    message = BytesParser(policy=email_policy.default).parsebytes(raw, headersonly=False)
    text = ""
    part = message.get_body(preferencelist=("plain",))
    if part is not None:
        try:
            text = part.get_content()
        except (LookupError, ValueError):
            text = ""
    text = "".join(ch for ch in str(text) if ch.isprintable() or ch in "\n\t")[:3000]
    attachments = [p.get_filename() or "(без имени)" for p in message.iter_attachments()]
    return {
        "headers": {
            h: _URL.sub("hxxp://", str(message.get(h, "")))[:300]
            for h in ("From", "To", "Subject", "Date", "Message-ID")
        },
        "text": _URL.sub("hxxp://", text),
        "attachments": [{"name": str(n)[:120]} for n in attachments][:20],
        "active_content_removed": True,
    }


# --- выпуск ---------------------------------------------------------------------------------
def request_release(row: QuarantineItemRecord, *, actor_email: str) -> QuarantineItemRecord:
    if row.state is not QuarantineState.QUARANTINED:
        raise EnforcementError("выпуск возможен только для письма в карантине", 409)
    row.release_requested_by = actor_email
    row.state = QuarantineState.RELEASE_PENDING
    if not needs_approval(row):
        row.release_approved_by = actor_email
    return row


def approve_release(row: QuarantineItemRecord, *, actor_email: str) -> QuarantineItemRecord:
    if row.state is not QuarantineState.RELEASE_PENDING:
        raise EnforcementError("нет ожидающего запроса на выпуск", 409)
    if row.release_approved_by:
        raise EnforcementError("выпуск уже согласован", 409)
    if actor_email == row.release_requested_by:
        raise EnforcementError("согласовать должен другой человек", 403)
    row.release_approved_by = actor_email
    return row


def cancel_release(row: QuarantineItemRecord) -> QuarantineItemRecord:
    if row.state is not QuarantineState.RELEASE_PENDING:
        raise EnforcementError("нет ожидающего запроса на выпуск", 409)
    row.state = QuarantineState.QUARANTINED
    row.release_requested_by = row.release_approved_by = ""
    row.release_token_hash = ""
    return row


def pending_for_node(
    session: Session, settings: Settings, organization_id: str, node_id: str
) -> list[dict[str, Any]]:
    """Узел забирает согласованные выпуски. Ссылка выдаётся здесь и живёт недолго; прежняя ссылка недействительна."""
    rows = session.execute(
        select(QuarantineItemRecord).where(
            QuarantineItemRecord.organization_id == organization_id,
            QuarantineItemRecord.node_id == node_id,
            QuarantineItemRecord.state == QuarantineState.RELEASE_PENDING,
            QuarantineItemRecord.release_approved_by != "",
            QuarantineItemRecord.release_token_used.is_(False),
        )
    ).scalars()
    out: list[dict[str, Any]] = []
    for row in rows:
        token = secrets.token_urlsafe(32)
        row.release_token_hash = _hash(token)
        row.release_token_expires_at = now() + timedelta(
            minutes=settings.quarantine_release_token_ttl_minutes
        )
        out.append(
            {
                "id": row.id,
                "token": token,
                "size_bytes": row.size_bytes,
                "original_route": row.original_route,
                "recipients": row.recipients,
                "sha256": row.content_sha256,
                "expires_at": row.release_token_expires_at.isoformat(),
            }
        )
    return out


def _check_token(row: QuarantineItemRecord, token: str) -> None:
    if row.state is not QuarantineState.RELEASE_PENDING or not row.release_token_hash:
        raise EnforcementError("выпуск не запрошен", 409)
    if row.release_token_used:
        raise EnforcementError("ссылка выпуска уже использована", 409)
    if row.release_token_expires_at is None or _aware(row.release_token_expires_at) <= now():
        raise EnforcementError("срок ссылки выпуска истёк", 410)
    if not hmac.compare_digest(row.release_token_hash, _hash(token or "")):
        raise EnforcementError("ссылка выпуска недействительна", 403)


def content_for_release(
    settings: Settings, storage: ObjectStorage, row: QuarantineItemRecord, token: str
) -> bytes:
    _check_token(row, token)
    return _raw(settings, storage, row)


def confirm_release(
    row: QuarantineItemRecord, token: str, *, delivered: bool, error: str = ""
) -> QuarantineItemRecord:
    """Узел подтверждает повторную подачу. Успех гасит ссылку навсегда; сбой оставляет выпуск ожидающим."""
    _check_token(row, token)
    if delivered:
        row.release_token_used = True
        row.state = QuarantineState.RELEASED
        row.released_by = row.release_approved_by or row.release_requested_by
        row.released_at = now()
        row.delivered_count += 1
        row.error = ""
    else:
        row.release_token_hash = ""
        row.error = error[:300]
    return row


def delete_item(
    storage: ObjectStorage, row: QuarantineItemRecord, *, actor_email: str
) -> QuarantineItemRecord:
    if row.state in (QuarantineState.DELETED, QuarantineState.EXPIRED):
        raise EnforcementError("письмо уже удалено", 409)
    if row.content_object_ref:
        storage.delete(row.content_object_ref)
    row.state = QuarantineState.DELETED
    row.deleted_by = actor_email
    row.release_token_hash = ""
    return row


def expire_due(session: Session, storage: ObjectStorage, organization_id: str) -> int:
    rows = (
        session.execute(
            select(QuarantineItemRecord).where(
                QuarantineItemRecord.organization_id == organization_id,
                QuarantineItemRecord.state.in_(
                    [QuarantineState.QUARANTINED, QuarantineState.RELEASE_PENDING]
                ),
                QuarantineItemRecord.expires_at <= now(),
            )
        )
        .scalars()
        .all()
    )
    for row in rows:
        if row.content_object_ref:
            storage.delete(row.content_object_ref)
        row.state = QuarantineState.EXPIRED
        row.release_token_hash = ""
    return len(rows)


def counts(session: Session, organization_id: str) -> dict[str, int]:
    rows = session.execute(
        select(QuarantineItemRecord.state, func.count())
        .where(QuarantineItemRecord.organization_id == organization_id)
        .group_by(QuarantineItemRecord.state)
    ).all()
    return {state.value: int(count) for state, count in rows}
