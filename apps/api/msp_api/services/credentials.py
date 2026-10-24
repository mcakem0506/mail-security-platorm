"""Раздельные учётные данные компонентов узла (ТЗ 1.3 §79, §80).

Раньше агент, синхронизация справочника, сборщик теневых копий и политика принуждения делили один токен:
утечка у любого из них давала доступ ко всем. Теперь у каждого компонента свой токен со своей областью, и
токен одной области не открывает другую. На время ротации в области действуют сразу два токена (через запятую),
поэтому смена не прерывает почту. Токены нигде не хранятся: приёмник запоминает только короткий отпечаток, чтобы
появление нового токена попало в аудит.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.base import utcnow
from ..db.models_enforcement import ComponentCredentialSeen

SCOPES = ("gateway-agent", "recipient-sync", "shadow-collector", "enforcement-policy", "metrics")

_FIELD = {
    "gateway-agent": "gateway_agent_token",
    "recipient-sync": "recipient_sync_token",
    "shadow-collector": "shadow_collector_token",
    "enforcement-policy": "enforcement_policy_token",
    "metrics": "metrics_token",
}

MIN_LENGTH = 32


@dataclass(frozen=True)
class Verdict:
    #: ``None`` — для области нет ни своего токена, ни разрешённого общего: приёмная точка закрыта.
    valid: bool | None
    fingerprint: str = ""
    shared: bool = False


def fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:12]


def scoped_tokens(settings: Settings, scope: str) -> tuple[str, ...]:
    raw = getattr(settings, _FIELD[scope], "") or ""
    return tuple(t.strip() for t in raw.split(",") if len(t.strip()) >= MIN_LENGTH)


def check(settings: Settings, scope: str, presented: str) -> Verdict:
    if scope not in _FIELD:
        raise ValueError("неизвестная область токена")
    own = scoped_tokens(settings, scope)
    shared = settings.gateway_ingest_token if settings.gateway_shared_token_allowed else ""
    shared_ok = len(shared) >= MIN_LENGTH
    if not own and not shared_ok:
        return Verdict(None)
    candidate = (presented or "").encode()
    for token in own:
        if hmac.compare_digest(token.encode(), candidate):
            return Verdict(True, fingerprint(token))
    if shared_ok and hmac.compare_digest(shared.encode(), candidate):
        # Общий токен действует, пока его не отключили: об этом должно быть видно (ТЗ 1.3 §79).
        return Verdict(True, fingerprint(shared), shared=True)
    return Verdict(False)


def remember(session: Session, scope: str, print_: str, *, now: datetime | None = None) -> bool:
    """Запомнить отпечаток. ``True`` — отпечаток новый (первое использование: событие аудита)."""
    moment = now or utcnow()
    row = session.execute(
        select(ComponentCredentialSeen).where(
            ComponentCredentialSeen.scope == scope, ComponentCredentialSeen.fingerprint == print_
        )
    ).scalar_one_or_none()
    if row is None:
        session.add(
            ComponentCredentialSeen(
                scope=scope, fingerprint=print_, first_seen=moment, last_seen=moment, uses=1
            )
        )
        session.flush()
        return True
    row.last_seen = moment
    row.uses += 1
    return False


def overview(session: Session, settings: Settings) -> list[dict[str, object]]:
    """Для консоли: что настроено и какие отпечатки видел приёмник. Значений токенов здесь нет."""
    rows = session.execute(select(ComponentCredentialSeen)).scalars().all()
    out: list[dict[str, object]] = []
    for scope in SCOPES:
        configured = scoped_tokens(settings, scope)
        out.append(
            {
                "scope": scope,
                "configured_tokens": len(configured),
                "rotation_overlap": len(configured) > 1,
                "fingerprints": [
                    {
                        "fingerprint": r.fingerprint,
                        "first_seen": r.first_seen.isoformat(),
                        "last_seen": r.last_seen.isoformat(),
                        "uses": r.uses,
                        "configured": r.fingerprint in {fingerprint(t) for t in configured},
                    }
                    for r in rows
                    if r.scope == scope
                ],
            }
        )
    return out


def split_status(settings: Settings) -> dict[str, object]:
    """Готовность разделения: у каждой области свой токен и общий отключён."""
    missing = [s for s in SCOPES if not scoped_tokens(settings, s)]
    shared_on = bool(
        settings.gateway_shared_token_allowed and len(settings.gateway_ingest_token) >= MIN_LENGTH
    )
    return {
        "split": not missing and not shared_on,
        "scopes_without_own_token": missing,
        "shared_token_accepted": shared_on,
    }
