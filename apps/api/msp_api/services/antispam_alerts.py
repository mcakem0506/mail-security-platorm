"""Тревоги анти-спама и аутентификации (ТЗ 1.2 §30, §36).

Как и у транспорта, тревога вычисляется из состояния. Два принципа:

* сканер, который молчит, — тревога, а не «спама нет»; но почта при этом идёт (отказоустойчивость), поэтому
  уровень WARNING, а не CRITICAL: потеряно наблюдение, а не доставка;
* узел, не сообщавший о сканере вообще, тревог по нему не получает: сканер необязателен для шлюза.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.models_antispam import (
    AuthConflictRecord,
    ConflictDisposition,
    DkimKeyStatus,
    ReputationProviderRecord,
    SpamScan,
)
from ..db.models_transport import TransportNode
from . import antispam
from .transport_alerts import CRITICAL, INFO, WARNING, Alert


def _age_seconds(moment: str | None) -> float | None:
    if not moment:
        return None
    try:
        parsed = datetime.fromisoformat(moment)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return (datetime.now(UTC) - parsed).total_seconds()


def _node_alerts(node: TransportNode, settings: Settings) -> list[Alert]:
    state: dict[str, Any] = (node.details or {}).get("rspamd") or {}
    if not state:
        return []
    ident = {"node_id": node.node_id, "node_name": node.name}
    alerts: list[Alert] = []
    age = _age_seconds(state.get("reported_at"))
    if age is None or age > settings.antispam_scanner_stale_seconds or state.get("up") is False:
        alerts.append(
            Alert(
                "RSPAMD_DOWN",
                WARNING,
                "Сканер анти-спама недоступен",
                "Почта идёт без проверки сканером; новые письма получают "
                "недостающее свидетельство, а не «чисто».",
                **ident,
            )
        )
        return alerts
    if state.get("redis_up") is False:
        alerts.append(
            Alert(
                "RSPAMD_REDIS_DOWN",
                WARNING,
                "Redis сканера недоступен",
                "Bayes, greylisting и накопительная репутация работают частично; "
                "проверки аутентификации — нет.",
                **ident,
            )
        )
    received = int(state.get("scans_received") or 0)
    errors = int(state.get("scan_errors") or 0)
    if received >= 20 and errors / received >= 0.05:
        alerts.append(
            Alert(
                "RSPAMD_SCAN_ERRORS",
                WARNING,
                "Растёт число ошибок сканирования",
                f"{errors} из {received}",
                **ident,
            )
        )
    if state.get("drift") == "DRIFTED":
        alerts.append(
            Alert(
                "RSPAMD_CONFIG_DRIFT",
                CRITICAL,
                "Конфигурация сканера изменена вне панели",
                "Действующий выпуск не совпадает с ожидаемым.",
                **ident,
            )
        )
    elif state.get("drift") in (None, "UNKNOWN"):
        alerts.append(
            Alert(
                "RSPAMD_CONFIG_STATE_UNKNOWN",
                INFO,
                "Соответствие конфигурации сканера не проверено",
                "",
                **ident,
            )
        )
    missing = state.get("dkim_missing_keys") or []
    if missing:
        alerts.append(
            Alert(
                "DKIM_KEY_MISSING_ON_NODE",
                WARNING,
                "На узле нет закрытого ключа действующего селектора",
                ", ".join(str(m) for m in missing[:5]),
                **ident,
            )
        )
    last = state.get("last_apply") or {}
    if last.get("outcome") in ("REJECTED", "ROLLED_BACK", "SYNC_FAILED"):
        alerts.append(
            Alert(
                "RSPAMD_CONFIG_NOT_APPLIED",
                WARNING,
                "Назначенная сканеру конфигурация не применена",
                f"{last.get('outcome')}: {last.get('detail', '')}",
                **ident,
            )
        )
    return alerts


def compute(session: Session, organization_id: str, settings: Settings) -> list[Alert]:
    alerts: list[Alert] = []
    for node in session.execute(
        select(TransportNode).where(TransportNode.organization_id == organization_id)
    ).scalars():
        alerts.extend(_node_alerts(node, settings))

    since = datetime.now(UTC) - timedelta(hours=1)
    rows: list[dict[str, Any] | None] = list(
        session.execute(
            select(SpamScan.auth)
            .where(SpamScan.organization_id == organization_id, SpamScan.received_at >= since)
            .limit(5000)
        ).scalars()
    )
    if len(rows) >= 20:
        temp = sum(
            1 for a in rows if any("TEMPERROR" in str(r) for r in (a or {}).get("incomplete_reasons", []))
        )
        if temp / len(rows) >= settings.antispam_temperror_ratio_warn:
            alerts.append(
                Alert(
                    "DNS_ERRORS",
                    WARNING,
                    "Много проверок завершилось временной ошибкой DNS",
                    f"{temp} из {len(rows)} за час; результатом это не FAIL, а недостающее свидетельство.",
                )
            )
        dmarc = sum(1 for a in rows if (a or {}).get("dmarc", {}).get("result") == "TEMPERROR")
        if dmarc / len(rows) >= settings.antispam_temperror_ratio_warn:
            alerts.append(
                Alert(
                    "DMARC_TEMPERROR_SPIKE",
                    WARNING,
                    "Всплеск временных ошибок DMARC",
                    f"{dmarc} из {len(rows)} за час",
                )
            )

    for provider in session.execute(
        select(ReputationProviderRecord).where(
            ReputationProviderRecord.organization_id == organization_id,
            ReputationProviderRecord.last_error != "",
        )
    ).scalars():
        alerts.append(
            Alert("RBL_PROVIDER_ERRORS", WARNING, "Провайдер репутации отвечает ошибками", provider.slug)
        )

    cutoff = datetime.now(UTC) - timedelta(hours=24)
    for key in antispam.dkim_keys_list(session, organization_id):
        stuck = key.status is DkimKeyStatus.DNS_PENDING and key.created_at < cutoff
        if key.status is DkimKeyStatus.FAILED or stuck:
            alerts.append(
                Alert(
                    "DKIM_LIFECYCLE",
                    WARNING,
                    "Ключ подписи не завершил жизненный цикл",
                    f"{key.domain}/{key.selector}: {key.status.value} {key.failure}".strip(),
                )
            )

    conflicts = session.execute(
        select(func.count())
        .select_from(AuthConflictRecord)
        .where(
            AuthConflictRecord.organization_id == organization_id,
            AuthConflictRecord.created_at >= since,
            AuthConflictRecord.disposition == ConflictDisposition.OPEN,
        )
    ).scalar_one()
    if conflicts >= 20:
        alerts.append(
            Alert(
                "AUTH_CONFLICT_SPIKE",
                WARNING,
                "Всплеск расхождений результатов аутентификации",
                f"{conflicts} за час",
            )
        )

    metrics = antispam.validation_metrics(session, organization_id, hours=24)
    if metrics.suggested_reject_reviewed >= 10 and metrics.suggested_reject_fp >= 3:
        alerts.append(
            Alert(
                "SUGGESTED_REJECT_FP_SPIKE",
                WARNING,
                "Среди писем с предложенным отказом много ложных",
                f"{metrics.suggested_reject_fp} из {metrics.suggested_reject_reviewed} просмотренных",
            )
        )
    return alerts


__all__ = ["compute"]
