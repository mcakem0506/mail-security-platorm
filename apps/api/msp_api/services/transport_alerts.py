"""Тревоги транспорта почты (ТЗ 1.1 §46).

Тревога вычисляется из состояния, а не хранится: узел вернулся в норму — тревога исчезла без
чьего-либо «закрыть». Это принципиально для границы организации: тревога, которую нужно гасить
руками, со временем гасится не глядя.

Два правила, из которых следуют почти все решения ниже:

* **«Нет данных» — не «в порядке».** Узел, не присылавший сигнал, — тревога (``DOWN``), а не
  пустая очередь. Проба, которая не выполнялась, не даёт ни тревоги, ни успеха; тревогу даёт
  только то, что проверено и не прошло, а непроверенное названо отдельной тревогой уровня
  ``INFO``, чтобы не молчать о слепом пятне.
* **Одна причина — одна тревога с адресом.** Тревога называет узел и уровень, на котором сломалось
  (``failed_layer``), чтобы оператор шёл туда, где сломалось, а не искал.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.models_transport import TransportNode
from . import transport

CRITICAL = "CRITICAL"
WARNING = "WARNING"
INFO = "INFO"
_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}


@dataclass(frozen=True)
class Alert:
    code: str
    severity: str
    title: str
    detail: str = ""
    node_id: str = ""
    node_name: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _node_alerts(node: TransportNode, settings: Settings) -> list[Alert]:
    state = transport.node_state(node, settings)
    ident = {"node_id": node.node_id, "node_name": node.name}
    if state in {"DOWN", "UNKNOWN"}:
        # Остальные показатели молчащего узла — устаревшие, и тревоги по ним были бы ложными.
        return [
            Alert(
                "GATEWAY_NODE_DOWN",
                CRITICAL if state == "DOWN" else WARNING,
                "Узел шлюза не отвечает"
                if state == "DOWN"
                else "Узел зарегистрирован, но сигналов не присылал",
                "Последний сигнал давно или ещё не поступал: очередь и состояние узла неизвестны.",
                **ident,
            )
        ]
    alerts: list[Alert] = []
    if node.queue_messages >= settings.gateway_queue_critical_messages:
        alerts.append(
            Alert(
                "QUEUE_GROWTH",
                CRITICAL,
                "Очередь выросла до критической",
                f"писем: {node.queue_messages}",
                **ident,
            )
        )
    elif node.queue_messages >= settings.gateway_queue_warn_messages:
        alerts.append(
            Alert("QUEUE_GROWTH", WARNING, "Очередь растёт", f"писем: {node.queue_messages}", **ident)
        )

    if node.oldest_message_seconds >= settings.gateway_oldest_critical_seconds:
        alerts.append(
            Alert(
                "OLDEST_MESSAGE_TOO_OLD",
                CRITICAL,
                "В очереди письмо старше допустимого",
                f"{node.oldest_message_seconds / 60:.0f} мин",
                **ident,
            )
        )
    elif node.oldest_message_seconds >= settings.gateway_oldest_warn_seconds:
        alerts.append(
            Alert(
                "OLDEST_MESSAGE_TOO_OLD",
                WARNING,
                "В очереди давно лежит письмо",
                f"{node.oldest_message_seconds / 60:.0f} мин",
                **ident,
            )
        )

    if node.exchange_ok is False:
        probes = (node.details or {}).get("probes") or {}
        broken = [
            f"{key.split(':', 1)[1]}: {value.get('failed_layer') or '?'}"
            for key, value in probes.items()
            if key.startswith("exchange:") and value.get("ok") is False
        ]
        alerts.append(
            Alert(
                "EXCHANGE_UNAVAILABLE",
                CRITICAL,
                "Exchange недоступен для доставки",
                "; ".join(broken),
                **ident,
            )
        )
    elif node.exchange_ok is None:
        alerts.append(
            Alert(
                "EXCHANGE_NOT_PROBED",
                INFO,
                "Доступность Exchange не проверяется",
                "Проба не настроена.",
                **ident,
            )
        )

    if node.pressure_state == "CRITICAL":
        alerts.append(
            Alert("DISK_PRESSURE", CRITICAL, "Критическое давление на диск или очередь", "", **ident)
        )
    elif node.pressure_state == "PRESSURE":
        alerts.append(Alert("DISK_PRESSURE", WARNING, "Давление на диск или очередь", "", **ident))

    if node.config_drift is True:
        alerts.append(
            Alert(
                "CONFIG_DRIFT",
                CRITICAL,
                "Конфигурация на узле изменена вне панели",
                "Файлы расходятся с принятым описанием.",
                **ident,
            )
        )

    if node.open_relay_safe is False:
        alerts.append(
            Alert(
                "OPEN_RELAY_SELFTEST_FAILED",
                CRITICAL,
                "Самопроверка: узел принял бы чужое письмо",
                "Недоверенный источник смог адресовать внешнего получателя. Немедленно слейте узел.",
                **ident,
            )
        )
    elif node.open_relay_safe is None:
        alerts.append(
            Alert("OPEN_RELAY_NOT_PROBED", INFO, "Самопроверка открытого релея не выполняется", "", **ident)
        )

    stale = (
        node.collector_report_age is None
        or node.collector_report_age > settings.gateway_collector_stale_seconds
    )
    if stale:
        alerts.append(
            Alert(
                "SHADOW_COLLECTOR_UNAVAILABLE",
                WARNING,
                "Сборщик теневых копий не отчитывается",
                "Почта идёт как шла; потеряно наблюдение за новыми письмами.",
                **ident,
            )
        )
    elif (node.shadow_pending_seconds or 0) >= settings.gateway_shadow_pending_warn_seconds:
        alerts.append(
            Alert(
                "SHADOW_COLLECTOR_BACKLOG",
                WARNING,
                "Копии писем копятся: панель их не принимает",
                f"самая старая ждёт {(node.shadow_pending_seconds or 0) / 60:.0f} мин",
                **ident,
            )
        )
    return alerts


def compute(session: Session, organization_id: str, settings: Settings) -> list[Alert]:
    nodes = list(
        session.execute(
            select(TransportNode)
            .where(TransportNode.organization_id == organization_id)
            .order_by(TransportNode.name)
        ).scalars()
    )
    alerts: list[Alert] = []
    if not nodes:
        alerts.append(
            Alert("NO_NODES", WARNING, "Ни один узел шлюза не зарегистрирован", "Никто не присылал сигналов.")
        )
    for node in nodes:
        alerts.extend(_node_alerts(node, settings))

    recipients = transport.recipients_status(session, organization_id, settings)
    if recipients["freshness"] == "STALE_HARD":
        alerts.append(
            Alert(
                "RECIPIENT_MAP_STALE",
                CRITICAL,
                "Справочник получателей безнадёжно устарел",
                "Узлы отвечают отправителям временным отказом, пока справочник не обновят.",
            )
        )
    elif recipients["freshness"] == "STALE_GRACE":
        alerts.append(
            Alert("RECIPIENT_MAP_STALE", WARNING, "Справочник получателей устарел", "Ещё в пределах допуска.")
        )

    for cert in transport.tls_status(session, organization_id):
        if cert["state"] == "EXPIRED":
            alerts.append(
                Alert(
                    "TLS_CERT_EXPIRING",
                    CRITICAL,
                    "Сертификат истёк",
                    f"{cert['usage']}: {cert['subject']}",
                    node_id=cert["node_id"],
                )
            )
        elif cert["state"] == "EXPIRING":
            alerts.append(
                Alert(
                    "TLS_CERT_EXPIRING",
                    WARNING,
                    "Сертификат скоро истекает",
                    f"{cert['usage']}: осталось дней — {int(cert['days_left'] or 0)}",
                    node_id=cert["node_id"],
                )
            )

    # Анти-спам (ТЗ 1.2): импорт здесь, потому что модуль тревог анти-спама использует типы этого модуля.
    from . import antispam_alerts

    alerts.extend(antispam_alerts.compute(session, organization_id, settings))
    return sorted(alerts, key=lambda a: (_ORDER[a.severity], a.code, a.node_id))
