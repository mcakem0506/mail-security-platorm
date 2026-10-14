"""Метрики узла в текстовом формате Prometheus (ТЗ 1.1 §45).

Только стандартная библиотека: модуль работает на узле, где нет ни pydantic, ни клиента
Prometheus. Экспозиция пишется вручную, а значит экранирование значений меток — наша
ответственность: в метку попадает текст, который задаёт внешний клиент (имя узла, код ответа),
и без экранирования одна строка с кавычкой ломает разбор всей страницы.

Кардинальность меток ограничена намеренно. В метки идут только значения из закрытых наборов
(направление, итог, класс кода ответа). Адреса, имена хостов клиентов, идентификаторы очереди
и тексты ответов в метки не попадают никогда: иначе любой, кто может подключиться к порту 25,
способен раздуть память агента и хранилище метрик.
"""

from __future__ import annotations

import json
import threading
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime

from .logparser import Direction, EventType, LogEvent
from .state import PressureState

#: Границы гистограммы задержки доставки, секунды.
DELAY_BUCKETS = (0.5, 1, 2, 5, 10, 30, 60, 300, 900, 3600)

#: Допустимые значения меток: всё остальное сводится к ``other``.
_DIRECTIONS = frozenset(d.value for d in Direction)
_OUTCOMES = frozenset({"sent", "deferred", "bounced", "expired"})
_REJECT_CLASSES = frozenset({"4xx", "5xx"})
_QUEUES = frozenset({"active", "deferred", "hold", "incoming", "corrupt"})


def escape_label(value: str) -> str:
    """Экранирование значения метки по правилам формата (обратная косая, кавычка, перевод строки)."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels(labels: Mapping[str, str]) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{escape_label(str(v))}"' for k, v in sorted(labels.items()))
    return "{" + inner + "}"


def _fmt(value: float) -> str:
    if value == int(value) and abs(value) < 1e15:
        return str(int(value))
    return repr(float(value))


def _bounded(value: str, allowed: frozenset[str]) -> str:
    return value if value in allowed else "other"


@dataclass
class QueueSnapshot:
    messages: int = 0
    bytes: int = 0
    oldest_seconds: float = 0.0
    by_queue: dict[str, int] = field(default_factory=dict)


def parse_postqueue_json(lines: Iterable[str], *, now: float) -> QueueSnapshot:
    """Разбор вывода ``postqueue -j`` (по одному JSON-объекту на строку).

    Каталог очереди напрямую не читается (ТЗ §34): структура файлов очереди — внутреннее дело
    Postfix, и разбор её руками ломается при смене версии. Битые строки пропускаются, а не
    обрывают подсчёт: частичная картина полезнее, чем ошибка вместо метрики.
    """
    snapshot = QueueSnapshot()
    oldest_arrival: float | None = None
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        snapshot.messages += 1
        size = record.get("message_size")
        if isinstance(size, int) and not isinstance(size, bool) and size >= 0:
            snapshot.bytes += size
        queue = record.get("queue_name")
        name = queue if isinstance(queue, str) and queue in _QUEUES else "other"
        snapshot.by_queue[name] = snapshot.by_queue.get(name, 0) + 1
        arrival = record.get("arrival_time")
        if isinstance(arrival, (int, float)) and not isinstance(arrival, bool) and arrival > 0:
            oldest_arrival = arrival if oldest_arrival is None else min(oldest_arrival, arrival)
    if oldest_arrival is not None:
        snapshot.oldest_seconds = max(0.0, now - oldest_arrival)
    return snapshot


class Metrics:
    """Счётчики, накапливаемые из событий журнала, и снимки состояния узла."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.connections: Counter[str] = Counter()
        self.received: Counter[str] = Counter()
        self.rejected: Counter[tuple[str, str]] = Counter()
        self.deferred: Counter[str] = Counter()
        self.delivered: Counter[str] = Counter()
        self.failures: Counter[tuple[str, str]] = Counter()
        self.shadow: Counter[str] = Counter()
        self.shadow_failures: Counter[str] = Counter()
        self.delay_buckets: list[int] = [0] * len(DELAY_BUCKETS)
        self.delay_count = 0
        self.delay_sum = 0.0
        self.queue = QueueSnapshot()
        self.disk_free_bytes: int | None = None
        self.pressure = PressureState.NORMAL
        self.recipient_map_age: float | None = None
        self.config_version = ""
        self.config_checksum = ""
        self.node_role = ""
        self.node_up = 1
        #: Пробы Exchange по уровням: (цель, уровень) -> 1 прошла, 0 упала. Нет записи — не проверялась.
        self.exchange_layers: dict[tuple[str, str], int] = {}
        #: Самопроверка открытого релея: 1 — отказ (хорошо), 0 — принял бы чужое письмо, None — не проверено.
        self.open_relay_safe: int | None = None
        #: Сборщик теневых копий: возраст его отчёта и самой старой копии в ожидании.
        self.collector_report_age: float | None = None
        self.shadow_pending_seconds: float | None = None
        #: Сроки сертификатов: назначение -> секунд до окончания (отрицательное — истёк).
        self.certificate_expiry: dict[str, float] = {}
        #: Дрейф конфигурации: 1 — файлы расходятся с принятым описанием; None — не проверено.
        self.config_drift: int | None = None

    # ------------------------------------------------------------------ события
    def observe(self, event: LogEvent) -> None:
        direction = _bounded(event.direction.value, _DIRECTIONS)
        with self._lock:
            kind = event.event_type
            if kind is EventType.CONNECT:
                self.connections[direction] += 1
            elif kind is EventType.QUEUED:
                # Событий QUEUED два на письмо: строка cleanup (с message-id) и строка qmgr (с размером).
                # Письмом считается вторая, она же и есть момент, когда оно легло в очередь.
                if event.status == "queued":
                    self.received[direction] += 1
            elif kind is EventType.REJECTED:
                self.rejected[(direction, _code_class(event.smtp_code))] += 1
            elif kind is EventType.DELIVERY:
                self._delivery(event, direction)
            elif kind is EventType.REMOTE_REPLY:
                self.failures[(direction, _code_class(event.smtp_code))] += 1
            elif kind is EventType.SHADOW:
                if event.status == "sent":
                    self.shadow["ok"] += 1
                else:
                    self.shadow_failures[_bounded(event.status, _OUTCOMES)] += 1

    def observe_all(self, events: Iterable[LogEvent]) -> None:
        for event in events:
            self.observe(event)

    def _delivery(self, event: LogEvent, direction: str) -> None:
        outcome = _bounded(event.status, _OUTCOMES)
        if outcome == "sent":
            self.delivered[direction] += 1
            if event.delay is not None and event.delay >= 0:
                self.delay_count += 1
                self.delay_sum += event.delay
                for i, bound in enumerate(DELAY_BUCKETS):
                    if event.delay <= bound:
                        self.delay_buckets[i] += 1
        elif outcome == "deferred":
            self.deferred[direction] += 1
        else:
            self.failures[(direction, "5xx" if outcome == "bounced" else outcome)] += 1

    # ------------------------------------------------------------------ экспозиция
    def render(self) -> str:
        with self._lock:
            out: list[str] = []

            def head(name: str, kind: str, help_text: str) -> None:
                out.append(f"# HELP {name} {help_text}")
                out.append(f"# TYPE {name} {kind}")

            def counter(name: str, help_text: str, values: Mapping[str, int]) -> None:
                head(name, "counter", help_text)
                for key in sorted(values):
                    out.append(f"{name}{_labels({'direction': key})} {values[key]}")
                if not values:
                    out.append(f"{name} 0")

            counter("msp_gateway_smtp_connections_total", "SMTP-соединения", self.connections)
            counter("msp_gateway_messages_received_total", "Принятые в очередь письма", self.received)

            head("msp_gateway_messages_rejected_total", "counter", "Отказы на этапе SMTP")
            for (direction, klass), count in sorted(self.rejected.items()):
                labels = _labels({"direction": direction, "class": klass})
                out.append(f"msp_gateway_messages_rejected_total{labels} {count}")
            if not self.rejected:
                out.append("msp_gateway_messages_rejected_total 0")

            counter("msp_gateway_messages_deferred_total", "Отложенные попытки доставки", self.deferred)
            counter("msp_gateway_messages_delivered_total", "Доставленные письма", self.delivered)

            head("msp_gateway_delivery_failures_total", "counter", "Неудачные доставки по классу ответа")
            for (direction, klass), count in sorted(self.failures.items()):
                labels = _labels({"direction": direction, "class": klass})
                out.append(f"msp_gateway_delivery_failures_total{labels} {count}")
            if not self.failures:
                out.append("msp_gateway_delivery_failures_total 0")

            head("msp_gateway_delivery_delay_seconds", "histogram", "Задержка доставки")
            for bound, count in zip(DELAY_BUCKETS, self.delay_buckets, strict=True):
                out.append(f'msp_gateway_delivery_delay_seconds_bucket{{le="{_fmt(bound)}"}} {count}')
            out.append(f'msp_gateway_delivery_delay_seconds_bucket{{le="+Inf"}} {self.delay_count}')
            out.append(f"msp_gateway_delivery_delay_seconds_sum {_fmt(self.delay_sum)}")
            out.append(f"msp_gateway_delivery_delay_seconds_count {self.delay_count}")

            head("msp_gateway_queue_messages", "gauge", "Писем в очереди")
            if self.queue.by_queue:
                for name, count in sorted(self.queue.by_queue.items()):
                    out.append(f"msp_gateway_queue_messages{_labels({'queue': name})} {count}")
            else:
                out.append("msp_gateway_queue_messages 0")
            head("msp_gateway_queue_bytes", "gauge", "Байт в очереди")
            out.append(f"msp_gateway_queue_bytes {self.queue.bytes}")
            head("msp_gateway_oldest_message_seconds", "gauge", "Возраст самого старого письма в очереди")
            out.append(f"msp_gateway_oldest_message_seconds {_fmt(self.queue.oldest_seconds)}")

            head("msp_gateway_disk_free_bytes", "gauge", "Свободно на диске очереди")
            if self.disk_free_bytes is not None:
                out.append(f"msp_gateway_disk_free_bytes {self.disk_free_bytes}")

            head("msp_gateway_pressure_state", "gauge", "Состояние давления (1 у текущего)")
            for state in PressureState:
                labels = _labels({"state": state.value})
                out.append(f"msp_gateway_pressure_state{labels} {int(state is self.pressure)}")

            head("msp_gateway_shadow_delivery_total", "counter", "Копии, переданные на анализ")
            out.append(f"msp_gateway_shadow_delivery_total {self.shadow['ok']}")
            head("msp_gateway_shadow_failures_total", "counter", "Сбои теневой копии")
            out.append(f"msp_gateway_shadow_failures_total {sum(self.shadow_failures.values())}")

            head("msp_gateway_recipient_map_age_seconds", "gauge", "Возраст справочника получателей")
            if self.recipient_map_age is not None:
                out.append(f"msp_gateway_recipient_map_age_seconds {_fmt(self.recipient_map_age)}")

            head("msp_gateway_config_info", "gauge", "Применённая конфигурация")
            info = {"version": self.config_version, "checksum": self.config_checksum, "role": self.node_role}
            out.append(f"msp_gateway_config_info{_labels(info)} 1")
            head("msp_gateway_node_up", "gauge", "Агент узла работает")
            out.append(f"msp_gateway_node_up {self.node_up}")

            head("msp_gateway_exchange_probe_ok", "gauge", "Проба Exchange по уровням (1 прошла, 0 упала)")
            for (target, layer), ok in sorted(self.exchange_layers.items()):
                labels = _labels({"target": target, "layer": layer})
                out.append(f"msp_gateway_exchange_probe_ok{labels} {ok}")
            head(
                "msp_gateway_open_relay_selftest_ok",
                "gauge",
                "Самопроверка открытого релея (1 отказ, 0 принял)",
            )
            if self.open_relay_safe is not None:
                out.append(f"msp_gateway_open_relay_selftest_ok {self.open_relay_safe}")
            head("msp_gateway_shadow_collector_report_age_seconds", "gauge", "Возраст отчёта сборщика копий")
            if self.collector_report_age is not None:
                out.append(
                    f"msp_gateway_shadow_collector_report_age_seconds {_fmt(self.collector_report_age)}"
                )
            head("msp_gateway_shadow_pending_seconds", "gauge", "Возраст самой старой копии в ожидании")
            if self.shadow_pending_seconds is not None:
                out.append(f"msp_gateway_shadow_pending_seconds {_fmt(self.shadow_pending_seconds)}")
            head("msp_gateway_certificate_expiry_seconds", "gauge", "Секунд до окончания сертификата")
            for usage, seconds in sorted(self.certificate_expiry.items()):
                labels = _labels({"usage": usage})
                out.append(f"msp_gateway_certificate_expiry_seconds{labels} {_fmt(seconds)}")
            head("msp_gateway_config_drift", "gauge", "Файлы конфигурации расходятся с принятым описанием")
            if self.config_drift is not None:
                out.append(f"msp_gateway_config_drift {self.config_drift}")
            return "\n".join(out) + "\n"


def _code_class(code: int | None) -> str:
    if code is None:
        return "other"
    klass = f"{code // 100}xx"
    return klass if klass in _REJECT_CLASSES else "other"


def age_seconds(generated_at: datetime | None, now: datetime) -> float | None:
    """Возраст справочника; ``None`` — справочник ни разу не загружался."""
    if generated_at is None:
        return None
    return max(0.0, (now - generated_at).total_seconds())
