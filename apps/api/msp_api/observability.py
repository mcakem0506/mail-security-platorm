"""Structured logging, correlation IDs and Prometheus metrics (ТЗ 31)."""

from __future__ import annotations

import json
import logging
import sys
import time
from collections.abc import Mapping
from contextvars import ContextVar
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

request_id_var: ContextVar[str] = ContextVar("request_id", default="")
job_id_var: ContextVar[str] = ContextVar("analysis_job_id", default="")
message_id_var: ContextVar[str] = ContextVar("message_id", default="")
incident_id_var: ContextVar[str] = ContextVar("incident_id", default="")

_RESERVED = frozenset(
    [
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "taskName",
    ]
)
# Keys that must never reach the logs, even if a caller passes them (ТЗ 31: PII minimisation).
_FORBIDDEN_LOG_KEYS = frozenset(
    {"password", "secret", "token", "api_key", "apikey", "cookie", "authorization", "body", "raw"}
)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in (
            ("request_id", request_id_var.get()),
            ("analysis_job_id", job_id_var.get()),
            ("message_id", message_id_var.get()),
            ("incident_id", incident_id_var.get()),
        ):
            if value:
                payload[key] = value
        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_"):
                continue
            if key.lower() in _FORBIDDEN_LOG_KEYS:
                payload[key] = "[redacted]"
            elif isinstance(value, str | int | float | bool | list | dict | None):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)[:4000]
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    handler = logging.StreamHandler(sys.stdout)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())
    for noisy in ("uvicorn.access", "httpx", "httpcore", "python_multipart"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


# ---------------------------------------------------------------------------------------------
# Metrics (ТЗ 31)
# ---------------------------------------------------------------------------------------------
REGISTRY = CollectorRegistry()

analyses_total = Counter(
    "msp_analyses_total", "Analyses completed", ["classification", "source"], registry=REGISTRY
)
analysis_duration = Histogram(
    "msp_analysis_duration_seconds",
    "Local analysis duration",
    ["stage"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30),
    registry=REGISTRY,
)
queue_depth = Gauge("msp_queue_depth", "Pending tasks per queue", ["queue"], registry=REGISTRY)
provider_latency = Histogram(
    "msp_provider_latency_seconds",
    "Threat intelligence provider latency",
    ["provider"],
    buckets=(0.1, 0.25, 0.5, 1, 2, 5, 10),
    registry=REGISTRY,
)
provider_errors = Counter(
    "msp_provider_errors_total", "Provider errors", ["provider", "kind"], registry=REGISTRY
)
provider_rate_limit = Counter(
    "msp_provider_rate_limit_total", "Provider rate-limit hits", ["provider"], registry=REGISTRY
)
parser_errors = Counter("msp_parser_errors_total", "Parser errors", ["kind"], registry=REGISTRY)
incidents_total = Counter("msp_incidents_total", "Incidents created", ["severity"], registry=REGISTRY)
campaign_size = Histogram(
    "msp_campaign_size",
    "Messages per campaign at correlation time",
    buckets=(1, 2, 5, 10, 25, 50, 100, 500),
    registry=REGISTRY,
)
remediation_actions = Counter(
    "msp_remediation_actions_total", "Remediation actions", ["action", "state"], registry=REGISTRY
)
false_positive_total = Counter(
    "msp_false_positive_total", "Messages classified as false positive", registry=REGISTRY
)
employee_reports = Counter(
    "msp_employee_reports_total", "Phishing reports submitted by employees", registry=REGISTRY
)
http_requests = Counter(
    "msp_http_requests_total", "HTTP requests", ["method", "path", "status"], registry=REGISTRY
)
http_duration = Histogram(
    "msp_http_request_duration_seconds",
    "HTTP request duration",
    ["method", "path"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
    registry=REGISTRY,
)


# -- durable intake (ТЗ 1.0.1 §4.1) -----------------------------------------------------------
intake_success = Counter(
    "msp_intake_success_total", "Reports ingested and acknowledged", ["source"], registry=REGISTRY
)
intake_retry = Counter(
    "msp_intake_retry_total", "Intake attempts that will be retried", ["source", "reason"], registry=REGISTRY
)
intake_failed = Counter(
    "msp_intake_failed_total", "Reports dead-lettered after repeated failures", ["source"], registry=REGISTRY
)
duplicate_report = Counter(
    "msp_duplicate_report_total", "Repeat reports of a message already ingested", registry=REGISTRY
)
intake_backlog = Gauge(
    "msp_intake_backlog", "Intake records not yet acknowledged", ["state"], registry=REGISTRY
)
unscannable_total = Counter(
    "msp_unscannable_total",
    "Messages deliberately not analysed because a limit was exceeded",
    ["reason"],
    registry=REGISTRY,
)

# -- mail gateways (ТЗ 1.0.2 §35) ---------------------------------------------------------------
gateway_events = Counter(
    "msp_gateway_events_total", "Gateway events accepted", ["provider", "source"], registry=REGISTRY
)
gateway_event_parse_errors = Counter(
    "msp_gateway_event_parse_errors_total",
    "Gateway events that could not be parsed or accepted",
    ["provider", "reason"],
    registry=REGISTRY,
)
gateway_api_requests = Counter(
    "msp_gateway_api_requests_total", "Gateway API requests", ["provider"], registry=REGISTRY
)
gateway_api_failures = Counter(
    "msp_gateway_api_failures_total", "Gateway API failures", ["provider", "kind"], registry=REGISTRY
)
gateway_conflicts = Counter(
    "msp_gateway_conflicts_total", "Verdict conflicts detected", ["kind"], registry=REGISTRY
)
gateway_untrusted_headers = Counter(
    "msp_gateway_untrusted_headers_total",
    "Gateway headers that could not be verified against the delivery chain",
    ["provider", "trust_state"],
    registry=REGISTRY,
)
gateway_provider_latency = Histogram(
    "msp_gateway_provider_latency_seconds",
    "Gateway provider call latency",
    ["provider"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
    registry=REGISTRY,
)
gateway_last_event_timestamp = Gauge(
    "msp_gateway_last_event_timestamp",
    "Unix time of the last accepted event per gateway",
    ["provider"],
    registry=REGISTRY,
)
gateway_health = Gauge(
    "msp_gateway_health",
    "Gateway health: 1 ok, 0.5 degraded, 0 unavailable",
    ["provider"],
    registry=REGISTRY,
)

# -- detection quality (ТЗ 1.0.1 §11) -----------------------------------------------------------
rule_triggers = Counter("msp_rule_triggers_total", "Rule activations", ["rule_id"], registry=REGISTRY)


def render_metrics() -> bytes:
    return generate_latest(REGISTRY)


class Timer:
    def __init__(self) -> None:
        self._start = time.monotonic()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start


# ---------------------------------------------------------------------------------------------
# Detection operations (ТЗ 1.0.3B §41)
# ---------------------------------------------------------------------------------------------
#: Analyst decisions, by classification. The denominator of every quality metric: when this
#: stops growing, precision and recall stop meaning anything, and the dashboards start showing
#: an old answer with a fresh timestamp.
feedback_total = Counter(
    "msp_feedback_total",
    "Analyst feedback recorded",
    ["classification"],
    registry=REGISTRY,
)
false_negative_total = Counter(
    "msp_false_negative_total",
    "Missed detections reported",
    ["root_cause"],
    registry=REGISTRY,
)
#: Open detection gaps, by severity. A gauge rather than a counter: what matters is how many
#: are open now, not how many have ever been opened.
detection_gap_open = Gauge(
    "msp_detection_gap_open",
    "Open detection gaps",
    ["severity"],
    registry=REGISTRY,
)
rule_trigger_total = Counter("msp_rule_trigger_total", "Rule triggers", ["rule_id"], registry=REGISTRY)
rule_tp_total = Counter(
    "msp_rule_tp_total", "Rule triggers confirmed by an analyst", ["rule_id"], registry=REGISTRY
)
rule_fp_total = Counter(
    "msp_rule_fp_total", "Rule triggers rejected by an analyst", ["rule_id"], registry=REGISTRY
)
#: Rule health as a number, so an alert can fire on a rule turning noisy without anyone opening
#: the console. 0 healthy, 1 no data, 2 low coverage, 3 degraded, 4 regressed, 5 noisy.
rule_health = Gauge("msp_rule_health", "Rule health (0 healthy … 5 noisy)", ["rule_id"], registry=REGISTRY)
replay_jobs_total = Counter(
    "msp_replay_jobs_total", "Replay and re-evaluation jobs", ["kind"], registry=REGISTRY
)
replay_duration = Histogram(
    "msp_replay_duration_seconds",
    "Duration of a re-evaluation job",
    buckets=(1, 5, 15, 60, 300, 900, 3600),
    registry=REGISTRY,
)
investigation_queue_depth = Gauge(
    "msp_investigation_queue_depth",
    "Open incidents in the analyst queue",
    ["priority"],
    registry=REGISTRY,
)
#: Incidents currently past their acknowledgement target, by priority.
#:
#: A gauge rather than the counter ТЗ 1.0.3B §41 names, and deliberately so. The queue is
#: recomputed every time anyone opens it, so a counter incremented from that path would count
#: the same breach once per page view — a number that grows with how often people look rather
#: than with how often the organisation is late. What an alert needs is "how many are late now",
#: and that is a gauge.
incident_sla_breached = Gauge(
    "msp_incident_sla_breached",
    "Incidents currently past their acknowledgement target",
    ["priority"],
    registry=REGISTRY,
)
#: The current detection release, as a labelled constant. Lets a dashboard answer "which rules
#: produced these verdicts" without joining anything.
detection_release_info = Gauge(
    "msp_detection_release_info",
    "Published detection release (always 1; the labels carry the information)",
    ["version", "dataset_version", "parser_version", "risk_engine_version"],
    registry=REGISTRY,
)

#: Health as a number, in the order an alert would want: higher is worse.
RULE_HEALTH_LEVEL: dict[str, int] = {
    "HEALTHY": 0,
    "NO_DATA": 1,
    "LOW_COVERAGE": 2,
    "DEGRADED": 3,
    "REGRESSED": 4,
    "NOISY": 5,
}


# ---------------------------------------------------------------------------------------------
# Профиль чтения QR-кодов (ТЗ 1.0.4 §6)
# ---------------------------------------------------------------------------------------------
#: Изображения, отданные декодеру. Знаменатель для всего остального здесь.
qr_images_total = Counter("msp_qr_images_total", "Images handed to the QR decoder", registry=REGISTRY)
qr_codes_found_total = Counter(
    "msp_qr_codes_found_total", "QR codes decoded out of those images", registry=REGISTRY
)
qr_decode_success_total = Counter(
    "msp_qr_decode_success_total", "Images the decoder processed without error", registry=REGISTRY
)
#: Таймаут и отказ разделены намеренно: первое означает «не успели», второе «не смогли», и
#: лечатся они по-разному — ресурсами и исправлением соответственно.
qr_decode_timeout_total = Counter(
    "msp_qr_decode_timeout_total", "Decoder batches killed by the timeout", registry=REGISTRY
)
qr_decode_failure_total = Counter(
    "msp_qr_decode_failure_total", "Images the decoder could not process", registry=REGISTRY
)
qr_worker_duration_seconds = Histogram(
    "msp_qr_worker_duration_seconds",
    "Wall time of one decoder batch, launch included",
    buckets=(0.25, 0.5, 1.0, 2.0, 5.0, 10.0),
    registry=REGISTRY,
)
#: Отдельно от общей длительности: запуск интерпретатора стоит около половины секунды, и без
#: этой метрики он читается как медленное декодирование.
qr_worker_spawn_duration_seconds = Histogram(
    "msp_qr_worker_spawn_duration_seconds",
    "Of that time, how much went on starting the process",
    buckets=(0.1, 0.25, 0.5, 1.0, 2.0),
    registry=REGISTRY,
)
#: Состояние компонента числом, в порядке, удобном для оповещения: больше — хуже.
QR_HEALTH_LEVEL: dict[str, int] = {
    "AVAILABLE": 0,
    "DISABLED": 1,
    "DEGRADED": 2,
    "FAILED": 3,
}
qr_component_health = Gauge(
    "msp_qr_component_health",
    "QR decoding component: 0 available, 1 disabled, 2 degraded, 3 failed",
    registry=REGISTRY,
)


# ---------------------------------------------------------------------------------------------
# Реальный поток (ТЗ 1.0.4 §12, §25)
# ---------------------------------------------------------------------------------------------
realflow_messages_total = Counter(
    "msp_realflow_messages_total",
    "Письма, взятые в набор валидации",
    ["source"],
    registry=REGISTRY,
)
realflow_sampled_total = Counter(
    "msp_realflow_sampled_total",
    "Попадания в выборку по причинам (у письма их может быть несколько)",
    ["reason"],
    registry=REGISTRY,
)
realflow_duplicates_total = Counter(
    "msp_realflow_duplicates_total",
    "Повторные поступления того же письма: узнаны по отпечатку и не посчитаны дважды",
    registry=REGISTRY,
)
realflow_reviewed_total = Counter(
    "msp_realflow_reviewed_total",
    "Разборы аналитиков по письмам реального потока",
    ["classification"],
    registry=REGISTRY,
)
#: Числители и знаменатели, а не доли. Prometheus не умеет «нет данных», и precision=0
#: читался бы как «платформа всегда ошибается», тогда как значит «никто ещё не разбирал».
realflow_confirmed_total = Gauge(
    "msp_realflow_confirmed_total",
    "Разборы, подтвердившие, что письмо стоило отметить",
    registry=REGISTRY,
)
realflow_false_positive_total = Gauge(
    "msp_realflow_false_positive_total",
    "Разборы, сказавшие, что отмечать было не за что",
    registry=REGISTRY,
)
realflow_missed_total = Gauge(
    "msp_realflow_missed_total",
    "Подтверждённые угрозы, которые платформа не отметила",
    registry=REGISTRY,
)
realflow_high_risk_unreviewed = Gauge(
    "msp_realflow_high_risk_unreviewed",
    "Письма с высоким риском, которые никто не разобрал: долг, а не ноль",
    registry=REGISTRY,
)
realflow_unscannable_total = Gauge(
    "msp_realflow_unscannable_total",
    "Письма, проверенные не до конца: шифрование, пароль на архиве, нераспознанный QR",
    registry=REGISTRY,
)
realflow_rule_pressure = Gauge(
    "msp_realflow_rule_pressure_per_1000",
    "Срабатываний правила на тысячу писем реального потока",
    ["rule_id"],
    registry=REGISTRY,
)
#: Записи, у которых срок хранения исходных данных истёк, а данные ещё на месте. Отдельная
#: метрика, а не метка состояния продвижения: это не шаг жизненного цикла письма, а нарушение
#: срока хранения (ТЗ §22), и смешивать их значило бы спрятать второе внутри первого.
realflow_raw_retention_overdue = Gauge(
    "msp_realflow_raw_retention_overdue",
    "Записи с истёкшим сроком хранения исходных данных, которые ещё не удалены",
    registry=REGISTRY,
)
realflow_promotion_state = Gauge(
    "msp_realflow_promotion_state",
    "Письма по шагам продвижения в корпус; продвижение не автоматическое (ТЗ §10)",
    ["state"],
    registry=REGISTRY,
)

#: Короткие похожие домены (ТЗ 1.0.4 §3, GAP-001).
short_domain_lookalike_total = Counter(
    "msp_short_domain_lookalike_total",
    "Обнаружения похожих коротких доменов по виду преобразования",
    ["transform"],
    registry=REGISTRY,
)
domain_variant_registry_size = Gauge(
    "msp_domain_variant_registry_size",
    "Размер реестра вариантов защищаемых доменов по статусу",
    ["status"],
    registry=REGISTRY,
)


def record_realflow_ingest(source: str, reasons: list[str], *, created: bool) -> None:
    """Приём письма в набор. Дубликат считается отдельно, а не как ещё одно письмо."""
    if not created:
        realflow_duplicates_total.inc()
        return
    realflow_messages_total.labels(source=source).inc()
    for reason in reasons:
        realflow_sampled_total.labels(reason=reason).inc()


def record_realflow_summary(summary: dict[str, Any]) -> None:
    """Перенести сводку в метрики.

    Доли в метрики не идут: ``precision`` в сводке может быть ``None``, и единственный способ
    выразить это в Prometheus — не выражать вовсе. Знаменатель виден по соседним числам.
    """
    realflow_confirmed_total.set(int(summary.get("true_positive") or 0))
    realflow_false_positive_total.set(int(summary.get("false_positive") or 0))
    realflow_missed_total.set(int(summary.get("false_negative") or 0))
    realflow_unscannable_total.set(int(summary.get("unscannable") or 0))
    sample = summary.get("sample") or {}
    realflow_high_risk_unreviewed.set(int(sample.get("high_risk_unreviewed") or 0))


def record_rule_pressure(rows: list[dict[str, Any]]) -> None:
    """Нагрузка правил на реальном потоке.

    ``PRODUCTION_NOISY`` здесь не выставляется: это вывод человека, глядящего на эти числа, а не
    следствие порога (ТЗ §12).
    """
    for row in rows:
        realflow_rule_pressure.labels(rule_id=str(row.get("rule_id"))).set(
            float(row.get("triggers_per_1000_messages") or 0.0)
        )


def record_promotion_states(counts: dict[str, int]) -> None:
    for state, value in counts.items():
        realflow_promotion_state.labels(state=state).set(int(value))


def _stat(stats: object, name: str) -> Any:
    """Прочитать поле статистики, не зная её формы.

    Разборщик отдаёт ``DecodeStats``, а сохранённое письмо — тот же набор словарём. Наблюдаемость
    не импортирует ни то, ни другое: она не должна тянуть за собой разбор писем, а разбор —
    наблюдаемость.
    """
    if isinstance(stats, Mapping):
        return stats.get(name)
    return getattr(stats, name, None)


def record_qr_decode(stats: object) -> None:
    """Перенести статистику одного письма в метрики (``DecodeStats`` или его словарь)."""
    submitted = int(_stat(stats, "images_submitted") or 0)
    if not submitted:
        # Декодер не вызывался. Записать нули означало бы утверждать, что письма с
        # изображениями были и в них ничего не нашлось.
        return
    qr_images_total.inc(submitted)
    qr_codes_found_total.inc(int(_stat(stats, "codes_found") or 0))
    qr_decode_success_total.inc(int(_stat(stats, "successes") or 0))
    qr_decode_timeout_total.inc(int(_stat(stats, "timeouts") or 0))
    qr_decode_failure_total.inc(int(_stat(stats, "failures") or 0))
    duration = float(_stat(stats, "duration_seconds") or 0.0)
    if duration:
        qr_worker_duration_seconds.observe(duration)
    spawn = _stat(stats, "spawn_seconds")
    if spawn is not None:
        qr_worker_spawn_duration_seconds.observe(float(spawn))
