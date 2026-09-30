"""Structured logging, correlation IDs and Prometheus metrics (ТЗ 31)."""

from __future__ import annotations

import json
import logging
import sys
import time
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
