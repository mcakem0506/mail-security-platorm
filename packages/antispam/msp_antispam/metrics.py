"""Метрики сканера на узле в формате Prometheus (ТЗ 1.2 §36).

Считаются приёмником результатов по записям самого сканера, без зависимостей: образ сканера не
содержит клиентской библиотеки Prometheus, а формат текстовой выдачи прост. Метки ограничены
перечислениями (направление, действие, результат): значения из письма в метки не попадают, иначе
отправитель мог бы раздувать число рядов.

Что означают метрики репутации — важно прочитать честно. Сканер не сообщает, сколько запросов к DNS он
выполнил и сколько из них закончились ошибкой. Поэтому:

* ``msp_rbl_queries_total`` — число просканированных писем, при которых провайдер был включён (то есть
  запрос должен был выполняться);
* ``msp_rbl_listed_total`` — сколько раз сработал символ провайдера;
* ``msp_rbl_errors_total`` — сколько раз сообщение об ошибке запроса нашлось в журнале сканера; пока
  журнал не подключён, значение остаётся нулём и не должно трактоваться как «ошибок нет» (метка
  ``source="not_collected"``).
"""

from __future__ import annotations

import threading
from collections import Counter
from collections.abc import Mapping
from typing import Any

from .symbols import (
    ARC_SYMBOLS,
    DIRECTION_SYMBOLS,
    DKIM_SIGNED_SYMBOL,
    DKIM_SYMBOLS,
    DMARC_SYMBOLS,
    RBL_PREFIX,
    SPF_SYMBOLS,
)

#: Все имена метрик, которые отдаёт узел. Проверка алертов сверяется с этим списком: правило,
#: ссылающееся на метрику, которой нет, не срабатывает никогда.
METRIC_NAMES = (
    "msp_rspamd_up",
    "msp_rspamd_redis_up",
    "msp_rspamd_scan_total",
    "msp_rspamd_scan_duration_seconds",
    "msp_rspamd_scan_duration_seconds_bucket",
    "msp_rspamd_scan_duration_seconds_sum",
    "msp_rspamd_scan_duration_seconds_count",
    "msp_rspamd_scan_errors_total",
    "msp_rspamd_suggested_actions_total",
    "msp_spf_results_total",
    "msp_dkim_results_total",
    "msp_dmarc_results_total",
    "msp_arc_results_total",
    "msp_rbl_queries_total",
    "msp_rbl_listed_total",
    "msp_rbl_errors_total",
    "msp_spam_fp_total",
    "msp_spam_fn_total",
    "msp_dkim_sign_total",
    "msp_dkim_sign_failures_total",
)

BUCKETS = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
ACTIONS = ("no action", "greylist", "add header", "rewrite subject", "soft reject", "reject")
_LABEL_SAFE = {a: a.replace(" ", "_") for a in ACTIONS}


def _symbols(record: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = record.get("symbols")
    if isinstance(raw, list):
        return [s for s in raw if isinstance(s, Mapping)]
    if isinstance(raw, Mapping):
        return [{"name": k, **v} for k, v in raw.items() if isinstance(v, Mapping)]
    return []


class ScanMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.scans: Counter[str] = Counter()
        self.actions: Counter[tuple[str, str]] = Counter()
        self.results: dict[str, Counter[str]] = {m: Counter() for m in ("spf", "dkim", "dmarc", "arc")}
        self.rbl_listed: Counter[str] = Counter()
        self.rbl_queries: Counter[str] = Counter()
        self.spam_fp = 0
        self.spam_fn = 0
        self.sign_ok = 0
        self.sign_failures = 0
        self.errors = 0
        self.duration_sum = 0.0
        self.duration_count = 0
        self.duration_buckets: Counter[float] = Counter()
        self.up = 0
        self.redis_up = 0
        self.signing_domains: frozenset[str] = frozenset()
        self.active_providers: frozenset[str] = frozenset()

    # --- наблюдения ----------------------------------------------------------------------
    def configure(self, *, signing_domains: frozenset[str], active_providers: frozenset[str]) -> None:
        with self._lock:
            self.signing_domains = signing_domains
            self.active_providers = active_providers

    def observe(self, record: Mapping[str, Any]) -> None:
        names = {str(s.get("name", "")) for s in _symbols(record)}
        direction = next((v for k, v in DIRECTION_SYMBOLS.items() if k in names), "UNKNOWN")
        action = str(record.get("action", "unknown")).lower()
        action = action if action in _LABEL_SAFE else "unknown"
        with self._lock:
            self.scans[direction] += 1
            self.actions[(direction, _LABEL_SAFE.get(action, "unknown"))] += 1
            for method, table in (
                ("spf", SPF_SYMBOLS),
                ("dkim", DKIM_SYMBOLS),
                ("dmarc", DMARC_SYMBOLS),
                ("arc", ARC_SYMBOLS),
            ):
                found = [table[n] for n in table if n in names]
                if found:
                    self.results[method][found[0]] += 1
            for name in names:
                if name.startswith(RBL_PREFIX):
                    provider = name[len(RBL_PREFIX) :].rsplit("_", 1)[0].lower()
                    # Метка только для известных провайдеров: остальное — «other», ряды не растут.
                    self.rbl_listed[provider if provider in self.active_providers else "other"] += 1
            for provider in self.active_providers:
                self.rbl_queries[provider[:24]] += 1
            seconds = _number(record.get("scan_time")) / 1000.0
            self.duration_sum += seconds
            self.duration_count += 1
            for bound in BUCKETS:
                if seconds <= bound:
                    self.duration_buckets[bound] += 1
            if direction == "OUTBOUND":
                sender = str(record.get("from", "")).rsplit("@", 1)[-1].lower()
                header_from = record.get("header_from")
                domain = sender
                if isinstance(header_from, list) and header_from:
                    domain = str(header_from[0]).rsplit("@", 1)[-1].strip("> ").lower()
                if DKIM_SIGNED_SYMBOL in names:
                    self.sign_ok += 1
                elif domain in self.signing_domains:
                    # Домен с действующим ключом, а подписи нет: подпись не сработала (ТЗ 1.2 §36).
                    self.sign_failures += 1

    def error(self) -> None:
        with self._lock:
            self.errors += 1

    def set_health(self, *, up: bool, redis_up: bool | None) -> None:
        with self._lock:
            self.up = 1 if up else 0
            self.redis_up = 1 if redis_up else 0

    # --- выдача --------------------------------------------------------------------------
    def render(self) -> str:
        with self._lock:
            lines: list[str] = []

            def emit(name: str, help_: str, kind: str, samples: list[tuple[str, float]]) -> None:
                lines.append(f"# HELP {name} {help_}")
                lines.append(f"# TYPE {name} {kind}")
                for labels, value in samples:
                    lines.append(f"{name}{labels} {_fmt(value)}")

            emit("msp_rspamd_up", "Сканер отвечает (1) или нет (0).", "gauge", [("", self.up)])
            emit(
                "msp_rspamd_redis_up",
                "Redis сканера доступен (1) или нет (0).",
                "gauge",
                [("", self.redis_up)],
            )
            emit(
                "msp_rspamd_scan_total",
                "Просканировано писем.",
                "counter",
                [(f'{{direction="{d}"}}', v) for d, v in sorted(self.scans.items())] or [("", 0)],
            )
            emit(
                "msp_rspamd_scan_errors_total",
                "Записей сканера, которые не удалось разобрать.",
                "counter",
                [("", self.errors)],
            )
            emit(
                "msp_rspamd_suggested_actions_total",
                "Родные действия сканера (предложения, не исполняются).",
                "counter",
                [(f'{{direction="{d}",action="{a}"}}', v) for (d, a), v in sorted(self.actions.items())]
                or [("", 0)],
            )
            duration = [(f'_bucket{{le="{b}"}}', self.duration_buckets[b]) for b in BUCKETS]
            lines.append("# HELP msp_rspamd_scan_duration_seconds Время сканирования письма.")
            lines.append("# TYPE msp_rspamd_scan_duration_seconds histogram")
            for suffix, value in duration:
                lines.append(f"msp_rspamd_scan_duration_seconds{suffix} {_fmt(value)}")
            lines.append(f'msp_rspamd_scan_duration_seconds_bucket{{le="+Inf"}} {_fmt(self.duration_count)}')
            lines.append(f"msp_rspamd_scan_duration_seconds_sum {_fmt(self.duration_sum)}")
            lines.append(f"msp_rspamd_scan_duration_seconds_count {_fmt(self.duration_count)}")
            for method in ("spf", "dkim", "dmarc", "arc"):
                emit(
                    f"msp_{method}_results_total",
                    f"Результаты {method.upper()} (нормализованные).",
                    "counter",
                    [(f'{{result="{r}"}}', v) for r, v in sorted(self.results[method].items())] or [("", 0)],
                )
            emit(
                "msp_rbl_queries_total",
                "Писем, при которых провайдер репутации был включён.",
                "counter",
                [(f'{{provider="{p}"}}', v) for p, v in sorted(self.rbl_queries.items())] or [("", 0)],
            )
            emit(
                "msp_rbl_listed_total",
                "Срабатываний символа провайдера репутации.",
                "counter",
                [(f'{{provider="{p}"}}', v) for p, v in sorted(self.rbl_listed.items())] or [("", 0)],
            )
            emit(
                "msp_rbl_errors_total",
                "Ошибок запросов к провайдерам (журнал не подключён).",
                "counter",
                [('{source="not_collected"}', 0)],
            )
            emit(
                "msp_spam_fp_total",
                "Ложные срабатывания спама по решениям аналитика.",
                "counter",
                [("", self.spam_fp)],
            )
            emit(
                "msp_spam_fn_total", "Пропуски спама по решениям аналитика.", "counter", [("", self.spam_fn)]
            )
            emit("msp_dkim_sign_total", "Подписанных исходящих писем.", "counter", [("", self.sign_ok)])
            emit(
                "msp_dkim_sign_failures_total",
                "Исходящих писем домена с действующим ключом без подписи.",
                "counter",
                [("", self.sign_failures)],
            )
            # Спам-классификация считается панелью; на узле единственная ось — действие сканера.
            return "\n".join(lines) + "\n"


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _fmt(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else f"{value:.6f}"
