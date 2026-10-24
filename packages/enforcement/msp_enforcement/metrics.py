"""Имена метрик службы принуждения узла (ТЗ 1.3 §64). Тест тревог проверяет, что правила ссылаются на существующие метрики."""

from __future__ import annotations

METRIC_NAMES = (
    "msp_enforcement_policy_info",
    "msp_enforcement_kill_switch_active",
    "msp_enforcement_local_bypass_active",
    "msp_enforcement_errors_total",
    "msp_enforcement_timeouts_total",
    "msp_enforcement_decisions_dropped_total",
    "msp_enforcement_panel_errors_total",
    "msp_enforcement_policy_stale",
    "msp_enforcement_decisions_total",
    "msp_enforcement_actions_total",
    "msp_enforcement_gate_errors_total",
    "msp_enforcement_quarantine_failopen_total",
)
