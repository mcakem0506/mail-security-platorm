"""Имена символов Rspamd, по которым определяются результаты проверок (ТЗ 1.2 §8–§11).

Отдельный лёгкий модуль без зависимостей: им пользуются и нормализация доказательств (``auth``), и
метрики узла, а узел работает в образе сканера, где пакета разбора почты нет.
"""

from __future__ import annotations

SPF_SYMBOLS: dict[str, str] = {
    "R_SPF_ALLOW": "PASS",
    "R_SPF_FAIL": "FAIL",
    "R_SPF_SOFTFAIL": "SOFTFAIL",
    "R_SPF_NEUTRAL": "NEUTRAL",
    "R_SPF_NA": "NONE",
    "R_SPF_DNSFAIL": "TEMPERROR",
    "R_SPF_PERMFAIL": "PERMERROR",
}
DKIM_SYMBOLS: dict[str, str] = {
    "R_DKIM_ALLOW": "PASS",
    "R_DKIM_REJECT": "FAIL",
    "R_DKIM_NA": "NONE",
    "R_DKIM_TEMPFAIL": "TEMPERROR",
    "R_DKIM_PERMFAIL": "PERMERROR",
}
DMARC_SYMBOLS: dict[str, str] = {
    "DMARC_POLICY_ALLOW": "PASS",
    "DMARC_POLICY_ALLOW_WITH_FAILURES": "PASS",
    "DMARC_POLICY_REJECT": "FAIL",
    "DMARC_POLICY_QUARANTINE": "FAIL",
    "DMARC_POLICY_SOFTFAIL": "FAIL",
    "DMARC_NA": "NONE",
    "DMARC_DNSFAIL": "TEMPERROR",
    "DMARC_BAD_POLICY": "PERMERROR",
}
ARC_SYMBOLS: dict[str, str] = {
    "ARC_ALLOW": "PASS",
    "ARC_REJECT": "FAIL",
    "ARC_INVALID": "FAIL",
    "ARC_NA": "NONE",
    "ARC_DNSFAIL": "UNKNOWN",
}
DKIM_SIGNED_SYMBOL = "DKIM_SIGNED"
RBL_PREFIX = "MSP_RBL_"
DIRECTION_SYMBOLS = {
    "MSP_DIRECTION_INBOUND": "INBOUND",
    "MSP_DIRECTION_OUTBOUND": "OUTBOUND",
    "MSP_DIRECTION_INTERNAL_TEST": "INTERNAL_TEST",
}
