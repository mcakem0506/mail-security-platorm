"""Свидетельства анти-спама и аутентификации как факты для правил (ТЗ 1.2 §26, §41).

Сканер (Rspamd) выполняет проверки SPF, DKIM, DMARC, ARC, репутации и спам-эвристики. Этот модуль
превращает его **нормализованный** результат в факты, не зная ничего о самом сканере:

* на вход приходят уже отобранные сигналы MSP (``AUTH_SPF_FAIL``, ``REPUTATION_LISTED``…), которые в
  отображении символов помечены как влияющие на риск; неизвестные символы сюда не попадают;
* класс спама факт риска не порождает: ``SPAM`` и ``HIGH_RISK`` — разные оси (§13). Единственный
  связанный со спамом сигнал — ``SPAM_HIGH_SCORE`` — даёт низкий вес и никогда не выставляет вердикт;
* чистый результат ничего не снижает: фактов «аутентификация пройдена, значит безопасно» нет;
* недоступный сканер на копии письма — недостающее свидетельство, а не «чисто».
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Сигнал отображения символов -> имя факта. Список закрытый: сигнал вне него фактом не становится.
SIGNAL_FACTS: dict[str, str] = {
    "AUTH_SPF_FAIL": "rspamd_spf_fail",
    "AUTH_SPF_SOFTFAIL": "rspamd_spf_softfail",
    "AUTH_DKIM_FAIL": "rspamd_dkim_fail",
    "AUTH_DMARC_POLICY_REJECT": "rspamd_dmarc_policy_reject",
    "AUTH_DMARC_POLICY_QUARANTINE": "rspamd_dmarc_policy_quarantine",
    "AUTH_DMARC_FAIL_MONITOR": "rspamd_dmarc_fail_monitor",
    "REPUTATION_LISTED": "rspamd_reputation_listed",
    "SPAM_HIGH_SCORE": "rspamd_spam_high_score",
    "PTR_MISSING": "rspamd_ptr_missing",
    "PTR_FCRDNS_FAIL": "rspamd_ptr_fcrdns_fail",
    "HELO_MISMATCH": "rspamd_helo_mismatch",
    "HELO_UNRESOLVABLE": "rspamd_helo_unresolvable",
}


@dataclass
class AntispamFindings:
    """Что сканер и локальная история сообщили об одном письме."""

    scan_present: bool = False
    #: Письмо должно было быть просканировано (пришло через шлюз с включённым сканером).
    expected: bool = False
    #: Сигналы, влияющие на риск (``risk_effect == INCREASE`` в отображении).
    risk_signals: list[str] = field(default_factory=list)
    auth_conflict: bool = False
    #: Отправитель из репутационного списка аналитика как вредоносный (подтверждено человеком).
    source_confirmed_hostile: bool = False
    mapping_version: str = ""
    details: dict[str, Any] = field(default_factory=dict)


def antispam_facts(findings: AntispamFindings | None) -> list[tuple[str, Any, dict[str, Any]]]:
    out: list[tuple[str, Any, dict[str, Any]]] = []
    if findings is None:
        return out
    if findings.scan_present:
        out.append(("rspamd_scan_present", True, {"mapping_version": findings.mapping_version}))
    for signal in findings.risk_signals:
        fact = SIGNAL_FACTS.get(signal)
        if fact is not None:
            out.append((fact, True, {"signal": signal, "mapping_version": findings.mapping_version}))
    if findings.auth_conflict:
        out.append(("rspamd_auth_conflict", True, {"mapping_version": findings.mapping_version}))
    if findings.source_confirmed_hostile:
        out.append(("rspamd_source_confirmed_hostile", True, {}))
    return out
