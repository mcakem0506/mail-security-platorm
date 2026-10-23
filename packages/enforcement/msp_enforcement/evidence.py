"""Свидетельства для движка решений из записи сканера (ТЗ 1.3 §13, §57).

Узел принимает запись самого Rspamd (с того же хоста, по закрытому каналу), разбирает её кодом этапа 1.2 и
строит ``EnforcementInput``. Заголовки письма не считаются доверенными: из них берётся только то, что и так
описывает само письмо (получатели, тема), но не оценки и не результаты проверок.
"""

from __future__ import annotations

import re
import time
from collections.abc import Mapping
from typing import Any

from msp_antispam.analysis import analyze
from msp_antispam.policy import SpamPolicy

from .engine import EnforcementInput, MalwareEvidence

_RBL = re.compile(r"^MSP_RBL_([A-Z0-9_]+?)_(CLIENT_IP|SENDER_DOMAIN|URL|HELO)$")


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)] if value else []


def input_from_record(
    record: Mapping[str, Any],
    *,
    direction: str = "INBOUND",
    elapsed_ms: float = 0.0,
    previous_attempt: str = "",
    risk_verdict: str = "UNKNOWN",
    malware: MalwareEvidence | None = None,
) -> EnforcementInput:
    """Запись сканера → свидетельства принуждения. ``trusted_evidence`` истинно только для записи с шлюза."""
    rcpt = _as_list(record.get("rcpt"))
    analysis = analyze(
        dict(record),
        SpamPolicy(),
        headers={"from": _as_list(record.get("header_from"))},
        recipient_count=len(rcpt),
    )
    evidence = analysis.evidence
    qid = str(record.get("qid") or "")
    message_id = str(record.get("message_id") or "").strip("<>")
    reason_codes = tuple(analysis.signals.codes(risk_only=True)) if analysis.signals else ()
    listed: list[str] = []
    for symbol in evidence.symbols if evidence else ():
        match = _RBL.match(symbol.name)
        if match:
            listed.append(match.group(1).lower())
    auth = analysis.auth
    dmarc = auth.dmarc if auth else None
    # Пересылка и списки: признаки рассылки/списка и ARC-цепочка, прошедшая проверку, смягчают DMARC (ТЗ §26).
    bulk = analysis.bulk
    forwarding = bool(bulk.list_headers)
    arc_pass = bool(auth and auth.arc.result.value == "PASS")
    return EnforcementInput(
        transport_message_id=qid,
        message_id=message_id,
        sender=str(record.get("from") or ""),
        recipients=tuple(rcpt),
        source_ip=str(record.get("ip") or ""),
        direction=direction,
        trusted_evidence=True,
        spam_score=evidence.score if evidence else 0.0,
        spam_class=analysis.spam_class.value,
        suggested_action=analysis.suggested_action.value,
        reason_codes=reason_codes,
        evidence_ids=(f"rspamd-qid:{qid}",) if qid else (),
        rbl_listed=tuple(sorted(set(listed))),
        dmarc_result=dmarc.result.value if dmarc else "NONE",
        dmarc_policy=dmarc.policy.value.upper() if dmarc and dmarc.policy else "NONE",
        forwarding_or_list=forwarding,
        arc_pass=arc_pass,
        risk_verdict=risk_verdict,
        malware=malware or MalwareEvidence(),
        elapsed_ms=elapsed_ms,
        previous_attempt=previous_attempt,
    )


class Stopwatch:
    def __init__(self) -> None:
        self._start = time.monotonic()

    def ms(self) -> float:
        return (time.monotonic() - self._start) * 1000.0
