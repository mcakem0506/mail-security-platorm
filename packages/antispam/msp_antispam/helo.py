"""Сигналы HELO/EHLO и состояние PTR/FCrDNS (ТЗ 1.2 §16).

Это свидетельства о репутации отправляющего сервера, а не жёсткий вердикт: добросовестный сервер
малого предприятия без PTR встречается постоянно, а правильная пара HELO/PTR ничего не доказывает.

Источник имени клиента — заголовок ``Received``, который добавил сам шлюз (верхний): Postfix
записывает туда обратное имя только если прямая проверка подтвердила тот же адрес, то есть если
FCrDNS прошёл. Остальные ``Received`` пришли извне и не используются.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from .auth import aligned
from .model import HeloEvidence, HeloSignal, PtrState, RspamdEvidence

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$"
)
_RECEIVED_FROM = re.compile(
    r"^from\s+(?P<helo>\S+)\s+\((?P<rdns>\S+)\s+\[(?P<ip>[0-9a-fA-F:.]+)\]\)", re.IGNORECASE
)

INTERNAL_ONLY_SUFFIXES = (".local", ".lan", ".internal", ".corp", ".localdomain", ".intranet", ".home")


def top_received(headers: Iterable[str]) -> tuple[str, str, str] | None:
    """(helo, rdns, ip) из верхнего ``Received``, добавленного шлюзом."""
    for raw in headers:
        text = " ".join(str(raw).split())
        match = _RECEIVED_FROM.match(text)
        if match:
            return match.group("helo"), match.group("rdns"), match.group("ip")
        return None
    return None


def _is_ip_literal(helo: str) -> bool:
    candidate = helo.strip("[]")
    if candidate.lower().startswith("ipv6:"):
        candidate = candidate[5:]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def helo_evidence(
    helo: str,
    *,
    rdns: str = "",
    scan: RspamdEvidence | None = None,
    protected_domains: Iterable[str] = (),
    client_is_trusted: bool = False,
) -> HeloEvidence:
    helo = (helo or "").strip()
    signals: list[HeloSignal] = []
    if not helo:
        signals.append(HeloSignal.MISSING)
    elif _is_ip_literal(helo):
        signals.append(HeloSignal.IP_LITERAL)
    elif not _HOSTNAME.match(helo):
        signals.append(HeloSignal.INVALID_SYNTAX)
    else:
        lowered = helo.lower()
        known_rdns = rdns and rdns.lower() != "unknown"
        if known_rdns and not aligned(lowered, rdns.lower()):
            signals.append(HeloSignal.MISMATCH)
        if not client_is_trusted:
            for domain in protected_domains:
                domain = domain.lower().strip(".")
                if domain and (lowered == domain or lowered.endswith("." + domain)):
                    signals.append(HeloSignal.PROTECTED_DOMAIN)
                    break
            if lowered.endswith(INTERNAL_ONLY_SUFFIXES) or "." not in lowered:
                signals.append(HeloSignal.INTERNAL_ONLY_FROM_EXTERNAL)

    names = {s.name for s in scan.symbols} if scan else set()
    if "RDNS_DNSFAIL" in names:
        state = PtrState.TEMPERROR
    elif "HFILTER_HOSTNAME_UNKNOWN" in names and rdns and rdns.lower() != "unknown":
        state = PtrState.FCRDNS_FAIL
    elif rdns and rdns.lower() != "unknown":
        # Postfix записал имя: прямая проверка совпала.
        state = PtrState.FCRDNS_PASS
    elif "RDNS_NONE" in names or not rdns or rdns.lower() == "unknown":
        state = PtrState.NONE
    else:
        state = PtrState.PTR_PRESENT
    return HeloEvidence(
        helo=helo[:255],
        signals=signals,
        ptr_state=state,
        ptr_name="" if not rdns or rdns.lower() == "unknown" else rdns[:255],
    )
