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
    peername_lookup: bool = True,
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
    known_rdns = bool(rdns) and rdns.lower() != "unknown"
    scanner_saw_ptr = scan is not None and bool(names) and not names & {"RDNS_NONE", "RDNS_DNSFAIL"}
    if "RDNS_DNSFAIL" in names:
        state = PtrState.TEMPERROR
    elif known_rdns:
        # Postfix записал обратное имя только потому, что прямая проверка подтвердила тот же адрес.
        state = PtrState.FCRDNS_PASS
    elif "RDNS_NONE" in names:
        state = PtrState.NONE
    elif scanner_saw_ptr and peername_lookup:
        # PTR есть (сканер его нашёл), а Postfix при включённом поиске имени написал «unknown»:
        # значит, прямая проверка не подтвердила адрес.
        state = PtrState.FCRDNS_FAIL
    elif scanner_saw_ptr:
        # Поиск имени в Postfix выключен: подтверждённость прямой записью неизвестна.
        state = PtrState.PTR_PRESENT
    else:
        state = PtrState.NONE
    return HeloEvidence(
        helo=helo[:255],
        signals=signals,
        ptr_state=state,
        ptr_name="" if not rdns or rdns.lower() == "unknown" else rdns[:255],
    )
