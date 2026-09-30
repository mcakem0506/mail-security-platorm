"""Parsing of the ``Received`` chain (ТЗ 1.0.1 §4.3).

The chain is the only evidence a message carries about the path it actually took. It is also
partly attacker-controlled: everything below the first hop the organisation operates was written
by machines outside it and may be entirely invented. The parser therefore reports what each hop
*claims*, and :mod:`msp_mail_gateway.trust` decides which claims are believable.

No DNS lookups happen here. A reverse lookup at analysis time describes the world now, not at
delivery time, and would make the same message produce different verdicts on re-analysis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from itertools import pairwise

from msp_mail_parser.parser import parse_mail_date

# "from <helo> (<rdns> [<ip>]) by <host> with <protocol> id <id>; <date>"
# Every clause is optional in practice, so each is matched independently rather than as one
# pattern: a single strict regex fails on the first unusual MTA and loses the whole chain.
_FROM_RE = re.compile(r"(?i)\bfrom\s+([^\s;()]+)")
_BY_RE = re.compile(r"(?i)\bby\s+([^\s;()]+)")
_WITH_RE = re.compile(r"(?i)\bwith\s+([A-Z0-9/._-]+)")
_ID_RE = re.compile(r"(?i)\bid\s+([^\s;()]+)")
_FOR_RE = re.compile(r"(?i)\bfor\s+<?([^\s;<>()]+@[^\s;<>()]+)>?")
_IPV4_RE = re.compile(r"\[?\b((?:\d{1,3}\.){3}\d{1,3})\b\]?")
_IPV6_RE = re.compile(r"\[?\b(?:IPv6:)?((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})\b\]?")
# The parenthesised part usually holds "(rdns [ip])" or "(unknown [ip])".
_PAREN_RE = re.compile(r"\(([^)]*)\)")
_TLS_RE = re.compile(r"(?i)\b(TLS[\w.]*|ESMTPS|ESMTPSA|SMTPS)\b")


@dataclass
class ReceivedHop:
    """One ``Received`` header, decomposed.

    ``index`` counts from the delivery end: hop 0 is the topmost header, written by the last
    machine to handle the message (normally the mailbox server), and the index grows towards
    the Internet. This matches how an organisation describes its own topology inwards.
    """

    index: int
    raw: str
    helo: str = ""
    rdns: str = ""
    by_host: str = ""
    ip: IPv4Address | IPv6Address | None = None
    protocol: str = ""
    queue_id: str = ""
    recipient: str = ""
    timestamp: datetime | None = None
    encrypted: bool = False
    unresolved: bool = False

    @property
    def ip_text(self) -> str:
        return str(self.ip) if self.ip is not None else ""

    @property
    def is_private_ip(self) -> bool:
        return self.ip is not None and (self.ip.is_private or self.ip.is_loopback)


def _first(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(1).strip().strip("<>").lower() if match else ""


def _extract_ip(text: str) -> IPv4Address | IPv6Address | None:
    """Prefer an address inside parentheses: that is the one the receiving MTA observed.

    An address in the ``from`` clause is whatever the sending host announced, so it is only
    used when the receiver recorded nothing better.
    """
    candidates: list[str] = []
    for paren in _PAREN_RE.findall(text):
        candidates.extend(_IPV4_RE.findall(paren))
        candidates.extend(_IPV6_RE.findall(paren))
    if not candidates:
        candidates.extend(_IPV4_RE.findall(text))
        candidates.extend(_IPV6_RE.findall(text))
    for raw in candidates:
        try:
            return ip_address(raw)
        except ValueError:
            continue
    return None


def _extract_rdns(text: str) -> tuple[str, bool]:
    """Reverse-DNS name the receiving MTA recorded, plus whether it failed to resolve."""
    for paren in _PAREN_RE.findall(text):
        stripped = paren.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        if lowered.startswith(("unknown", "helo=")) or "unknown" in lowered.split()[0:1]:
            return "", True
        token = stripped.split()[0].strip("[]").lower()
        if token and not token[0].isdigit() and "=" not in token:
            return token, False
    return "", False


def parse_received(headers: list[str]) -> list[ReceivedHop]:
    """Decompose the ``Received`` chain, newest first."""
    hops: list[ReceivedHop] = []
    for index, raw in enumerate(headers[:100]):
        text = raw.strip()
        body, _, date_part = text.rpartition(";")
        rdns, unresolved = _extract_rdns(text)
        hops.append(
            ReceivedHop(
                index=index,
                raw=text[:1000],
                helo=_first(_FROM_RE, body or text),
                rdns=rdns,
                by_host=_first(_BY_RE, body or text),
                ip=_extract_ip(body or text),
                protocol=_first(_WITH_RE, body or text),
                queue_id=_first(_ID_RE, body or text),
                recipient=_first(_FOR_RE, body or text),
                timestamp=parse_mail_date(date_part.strip()) if date_part.strip() else None,
                encrypted=bool(_TLS_RE.search(body or text)),
                unresolved=unresolved,
            )
        )
    return hops


def last_external_hop(hops: list[ReceivedHop], internal_networks: list[str]) -> ReceivedHop | None:
    """The hop where the message entered the organisation.

    Walking from the delivery end outwards, this is the first hop whose source address is not on
    an internal network. Everything beyond it is attacker-controlled. When no internal networks
    are configured the outermost hop is returned, which is the safe assumption.
    """
    from ipaddress import ip_network

    networks = []
    for raw in internal_networks:
        try:
            networks.append(ip_network(raw.strip(), strict=False))
        except ValueError:
            continue
    if not networks:
        return hops[-1] if hops else None
    for hop in hops:
        if hop.ip is None:
            continue
        if not any(hop.ip in network for network in networks):
            return hop
    return hops[-1] if hops else None


@dataclass
class ChainSummary:
    """Facts about the chain itself, independent of any gateway."""

    hop_count: int = 0
    originating_ip: str = ""
    originating_host: str = ""
    unresolved_hops: int = 0
    unencrypted_hops: int = 0
    time_gaps_seconds: list[float] = field(default_factory=list)
    out_of_order: bool = False

    @property
    def max_gap_seconds(self) -> float:
        return max(self.time_gaps_seconds) if self.time_gaps_seconds else 0.0


def summarise(hops: list[ReceivedHop]) -> ChainSummary:
    summary = ChainSummary(hop_count=len(hops))
    if not hops:
        return summary
    outermost = hops[-1]
    summary.originating_ip = outermost.ip_text
    summary.originating_host = outermost.rdns or outermost.helo
    summary.unresolved_hops = sum(1 for hop in hops if hop.unresolved)
    summary.unencrypted_hops = sum(1 for hop in hops if not hop.encrypted)
    stamped = [hop for hop in hops if hop.timestamp is not None]
    for newer, older in pairwise(stamped):
        assert newer.timestamp is not None and older.timestamp is not None  # narrowed by filter
        delta = (newer.timestamp - older.timestamp).total_seconds()
        if delta < 0:
            # A hop claiming to be older than the one before it: forged or badly-set clocks.
            summary.out_of_order = True
        summary.time_gaps_seconds.append(abs(delta))
    return summary
