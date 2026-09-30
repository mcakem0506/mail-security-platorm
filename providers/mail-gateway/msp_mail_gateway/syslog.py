"""Syslog gateway provider (ТЗ 1.0.2 §20).

Many gateways will not expose an API but will happily stream their mail log. Syslog is therefore
a first-class ingestion path — and a dangerous one, because plain syslog has no authentication at
all: anything that can reach the port can claim to be the gateway.

The safeguards are structural, in :class:`SyslogIngestor`, so they apply whichever transport
delivered the datagram:

* **source allowlist** — an event from an address that is not a registered gateway node is
  rejected outright, never merely flagged;
* **replay protection** — an event whose timestamp is outside the acceptance window is rejected,
  so a captured log line cannot be re-sent later to re-open a closed verdict;
* **deduplication** — the same event delivered twice (UDP retransmission, two collectors) yields
  one piece of evidence, not two;
* **dead-letter** — a line that cannot be parsed is kept with its reason instead of being dropped
  silently, because a format the platform does not know is an integration gap, not a non-event.

Transport preference is TCP or TLS. UDP is supported because some appliances offer nothing else,
and a UDP source is recorded as such so an analyst can see the evidence is unauthenticated.
"""

from __future__ import annotations

import contextlib
import logging
import re
import socket
import ssl
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network

from msp_contracts import (
    GatewayCapability,
    GatewayCategory,
    GatewayEvidence,
    GatewayEvidenceSource,
    GatewayMessageRef,
    GatewayVerdictType,
    ProviderHealth,
    TrustState,
    utcnow,
)
from msp_mail_parser.parser import parse_mail_date

from .base import BaseGatewayProvider, GatewayContext, GatewayProviderConfig
from .headers import classify_value, extract_score

logger = logging.getLogger(__name__)

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP PROCID MSGID [SD] MSG
_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$",
    re.DOTALL,
)
# RFC 3164: <PRI>MMM dd hh:mm:ss HOSTNAME TAG: MSG
_RFC3164_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<tag>[^:]{1,64}):\s*(?P<rest>.*)$",
    re.DOTALL,
)
_KV_RE = re.compile(r"""(?P<key>[A-Za-z0-9_.-]+)\s*=\s*(?P<value>"[^"]*"|'[^']*'|[^\s,;]+)""")
_MESSAGE_ID_RE = re.compile(r"(?i)\bmessage[-_ ]?id\s*[=:]\s*<?([^\s<>,;]+@[^\s<>,;]+)>?")
_QUEUE_ID_RE = re.compile(r"(?i)\b(?:queue[-_ ]?id|qid)\s*[=:]\s*([A-Za-z0-9._-]{3,64})")


class SyslogRejected(ValueError):
    """An event that must not become evidence, with the reason recorded for the dead letter."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass
class SyslogEvent:
    """A parsed syslog line, before any trust decision."""

    raw: str
    source_ip: str
    transport: str = "tcp"
    facility: int = 0
    severity: int = 6
    timestamp: datetime | None = None
    hostname: str = ""
    app: str = ""
    msgid: str = ""
    message: str = ""
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def internet_message_id(self) -> str:
        return self.fields.get("message_id", "")

    @property
    def queue_id(self) -> str:
        return self.fields.get("queue_id", "")

    def dedup_key(self) -> str:
        """Identity of the event, so a retransmission does not become a second observation."""
        return "|".join(
            (
                self.source_ip,
                self.hostname,
                self.app,
                self.msgid,
                self.queue_id,
                self.internet_message_id,
                self.timestamp.isoformat() if self.timestamp else "",
                self.message[:200],
            )
        )


@dataclass
class DeadLetter:
    raw: str
    source_ip: str
    reason: str
    detail: str = ""
    received_at: datetime = field(default_factory=utcnow)


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def parse_syslog(line: str, source_ip: str, transport: str = "tcp") -> SyslogEvent:
    """Parse one syslog line in either RFC 5424 or RFC 3164 framing."""
    text = line.strip()
    if not text:
        raise SyslogRejected("empty_line")
    if len(text) > 32 * 1024:
        # An oversized event is a resource problem, not a message: refuse it before parsing.
        raise SyslogRejected("oversized_event", f"{len(text)} bytes")

    event = SyslogEvent(raw=text[:8000], source_ip=source_ip, transport=transport)
    match = _RFC5424_RE.match(text)
    if match is not None:
        pri = int(match.group("pri"))
        event.facility, event.severity = pri // 8, pri % 8
        event.timestamp = parse_mail_date(match.group("ts")) or _parse_iso(match.group("ts"))
        event.hostname = match.group("host")[:255]
        event.app = match.group("app")[:64]
        event.msgid = match.group("msgid")[:128]
        event.message = match.group("rest")[:8000]
    else:
        match = _RFC3164_RE.match(text)
        if match is None:
            raise SyslogRejected("unparseable_format", text[:120])
        pri = int(match.group("pri"))
        event.facility, event.severity = pri // 8, pri % 8
        event.timestamp = _parse_bsd_timestamp(match.group("ts"))
        event.hostname = match.group("host")[:255]
        event.app = match.group("tag")[:64]
        event.message = match.group("rest")[:8000]

    for kv in _KV_RE.finditer(event.message):
        key = kv.group("key").strip().lower().replace("-", "_")
        event.fields.setdefault(key, _unquote(kv.group("value"))[:500])
    mid = _MESSAGE_ID_RE.search(event.message)
    if mid:
        event.fields["message_id"] = mid.group(1)[:500]
    qid = _QUEUE_ID_RE.search(event.message)
    if qid:
        event.fields["queue_id"] = qid.group(1)[:64]
    return event


def _parse_iso(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_bsd_timestamp(value: str) -> datetime | None:
    """RFC 3164 timestamps carry no year; assume the current one and step back at a boundary."""
    now = utcnow()
    for year in (now.year, now.year - 1):
        try:
            parsed = datetime.strptime(f"{value} {year}", "%b %d %H:%M:%S %Y")
        except ValueError:
            continue
        stamped = parsed.replace(tzinfo=now.tzinfo)
        if stamped <= now + timedelta(days=1):
            return stamped
    return None


@dataclass
class SyslogIngestorConfig:
    provider_id: str
    #: Networks or addresses permitted to send events. Empty means nothing is accepted.
    allowed_sources: tuple[str, ...] = ()
    #: How far in the past an event may be stamped before it is treated as a replay.
    max_age_seconds: int = 900
    #: How far in the future a clock may legitimately run.
    max_skew_seconds: int = 300
    dedup_window: int = 20_000
    max_dead_letters: int = 500
    require_authenticated_transport: bool = False


class SyslogIngestor:
    """Transport-independent core: allowlist, replay protection, dedup, dead-letter."""

    def __init__(self, config: SyslogIngestorConfig) -> None:
        self.config = config
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._dead_letters: list[DeadLetter] = []
        self._lock = threading.Lock()
        self.accepted = 0
        self.rejected = 0
        self.duplicates = 0
        self.last_event_at: datetime | None = None

    # -- checks --------------------------------------------------------------------------------
    def source_allowed(self, source_ip: str) -> bool:
        if not self.config.allowed_sources:
            return False
        try:
            address = ip_address(source_ip)
        except ValueError:
            return False
        for entry in self.config.allowed_sources:
            try:
                if address in ip_network(entry.strip(), strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _check_replay(self, event: SyslogEvent) -> None:
        if event.timestamp is None:
            # Without a timestamp a replay cannot be distinguished from a fresh event.
            raise SyslogRejected("missing_timestamp")
        now = utcnow()
        age = (now - event.timestamp).total_seconds()
        if age > self.config.max_age_seconds:
            raise SyslogRejected("replay_too_old", f"{int(age)}s")
        if age < -self.config.max_skew_seconds:
            raise SyslogRejected("timestamp_in_future", f"{int(-age)}s")

    def _check_duplicate(self, event: SyslogEvent) -> None:
        key = event.dedup_key()
        with self._lock:
            if key in self._seen:
                self.duplicates += 1
                raise SyslogRejected("duplicate_event")
            self._seen[key] = now = utcnow().timestamp()
            while len(self._seen) > self.config.dedup_window:
                self._seen.popitem(last=False)
            del now

    # -- ingestion -----------------------------------------------------------------------------
    def ingest(self, line: str, source_ip: str, transport: str = "tcp") -> SyslogEvent:
        """Accept one line, or raise :class:`SyslogRejected` and record a dead letter."""
        try:
            if not self.source_allowed(source_ip):
                raise SyslogRejected("source_not_allowed", source_ip)
            if self.config.require_authenticated_transport and transport not in {"tls", "tcp"}:
                raise SyslogRejected("unauthenticated_transport", transport)
            event = parse_syslog(line, source_ip, transport)
            self._check_replay(event)
            self._check_duplicate(event)
        except SyslogRejected as rejection:
            self.rejected += 1
            self._record_dead_letter(line, source_ip, rejection)
            raise
        self.accepted += 1
        self.last_event_at = utcnow()
        return event

    def _record_dead_letter(self, line: str, source_ip: str, rejection: SyslogRejected) -> None:
        # A duplicate is expected traffic, not an integration gap: it is counted, not stored.
        if rejection.reason == "duplicate_event":
            return
        with self._lock:
            self._dead_letters.append(
                DeadLetter(
                    raw=line[:2000],
                    source_ip=source_ip,
                    reason=rejection.reason,
                    detail=rejection.detail,
                )
            )
            if len(self._dead_letters) > self.config.max_dead_letters:
                del self._dead_letters[: len(self._dead_letters) - self.config.max_dead_letters]

    @property
    def dead_letters(self) -> list[DeadLetter]:
        with self._lock:
            return list(self._dead_letters)


#: Vendor-neutral keys that commonly carry a verdict in a mail log line.
_VERDICT_FIELDS = ("verdict", "action", "result", "disposition", "status", "scan_result")
_THREAT_FIELDS = ("threat", "virus", "malware", "signature", "threat_name", "rule")
_SCORE_FIELDS = ("score", "spam_score", "rate", "rating")


def event_to_evidence(event: SyslogEvent, provider_id: str, provider_type: str) -> GatewayEvidence:
    """Normalise an accepted syslog event into gateway evidence.

    The event reached here only after passing the allowlist, so it is trusted: unlike a header,
    it did not travel inside the message an attacker controls.
    """
    verdict_text = ""
    for key in _VERDICT_FIELDS:
        if event.fields.get(key):
            verdict_text = event.fields[key]
            break
    verdict = classify_value(verdict_text) or classify_value(event.message) or GatewayVerdictType.UNKNOWN
    threat = next((event.fields[key] for key in _THREAT_FIELDS if event.fields.get(key)), "")
    score = extract_score(*[event.fields.get(key, "") for key in _SCORE_FIELDS], event.message)
    category = GatewayCategory.UNKNOWN
    lowered = event.message.lower()
    if "phish" in lowered:
        category = GatewayCategory.ANTIPHISHING
    elif "spam" in lowered:
        category = GatewayCategory.ANTISPAM
    elif "virus" in lowered or "malware" in lowered:
        category = GatewayCategory.ANTIVIRUS
    return GatewayEvidence(
        provider_id=provider_id,
        provider_type=provider_type,
        message_id=event.internet_message_id,
        timestamp=event.timestamp or utcnow(),
        verdict=verdict,
        category=category,
        confidence=0.75,
        score=score,
        threat_name=threat[:120],
        engine=event.app,
        source=GatewayEvidenceSource.SYSLOG,
        trusted=True,
        trust_state=TrustState.TRUSTED,
        trust_reason=f"событие получено от разрешённого источника {event.source_ip} ({event.transport})",
        raw_reference=event.msgid or event.queue_id or event.dedup_key()[:64],
        normalized_detail={
            "queue_id": event.queue_id,
            "hostname": event.hostname,
            "transport": event.transport,
            "severity": event.severity,
        },
    )


class SyslogGatewayProvider(BaseGatewayProvider):
    """Provider fed by a syslog stream rather than by message headers."""

    provider_type = "syslog"

    def __init__(self, config: GatewayProviderConfig, ingestor: SyslogIngestor | None = None) -> None:
        super().__init__(config)
        settings = config.settings
        self.ingestor = ingestor or SyslogIngestor(
            SyslogIngestorConfig(
                provider_id=config.provider_id,
                allowed_sources=tuple(str(s) for s in (settings.get("allowed_sources") or [])),
                max_age_seconds=int(settings.get("max_age_seconds", 900)),
                require_authenticated_transport=bool(settings.get("require_authenticated_transport", False)),
            )
        )
        self._events: OrderedDict[str, list[GatewayEvidence]] = OrderedDict()
        self._max_correlated = int(settings.get("max_correlated_messages", 10_000))

    def capabilities(self) -> set[GatewayCapability]:
        return {GatewayCapability.SYSLOG_EVENTS, GatewayCapability.MESSAGE_TRACE}

    def health(self) -> ProviderHealth:
        if not self.config.enabled:
            return ProviderHealth(provider_id=self.provider_id, status="disabled")
        if not self.ingestor.config.allowed_sources:
            return ProviderHealth(
                provider_id=self.provider_id,
                status="degraded",
                mode=self.provider_type,
                detail="не задан список разрешённых источников: события не принимаются",
            )
        detail = f"принято {self.ingestor.accepted}, отклонено {self.ingestor.rejected}"
        status = "ok" if self.ingestor.accepted or not self.ingestor.rejected else "degraded"
        return ProviderHealth(
            provider_id=self.provider_id, status=status, mode=self.provider_type, detail=detail
        )

    def ingest_line(self, line: str, source_ip: str, transport: str = "tcp") -> GatewayEvidence:
        event = self.ingestor.ingest(line, source_ip, transport)
        evidence = event_to_evidence(event, self.provider_id, self.provider_type)
        key = (event.internet_message_id or event.queue_id or "").strip().strip("<>").lower()
        if key:
            bucket = self._events.setdefault(key, [])
            bucket.append(evidence)
            self._events.move_to_end(key)
            while len(self._events) > self._max_correlated:
                self._events.popitem(last=False)
        return evidence

    def get_verdict(self, ref: GatewayMessageRef) -> GatewayEvidence | None:
        """Correlate by Message-ID first, then by queue id (ТЗ 1.0.2 §23)."""
        for candidate in (ref.internet_message_id, ref.queue_id, ref.gateway_message_id):
            key = (candidate or "").strip().strip("<>").lower()
            if not key:
                continue
            events = self._events.get(key)
            if events:
                negative = [e for e in events if e.verdict.is_negative]
                return negative[0] if negative else events[-1]
        return None

    def parse_message_headers(
        self, headers: list[tuple[str, str]], context: GatewayContext
    ) -> list[GatewayEvidence]:
        """A syslog provider correlates by identifier, not by reading the message's own headers."""
        if not context.internet_message_id:
            return []
        evidence = self.get_verdict(
            GatewayMessageRef(provider_id=self.provider_id, internet_message_id=context.internet_message_id)
        )
        return [evidence] if evidence is not None else []


class SyslogListener:
    """Minimal TCP/TLS/UDP receiver.

    Kept deliberately small: it reads lines and hands them to the ingestor, which owns every
    security decision. That way the checks are exercised by tests without opening a socket.
    """

    def __init__(
        self,
        provider: SyslogGatewayProvider,
        *,
        host: str = "127.0.0.1",
        port: int = 6514,
        transport: str = "tcp",
        tls_certfile: str | None = None,
        tls_keyfile: str | None = None,
        tls_client_ca: str | None = None,
    ) -> None:
        self.provider = provider
        self.host = host
        self.port = port
        self.transport = transport
        self.tls_certfile = tls_certfile
        self.tls_keyfile = tls_keyfile
        self.tls_client_ca = tls_client_ca
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def _tls_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        if self.tls_certfile:
            context.load_cert_chain(self.tls_certfile, self.tls_keyfile)
        if self.tls_client_ca:
            # Where the appliance supports it, client certificates give the source an identity
            # that an IP allowlist alone cannot (ТЗ 1.0.2 §20).
            context.load_verify_locations(self.tls_client_ca)
            context.verify_mode = ssl.CERT_REQUIRED
        return context

    def start(self) -> None:
        if self.transport == "udp":
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.bind((self.host, self.port))
        else:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            raw.bind((self.host, self.port))
            raw.listen(16)
            self._socket = (
                self._tls_context().wrap_socket(raw, server_side=True) if (self.transport == "tls") else raw
            )
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="syslog-listener", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._socket is not None:
            with contextlib.suppress(OSError):
                self._socket.close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _serve(self) -> None:
        assert self._socket is not None
        while not self._stop.is_set():
            try:
                if self.transport == "udp":
                    data, address = self._socket.recvfrom(65535)
                    self._handle(data.decode("utf-8", "replace"), address[0], "udp")
                else:
                    connection, address = self._socket.accept()
                    with connection:
                        connection.settimeout(30)
                        buffer = b""
                        while not self._stop.is_set():
                            chunk = connection.recv(65535)
                            if not chunk:
                                break
                            buffer += chunk
                            while b"\n" in buffer:
                                line, buffer = buffer.split(b"\n", 1)
                                self._handle(line.decode("utf-8", "replace"), address[0], self.transport)
            except OSError:
                if self._stop.is_set():
                    return
                continue

    def _handle(self, line: str, source_ip: str, transport: str) -> None:
        try:
            self.provider.ingest_line(line, source_ip, transport)
        except SyslogRejected as rejection:
            logger.info("syslog.rejected", extra={"reason": rejection.reason, "source": source_ip})


def build(config: GatewayProviderConfig) -> SyslogGatewayProvider:
    return SyslogGatewayProvider(config)
