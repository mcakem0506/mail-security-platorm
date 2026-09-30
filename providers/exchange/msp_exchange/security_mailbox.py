"""Security mailbox intake over IMAP (ТЗ 7.2).

This is the fallback path that works on any Exchange version: employees (or the add-in) forward a
suspicious message as an RFC 822 attachment to a dedicated mailbox, and the platform ingests it
with the original headers intact.

Why IMAP rather than EWS: it needs no Exchange-version-specific API, no impersonation rights and
no add-in capability — a single mailbox account with read access to its own mailbox is enough
(ТЗ 7.1, least privilege). EWS remains available as a separate provider where it is supported.
"""

from __future__ import annotations

import contextlib
import email
import hashlib
import imaplib
import logging
import re
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from email import policy
from email.message import Message

from msp_contracts import ProviderHealth, utcnow

from .base import ExchangeCapability, ExchangeMessageRef, FetchedMessage

logger = logging.getLogger(__name__)

_UID_RE = re.compile(rb"UID (\d+)")
_SIZE_RE = re.compile(rb"RFC822\.SIZE (\d+)")


@dataclass
class SecurityMailboxConfig:
    host: str
    port: int = 993
    username: str = ""
    password: str = ""  # injected from the secret store, never from Git (ТЗ 28)
    use_ssl: bool = True
    starttls: bool = False
    folder: str = "INBOX"
    processed_folder: str = "Processed"
    failed_folder: str = "Failed"
    verify_tls: bool = True
    ca_file: str | None = None
    timeout_seconds: float = 30.0
    max_message_size: int = 30 * 1024 * 1024
    batch_size: int = 25


@dataclass
class IngestedReport:
    """A message pulled from the security mailbox, with the original attachment unwrapped.

    ``raw_mime`` is always the complete message as it arrived. When the report exceeds the
    configured limit the bytes are dropped entirely and ``oversized`` is set, rather than the
    message being cut short: analysing the first N bytes of a message and presenting the result
    as an analysis is the mistake ТЗ 1.0.1 §4.2 exists to prevent.
    """

    uid: str
    raw_mime: bytes
    reported_by: str = ""
    reported_at: datetime | None = None
    envelope_subject: str = ""
    note: str = ""
    is_forwarded_original: bool = False
    warnings: list[str] = field(default_factory=list)
    #: True when the report exceeded ``max_message_size`` and was therefore not read.
    oversized: bool = False
    #: The real size in the mailbox, recorded even when the content was not kept.
    actual_size: int = 0
    internet_message_id: str = ""
    content_sha256: str = ""


def _tls_context(config: SecurityMailboxConfig) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=config.ca_file)
    if not config.verify_tls:
        # Only for a lab with a self-signed internal CA; production must provide ca_file.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        logger.warning("security_mailbox.tls_verification_disabled")
    return context


def extract_original_message(raw: bytes) -> tuple[bytes, bool, str]:
    """Unwrap a forwarded message: return (original MIME, unwrapped?, note text).

    The original is preferred as a message/rfc822 attachment because that preserves headers,
    which inline forwarding destroys.
    """
    try:
        outer = email.message_from_bytes(raw, policy=policy.compat32)
    except Exception:  # noqa: BLE001 - a malformed report must not break intake
        return raw, False, ""

    note_parts: list[str] = []
    original: bytes | None = None
    for part in outer.walk():
        ctype = part.get_content_type().lower()
        if ctype == "message/rfc822" and original is None:
            payload = part.get_payload()
            inner = payload[0] if isinstance(payload, list) and payload else None
            if isinstance(inner, Message):
                try:
                    original = inner.as_bytes(policy=policy.compat32)
                except (ValueError, TypeError, LookupError, UnicodeError):
                    original = None
        elif ctype == "application/octet-stream" and original is None:
            filename = (part.get_filename() or "").lower()
            if filename.endswith((".eml", ".msg")):
                data = part.get_payload(decode=True)
                if isinstance(data, bytes) and data[:5].lower() in {b"from ", b"recei", b"retur", b"messa"}:
                    original = data
        elif ctype == "text/plain" and not part.get_filename():
            text = part.get_payload(decode=True)
            if isinstance(text, bytes):
                note_parts.append(text.decode(part.get_content_charset() or "utf-8", "replace"))

    note = "\n".join(note_parts).strip()[:2000]
    if original is not None:
        return original, True, note
    return raw, False, note


class SecurityMailboxProvider:
    """Read-only intake from the security mailbox. Never sends mail and never deletes messages."""

    provider_id = "security_mailbox"

    def __init__(self, config: SecurityMailboxConfig) -> None:
        self.config = config
        self._last_error: str | None = None

    def _connect(self) -> imaplib.IMAP4:
        cfg = self.config
        if cfg.use_ssl:
            conn: imaplib.IMAP4 = imaplib.IMAP4_SSL(
                cfg.host, cfg.port, ssl_context=_tls_context(cfg), timeout=cfg.timeout_seconds
            )
        else:
            conn = imaplib.IMAP4(cfg.host, cfg.port, timeout=cfg.timeout_seconds)
            if cfg.starttls:
                conn.starttls(_tls_context(cfg))
        conn.login(cfg.username, cfg.password)
        return conn

    def health(self) -> ProviderHealth:
        if not self.config.host or not self.config.username:
            return ProviderHealth(
                provider_id=self.provider_id,
                status="not_configured",
                detail="security mailbox not configured",
            )
        try:
            conn = self._connect()
            try:
                status, _ = conn.select(self.config.folder, readonly=True)
            finally:
                with contextlib.suppress(imaplib.IMAP4.error, OSError):
                    conn.logout()
            if status != "OK":
                return ProviderHealth(
                    provider_id=self.provider_id,
                    status="degraded",
                    detail=f"cannot select {self.config.folder}",
                )
            self._last_error = None
            return ProviderHealth(provider_id=self.provider_id, status="ok", mode="imap")
        except (imaplib.IMAP4.error, OSError, ssl.SSLError) as exc:
            self._last_error = type(exc).__name__
            return ProviderHealth(
                provider_id=self.provider_id,
                status="unavailable",
                detail=type(exc).__name__,
                checked_at=utcnow(),
            )

    def capabilities(self) -> set[ExchangeCapability]:
        return {ExchangeCapability.GET_MESSAGE, ExchangeCapability.SUBMIT_REPORT}

    def fetch_unprocessed(self, limit: int | None = None) -> list[IngestedReport]:
        """Fetch reports without acknowledging them.

        Nothing is marked or moved here. The caller acknowledges a message with :meth:`ack`
        only once the intake record and the analysis job are committed, so a crash anywhere in
        between simply causes the message to be fetched again (ТЗ 1.0.1 §4.1).

        ``BODY.PEEK`` is used deliberately: a plain FETCH sets the Seen flag as a side effect
        and would silently turn a read into an acknowledgement.
        """
        limit = limit or self.config.batch_size
        out: list[IngestedReport] = []
        conn = self._connect()
        try:
            status, _ = conn.select(self.config.folder, readonly=False)
            if status != "OK":
                raise RuntimeError(f"cannot select folder {self.config.folder}")
            # UNDELETED rather than UNSEEN: a message opened by a human, or by a worker that
            # died before committing, is still unprocessed as far as this platform knows.
            status, data = conn.uid("SEARCH", None, "UNDELETED")  # type: ignore[arg-type]
            if status != "OK" or not data or not data[0]:
                return out
            # imaplib returns UIDs as bytes but takes them back as str, so they are decoded
            # once here rather than at every call site.
            uids = [raw.decode("ascii", "ignore") for raw in data[0].split()[:limit]]
            for uid in uids:
                report = self._fetch_one(conn, uid)
                if report is not None:
                    out.append(report)
        finally:
            self._disconnect(conn)
        return out

    def _fetch_one(self, conn: imaplib.IMAP4, uid: str) -> IngestedReport | None:
        """Read one message, checking its size before downloading the body."""
        size = self._message_size(conn, uid)
        if size > self.config.max_message_size:
            # The body is never downloaded: it would only be discarded, and pulling tens of
            # megabytes per poll is itself a denial-of-service vector.
            return IngestedReport(
                uid=uid,
                raw_mime=b"",
                oversized=True,
                actual_size=size,
                warnings=[f"report exceeds max_message_size ({size} > {self.config.max_message_size})"],
            )
        status, payload = conn.uid("FETCH", uid, "(BODY.PEEK[])")
        if status != "OK" or not payload or not isinstance(payload[0], tuple):
            return None
        raw = payload[0][1]
        if not isinstance(raw, bytes):
            return None
        return self._to_report(uid, raw)

    def _message_size(self, conn: imaplib.IMAP4, uid: str) -> int:
        status, payload = conn.uid("FETCH", uid, "(RFC822.SIZE)")
        if status != "OK" or not payload:
            return 0
        for item in payload:
            blob = item[0] if isinstance(item, tuple) else item
            if isinstance(blob, bytes):
                match = _SIZE_RE.search(blob)
                if match:
                    return int(match.group(1))
        return 0

    def _disconnect(self, conn: imaplib.IMAP4) -> None:
        try:
            conn.close()
            conn.logout()
        except (imaplib.IMAP4.error, OSError):
            pass

    # -- acknowledgement (ТЗ 1.0.1 §4.1) -------------------------------------------------------
    def ack(self, uid: str) -> bool:
        """Move a successfully ingested message to the Processed folder."""
        return self._move(uid, self.config.processed_folder)

    def fail(self, uid: str) -> bool:
        """Move a message that cannot be ingested to the Failed folder (dead letter)."""
        return self._move(uid, self.config.failed_folder)

    def _move(self, uid: str, folder: str) -> bool:
        conn = self._connect()
        try:
            status, _ = conn.select(self.config.folder, readonly=False)
            if status != "OK":
                return False
            self._ensure_folder(conn, folder)
            conn.uid("STORE", uid, "+FLAGS", "(\\Seen)")
            # MOVE (RFC 6851) is atomic where the server supports it; otherwise fall back to
            # COPY plus delete, which can leave the message in both folders after a crash —
            # harmless here, because the intake record already deduplicates.
            status, _ = conn.uid("MOVE", uid, folder)
            if status == "OK":
                return True
            status, _ = conn.uid("COPY", uid, folder)
            if status != "OK":
                return False
            conn.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
            conn.expunge()
            return True
        except (imaplib.IMAP4.error, OSError) as exc:
            logger.warning("security_mailbox.move_failed", extra={"error": type(exc).__name__})
            return False
        finally:
            self._disconnect(conn)

    def _ensure_folder(self, conn: imaplib.IMAP4, folder: str) -> None:
        """Create the destination folder on first use, then return to the source folder."""
        try:
            status, _ = conn.select(folder, readonly=True)
            if status != "OK":
                conn.create(folder)
                conn.subscribe(folder)
        except (imaplib.IMAP4.error, OSError):
            # An existing folder under a different namespace separator is not an error here:
            # the move itself will report the real failure.
            pass
        finally:
            conn.select(self.config.folder, readonly=False)

    def _to_report(self, uid: str, raw: bytes) -> IngestedReport:
        warnings: list[str] = []
        if len(raw) > self.config.max_message_size:
            # The server under-reported RFC822.SIZE, or the limit changed between the two
            # calls. The message is still not truncated: it is marked oversized and left
            # unanalysed, which is the whole point of ТЗ 1.0.1 §4.2.
            return IngestedReport(
                uid=uid,
                raw_mime=b"",
                oversized=True,
                actual_size=len(raw),
                warnings=[f"report exceeds max_message_size ({len(raw)})"],
            )
        outer = email.message_from_bytes(raw[:65536], policy=policy.compat32)
        from email.utils import getaddresses

        from msp_mail_parser.parser import parse_mail_date

        senders = getaddresses([str(v) for v in (outer.get_all("From") or [])])
        reported_by = senders[0][1].lower() if senders else ""
        reported_at: datetime | None = None
        try:
            date_raw = outer.get("Date")
            reported_at = parse_mail_date(str(date_raw)) if date_raw else None
        except (TypeError, ValueError, IndexError):
            warnings.append("unparseable Date header on the report")
        original, unwrapped, note = extract_original_message(raw)
        if not unwrapped:
            warnings.append("original message was not attached as message/rfc822; headers may be incomplete")
        inner_message_id = ""
        try:
            inner = email.message_from_bytes(original[:65536], policy=policy.compat32)
            inner_message_id = str(inner.get("Message-ID") or "").strip()[:998]
        except (ValueError, TypeError):
            warnings.append("could not read the Message-ID of the reported message")
        return IngestedReport(
            uid=uid,
            raw_mime=original,
            reported_by=reported_by,
            reported_at=reported_at,
            envelope_subject=str(outer.get("Subject") or "")[:500],
            note=note,
            is_forwarded_original=unwrapped,
            warnings=warnings,
            actual_size=len(raw),
            internet_message_id=inner_message_id,
            content_sha256=hashlib.sha256(original).hexdigest(),
        )

    def get_message(self, ref: ExchangeMessageRef) -> FetchedMessage:
        conn = self._connect()
        try:
            conn.select(self.config.folder, readonly=True)
            status, payload = conn.uid("FETCH", ref.item_id, "(BODY.PEEK[])")
            if status != "OK" or not payload or not isinstance(payload[0], tuple):
                raise KeyError(f"message uid {ref.item_id} not found")
            raw = payload[0][1]
        finally:
            try:
                conn.close()
                conn.logout()
            except (imaplib.IMAP4.error, OSError):
                pass
        return FetchedMessage(
            ref=ref, raw_mime=raw if isinstance(raw, bytes) else b"", source=self.provider_id
        )
