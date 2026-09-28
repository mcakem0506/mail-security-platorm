"""Safe MIME / EML parser (ТЗ 8).

* bounded: message size, MIME depth, part count, attachment count/size, URL count, timeout;
* tolerant: malformed messages yield a partial result with ``errors`` instead of an exception;
* inert: no network, no execution, HTML is only tokenised and sanitised.
"""

from __future__ import annotations

import codecs
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from email import message_from_bytes, policy
from email.header import Header, decode_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime

from msp_contracts import Address, AttachmentMeta, ExtractedUrl

from .archive import inspect_archive
from .domains import split_domain
from .filetype import (
    ARCHIVE_TYPES,
    detect_type,
    extension_mismatch,
    last_extension,
    normalize_filename,
)
from .html_safe import html_to_text, normalize_whitespace, sanitize_html
from .limits import Deadline, LimitExceeded, ParserLimits
from .urls import dedupe_urls, extract_urls_from_html, extract_urls_from_text

_ENCRYPTED_TYPES = {"multipart/encrypted", "application/pgp-encrypted"}
_PKCS7 = {"application/pkcs7-mime", "application/x-pkcs7-mime"}
# Bidirectional formatting characters, used to disguise a file extension: a name containing
# RIGHT-TO-LEFT OVERRIDE before "gnp.exe" is displayed to the user as "...exe.png".
# They are built from code points rather than written literally:
# literal bidi controls in source code are themselves a supply-chain hazard, because they can
# make reviewed code read differently from what the interpreter executes.
_BIDI_CONTROL_CHARS = tuple(
    chr(code)
    for code in (
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2066,  # LEFT-TO-RIGHT ISOLATE
        0x2067,  # RIGHT-TO-LEFT ISOLATE
        0x2068,  # FIRST STRONG ISOLATE
        0x2069,  # POP DIRECTIONAL ISOLATE
    )
)


@dataclass
class ParsedAttachment:
    meta: AttachmentMeta
    content: bytes | None = None


@dataclass
class ParsedMessage:
    size: int
    sha256: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    from_: Address | None = None
    sender: Address | None = None
    reply_to: list[Address] = field(default_factory=list)
    return_path: str = ""
    to: list[Address] = field(default_factory=list)
    cc: list[Address] = field(default_factory=list)
    subject: str = ""
    message_id: str = ""
    date: datetime | None = None
    received: list[str] = field(default_factory=list)
    authentication_results: list[str] = field(default_factory=list)
    received_spf: list[str] = field(default_factory=list)
    dkim_signatures: int = 0
    text_body: str = ""
    html_body: str = ""
    normalized_text: str = ""
    sanitized_html: str = ""
    urls: list[ExtractedUrl] = field(default_factory=list)
    html_stats: dict[str, int] = field(default_factory=dict)
    attachments: list[ParsedAttachment] = field(default_factory=list)
    nested_messages: int = 0
    encrypted: bool = False
    signed: bool = False
    mime_depth: int = 0
    part_count: int = 0
    errors: list[str] = field(default_factory=list)
    limits_hit: list[str] = field(default_factory=list)

    @property
    def parse_ok(self) -> bool:
        return "FATAL" not in {e.split(":", 1)[0] for e in self.errors}

    def header(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return None

    def header_all(self, name: str) -> list[str]:
        low = name.lower()
        return [v for k, v in self.headers if k.lower() == low]


_FALLBACK_CHARSETS = ("utf-8", "cp1251", "koi8-r", "latin-1")


def _decode_raw_bytes(data: bytes, charset: str | None) -> str:
    """Decode a header chunk, repairing raw 8-bit headers that violate RFC 2047.

    Unencoded UTF-8 (and cp1251) in headers is common in the wild; the stdlib reports it as
    ``unknown-8bit`` and would otherwise turn the text into replacement characters.
    """
    candidates: tuple[str, ...]
    if charset and charset.lower() not in {"unknown-8bit", "x-unknown", "unknown"}:
        candidates = (charset, *_FALLBACK_CHARSETS)
    else:
        candidates = _FALLBACK_CHARSETS
    for cs in candidates:
        try:
            return data.decode(cs)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", errors="replace")


def decode_header_value(value: object) -> str:
    if value is None:
        return ""
    try:
        chunks = decode_header(value if isinstance(value, Header) else str(value))
    except (UnicodeError, LookupError, ValueError, TypeError, IndexError):
        return str(value)
    parts: list[str] = []
    for payload, charset in chunks:
        if isinstance(payload, bytes):
            parts.append(_decode_raw_bytes(payload, charset))
        else:
            parts.append(payload)
    text = "".join(parts)
    # Repair mojibake produced upstream when raw UTF-8 was read as a single-byte charset.
    if "�" in text:
        try:
            repaired = str(value).encode("latin-1", errors="strict").decode("utf-8", errors="strict")
        except (UnicodeDecodeError, UnicodeEncodeError, TypeError, ValueError):
            return text
        return repaired
    return text


def _make_address(name: str, addr: str) -> Address:
    addr = (addr or "").strip().strip("<>").strip()
    local, _, domain = addr.rpartition("@") if "@" in addr else (addr, "", "")
    parts = split_domain(domain) if domain else None
    return Address(
        display_name=decode_header_value(name).strip().strip('"').strip()[:512],
        address=(f"{local}@{parts.host}" if parts and parts.host else addr).lower()[:512],
        local_part=local.lower()[:256],
        domain=parts.host if parts else "",
        domain_ascii=parts.host_ascii if parts else "",
    )


def parse_address_list(raw_values: Sequence[object]) -> list[Address]:
    """Decode each header value before address parsing: RFC 2047 words and raw 8-bit headers."""
    decoded = [decode_header_value(v) for v in raw_values if v is not None]
    out: list[Address] = []
    for name, addr in getaddresses(decoded):
        if not name and not addr:
            continue
        out.append(_make_address(name, addr))
    return out


def _decode_part_text(part: Message, errors: list[str]) -> str:
    try:
        payload = part.get_payload(decode=True)
    except (ValueError, TypeError, AssertionError) as exc:
        errors.append(f"PAYLOAD_DECODE:{type(exc).__name__}")
        return ""
    if not isinstance(payload, bytes):
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        codecs.lookup(charset)
    except LookupError:
        errors.append(f"UNKNOWN_CHARSET:{charset[:40]}")
        charset = "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeError):
        return payload.decode("latin-1", errors="replace")


def _filename(part: Message) -> str | None:
    try:
        fn = part.get_filename()
    except (ValueError, TypeError, LookupError, UnicodeError):
        fn = None
    if fn is None:
        ct_name = part.get_param("name")
        if isinstance(ct_name, tuple):
            ct_name = ct_name[2]
        fn = str(ct_name) if ct_name else None
    return decode_header_value(fn) if fn else None


class _Walker:
    def __init__(self, result: ParsedMessage, limits: ParserLimits, deadline: Deadline) -> None:
        self.r = result
        self.limits = limits
        self.deadline = deadline
        self.text_parts: list[str] = []
        self.html_parts: list[str] = []
        self.extra_urls: list[ExtractedUrl] = []

    def walk(self, part: Message, depth: int) -> None:
        self.deadline.check()
        self.r.part_count += 1
        self.r.mime_depth = max(self.r.mime_depth, depth)
        if self.r.part_count > self.limits.max_parts:
            raise LimitExceeded("MAX_PARTS")
        if depth > self.limits.max_mime_depth:
            if "MAX_MIME_DEPTH" not in self.r.limits_hit:
                self.r.limits_hit.append("MAX_MIME_DEPTH")
            return
        for defect in getattr(part, "defects", [])[:20]:
            self.r.errors.append(f"MIME_DEFECT:{type(defect).__name__}")
        ctype = part.get_content_type().lower()
        if ctype in _ENCRYPTED_TYPES or (
            ctype in _PKCS7 and "signed-data" not in str(part.get_param("smime-type") or "")
        ):
            self.r.encrypted = True
        if ctype == "multipart/signed":
            self.r.signed = True
        if ctype.startswith("multipart/"):
            payload = part.get_payload()
            if not isinstance(payload, list):
                self.r.errors.append("MALFORMED_MULTIPART")
                return
            for sub in payload:
                if isinstance(sub, Message):
                    self.walk(sub, depth + 1)
            return
        if ctype == "message/rfc822":
            self.r.nested_messages += 1
            payload = part.get_payload()
            inner = payload[0] if isinstance(payload, list) and payload else None
            if isinstance(inner, Message):
                try:
                    data = inner.as_bytes(policy=policy.compat32)
                except (ValueError, TypeError, LookupError, UnicodeError):
                    data = b""
                self._add_attachment(_filename(part) or "attached-message.eml", ctype, data, depth)
                self.walk(inner, depth + 1)
            return
        filename = _filename(part)
        disposition = (part.get_content_disposition() or "").lower()
        is_attachment = disposition == "attachment" or bool(filename) or not ctype.startswith("text/")
        if ctype in {"text/plain", "text/html"} and not is_attachment:
            text = _decode_part_text(part, self.r.errors)
            if ctype == "text/plain":
                self.text_parts.append(text)
            else:
                self.html_parts.append(text[: self.limits.max_html_size])
            return
        try:
            payload_raw = part.get_payload(decode=True)
        except (ValueError, TypeError, AssertionError):
            self.r.errors.append("ATTACHMENT_DECODE_ERROR")
            payload_raw = None
        data = payload_raw if isinstance(payload_raw, bytes) else b""
        self._add_attachment(filename or f"part-{self.r.part_count}", ctype, data, depth)

    def _add_attachment(self, filename: str, declared: str, data: bytes, depth: int) -> None:
        top_level = [a for a in self.r.attachments if a.meta.depth == 0]
        if len(top_level) >= self.limits.max_attachments:
            if "MAX_ATTACHMENTS" not in self.r.limits_hit:
                self.r.limits_hit.append("MAX_ATTACHMENTS")
            return
        oversized = len(data) > self.limits.max_attachment_size
        name = normalize_filename(filename)
        detected = detect_type(data[: 8 * 1024 * 1024] if not oversized else data[:65536], name)
        ext = last_extension(name)
        flags = list(detected.details)
        if oversized:
            flags.append("OVERSIZED_NOT_RETAINED")
            if "MAX_ATTACHMENT_SIZE" not in self.r.limits_hit:
                self.r.limits_hit.append("MAX_ATTACHMENT_SIZE")
        if ext and extension_mismatch(ext, detected):
            flags.append("EXTENSION_MISMATCH")
        # Bidirectional overrides are written as escapes, never as literal characters:
        # literal bidi control characters in source are themselves a supply-chain risk.
        if any(ch in filename for ch in _BIDI_CONTROL_CHARS):
            flags.append("RTLO_FILENAME")
        meta = AttachmentMeta(
            filename=filename[:255],
            normalized_filename=name,
            declared_mime=declared,
            detected_type=detected.type,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            sha1=hashlib.sha1(data, usedforsecurity=False).hexdigest(),
            md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
            extension=ext,
            is_archive=detected.type in ARCHIVE_TYPES,
            depth=0,
            flags=flags,
        )
        parsed = ParsedAttachment(meta=meta, content=None if oversized else data)
        self.r.attachments.append(parsed)
        if oversized:
            return
        if meta.is_archive:
            report = inspect_archive(data, detected.type, self.limits, self.deadline)
            meta.archive = report.summary()
            meta.encrypted = report.encrypted
            meta.flags.extend(sorted(report.flags))
            for ex in report.extracted:
                child_flags = list(ex.entry.details)
                child_ext = ex.entry.extension
                child_det = detect_type(ex.data, ex.entry.name)
                if child_ext and extension_mismatch(child_ext, child_det):
                    child_flags.append("EXTENSION_MISMATCH")
                self.r.attachments.append(
                    ParsedAttachment(
                        meta=AttachmentMeta(
                            filename=ex.entry.name,
                            normalized_filename=normalize_filename(ex.entry.name),
                            declared_mime="application/octet-stream",
                            detected_type=child_det.type,
                            size=len(ex.data),
                            sha256=ex.entry.sha256 or hashlib.sha256(ex.data).hexdigest(),
                            extension=child_ext,
                            is_archive=child_det.type in ARCHIVE_TYPES,
                            depth=ex.entry.depth,
                            parent_sha256=meta.sha256,
                            flags=child_flags,
                        ),
                        content=None,  # archive members are analysed statically, not retained
                    )
                )
        if detected.category == "html" and len(data) <= 2 * 1024 * 1024:
            html = data.decode("utf-8", errors="replace")
            urls, stats = extract_urls_from_html(html, limit=self.limits.max_urls)
            for u in urls:
                self.extra_urls.append(u.model_copy(update={"source": f"attachment:{u.source}"}))
            if stats.get("password_inputs"):
                meta.flags.append("HTML_PASSWORD_FORM")
            if stats.get("scripts"):
                meta.flags.append("HTML_SCRIPT")
            low = html.lower()
            if "atob(" in low or "fromcharcode" in low or "msSaveOrOpenBlob".lower() in low:
                meta.flags.append("HTML_SMUGGLING_PATTERN")


def parse_message(raw: bytes, limits: ParserLimits | None = None) -> ParsedMessage:
    limits = limits or ParserLimits()
    result = ParsedMessage(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    if len(raw) > limits.max_message_size:
        result.errors.append("FATAL:MAX_MESSAGE_SIZE")
        result.limits_hit.append("MAX_MESSAGE_SIZE")
        return result
    deadline = Deadline(limits.timeout_seconds)
    try:
        msg = message_from_bytes(raw, policy=policy.compat32)
    except Exception as exc:  # noqa: BLE001 - parser must never crash the worker
        result.errors.append(f"FATAL:UNPARSEABLE:{type(exc).__name__}")
        return result

    # --- headers ---------------------------------------------------------------------------
    for name, value in list(msg.items())[:1000]:
        result.headers.append((str(name)[:200], decode_header_value(value)[:8192]))
    raw_from = msg.get_all("From") or []
    froms = parse_address_list(raw_from)
    if len(froms) > 1:
        result.errors.append("MULTIPLE_FROM")
    result.from_ = froms[0] if froms else None
    senders = parse_address_list(msg.get_all("Sender") or [])
    result.sender = senders[0] if senders else None
    result.reply_to = parse_address_list(msg.get_all("Reply-To") or [])
    rp = parse_address_list(msg.get_all("Return-Path") or [])
    result.return_path = rp[0].address if rp else ""
    result.to = parse_address_list(msg.get_all("To") or [])[:1000]
    result.cc = parse_address_list(msg.get_all("Cc") or [])[:1000]
    result.subject = decode_header_value(msg.get("Subject"))[:998]
    result.message_id = str(msg.get("Message-ID") or "").strip()[:998]
    try:
        date_raw = msg.get("Date")
        result.date = parsedate_to_datetime(str(date_raw)) if date_raw else None
    except (TypeError, ValueError, IndexError):
        result.errors.append("BAD_DATE")
    result.received = [decode_header_value(v)[:4096] for v in (msg.get_all("Received") or [])][:100]
    result.authentication_results = [
        decode_header_value(v)[:4096] for v in (msg.get_all("Authentication-Results") or [])
    ][:20]
    result.received_spf = [decode_header_value(v)[:2048] for v in (msg.get_all("Received-SPF") or [])][:10]
    result.dkim_signatures = len(msg.get_all("DKIM-Signature") or [])

    # --- body ------------------------------------------------------------------------------
    walker = _Walker(result, limits, deadline)
    try:
        walker.walk(msg, 0)
    except LimitExceeded as exc:
        result.limits_hit.append(exc.code)
        result.errors.append(f"LIMIT:{exc.code}")
    except RecursionError:
        result.limits_hit.append("MAX_MIME_DEPTH")
    except Exception as exc:  # noqa: BLE001 - malformed input must produce a partial result
        result.errors.append(f"PARSE_ERROR:{type(exc).__name__}")

    result.text_body = "\n".join(walker.text_parts)[: limits.max_text_chars]
    result.html_body = "\n".join(walker.html_parts)[: limits.max_html_size]
    urls: list[ExtractedUrl] = []
    try:
        if result.html_body:
            html_urls, stats = extract_urls_from_html(result.html_body, limit=limits.max_urls)
            urls.extend(html_urls)
            result.html_stats = stats
            result.sanitized_html = sanitize_html(result.html_body, limits.max_html_size)
        base_text = result.text_body or html_to_text(result.html_body)
        result.normalized_text = normalize_whitespace(base_text, limits.max_text_chars)
        text_urls = extract_urls_from_text(result.normalized_text, limit=limits.max_urls)
        if result.html_body:
            # URLs only visible as text inside HTML are recorded as visible_text source.
            text_urls = [u.model_copy(update={"source": "visible_text"}) for u in text_urls]
        urls.extend(text_urls)
        urls.extend(walker.extra_urls)
    except LimitExceeded as exc:
        result.limits_hit.append(exc.code)
    result.urls = dedupe_urls(urls, limits.max_urls)
    if len(urls) > limits.max_urls:
        result.limits_hit.append("MAX_URLS")
    return result
