"""URL extraction and normalisation (ТЗ 11.1 / 11.2). URLs are never fetched here."""

from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlsplit

from msp_contracts import ExtractedUrl

from .domains import is_ip_literal, split_domain, to_ascii

_TEXT_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'` 　]{2,2048}")
_TRAILING = ".,;:!?)]}'\"»…"
_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}
_TOKENISH = re.compile(r"^(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9_\-=%.]{24,}$")
_SPECIAL_SCHEMES = {"javascript", "data", "vbscript", "file"}


def _strip_trailing(url: str) -> str:
    while url and url[-1] in _TRAILING:
        if url[-1] == ")" and url.count("(") >= url.count(")"):
            break
        url = url[:-1]
    return url


def _obfuscated_ipv4(host: str) -> str | None:
    """Decode integer / hex host forms like http://3232235777/ or http://0xC0A80001/."""
    try:
        if host.isdigit():
            value = int(host)
        elif host.lower().startswith("0x") and all(c in "0123456789abcdef" for c in host[2:].lower()):
            value = int(host, 16)
        else:
            return None
    except ValueError:
        return None
    if 0 <= value < 2**32:
        return str(ipaddress.IPv4Address(value))
    return None


def _redact_path(path: str) -> str:
    segments = path.split("/")
    return "/".join("[redacted]" if _TOKENISH.match(s) else s for s in segments)


def normalize_url(raw: str, source: str = "text", visible_text: str | None = None) -> ExtractedUrl:
    original = raw
    raw = raw.strip().strip("<>").strip()
    raw = "".join(ch for ch in raw if ch not in "\r\n\t")
    if raw.lower().startswith("www."):
        raw = "http://" + raw
    base = {"raw": original[:4096], "source": source, "visible_text": visible_text}
    try:
        parts = urlsplit(raw)
        scheme = (parts.scheme or "").lower()
        if scheme in _SPECIAL_SCHEMES:
            return ExtractedUrl(
                **base,
                normalized=f"{scheme}:[content]",
                redacted=f"{scheme}:[content]",
                scheme=scheme,
                host="",
                host_ascii="",
                registrable_domain="",
            )
        netloc = parts.netloc
        has_userinfo = "@" in netloc
        hostport = netloc.rsplit("@", 1)[-1]
        host = (parts.hostname or "").strip(".")
        try:
            port = parts.port
        except ValueError:
            port = None
        ip_from_int = _obfuscated_ipv4(host)
        if ip_from_int:
            host = ip_from_int
        dom = split_domain(host)
        host_ascii = dom.host_ascii or to_ascii(host)
        port_part = f":{port}" if port and _DEFAULT_PORTS.get(scheme) != port else ""
        host_repr = f"[{host_ascii}]" if ":" in host_ascii else host_ascii
        path = parts.path or "/"
        normalized = f"{scheme}://{host_repr}{port_part}{path}"
        query_keys = [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)][:50]
        if parts.query:
            normalized += "?" + parts.query
        redacted = f"{scheme}://{host_repr}{port_part}{_redact_path(path)}"
        if parts.query:
            redacted += "?" + "&".join(f"{k}=…" for k in query_keys) if query_keys else "?…"
        return ExtractedUrl(
            **base,
            normalized=normalized[:4096],
            redacted=redacted[:1024],
            scheme=scheme,
            host=dom.host or host,
            host_ascii=host_ascii,
            registrable_domain=dom.registrable,
            subdomain=dom.subdomain,
            port=port,
            path=path[:2048],
            has_query=bool(parts.query),
            query_keys=query_keys,
            has_fragment=bool(parts.fragment),
            has_userinfo=has_userinfo and bool(hostport),
            is_ip_literal=dom.is_ip or is_ip_literal(host),
        )
    except (ValueError, UnicodeError) as exc:
        return ExtractedUrl(
            **base,
            normalized=raw[:4096],
            redacted="[unparseable-url]",
            scheme="",
            host="",
            host_ascii="",
            registrable_domain="",
            parse_error=type(exc).__name__,
        )


def extract_urls_from_text(text: str, source: str = "text", limit: int = 500) -> list[ExtractedUrl]:
    out: list[ExtractedUrl] = []
    for m in _TEXT_URL_RE.finditer(text or ""):
        url = _strip_trailing(m.group(0))
        if len(url) < 8:
            continue
        out.append(normalize_url(url, source=source))
        if len(out) >= limit:
            break
    return out


class _LinkCollector(HTMLParser):
    """Collects link targets without resolving or loading anything."""

    def __init__(self, limit: int) -> None:
        super().__init__(convert_charrefs=True)
        self.limit = limit
        self.items: list[tuple[str, str, str | None]] = []  # (url, source, visible_text)
        self._anchor_stack: list[tuple[str, list[str]]] = []
        self.password_inputs = 0
        self.forms = 0
        self.external_form_actions: list[str] = []
        self.scripts = 0

    def _add(self, url: str | None, source: str, visible: str | None = None) -> None:
        if url and len(self.items) < self.limit:
            self.items.append((url.strip(), source, visible))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" or tag == "area":
            if tag == "a":
                self._anchor_stack.append((a.get("href", ""), []))
            else:
                self._add(a.get("href"), "href")
        elif tag == "form":
            self.forms += 1
            self._add(a.get("action"), "form")
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.password_inputs += 1
        elif tag in {"img", "image"}:
            self._add(a.get("src"), "img")
        elif tag in {"iframe", "frame", "embed"}:
            self._add(a.get("src"), "iframe")
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", a.get("content", ""), re.I)
            if m:
                self._add(m.group(1), "meta")
        elif tag == "script":
            self.scripts += 1
            self._add(a.get("src"), "script")
        elif tag == "base":
            self._add(a.get("href"), "base")

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._anchor_stack:
            href, texts = self._anchor_stack.pop()
            visible = re.sub(r"\s+", " ", "".join(texts)).strip()[:512]
            self._add(href, "href", visible or None)

    def handle_data(self, data: str) -> None:
        if self._anchor_stack:
            self._anchor_stack[-1][1].append(data)


def extract_urls_from_html(html: str, limit: int = 500) -> tuple[list[ExtractedUrl], dict[str, int]]:
    collector = _LinkCollector(limit)
    try:
        collector.feed(html or "")
        collector.close()
    except (AssertionError, ValueError):  # pragma: no cover - HTMLParser is lenient
        pass
    urls: list[ExtractedUrl] = []
    for url, source, visible in collector.items:
        low = url.lower()
        if low.startswith(("mailto:", "tel:", "cid:", "#")) or not low:
            continue
        if not re.match(r"^[a-z][a-z0-9+.\-]*:", low) and not low.startswith("//") and not low.startswith("www."):
            continue  # relative link without base, nothing to analyse
        if low.startswith("//"):
            url = "https:" + url
        urls.append(normalize_url(url, source=source, visible_text=visible))
    stats = {
        "forms": collector.forms,
        "password_inputs": collector.password_inputs,
        "scripts": collector.scripts,
    }
    return urls, stats


def dedupe_urls(urls: list[ExtractedUrl], limit: int = 500) -> list[ExtractedUrl]:
    seen: set[tuple[str, str, str | None]] = set()
    out: list[ExtractedUrl] = []
    for u in urls:
        key = (u.normalized, u.source, u.visible_text)
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
        if len(out) >= limit:
            break
    return out
