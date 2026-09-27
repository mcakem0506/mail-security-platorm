"""Domain helpers: IDNA conversion and registrable domain via an offline Public Suffix List."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache

import idna
import tldextract

# Offline only: never fetch the PSL from the network at runtime (bundled snapshot).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


@dataclass(frozen=True)
class DomainParts:
    host: str  # unicode, lower-case
    host_ascii: str  # punycode, lower-case
    registrable: str  # unicode registrable domain (eTLD+1), or host when no public suffix
    registrable_ascii: str
    subdomain: str
    suffix: str
    label: str  # the eTLD+1 label without suffix, e.g. "example" for example.co.uk
    is_ip: bool
    is_idn: bool


def to_ascii(host: str) -> str:
    host = (host or "").strip().strip(".").lower()
    if not host:
        return ""
    try:
        return idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError:
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError:
            return host


def to_unicode(host: str) -> str:
    host = (host or "").strip().strip(".").lower()
    if not host:
        return ""
    if "xn--" not in host:
        return host
    try:
        return idna.decode(host)
    except idna.IDNAError:
        try:
            return host.encode("ascii").decode("idna")
        except UnicodeError:
            return host


def is_ip_literal(host: str) -> bool:
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


@lru_cache(maxsize=8192)
def split_domain(host: str) -> DomainParts:
    host_u = to_unicode(host)
    host_a = to_ascii(host_u) if host_u else ""
    if not host_u:
        return DomainParts("", "", "", "", "", "", "", False, False)
    if is_ip_literal(host_u):
        h = host_u.strip("[]")
        return DomainParts(h, h, h, h, "", "", h, True, False)
    ext = _EXTRACT(host_a)
    if ext.suffix and ext.domain:
        reg_a = f"{ext.domain}.{ext.suffix}"
        return DomainParts(
            host=host_u,
            host_ascii=host_a,
            registrable=to_unicode(reg_a),
            registrable_ascii=reg_a,
            subdomain=to_unicode(ext.subdomain) if ext.subdomain else "",
            suffix=ext.suffix,
            label=to_unicode(ext.domain),
            is_ip=False,
            is_idn="xn--" in host_a,
        )
    return DomainParts(host_u, host_a, host_u, host_a, "", "", host_u.split(".")[0], False, "xn--" in host_a)


def registrable_domain(host: str) -> str:
    return split_domain(host).registrable


def is_subdomain_or_equal(host: str, domain: str) -> bool:
    host, domain = to_ascii(host), to_ascii(domain)
    return bool(domain) and (host == domain or host.endswith("." + domain))
