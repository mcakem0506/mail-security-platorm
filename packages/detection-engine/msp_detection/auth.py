"""SPF / DKIM / DMARC interpretation from trusted headers (ТЗ 9.2).

The platform deliberately does NOT compute its own post-hoc SPF verdict: without the real SMTP
envelope and connecting IP that result would be misleading. Instead it reads the results recorded
by the mail infrastructure. Absence of DKIM is not phishing; SPF pass is not "safe".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_METHOD_RE = re.compile(
    r"(?i)\b(spf|dkim|dmarc|arc|compauth)\s*=\s*([a-z]+)((?:\s*\([^)]*\))?(?:\s+[\w.\-]+=(?:\"[^\"]*\"|[^;\s]+))*)"
)
_PROP_RE = re.compile(r"(?i)([\w.\-]+)=(\"[^\"]*\"|[^;\s]+)")
_SPF_HEADER_RE = re.compile(r"(?i)^\s*(pass|fail|softfail|neutral|none|temperror|permerror)")

_FAIL_RESULTS = {"fail", "permerror"}
_SOFT_RESULTS = {"softfail", "neutral", "policy", "temperror"}


@dataclass
class MethodResult:
    method: str
    result: str
    properties: dict[str, str] = field(default_factory=dict)
    authserv: str = ""


@dataclass
class AuthResults:
    """Aggregated authentication state extracted from trusted headers."""

    results: list[MethodResult] = field(default_factory=list)
    evidence: dict[str, dict[str, Any]] = field(default_factory=dict)

    def best(self, method: str) -> MethodResult | None:
        """Most significant result for a method (fail beats pass: fail-closed reading)."""
        candidates = [r for r in self.results if r.method == method]
        if not candidates:
            return None
        # Ordering, not credentials: bandit flags the "pass" key as a password literal.
        order = {
            "fail": 0,
            "permerror": 1,
            "softfail": 2,
            "temperror": 3,
            "neutral": 4,
            "none": 5,
            "pass": 6,  # nosec
        }
        return sorted(candidates, key=lambda r: order.get(r.result, 7))[0]

    def merge_received_spf(self, spf_results: list[MethodResult]) -> None:
        if not any(r.method == "spf" for r in self.results):
            self.results.extend(spf_results)

    def as_facts(self) -> dict[str, Any]:
        facts: dict[str, Any] = {}
        for method in ("spf", "dkim", "dmarc", "compauth"):
            res = self.best(method)
            if res is None:
                facts[f"{method}_present"] = False
                continue
            facts[f"{method}_present"] = True
            facts[f"{method}_result"] = res.result
            ev: dict[str, Any] = {"result": res.result, "authserv": res.authserv}
            ev.update(
                {k: v for k, v in res.properties.items() if k.startswith(("header.", "smtp.", "d", "i"))}
            )
            self.evidence[f"{method}_result"] = ev
            if res.result in _FAIL_RESULTS:
                facts[f"{method}_fail"] = True
                self.evidence[f"{method}_fail"] = ev
            elif res.result in _SOFT_RESULTS:
                facts[f"{method}_soft_fail"] = True
                self.evidence[f"{method}_soft_fail"] = ev
            elif res.result == "pass":
                facts[f"{method}_pass"] = True
        if facts.get("dmarc_fail") and facts.get("spf_fail") and not facts.get("dkim_pass"):
            facts["authentication_fully_failed"] = True
            self.evidence["authentication_fully_failed"] = {
                "spf": facts.get("spf_result"),
                "dkim": facts.get("dkim_result"),
                "dmarc": facts.get("dmarc_result"),
            }
        # DKIM aligned with the From domain is the strongest positive signal we can read.
        dkim = self.best("dkim")
        if dkim is not None and dkim.result == "pass":
            signing_domain = (dkim.properties.get("header.d") or dkim.properties.get("d") or "").strip('"')
            if signing_domain:
                facts["dkim_signing_domain"] = signing_domain.lower()
        return facts


def _parse_props(blob: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for m in _PROP_RE.finditer(blob or ""):
        key, value = m.group(1).lower(), m.group(2).strip('"')
        if key in {"spf", "dkim", "dmarc", "arc", "compauth"}:
            continue
        props[key] = value[:256]
    return props


def parse_authentication_results(headers: list[str]) -> AuthResults:
    out = AuthResults()
    for header in headers or []:
        authserv = header.split(";", 1)[0].strip().split()[0] if ";" in header else ""
        for m in _METHOD_RE.finditer(header):
            method, result, rest = m.group(1).lower(), m.group(2).lower(), m.group(3) or ""
            out.results.append(
                MethodResult(
                    method=method, result=result, properties=_parse_props(rest), authserv=authserv[:200]
                )
            )
    return out


def parse_received_spf(headers: list[str]) -> list[MethodResult]:
    out: list[MethodResult] = []
    for header in headers or []:
        m = _SPF_HEADER_RE.match(header)
        if m:
            out.append(MethodResult(method="spf", result=m.group(1).lower(), properties=_parse_props(header)))
    return out


_RECEIVED_IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")
_RECEIVED_FROM_RE = re.compile(r"(?i)^\s*from\s+([^\s;()]+)")


def received_chain_facts(received: list[str]) -> list[tuple[str, Any, dict[str, Any]]]:
    """Facts derived from the Received chain (no DNS lookups, header data only)."""
    out: list[tuple[str, Any, dict[str, Any]]] = []
    if not received:
        out.append(("received_chain_missing", True, {}))
        return out
    out.append(("received_hop_count", len(received), {}))
    first = received[-1]  # earliest hop
    ips = _RECEIVED_IP_RE.findall(first)
    host_match = _RECEIVED_FROM_RE.match(first)
    if host_match:
        out.append(("originating_host", host_match.group(1).lower()[:255], {"received": first[:300]}))
    if ips:
        out.append(("originating_ip", ips[0], {"received": first[:300]}))
    joined = " ".join(received).lower()
    if "unknown" in joined and "helo=" in joined:
        out.append(("received_unresolved_host", True, {}))
    return out
