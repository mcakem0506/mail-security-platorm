"""Verdicts left in headers by an existing Secure Email Gateway (ТЗ 2.1, 21).

The platform is a companion, not a replacement: where an organisation already runs a gateway
(Kaspersky Secure Mail Gateway, Exchange Online Protection, and others), that gateway has already
examined the message at delivery time with capabilities this platform deliberately does not have
— notably a full antivirus engine and, in some deployments, a sandbox.

Those results are read as an additional *source*, on three conditions:

* they are treated as a signal, never as the final verdict — the same rule that applies to every
  other provider (ТЗ 2.1);
* a "clean" gateway verdict never lowers the platform's own risk. A gateway that found nothing
  has not proved the message is safe, and BEC mail without links or attachments is exactly what
  such gateways pass through (ТЗ 49.9);
* headers are trusted only when they come from the organisation's own infrastructure, because a
  header can be forged by the sender. The caller decides which gateways are trusted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Each gateway writes its own headers. Patterns are deliberately narrow: a header that merely
# mentions a product name is not evidence of a verdict.
_KSMG_STATUS = re.compile(r"(?i)\b(clean|not[\s_-]?detected|detected|infected|spam|probable|phishing)\b")
_EOP_SCL = re.compile(r"(?i)\bSCL:(-?\d+)")
_EOP_BCL = re.compile(r"(?i)\bBCL:(\d+)")
_SPAM_SCORE = re.compile(r"(?i)(?:score|points)[=:\s]+(-?\d+(?:\.\d+)?)")


@dataclass(frozen=True)
class GatewayVerdict:
    gateway: str
    verdict: str  # malicious | spam | suspicious | clean | unknown
    detail: str = ""
    raw_header: str = ""
    threat_name: str = ""
    score: float | None = None

    @property
    def is_negative(self) -> bool:
        return self.verdict in {"malicious", "spam", "suspicious"}


@dataclass
class GatewayInspection:
    verdicts: list[GatewayVerdict] = field(default_factory=list)
    gateways_seen: list[str] = field(default_factory=list)
    untrusted_claims: list[str] = field(default_factory=list)

    @property
    def any_negative(self) -> bool:
        return any(v.is_negative for v in self.verdicts)


def _first(headers: dict[str, list[str]], *names: str) -> str:
    for name in names:
        values = headers.get(name.lower())
        if values:
            return values[0]
    return ""


def _all_matching(headers: dict[str, list[str]], prefix: str) -> list[tuple[str, str]]:
    prefix = prefix.lower()
    return [(name, value) for name, values in headers.items() if name.startswith(prefix) for value in values]


def _parse_ksmg(headers: dict[str, list[str]]) -> list[GatewayVerdict]:
    """Kaspersky Secure Mail Gateway.

    KSMG stamps X-KSMG-* headers; the exact set depends on version and policy, so the parser
    reads what is present rather than requiring a fixed layout.
    """
    found = _all_matching(headers, "x-ksmg-")
    if not found:
        return []

    av_status = _first(headers, "x-ksmg-antivirus-status", "x-ksmg-av-status")
    av_method = _first(headers, "x-ksmg-antivirus-method", "x-ksmg-av-method")
    spam_status = _first(headers, "x-ksmg-antispam-status", "x-ksmg-as-status")
    phishing = _first(headers, "x-ksmg-antiphishing-status", "x-ksmg-ap-status")
    rate = _first(headers, "x-ksmg-antispam-rate", "x-ksmg-antispam-info")

    verdicts: list[GatewayVerdict] = []

    def classify(value: str, kind: str) -> str | None:
        match = _KSMG_STATUS.search(value)
        if not match:
            return None
        # "word" rather than "token": this is a parsed status keyword, not a credential.
        word = match.group(1).lower().replace("_", "").replace("-", "").replace(" ", "")
        if word in {"detected", "infected"}:
            return "malicious" if kind != "spam" else "spam"
        if word == "phishing":
            return "malicious"
        if word == "spam":
            return "spam"
        if word == "probable":
            return "suspicious"
        if word in {"clean", "notdetected"}:
            return "clean"
        return None

    if av_status:
        verdict = classify(av_status, "av")
        if verdict:
            threat = ""
            if verdict == "malicious":
                # The threat name usually follows the status, e.g. "Detected: EICAR-Test-File".
                parts = re.split(r"[:;]", av_status, maxsplit=1)
                threat = parts[1].strip()[:120] if len(parts) > 1 else ""
            verdicts.append(
                GatewayVerdict(
                    "ksmg", verdict, detail=av_method[:120], raw_header=av_status[:200], threat_name=threat
                )
            )
    for value, kind in ((spam_status, "spam"), (phishing, "phishing")):
        if not value:
            continue
        verdict = classify(value, kind)
        if verdict:
            score_match = _SPAM_SCORE.search(rate or value)
            verdicts.append(
                GatewayVerdict(
                    "ksmg",
                    verdict,
                    detail=kind,
                    raw_header=value[:200],
                    score=float(score_match.group(1)) if score_match else None,
                )
            )
    if not verdicts:
        # KSMG processed the message but the verdict could not be read: record the fact only.
        verdicts.append(GatewayVerdict("ksmg", "unknown", detail="headers present, verdict not parsed"))
    return verdicts


def _parse_eop(headers: dict[str, list[str]]) -> list[GatewayVerdict]:
    """Exchange Online Protection / Forefront spam confidence levels."""
    value = _first(headers, "x-forefront-antispam-report", "x-microsoft-antispam")
    if not value:
        return []
    verdicts: list[GatewayVerdict] = []
    scl_match = _EOP_SCL.search(value)
    if scl_match:
        scl = int(scl_match.group(1))
        # Microsoft's scale: -1 trusted, 0-1 not spam, 5-6 spam, 9 high-confidence spam.
        verdict = "spam" if scl >= 5 else "clean" if scl <= 1 else "suspicious"
        verdicts.append(
            GatewayVerdict("eop", verdict, detail=f"SCL={scl}", raw_header=value[:200], score=float(scl))
        )
    bcl_match = _EOP_BCL.search(value)
    if bcl_match and int(bcl_match.group(1)) >= 7:
        verdicts.append(
            GatewayVerdict("eop", "spam", detail=f"BCL={bcl_match.group(1)}", raw_header=value[:200])
        )
    return verdicts


def _parse_spamassassin(headers: dict[str, list[str]]) -> list[GatewayVerdict]:
    flag = _first(headers, "x-spam-flag")
    status = _first(headers, "x-spam-status")
    if not flag and not status:
        return []
    is_spam = flag.strip().lower().startswith("yes") or status.strip().lower().startswith("yes")
    score_match = _SPAM_SCORE.search(status)
    return [
        GatewayVerdict(
            "spamassassin",
            "spam" if is_spam else "clean",
            raw_header=(status or flag)[:200],
            score=float(score_match.group(1)) if score_match else None,
        )
    ]


def _parse_generic_virus_scanner(headers: dict[str, list[str]]) -> list[GatewayVerdict]:
    """X-Virus-Scanned / X-Virus-Status, written by several MTAs and scanners."""
    status = _first(headers, "x-virus-status")
    scanned = _first(headers, "x-virus-scanned")
    if not status and not scanned:
        return []
    lowered = status.lower()
    if "infected" in lowered or "found" in lowered:
        return [GatewayVerdict("virus_scanner", "malicious", raw_header=status[:200])]
    if "clean" in lowered or scanned:
        return [GatewayVerdict("virus_scanner", "clean", raw_header=(status or scanned)[:200])]
    return []


_PARSERS = (
    ("ksmg", _parse_ksmg),
    ("eop", _parse_eop),
    ("spamassassin", _parse_spamassassin),
    ("virus_scanner", _parse_generic_virus_scanner),
)


def inspect_gateway_headers(
    headers: list[tuple[str, str]], trusted_gateways: tuple[str, ...] = ()
) -> GatewayInspection:
    """Read verdicts an upstream gateway left in the headers.

    ``trusted_gateways`` names the gateways whose headers the organisation actually operates.
    A verdict from a gateway that is not on that list is recorded as an untrusted claim and is
    not used: any sender can add an X-Spam-Status header saying their message is clean.
    """
    indexed: dict[str, list[str]] = {}
    for name, value in headers:
        indexed.setdefault(name.lower(), []).append(value)

    inspection = GatewayInspection()
    trusted = {g.lower() for g in trusted_gateways}
    for gateway, parser in _PARSERS:
        verdicts = parser(indexed)
        if not verdicts:
            continue
        inspection.gateways_seen.append(gateway)
        if gateway in trusted:
            inspection.verdicts.extend(verdicts)
        else:
            inspection.untrusted_claims.append(gateway)
    return inspection


def gateway_facts(
    headers: list[tuple[str, str]], trusted_gateways: tuple[str, ...] = ()
) -> list[tuple[str, Any, dict[str, Any]]]:
    """Turn gateway verdicts into facts for the rule engine.

    Only negative verdicts become facts. A "clean" verdict is recorded for the analyst's benefit
    but never produces a fact that could reduce risk — the gateway's silence is not evidence.
    """
    inspection = inspect_gateway_headers(headers, trusted_gateways)
    out: list[tuple[str, Any, dict[str, Any]]] = []

    for verdict in inspection.verdicts:
        evidence = {
            "gateway": verdict.gateway,
            "verdict": verdict.verdict,
            "detail": verdict.detail,
            "threat_name": verdict.threat_name,
            "score": verdict.score,
        }
        if verdict.verdict == "malicious":
            out.append(("gateway_detected_malware", True, evidence))
        elif verdict.verdict == "spam":
            out.append(("gateway_detected_spam", True, evidence))
        elif verdict.verdict == "suspicious":
            out.append(("gateway_marked_suspicious", True, evidence))

    if inspection.gateways_seen:
        out.append(
            (
                "upstream_gateway_present",
                True,
                {"gateways": inspection.gateways_seen, "trusted": list(trusted_gateways)},
            )
        )
    if inspection.untrusted_claims:
        # A gateway header the organisation does not operate is itself worth noticing: it is a
        # known trick to make a message look pre-screened.
        out.append(
            (
                "untrusted_gateway_header",
                True,
                {"gateways": inspection.untrusted_claims},
            )
        )
    return out
