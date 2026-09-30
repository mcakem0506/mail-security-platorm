"""Shared header-reading helpers for gateway adapters.

Every vendor writes its own headers, but the shapes repeat: a status word, sometimes a threat
name after a colon, sometimes a numeric score. These helpers normalise that once so each adapter
carries only what is genuinely vendor-specific.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from msp_contracts import GatewayCategory, GatewayVerdictType

#: Status words, longest first so "not detected" wins over "detected".
_VERDICT_WORDS: tuple[tuple[str, GatewayVerdictType], ...] = (
    ("not detected", GatewayVerdictType.CLEAN_OBSERVED),
    ("not_detected", GatewayVerdictType.CLEAN_OBSERVED),
    ("no detection", GatewayVerdictType.CLEAN_OBSERVED),
    ("not scanned", GatewayVerdictType.UNKNOWN),
    ("no threats", GatewayVerdictType.CLEAN_OBSERVED),
    ("probably spam", GatewayVerdictType.SUSPICIOUS),
    ("probable spam", GatewayVerdictType.SUSPICIOUS),
    ("probable", GatewayVerdictType.SUSPICIOUS),
    ("suspicious", GatewayVerdictType.SUSPICIOUS),
    ("phishing", GatewayVerdictType.PHISHING),
    ("phish", GatewayVerdictType.PHISHING),
    ("malware", GatewayVerdictType.MALICIOUS),
    ("infected", GatewayVerdictType.MALICIOUS),
    ("detected", GatewayVerdictType.MALICIOUS),
    ("virus", GatewayVerdictType.MALICIOUS),
    ("blocked", GatewayVerdictType.MALICIOUS),
    ("bulk", GatewayVerdictType.SPAM),
    ("spam", GatewayVerdictType.SPAM),
    ("clean", GatewayVerdictType.CLEAN_OBSERVED),
    ("passed", GatewayVerdictType.CLEAN_OBSERVED),
    ("ok", GatewayVerdictType.CLEAN_OBSERVED),
    ("error", GatewayVerdictType.ERROR),
    ("failed", GatewayVerdictType.ERROR),
    ("timeout", GatewayVerdictType.ERROR),
)

_SCORE_RE = re.compile(r"(?i)(?:score|points|rate|rating)\s*[=:]?\s*(-?\d+(?:[.,]\d+)?)")
_BARE_NUMBER_RE = re.compile(r"^\s*(-?\d+(?:[.,]\d+)?)\s*$")
_THREAT_RE = re.compile(r"(?i)(?:detected|infected|found|threat|malware|virus)\s*[:=]\s*([^\s;,]{2,120})")


class HeaderIndex:
    """Case-insensitive multi-value view over a message's headers."""

    def __init__(self, headers: Iterable[tuple[str, str]]) -> None:
        self._by_name: dict[str, list[str]] = {}
        for name, value in headers:
            self._by_name.setdefault(name.strip().lower(), []).append(value)

    def first(self, *names: str) -> str:
        for name in names:
            values = self._by_name.get(name.strip().lower())
            if values:
                return values[0]
        return ""

    def all(self, name: str) -> list[str]:
        return list(self._by_name.get(name.strip().lower(), ()))

    def with_prefix(self, prefix: str) -> list[tuple[str, str]]:
        prefix = prefix.lower()
        return [
            (name, value)
            for name, values in self._by_name.items()
            if name.startswith(prefix)
            for value in values
        ]

    def names(self) -> set[str]:
        return set(self._by_name)

    def present(self, *names: str) -> bool:
        return any(name.strip().lower() in self._by_name for name in names)


def classify_value(value: str) -> GatewayVerdictType | None:
    """Map a vendor status string onto the normalised verdict set.

    Returns ``None`` when nothing recognisable is present, which the caller reports as
    ``UNKNOWN`` rather than guessing.
    """
    if not value:
        return None
    lowered = " " + re.sub(r"[_\-]+", " ", value.strip().lower()) + " "
    for word, verdict in _VERDICT_WORDS:
        if f" {word} " in lowered or lowered.strip().startswith(word):
            return verdict
    if lowered.strip().startswith("yes"):
        return GatewayVerdictType.SPAM
    if lowered.strip().startswith("no"):
        return GatewayVerdictType.CLEAN_OBSERVED
    return None


def extract_score(*values: str) -> float | None:
    for value in values:
        if not value:
            continue
        match = _SCORE_RE.search(value) or _BARE_NUMBER_RE.match(value)
        if match:
            try:
                return float(match.group(1).replace(",", "."))
            except ValueError:
                continue
    return None


def extract_threat_name(value: str) -> str:
    match = _THREAT_RE.search(value or "")
    if match:
        return match.group(1).strip().strip(".,;")[:120]
    # "Status: Detected; Name" style, where the name simply follows a separator.
    parts = re.split(r"[;:]", value or "", maxsplit=1)
    if len(parts) == 2 and classify_value(parts[0]) in {
        GatewayVerdictType.MALICIOUS,
        GatewayVerdictType.PHISHING,
    }:
        return parts[1].strip()[:120]
    return ""


def category_for_header(name: str) -> GatewayCategory:
    """Infer which engine wrote a header from its name."""
    lowered = name.lower()
    if "phish" in lowered:
        return GatewayCategory.ANTIPHISHING
    if "spam" in lowered or "scl" in lowered or "bcl" in lowered:
        return GatewayCategory.ANTISPAM
    if "virus" in lowered or "antivirus" in lowered or "av" in lowered.split("-"):
        return GatewayCategory.ANTIVIRUS
    if "sandbox" in lowered or "atp" in lowered or "detonation" in lowered:
        return GatewayCategory.SANDBOX
    if "reputation" in lowered or "rep" in lowered.split("-"):
        return GatewayCategory.REPUTATION
    if "policy" in lowered or "rule" in lowered:
        return GatewayCategory.POLICY
    if "dlp" in lowered:
        return GatewayCategory.DLP
    return GatewayCategory.UNKNOWN
