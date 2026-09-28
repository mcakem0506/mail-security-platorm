"""Optional semantic analysis of message text (ТЗ 16.4).

Constraints that are structural here, not configurable away:
* the provider is DISABLED by default and must be enabled explicitly;
* text is redacted before it leaves the process — addresses, URLs, IBANs, card and phone numbers,
  and amounts are replaced with placeholders;
* attachments are never sent;
* the output is a *signal*, never a verdict (ТЗ 49.14) — the risk engine treats it as one weak
  input among many;
* a local model is preferred; an external LLM additionally requires an explicit DPA flag.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from msp_contracts import ProviderHealth

logger = logging.getLogger(__name__)

_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"[\w.+\-]+@[\w\-]+\.[\w.\-]+"), "[EMAIL]"),
    (re.compile(r"(?i)\b(?:https?://|www\.)\S+"), "[URL]"),
    (re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"), "[IBAN]"),
    (re.compile(r"\b(?:\d[ \-]?){13,19}\b"), "[CARD]"),
    (re.compile(r"\b\d{20}\b"), "[ACCOUNT]"),
    (re.compile(r"(?:\+7|8|\+\d{1,3})[\s\-()]?\d{3}[\s\-()]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}"), "[PHONE]"),
    (re.compile(r"\b\d[\d\s.,]{4,}\s*(?:руб\.?|₽|\$|€|usd|eur|rub)\b", re.IGNORECASE), "[AMOUNT]"),
    (re.compile(r"\b\d{4}\s?\d{6}\b"), "[DOCID]"),
)


def redact_text(text: str, max_chars: int = 4000) -> str:
    """Remove identifiers before any text leaves the platform (ТЗ 2.4)."""
    redacted = text or ""
    for pattern, placeholder in _REDACTIONS:
        redacted = pattern.sub(placeholder, redacted)
    return redacted[:max_chars]


@dataclass
class SemanticSignal:
    label: str
    score: float
    rationale: str = ""


@runtime_checkable
class MessageSemanticAnalysisProvider(Protocol):
    provider_id: str

    def analyze_redacted_text(self, text: str) -> list[SemanticSignal]: ...
    def health(self) -> ProviderHealth: ...


@dataclass
class SemanticConfig:
    enabled: bool = False
    backend: str = "disabled"  # disabled|local|external
    model: str = ""
    endpoint: str = ""
    external_dpa_approved: bool = False
    max_chars: int = 4000
    min_score: float = 0.6

    def validate(self) -> None:
        if self.enabled and self.backend == "external" and not self.external_dpa_approved:
            raise ValueError("external semantic analysis requires an explicit DPA/security approval flag")


@dataclass
class DisabledSemanticProvider:
    """Default provider: performs no analysis and says so, rather than silently returning nothing."""

    provider_id: str = "semantic_disabled"
    config: SemanticConfig = field(default_factory=SemanticConfig)

    def analyze_redacted_text(self, text: str) -> list[SemanticSignal]:
        return []

    def health(self) -> ProviderHealth:
        return ProviderHealth(
            provider_id=self.provider_id,
            status="disabled",
            mode="disabled",
            detail="Semantic analysis is disabled by default (ТЗ 16.4)",
        )
