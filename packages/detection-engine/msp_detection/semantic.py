"""Optional semantic analysis of message intent (ТЗ 1.0.3B §34).

Disabled by default, and built so that enabling it cannot change the shape of a verdict:

* **a semantic signal can never produce MALICIOUS on its own.** It is a fact among facts, never
  a verdict. A model that can condemn a message by itself is a model whose mistakes nobody can
  argue with — and the whole product rests on verdicts an analyst can argue with.
* **no external SaaS model without an explicit policy decision.** The default provider is local
  and reads nothing out of the organisation. An on-premise model is the preferred alternative;
  a hosted one requires the policy gate, like any other outbound lookup.
* **unavailability is not cleanliness.** When the provider is off or unreachable, the facts are
  simply absent and the scan is marked incomplete. "The model said nothing" must never read the
  same as "the model found nothing".

The local provider is the regex intent analysis the platform already uses. It is kept behind the
same interface so a deployment that adds a model is adding a second opinion to an existing one
rather than replacing the only one it has.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

logger = logging.getLogger(__name__)

#: Intents the stage asks for (§34). Names match the facts the rules already consume, so a
#: semantic provider contributes to the same vocabulary rather than inventing a parallel one.
SEMANTIC_INTENTS: tuple[str, ...] = (
    "intent_payment_request",
    "intent_credential_request",
    "tone_secrecy",
    "tone_urgency",
    "intent_executive_context",
    "intent_unusual_supplier_request",
)

#: Weight ceiling for a semantic signal. Chosen so that semantic facts alone cannot cross the
#: MALICIOUS threshold however many of them fire: they can raise suspicion, never settle it.
MAX_SEMANTIC_WEIGHT = 20.0


@dataclass
class SemanticFinding:
    """One intent the provider believes it found."""

    fact: str
    confidence: float
    evidence: str = ""
    model: str = "local"

    def as_dict(self) -> dict[str, Any]:
        return {
            "fact": self.fact,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence[:200],
            "model": self.model,
        }


@dataclass
class SemanticResult:
    findings: list[SemanticFinding] = field(default_factory=list)
    provider: str = "disabled"
    available: bool = False
    #: Set when the provider was asked and could not answer. The caller turns this into missing
    #: evidence, because a question nobody answered is not an answer.
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "available": self.available,
            "error": self.error,
            "findings": [finding.as_dict() for finding in self.findings],
        }


class SemanticAnalysisProvider(Protocol):
    """What a semantic provider has to offer."""

    provider_id: str

    def available(self) -> bool: ...

    def analyze(self, *, subject: str, body: str, language: str = "ru") -> SemanticResult: ...


class DisabledSemanticProvider:
    """The default: answers nothing, and says so.

    Chosen as the default deliberately. A platform whose detection quietly depends on a model
    being switched on is a platform that behaves differently in two deployments for reasons
    nobody wrote down.
    """

    provider_id = "disabled"

    def available(self) -> bool:
        return False

    def analyze(self, *, subject: str, body: str, language: str = "ru") -> SemanticResult:
        _ = subject, body, language
        return SemanticResult(provider=self.provider_id, available=False)


class LocalSemanticProvider:
    """Intent analysis that runs inside the deployment, with no model and no network.

    This is the regex intent analysis the platform already performs, exposed through the
    semantic interface so that a deployment adding a model is adding a second opinion rather
    than acquiring its first one.
    """

    provider_id = "local"

    def available(self) -> bool:
        return True

    def analyze(self, *, subject: str, body: str, language: str = "ru") -> SemanticResult:
        from .bec import _INTENTS

        _ = language
        text = f"{subject}\n{body}"[:100_000]
        result = SemanticResult(provider=self.provider_id, available=True)
        for intent in _INTENTS:
            hits = [
                re.sub(r"\s+", " ", match.group(0))[:200]
                for pattern in intent.patterns
                if (match := re.search(pattern, text))
            ]
            if len(hits) >= intent.min_hits:
                result.findings.append(
                    SemanticFinding(
                        fact=intent.fact,
                        confidence=0.6,
                        evidence=hits[0],
                        model="patterns",
                    )
                )
        return result


def cap_semantic_signals(signals: list[Any]) -> list[Any]:
    """Hold semantic signals below the weight that could settle a verdict (ТЗ 1.0.3B §34).

    Applied where signals are assembled rather than inside a rule, so the guarantee does not
    depend on every future rule author remembering it. A semantic signal also never counts as
    hard: a hard signal pins a classification, which is exactly the authority a model must not
    have.
    """
    for signal in signals:
        if str(getattr(signal, "source", "")) != "semantic":
            continue
        if getattr(signal, "weight", 0.0) > MAX_SEMANTIC_WEIGHT:
            signal.weight = MAX_SEMANTIC_WEIGHT
        signal.hard = False
    return signals


def build_provider(kind: str = "disabled") -> SemanticAnalysisProvider:
    """Pick a provider by name.

    An external hosted model is not constructible here. Sending corporate mail bodies to a SaaS
    model is a policy decision with its own gate (ТЗ 1.0.3B §34, 1.0.3 §41), and a provider that
    could be switched on by a configuration string would route around that decision.
    """
    match kind:
        case "local":
            return LocalSemanticProvider()
        case "disabled" | "":
            return DisabledSemanticProvider()
    logger.warning("semantic.unknown_provider", extra={"kind": kind})
    return DisabledSemanticProvider()
