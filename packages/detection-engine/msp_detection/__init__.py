"""Rule-based, explainable mail detection engine."""

from .context import (
    ActiveException,
    AnalysisContext,
    DetectionPolicy,
    DirectoryUser,
    ProtectedIdentity,
    SenderHistory,
)
from .engine import ENGINE_VERSION, DetectionResult, EnrichmentInput, ScanFinding, analyze
from .facts import FactSet, build_facts
from .gateway import GatewayFindings, gateway_facts
from .rules import Rule, RuleError, RuleSet, default_ruleset
from .similarity import (
    compare_labels,
    has_homoglyph,
    has_mixed_script_token,
    is_personal_name,
    name_similarity,
    skeleton,
)

__all__ = [
    "ENGINE_VERSION",
    "ActiveException",
    "AnalysisContext",
    "DetectionPolicy",
    "DetectionResult",
    "DirectoryUser",
    "EnrichmentInput",
    "FactSet",
    "GatewayFindings",
    "ProtectedIdentity",
    "Rule",
    "RuleError",
    "RuleSet",
    "ScanFinding",
    "SenderHistory",
    "analyze",
    "build_facts",
    "compare_labels",
    "default_ruleset",
    "gateway_facts",
    "has_homoglyph",
    "has_mixed_script_token",
    "is_personal_name",
    "name_similarity",
    "skeleton",
]
