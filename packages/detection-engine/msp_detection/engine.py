"""Detection engine entry point: ParsedMessage + context -> facts + signals.

External enrichment (TI, AV, semantic analysis) is merged as *facts* before rule evaluation, so
enrichment and local detection share one explainable pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from msp_contracts import TI_FAILURE_STATUSES, Indicator, IOCType, Signal, TIResult, TIStatus
from msp_mail_parser import ParsedMessage

from .context import AnalysisContext
from .facts import FactSet, build_facts
from .rules import RuleSet, default_ruleset

ENGINE_VERSION = "detection-1.0.0"


@dataclass
class ScanFinding:
    """Result of a local malware scanner for one attachment."""

    sha256: str
    filename: str
    malicious: bool
    signature: str | None = None
    scanner: str = ""


@dataclass
class EnrichmentInput:
    ti_results: list[TIResult] = field(default_factory=list)
    scan_findings: list[ScanFinding] = field(default_factory=list)
    semantic_signals: list[str] = field(default_factory=list)
    campaign_matches: list[dict[str, Any]] = field(default_factory=list)
    incident_indicator_hits: list[str] = field(default_factory=list)
    ti_configured: bool = False


def _ti_facts(fs: FactSet, enrichment: EnrichmentInput) -> None:
    by_type: dict[IOCType, list[TIResult]] = {}
    for r in enrichment.ti_results:
        by_type.setdefault(r.ioc_type, []).append(r)

    mapping = {
        IOCType.URL: ("ti_url_known_bad", "ti_url_suspicious"),
        IOCType.DOMAIN: ("ti_domain_known_bad", "ti_domain_suspicious"),
        IOCType.IPV4: ("ti_ip_known_bad", "ti_ip_suspicious"),
        IOCType.IPV6: ("ti_ip_known_bad", "ti_ip_suspicious"),
        IOCType.SHA256: ("ti_file_known_bad", "ti_file_suspicious"),
        IOCType.EMAIL: ("ti_sender_known_bad", "ti_sender_suspicious"),
    }
    failures: list[str] = []
    any_answer = False
    for ioc_type, results in by_type.items():
        bad_fact, susp_fact = mapping.get(ioc_type, (None, None))
        for r in results:
            if r.status in TI_FAILURE_STATUSES:
                failures.append(f"{r.provider_id}:{r.status.value}")
                continue
            if r.status not in {TIStatus.NOT_SUPPORTED, TIStatus.POLICY_BLOCKED}:
                any_answer = True
            ev = {
                "provider": r.provider_id,
                "indicator": r.indicator,
                "status": r.status.value,
                "malicious_count": r.malicious_count,
                "categories": r.categories[:5],
                "fetched_at": r.fetched_at.isoformat(),
                "from_cache": r.from_cache,
            }
            if r.status == TIStatus.KNOWN_BAD and bad_fact:
                fs.set(bad_fact, True, **ev)
            elif r.status == TIStatus.SUSPICIOUS and susp_fact:
                fs.set(susp_fact, True, **ev)
            if ioc_type == IOCType.DOMAIN and r.first_seen is not None:
                age_days = (fs.get("_now_ts") or 0) and 0  # age computed by caller policy
                if r.summary.get("recently_registered") or r.summary.get("domain_age_days", 999) < 30:
                    fs.set(
                        "ti_domain_recently_registered",
                        True,
                        provider=r.provider_id,
                        indicator=r.indicator,
                        first_seen=r.first_seen.isoformat(),
                        domain_age_days=r.summary.get("domain_age_days", age_days),
                    )
    if failures:
        fs.set("ti_providers_unavailable", True, providers=sorted(set(failures))[:6])
        fs.missing_evidence.append("Threat Intelligence enrichment incomplete: " + ", ".join(sorted(set(failures))[:3]))
    if not enrichment.ti_configured:
        fs.missing_evidence.append("No external Threat Intelligence provider is configured")
    elif not any_answer and enrichment.ti_results:
        fs.missing_evidence.append("Threat Intelligence returned no usable data")


def _scan_facts(fs: FactSet, enrichment: EnrichmentInput) -> None:
    for finding in enrichment.scan_findings:
        if finding.malicious:
            fs.set(
                "av_detection",
                True,
                scanner=finding.scanner,
                signature=finding.signature,
                filename=finding.filename,
                sha256=finding.sha256,
            )


def _extra_facts(fs: FactSet, enrichment: EnrichmentInput) -> None:
    for sig in enrichment.semantic_signals:
        fs.set("semantic_social_engineering", True, signals=enrichment.semantic_signals[:5])
        break
    active = [c for c in enrichment.campaign_matches if c.get("confirmed_malicious")]
    if active:
        fs.set(
            "known_active_campaign",
            True,
            campaign_id=active[0].get("campaign_id"),
            messages=active[0].get("message_count"),
        )
    if enrichment.incident_indicator_hits:
        fs.set(
            "indicator_seen_in_confirmed_incident",
            True,
            indicators=enrichment.incident_indicator_hits[:5],
        )


@dataclass
class DetectionResult:
    facts: FactSet
    signals: list[Signal]
    indicators: list[Indicator]
    ruleset_fingerprint: str
    engine_version: str = ENGINE_VERSION

    @property
    def active_signals(self) -> list[Signal]:
        return [s for s in self.signals if not s.suppressed]

    @property
    def suppressed_signals(self) -> list[Signal]:
        return [s for s in self.signals if s.suppressed]


def analyze(
    msg: ParsedMessage,
    ctx: AnalysisContext,
    enrichment: EnrichmentInput | None = None,
    ruleset: RuleSet | None = None,
) -> DetectionResult:
    rules = ruleset or default_ruleset()
    fs = build_facts(msg, ctx)
    if enrichment is not None:
        _ti_facts(fs, enrichment)
        _scan_facts(fs, enrichment)
        _extra_facts(fs, enrichment)
    signals = rules.evaluate(fs, ctx)
    return DetectionResult(
        facts=fs,
        signals=signals,
        indicators=fs.indicators,
        ruleset_fingerprint=rules.version_fingerprint,
    )
