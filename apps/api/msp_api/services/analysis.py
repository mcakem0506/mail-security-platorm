"""Analysis pipeline: intake -> parse -> detect -> enrich -> verdict -> persist.

Local analysis always completes first and is persisted on its own; Threat Intelligence enrichment
is a separate, asynchronous stage that can only *raise* the verdict. A provider outage therefore
degrades enrichment, never the analysis or the add-in (ТЗ 2.3, 35).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from msp_contracts import (
    AnalysisStatus,
    IntakeSource,
    IOCType,
    JobState,
    RiskLevel,
    RiskVerdict,
    Severity,
    TIState,
)
from msp_detection import (
    ActiveException,
    AnalysisContext,
    DetectionPolicy,
    DetectionResult,
    DirectoryUser,
    EnrichmentInput,
    ScanFinding,
    SenderHistory,
    analyze,
    default_ruleset,
)
from msp_detection import (
    ProtectedIdentity as ProtectedIdentitySpec,
)
from msp_detection.auth import parse_authentication_results, parse_received_spf
from msp_detection.rules import RuleSet
from msp_mail_parser import ParsedMessage, ParserLimits, parse_message
from msp_risk import RISK_ENGINE_VERSION, RiskThresholds, employee_reasons, evaluate
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.base import utcnow
from ..db.models import (
    AnalysisJob,
    AnalysisResult,
    Attachment,
    DetectionException,
    DetectionSignal,
    Indicator,
    IndicatorObservation,
    MailboxIdentity,
    MailContent,
    MailHeader,
    MailMessage,
    MailRecipient,
    Organization,
    ProtectedIdentity,
    ProviderLookup,
    RiskVerdictHistory,
)
from .campaigns import build_fingerprint, correlate
from .storage import ObjectStorage, build_key

logger = logging.getLogger(__name__)

_STATUS_BY_RISK = {
    RiskLevel.LOW_RISK: AnalysisStatus.LOW_RISK,
    RiskLevel.SUSPICIOUS: AnalysisStatus.SUSPICIOUS,
    RiskLevel.HIGH_RISK: AnalysisStatus.HIGH_RISK,
    RiskLevel.MALICIOUS: AnalysisStatus.MALICIOUS,
    RiskLevel.UNKNOWN: AnalysisStatus.UNKNOWN,
}
_RULESET: RuleSet | None = None


def get_ruleset() -> RuleSet:
    global _RULESET
    if _RULESET is None:
        _RULESET = default_ruleset()
    return _RULESET


def reload_ruleset() -> RuleSet:
    global _RULESET
    _RULESET = default_ruleset()
    return _RULESET


# ---------------------------------------------------------------------------------------------
# Context assembly
# ---------------------------------------------------------------------------------------------
def build_context(
    session: Session,
    settings: Settings,
    *,
    organization_id: str,
    source: IntakeSource,
    reported_by: str | None = None,
    recipient_mailbox: str = "",
    sender_address: str = "",
    exclude_message_id: str | None = None,
) -> AnalysisContext:
    org = session.get(Organization, organization_id)
    corporate = tuple(org.corporate_domains or ()) if org else settings.corporate_domain_list
    trusted = tuple(org.trusted_infrastructure_domains or ()) if org else settings.trusted_infrastructure_list
    # Which upstream gateways the organisation actually runs. Per-organisation settings win over
    # the deployment default, because only the organisation knows what sits in front of Exchange.
    org_gateways = (org.settings or {}).get("trusted_gateways") if org else None
    trusted_gateways = (
        tuple(str(g).lower() for g in org_gateways) if org_gateways else settings.trusted_gateway_list
    )

    identities = (
        session.execute(
            select(ProtectedIdentity).where(
                ProtectedIdentity.organization_id == organization_id, ProtectedIdentity.enabled.is_(True)
            )
        )
        .scalars()
        .all()
    )
    protected = tuple(
        ProtectedIdentitySpec(
            identity_id=pi.id,
            display_name=pi.display_name,
            email=pi.email,
            categories=tuple(_as_categories(pi.categories)),
            aliases=tuple(pi.aliases or ()),
            name_variants=tuple(pi.name_variants or ()),
            approved_delegates=tuple(pi.approved_delegates or ()),
            approved_external_systems=tuple(pi.approved_external_systems or ()),
            department=pi.department,
            title=pi.title,
        )
        for pi in identities
    )

    directory = (
        session.execute(
            select(MailboxIdentity)
            .where(
                MailboxIdentity.organization_id == organization_id,
                MailboxIdentity.enabled.is_(True),
            )
            .limit(5000)
        )
        .scalars()
        .all()
    )
    users = tuple(
        DirectoryUser(
            email=d.address,
            display_name=d.display_name,
            aliases=tuple(d.aliases or ()),
            department=d.department,
            title=d.title,
        )
        for d in directory
        if d.display_name
    )

    now = utcnow()
    exceptions = (
        session.execute(
            select(DetectionException).where(
                DetectionException.organization_id == organization_id,
                DetectionException.revoked_at.is_(None),
            )
        )
        .scalars()
        .all()
    )
    active_exceptions = tuple(
        ActiveException(
            exception_id=e.id,
            exception_type=e.exception_type,
            value=e.value,
            rule_id=e.rule_id,
            owner=e.owner_email,
            reason=e.reason,
            expires_at=e.expires_at,
        )
        for e in exceptions
    )

    recipient = (
        session.execute(
            select(MailboxIdentity).where(
                MailboxIdentity.organization_id == organization_id,
                func.lower(MailboxIdentity.address) == recipient_mailbox.lower(),
            )
        ).scalar_one_or_none()
        if recipient_mailbox
        else None
    )
    recipient_protected = False
    if recipient is not None:
        recipient_protected = (
            session.execute(
                select(func.count())
                .select_from(ProtectedIdentity)
                .where(
                    ProtectedIdentity.organization_id == organization_id,
                    func.lower(ProtectedIdentity.email) == recipient.address.lower(),
                )
            ).scalar_one()
            > 0
        )

    return AnalysisContext(
        organization_id=organization_id,
        organization_name=org.name if org else settings.organization_name,
        corporate_domains=corporate,
        trusted_infrastructure_domains=trusted,
        trusted_gateways=trusted_gateways,
        protected_identities=protected,
        directory_users=users,
        exceptions=active_exceptions,
        policy=DetectionPolicy(
            suspicious_threshold=settings.suspicious_threshold,
            high_risk_threshold=settings.high_risk_threshold,
            malicious_threshold=settings.malicious_threshold,
            url_fetch_enabled=settings.url_fetch_enabled,
            semantic_analysis_enabled=settings.semantic_enabled,
        ),
        source=source,
        reported_by=reported_by,
        recipient_department=recipient.department if recipient else "",
        recipient_is_protected=recipient_protected,
        sender_history=_sender_history(
            session, organization_id, sender_address, exclude_message_id=exclude_message_id
        ),
        now=now,
    )


def _as_categories(values: Any) -> list[Any]:
    from msp_contracts import ProtectedCategory

    out = []
    for value in values or ():
        try:
            out.append(ProtectedCategory(str(value)))
        except ValueError:
            continue
    return out


def _sender_history(
    session: Session,
    organization_id: str,
    sender_address: str,
    *,
    exclude_message_id: str | None = None,
) -> SenderHistory:
    """History of *other* messages from this sender.

    The message under analysis must be excluded: it is already persisted by the time enrichment
    re-runs, and counting it would let a message mark its own sender as previously malicious.
    """
    if not sender_address:
        return SenderHistory()
    filters = [
        MailMessage.organization_id == organization_id,
        func.lower(MailMessage.sender_address) == sender_address.lower(),
    ]
    if exclude_message_id:
        filters.append(MailMessage.id != exclude_message_id)
    row = session.execute(
        select(
            func.count(MailMessage.id),
            func.min(MailMessage.received_at),
            func.count(MailMessage.reported_by),
        ).where(*filters)
    ).one()
    count, first_seen, reported = int(row[0] or 0), row[1], int(row[2] or 0)
    malicious = session.execute(
        select(func.count(AnalysisResult.id))
        .join(MailMessage, MailMessage.id == AnalysisResult.message_id)
        .where(*filters, AnalysisResult.classification == RiskLevel.MALICIOUS)
    ).scalar_one()
    return SenderHistory(
        known_sender=count > 0,
        first_seen=first_seen,
        message_count=count,
        previously_reported=reported,
        previously_malicious=int(malicious or 0),
    )


# ---------------------------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------------------------
@dataclass
class AnalysisOutcome:
    job: AnalysisJob
    message: MailMessage
    verdict: RiskVerdict
    detection: DetectionResult
    parsed: ParsedMessage
    duration_ms: int
    campaign_id: str | None = None
    warnings: list[str] = field(default_factory=list)


def persist_message(
    session: Session,
    parsed: ParsedMessage,
    *,
    organization_id: str,
    raw: bytes,
    source: IntakeSource,
    source_mailbox: str = "",
    exchange_item_id: str = "",
    reported_by: str | None = None,
    storage: ObjectStorage | None = None,
    store_raw: bool = True,
) -> MailMessage:
    """Store metadata in PostgreSQL and raw content in object storage (ТЗ 26.1)."""
    fingerprint = build_fingerprint(parsed)
    message = MailMessage(
        organization_id=organization_id,
        internet_message_id=parsed.message_id[:998],
        raw_sha256=parsed.sha256,
        subject=parsed.subject[:1000],
        sender_address=parsed.from_.address if parsed.from_ else "",
        sender_display_name=parsed.from_.display_name if parsed.from_ else "",
        sender_domain=parsed.from_.domain_ascii if parsed.from_ else "",
        reply_to_address=parsed.reply_to[0].address if parsed.reply_to else "",
        return_path=parsed.return_path,
        recipient_count=len(parsed.to) + len(parsed.cc),
        size_bytes=parsed.size,
        sent_at=parsed.date,
        received_at=parsed.date or utcnow(),
        source=source,
        source_mailbox=source_mailbox[:320],
        exchange_item_id=exchange_item_id[:512],
        has_attachments=any(a.meta.depth == 0 for a in parsed.attachments),
        url_count=len(parsed.urls),
        encrypted=parsed.encrypted,
        parse_errors=parsed.errors[:20],
        campaign_fingerprint=fingerprint.value,
        campaign_components=dict(fingerprint.components),
        body_simhash=fingerprint.simhash_hex,
        reported_by=reported_by,
    )
    session.add(message)
    session.flush()

    for kind, addresses in (("to", parsed.to), ("cc", parsed.cc)):
        for address in addresses[:200]:
            session.add(
                MailRecipient(
                    message_id=message.id,
                    address=address.address,
                    display_name=address.display_name,
                    kind=kind,
                )
            )
    for position, (name, value) in enumerate(parsed.headers[:200]):
        session.add(MailHeader(message_id=message.id, name=name, value=value[:8000], position=position))

    content = MailContent(
        message_id=message.id,
        normalized_text=parsed.normalized_text[:1_000_000] or None,
        sanitized_html=parsed.sanitized_html[:1_000_000] or None,
    )
    if storage is not None and store_raw:
        try:
            key = build_key("eml", parsed.sha256, organization_id=organization_id, extension="eml")
            storage.put(key, raw, content_type="message/rfc822")
            content.raw_eml_key = key
        except Exception as exc:  # noqa: BLE001 - analysis must not fail on storage problems
            logger.warning("storage.raw_eml_failed", extra={"error": type(exc).__name__})
    session.add(content)

    for att in parsed.attachments:
        meta = att.meta
        record = Attachment(
            message_id=message.id,
            filename=meta.filename,
            normalized_filename=meta.normalized_filename,
            declared_mime=meta.declared_mime,
            detected_type=meta.detected_type,
            extension=meta.extension,
            size_bytes=meta.size,
            sha256=meta.sha256,
            sha1=meta.sha1,
            md5=meta.md5,
            depth=meta.depth,
            parent_sha256=meta.parent_sha256,
            is_archive=meta.is_archive,
            encrypted=meta.encrypted,
            flags=list(meta.flags),
            archive_summary=meta.archive or {},
        )
        if storage is not None and att.content is not None and meta.depth == 0:
            try:
                key = build_key(
                    "attachment",
                    meta.sha256,
                    organization_id=organization_id,
                    extension=meta.extension or "bin",
                )
                storage.put(key, att.content)
                record.storage_key = key
            except Exception as exc:  # noqa: BLE001
                logger.warning("storage.attachment_failed", extra={"error": type(exc).__name__})
        session.add(record)

    auth = parse_authentication_results(parsed.authentication_results)
    auth.merge_received_spf(parse_received_spf(parsed.received_spf))
    facts = auth.as_facts()
    message.auth_summary = {
        method: facts.get(f"{method}_result")
        for method in ("spf", "dkim", "dmarc", "compauth")
        if facts.get(f"{method}_present")
    }
    return message


def persist_indicators(
    session: Session, *, organization_id: str, message_id: str, detection: DetectionResult
) -> None:
    now = utcnow()
    for ind in detection.indicators[:200]:
        existing = session.execute(
            select(Indicator).where(
                Indicator.organization_id == organization_id,
                Indicator.ioc_type == ind.ioc_type,
                Indicator.value == ind.value,
            )
        ).scalar_one_or_none()
        if existing is None:
            existing = Indicator(
                organization_id=organization_id,
                ioc_type=ind.ioc_type,
                value=ind.value[:1024],
                first_seen=now,
                last_seen=now,
                sighting_count=0,
            )
            session.add(existing)
            session.flush()
        existing.last_seen = now
        existing.sighting_count += 1
        session.add(
            IndicatorObservation(
                indicator_id=existing.id,
                message_id=message_id,
                context=ind.context[:64],
                observed_at=now,
            )
        )


def persist_result(
    session: Session,
    *,
    job: AnalysisJob,
    message: MailMessage,
    detection: DetectionResult,
    verdict: RiskVerdict,
) -> AnalysisResult:
    result = session.execute(
        select(AnalysisResult).where(AnalysisResult.job_id == job.id)
    ).scalar_one_or_none()
    if result is None:
        result = AnalysisResult(job_id=job.id, message_id=message.id, classification=verdict.classification)
        session.add(result)
        session.flush()
    else:
        for signal in list(result.signals):
            session.delete(signal)

    result.classification = verdict.classification
    result.score = verdict.score
    result.confidence = verdict.confidence
    result.confidence_value = verdict.confidence_value
    result.recommendation = verdict.recommendation
    result.reasons = [r.model_dump(mode="json") for r in verdict.reasons]
    result.hard_signals = [r.model_dump(mode="json") for r in verdict.hard_signals]
    result.suppressed_signals = [r.model_dump(mode="json") for r in verdict.suppressed]
    result.sources = list(verdict.sources)
    result.missing_evidence = list(verdict.missing_evidence)
    result.facts = {k: v for k, v in detection.facts.truthy().items() if k != "subject"}
    result.engine_version = detection.engine_version
    result.ruleset_fingerprint = detection.ruleset_fingerprint[:4000]
    result.risk_engine_version = RISK_ENGINE_VERSION

    for detected in detection.signals:
        session.add(
            DetectionSignal(
                result_id=result.id,
                signal_id=detected.id,
                rule_id=detected.rule_id,
                rule_version=detected.rule_version,
                category=detected.category,
                title=detected.title,
                explanation=detected.explanation,
                severity=detected.severity,
                confidence=detected.confidence,
                weight=detected.weight,
                source=detected.source,
                evidence=detected.evidence,
                hard=detected.hard,
                internal=detected.internal,
                suppressed=detected.suppressed,
                suppressed_by=detected.suppressed_by,
                observed_at=detected.observed_at,
            )
        )
    return result


# ---------------------------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------------------------
def run_local_analysis(
    session: Session,
    settings: Settings,
    *,
    job: AnalysisJob,
    raw: bytes,
    storage: ObjectStorage | None = None,
    scan_findings: list[ScanFinding] | None = None,
) -> AnalysisOutcome:
    """Stage 1: parsing, local detection and an explainable verdict — no external calls."""
    started = time.monotonic()
    job.state = JobState.ANALYZING
    job.status = AnalysisStatus.ANALYZING
    job.started_at = utcnow()
    session.flush()

    parsed = parse_message(raw, ParserLimits())
    context = build_context(
        session,
        settings,
        organization_id=job.organization_id,
        source=job.source,
        reported_by=job.requester_mailbox or None,
        recipient_mailbox=job.requester_mailbox,
        sender_address=parsed.from_.address if parsed.from_ else "",
    )
    message = persist_message(
        session,
        parsed,
        organization_id=job.organization_id,
        raw=raw,
        source=job.source,
        source_mailbox=job.requester_mailbox,
        reported_by=job.requester_mailbox if job.is_report else None,
        storage=storage,
    )
    job.message_id = message.id
    # History was computed before this message existed; keep it that way for the flushed row.
    context.sender_history = _sender_history(
        session,
        job.organization_id,
        parsed.from_.address if parsed.from_ else "",
        exclude_message_id=message.id,
    )

    enrichment = EnrichmentInput(scan_findings=list(scan_findings or []), ti_configured=False)
    detection = analyze(parsed, context, enrichment, ruleset=get_ruleset())
    verdict = evaluate(
        detection.signals,
        missing_evidence=detection.facts.missing_evidence,
        thresholds=RiskThresholds(
            settings.suspicious_threshold, settings.high_risk_threshold, settings.malicious_threshold
        ),
        analysis_complete=False,  # TI enrichment has not run yet
        content_encrypted=parsed.encrypted,
        unparseable=not parsed.parse_ok,
    )
    persist_indicators(
        session, organization_id=job.organization_id, message_id=message.id, detection=detection
    )
    persist_result(session, job=job, message=message, detection=detection, verdict=verdict)

    correlation = correlate(
        session,
        organization_id=job.organization_id,
        message=message,
        fingerprint=build_fingerprint(parsed),
        classification=verdict.classification.value,
    )
    duration = int((time.monotonic() - started) * 1000)
    job.state = JobState.PARTIAL
    job.ti_state = TIState.PENDING if collect_ti_indicators(detection) else TIState.NOT_REQUIRED
    job.status = _STATUS_BY_RISK[verdict.classification]
    job.duration_ms = duration
    job.warnings = list(parsed.limits_hit)
    session.add(
        RiskVerdictHistory(
            message_id=message.id,
            classification=verdict.classification,
            score=verdict.score,
            reason="local analysis",
        )
    )
    return AnalysisOutcome(
        job=job,
        message=message,
        verdict=verdict,
        detection=detection,
        parsed=parsed,
        duration_ms=duration,
        campaign_id=correlation.campaign.id if correlation.campaign else None,
    )


def apply_enrichment(
    session: Session,
    settings: Settings,
    *,
    job: AnalysisJob,
    parsed: ParsedMessage,
    detection: DetectionResult,
    enrichment: EnrichmentInput,
) -> RiskVerdict:
    """Stage 2: re-evaluate with Threat Intelligence. Enrichment can only raise the verdict."""
    message = session.get(MailMessage, job.message_id) if job.message_id else None
    if message is None:
        raise ValueError("cannot apply enrichment: job has no message")

    context = build_context(
        session,
        settings,
        organization_id=job.organization_id,
        source=job.source,
        reported_by=job.requester_mailbox or None,
        recipient_mailbox=job.requester_mailbox,
        sender_address=message.sender_address,
        exclude_message_id=message.id,
    )
    updated = analyze(parsed, context, enrichment, ruleset=get_ruleset())
    verdict = evaluate(
        updated.signals,
        missing_evidence=updated.facts.missing_evidence,
        thresholds=RiskThresholds(
            settings.suspicious_threshold, settings.high_risk_threshold, settings.malicious_threshold
        ),
        analysis_complete=True,
        content_encrypted=parsed.encrypted,
        unparseable=not parsed.parse_ok,
    )
    for result in enrichment.ti_results[:200]:
        session.add(
            ProviderLookup(
                analysis_job_id=job.id,
                provider_id=result.provider_id,
                ioc_type=result.ioc_type,
                indicator_value=result.indicator[:1024],
                status=result.status,
                malicious_count=result.malicious_count,
                total_count=result.total_count,
                categories=list(result.categories),
                summary=dict(result.summary),
                from_cache=result.from_cache,
                latency_ms=result.latency_ms,
                error=result.error,
                fetched_at=result.fetched_at,
            )
        )
        if result.status.value == "KNOWN_BAD":
            indicator = session.execute(
                select(Indicator).where(
                    Indicator.organization_id == job.organization_id,
                    Indicator.value == result.indicator.lower(),
                )
            ).scalar_one_or_none()
            if indicator is not None:
                indicator.worst_status = result.status

    previous = session.execute(
        select(AnalysisResult).where(AnalysisResult.job_id == job.id)
    ).scalar_one_or_none()
    previous_classification = previous.classification if previous else None
    persist_result(session, job=job, message=message, detection=updated, verdict=verdict)

    failed = any(
        r.status.value in {"RATE_LIMITED", "PROVIDER_UNAVAILABLE", "ERROR"} for r in enrichment.ti_results
    )
    job.ti_state = (
        TIState.PARTIAL
        if failed and enrichment.ti_results
        else TIState.COMPLETED
        if enrichment.ti_results
        else TIState.NOT_CONFIGURED
        if not enrichment.ti_configured
        else TIState.UNAVAILABLE
    )
    job.state = JobState.COMPLETED
    job.status = _STATUS_BY_RISK[verdict.classification]
    job.finished_at = utcnow()
    if previous_classification != verdict.classification:
        session.add(
            RiskVerdictHistory(
                message_id=message.id,
                classification=verdict.classification,
                score=verdict.score,
                reason="threat intelligence enrichment",
            )
        )
    return verdict


def collect_ti_indicators(detection: DetectionResult, limit: int = 40) -> list[Any]:
    """Indicators worth an external lookup; internal-only types are filtered out by the hub."""
    wanted = {IOCType.SHA256, IOCType.DOMAIN, IOCType.URL, IOCType.IPV4, IOCType.IPV6}
    return [i for i in detection.indicators if i.ioc_type in wanted][:limit]


def employee_view(verdict: RiskVerdict, job: AnalysisJob, limit: int = 5) -> dict[str, Any]:
    """The employee-facing projection (ТЗ 6.4): no internal rules, no raw provider data."""
    return {
        "job_id": job.id,
        "status": job.status.value,
        "classification": verdict.classification.value,
        "confidence": verdict.confidence,
        "recommendation": verdict.recommendation,
        "reasons": [
            {"title": r.title, "explanation": r.explanation, "severity": r.severity.value}
            for r in employee_reasons(verdict, limit)
        ],
        "analysis_incomplete": bool(verdict.missing_evidence),
        "analyzed_at": (job.finished_at or job.started_at or utcnow()).isoformat(),
        "reported_to_security": job.is_report,
        "ti_state": job.ti_state.value,
    }


def severity_for_incident(verdict: RiskVerdict) -> Severity:
    return {
        RiskLevel.MALICIOUS: Severity.CRITICAL,
        RiskLevel.HIGH_RISK: Severity.HIGH,
        RiskLevel.SUSPICIOUS: Severity.MEDIUM,
    }.get(verdict.classification, Severity.LOW)
