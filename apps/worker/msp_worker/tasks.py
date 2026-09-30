"""Background tasks: enrichment, scanning, mailbox intake, directory sync, retention.

Every task is defensive: an external failure degrades that task only, is recorded on the job,
and never rolls back the local analysis that already succeeded (ТЗ 2.3).
"""

from __future__ import annotations

import io
import logging
from datetime import timedelta
from typing import Any

from msp_api.config import get_settings
from msp_api.db.base import utcnow
from msp_api.db.models import (
    AnalysisJob,
    AnalysisResult,
    Attachment,
    AuditEvent,
    Campaign,
    DetectionException,
    DirectorySyncRun,
    Indicator,
    IntakeRecord,
    MailboxIdentity,
    MailContent,
    MailMessage,
    Notification,
    Organization,
    ProviderLookup,
    RetentionRun,
)
from msp_api.db.session import session_scope
from msp_api.deps import get_scanner, get_ti_hub
from msp_api.observability import (
    analyses_total,
    analysis_duration,
    duplicate_report,
    intake_backlog,
    intake_failed,
    intake_retry,
    intake_success,
    provider_errors,
    provider_latency,
    provider_rate_limit,
    unscannable_total,
)
from msp_api.security.audit import AuditAction, record
from msp_api.services.analysis import (
    apply_enrichment,
    build_context,
    collect_ti_indicators,
    get_ruleset,
    run_local_analysis,
)
from msp_api.services.intake import (
    attach_job,
    begin_intake,
    intake_stats,
    mark_acknowledged,
    mark_failed,
    unscannable_job,
)
from msp_api.services.protected_identities import parse_protected_groups
from msp_api.services.protected_identities import sync_from_directory as sync_protected_identities
from msp_api.services.storage import build_storage
from msp_contracts import (
    AnalysisStatus,
    IntakeSource,
    IntakeState,
    JobState,
    RiskLevel,
    TIState,
    TIStatus,
)
from msp_detection import EnrichmentInput, ScanFinding
from msp_mail_parser import parse_message
from sqlalchemy import delete, func, select

from .app import celery_app

logger = logging.getLogger(__name__)

_MALICIOUS_LEVELS = {RiskLevel.MALICIOUS, RiskLevel.HIGH_RISK}


def _load_parsed(session, job: AnalysisJob, settings):  # type: ignore[no-untyped-def]
    """Re-read the raw EML from object storage for a second-stage evaluation."""
    content = session.execute(
        select(MailContent).where(MailContent.message_id == job.message_id)
    ).scalar_one_or_none()
    if content is None or not content.raw_eml_key:
        return None
    try:
        raw = build_storage(settings).get(content.raw_eml_key)
    except Exception as exc:  # noqa: BLE001
        logger.warning("worker.raw_eml_unavailable", extra={"error": type(exc).__name__})
        return None
    return parse_message(raw)


@celery_app.task(name="msp.enrich_analysis", bind=True, max_retries=2, default_retry_delay=30)
def enrich_analysis(self, job_id: str) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    """Stage 2: Threat Intelligence enrichment plus local scanning (ТЗ 13, 35)."""
    settings = get_settings()
    with session_scope() as session:
        job = session.get(AnalysisJob, job_id)
        if job is None or job.message_id is None:
            return {"job_id": job_id, "skipped": "job or message missing"}
        if job.state is JobState.COMPLETED:
            return {"job_id": job_id, "skipped": "already complete"}

        parsed = _load_parsed(session, job, settings)
        if parsed is None:
            job.ti_state = TIState.UNAVAILABLE
            job.state = JobState.COMPLETED
            job.finished_at = utcnow()
            job.warnings = [*(job.warnings or []), "raw message unavailable for enrichment"]
            return {"job_id": job_id, "skipped": "raw message unavailable"}

        context = build_context(
            session,
            settings,
            organization_id=job.organization_id,
            source=job.source,
            recipient_mailbox=job.requester_mailbox,
            sender_address=parsed.from_.address if parsed.from_ else "",
            exclude_message_id=job.message_id,
        )
        from msp_detection import analyze

        detection = analyze(parsed, context, ruleset=get_ruleset())

        hub = get_ti_hub()
        ti_results = []
        if hub.configured:
            try:
                ti_results = hub.enrich(collect_ti_indicators(detection))
            except Exception as exc:  # noqa: BLE001 - enrichment failure is not analysis failure
                logger.warning("worker.ti_failed", extra={"error": type(exc).__name__})
                provider_errors.labels("hub", type(exc).__name__).inc()
        for result in ti_results:
            if result.latency_ms is not None:
                provider_latency.labels(result.provider_id).observe(result.latency_ms / 1000)
            if result.status is TIStatus.RATE_LIMITED:
                provider_rate_limit.labels(result.provider_id).inc()
            elif result.status in {TIStatus.ERROR, TIStatus.PROVIDER_UNAVAILABLE}:
                provider_errors.labels(result.provider_id, result.status.value).inc()

        scan_findings = _scan_attachments(session, job, settings)
        enrichment = EnrichmentInput(
            ti_results=ti_results,
            scan_findings=scan_findings,
            campaign_matches=_campaign_matches(session, job),
            incident_indicator_hits=_incident_indicator_hits(session, job, detection),
            ti_configured=hub.configured,
        )
        verdict = apply_enrichment(
            session, settings, job=job, parsed=parsed, detection=detection, enrichment=enrichment
        )
        analyses_total.labels(verdict.classification.value, job.source.value).inc()
        if job.duration_ms:
            analysis_duration.labels("enriched").observe(job.duration_ms / 1000)

        if verdict.classification in _MALICIOUS_LEVELS:
            analysed = session.get(MailMessage, job.message_id)
            subject = (analysed.subject if analysed else "")[:120]
            _queue_notification(
                session,
                organization_id=job.organization_id,
                event="high_risk" if verdict.classification is RiskLevel.HIGH_RISK else "malicious",
                subject=f"[{verdict.classification.value}] {subject}",
                recipient=settings.security_team_email,
                payload={"job_id": job.id, "message_id": job.message_id, "score": verdict.score},
            )
        return {
            "job_id": job_id,
            "classification": verdict.classification.value,
            "ti_results": len(ti_results),
            "ti_state": job.ti_state.value,
        }


def _scan_attachments(session, job: AnalysisJob, settings) -> list[ScanFinding]:  # type: ignore[no-untyped-def]
    """Scan retained attachments with the local scanner, if one is configured (ТЗ 12.3)."""
    findings: list[ScanFinding] = []
    scanner = get_scanner()
    if scanner.health().status not in {"ok", "degraded"}:
        return findings
    storage = build_storage(settings)
    attachments = (
        session.execute(
            select(Attachment).where(
                Attachment.message_id == job.message_id,
                Attachment.storage_key.is_not(None),
                Attachment.purged_at.is_(None),
            )
        )
        .scalars()
        .all()
    )
    for attachment in attachments:
        try:
            data = storage.get(attachment.storage_key)
            result = scanner.scan_stream(io.BytesIO(data), size=len(data))
        except Exception as exc:  # noqa: BLE001
            logger.warning("worker.scan_failed", extra={"error": type(exc).__name__})
            attachment.scan_result = {"error": type(exc).__name__, "conclusive": False}
            continue
        attachment.scan_result = {
            "scanner": result.scanner,
            "malicious": result.malicious,
            "signature": result.signature,
            "conclusive": result.conclusive,
            "checked_at": utcnow().isoformat(),
        }
        if result.malicious:
            findings.append(
                ScanFinding(
                    sha256=attachment.sha256,
                    filename=attachment.normalized_filename,
                    malicious=True,
                    signature=result.signature,
                    scanner=result.scanner,
                )
            )
    return findings


def _campaign_matches(session, job: AnalysisJob) -> list[dict[str, Any]]:  # type: ignore[no-untyped-def]
    from msp_api.db.models import CampaignMessage

    campaign_id = session.execute(
        select(CampaignMessage.campaign_id).where(CampaignMessage.message_id == job.message_id)
    ).scalar_one_or_none()
    if campaign_id is None:
        return []
    campaign = session.get(Campaign, campaign_id)
    if campaign is None:
        return []
    return [
        {
            "campaign_id": campaign.id,
            "message_count": campaign.message_count,
            "confirmed_malicious": campaign.confirmed_malicious,
        }
    ]


def _incident_indicator_hits(session, job: AnalysisJob, detection) -> list[str]:  # type: ignore[no-untyped-def]
    values = [i.value for i in detection.indicators[:100]]
    if not values:
        return []
    rows = (
        session.execute(
            select(Indicator.value).where(
                Indicator.organization_id == job.organization_id,
                Indicator.value.in_(values),
                Indicator.confirmed_malicious.is_(True),
            )
        )
        .scalars()
        .all()
    )
    return list(rows)[:10]


@celery_app.task(name="msp.poll_security_mailbox")
def poll_security_mailbox() -> dict[str, Any]:
    """Durable intake from the security mailbox (ТЗ 7.2, ТЗ 1.0.1 §4.1).

    The order of operations is the whole point: the message is recorded, stored and queued, the
    transaction is committed, and only then is the mailbox told. A worker that dies at any step
    before the commit leaves the message untouched, so the next poll picks it up again; one that
    dies after the commit causes a re-fetch that deduplication turns into a no-op.

    Acknowledgement happens *outside* the transaction on purpose. An IMAP move cannot take part
    in a database transaction, so one of the two must go second — and a message acknowledged
    before the commit would be lost, while a message committed before the acknowledgement is
    merely seen twice.
    """
    settings = get_settings()
    if settings.exchange_provider != "security_mailbox" or not settings.security_mailbox_host:
        return {"skipped": "security mailbox not configured"}

    from msp_exchange import SecurityMailboxConfig, SecurityMailboxProvider

    provider = SecurityMailboxProvider(
        SecurityMailboxConfig(
            host=settings.security_mailbox_host,
            port=settings.security_mailbox_port,
            username=settings.security_mailbox_user,
            password=settings.security_mailbox_password,
            folder=settings.security_mailbox_folder,
            use_ssl=settings.security_mailbox_ssl,
            ca_file=settings.security_mailbox_ca_file,
            max_message_size=settings.limit_message_size,
        )
    )
    try:
        reports = provider.fetch_unprocessed()
    except Exception as exc:  # noqa: BLE001
        logger.warning("worker.mailbox_poll_failed", extra={"error": type(exc).__name__})
        return {"error": type(exc).__name__}

    source_id = f"{settings.security_mailbox_user}:{settings.security_mailbox_folder}"
    summary = {"fetched": len(reports), "processed": 0, "duplicates": 0, "unscannable": 0, "failed": 0}
    # (uid, disposition) pairs, applied to the mailbox only after the transaction commits.
    acknowledgements: list[tuple[str, str]] = []

    for report in reports:
        with session_scope() as session:
            org = session.execute(select(Organization)).scalars().first()
            if org is None:
                return {"skipped": "no organization configured"}
            disposition = _ingest_report(session, settings, org.id, source_id, report, summary)
        if disposition:
            acknowledgements.append((report.uid, disposition))

    for uid, disposition in acknowledgements:
        try:
            moved = provider.ack(uid) if disposition == "ack" else provider.fail(uid)
        except Exception as exc:  # noqa: BLE001 - a failed move only causes a harmless re-fetch
            logger.warning("worker.mailbox_ack_failed", extra={"error": type(exc).__name__})
            continue
        if moved and disposition == "ack":
            with session_scope() as session:
                record = session.execute(
                    select(IntakeRecord).where(
                        IntakeRecord.source_id == source_id, IntakeRecord.mailbox_uid == uid
                    )
                ).scalar_one_or_none()
                if record is not None and record.state is not IntakeState.DUPLICATE:
                    mark_acknowledged(record)

    with session_scope() as session:
        org = session.execute(select(Organization)).scalars().first()
        if org is not None:
            for state, count in intake_stats(session, org.id)["by_state"].items():
                intake_backlog.labels(state).set(count)
    return summary


def _ingest_report(session, settings, organization_id, source_id, report, summary):  # type: ignore[no-untyped-def]
    """Persist one report and queue its analysis. Returns how to dispose of the mailbox item."""
    outcome = begin_intake(
        session,
        settings,
        organization_id=organization_id,
        source=IntakeSource.SECURITY_MAILBOX,
        source_id=source_id,
        mailbox_uid=report.uid,
        raw=report.raw_mime,
        internet_message_id=report.internet_message_id,
        content_sha256=report.content_sha256,
        reported_by=report.reported_by,
        oversized=report.oversized,
        actual_size=report.actual_size,
        warnings=report.warnings,
        storage=build_storage(settings),
    )
    record = outcome.record

    if outcome.is_duplicate:
        # A repeat report is not noise: several people reporting the same message is how a
        # campaign becomes visible. It is linked to the first one rather than re-analysed.
        summary["duplicates"] += 1
        duplicate_report.inc()
        return "ack"

    if record.state is IntakeState.ACKNOWLEDGED:
        return "ack"

    if report.oversized:
        # Deliberately not analysed. The job exists and says UNKNOWN, so nothing anywhere in
        # the product can present this message as checked (ТЗ 1.0.1 §4.2).
        reason = (
            f"письмо размером {report.actual_size} байт превышает предел анализа "
            f"({settings.limit_message_size}); анализ не выполнялся"
        )
        job = unscannable_job(session, organization_id=organization_id, record=record, reason=reason)
        summary["unscannable"] += 1
        unscannable_total.labels("message_size").inc()
        _queue_notification(
            session,
            organization_id=organization_id,
            event="unscannable",
            subject="Письмо не проверено: превышен предел размера",
            recipient=settings.security_team_email,
            payload={"analysis_job_id": job.id, "size_bytes": report.actual_size},
            body=reason,
        )
        return "ack"

    job = AnalysisJob(
        organization_id=organization_id,
        source=IntakeSource.SECURITY_MAILBOX,
        requester_mailbox=report.reported_by,
        is_report=True,
        user_note=report.note[:2000],
        idempotency_key=f"intake:{record.id}",
    )
    session.add(job)
    session.flush()
    try:
        run_local_analysis(session, settings, job=job, raw=report.raw_mime, storage=build_storage(settings))
    except Exception as exc:
        logger.exception("worker.mailbox_analysis_failed", extra={"analysis_job_id": job.id})
        job.state = JobState.FAILED
        job.status = AnalysisStatus.ERROR
        job.error = type(exc).__name__
        dead_lettered = mark_failed(record, type(exc).__name__)
        if dead_lettered:
            summary["failed"] += 1
            intake_failed.labels(IntakeSource.SECURITY_MAILBOX.value).inc()
            return "fail"
        intake_retry.labels(IntakeSource.SECURITY_MAILBOX.value, type(exc).__name__).inc()
        return ""

    if report.warnings:
        job.warnings = [*(job.warnings or []), *report.warnings]
    attach_job(record, job)
    summary["processed"] += 1
    intake_success.labels(IntakeSource.SECURITY_MAILBOX.value).inc()
    enrich_analysis.delay(job.id)
    return "ack"


@celery_app.task(name="msp.sync_directory")
def sync_directory() -> dict[str, Any]:
    """Read-only Active Directory sync (ТЗ 10)."""
    settings = get_settings()
    if not settings.ad_enabled:
        return {"skipped": "active directory disabled"}

    from msp_ad import ActiveDirectoryConfig, ActiveDirectoryProvider

    protected_rules = parse_protected_groups(settings.ad_protected_groups)
    provider = ActiveDirectoryProvider(
        ActiveDirectoryConfig(
            server=settings.ad_server,
            port=settings.ad_port,
            use_ssl=settings.ad_use_ssl,
            bind_dn=settings.ad_bind_dn,
            bind_password=settings.ad_bind_password,
            base_dn=settings.ad_base_dn,
            ca_file=settings.ad_ca_file,
            include_optional_attributes=settings.ad_include_optional_attributes,
            # Group membership is read only when it is actually used to derive protected
            # identities: reading more of the directory than needed is a privacy decision.
            include_groups=bool(protected_rules),
        )
    )
    with session_scope() as session:
        org = session.execute(select(Organization)).scalars().first()
        if org is None:
            return {"skipped": "no organization configured"}
        previous = session.execute(
            select(DirectorySyncRun)
            .where(DirectorySyncRun.organization_id == org.id)
            .order_by(DirectorySyncRun.started_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        since = previous.high_watermark if previous and not previous.errors else None

        result = provider.sync(since)
        run = DirectorySyncRun(
            organization_id=org.id,
            provider_id=provider.provider_id,
            incremental=result.incremental,
            errors=result.errors,
            high_watermark=result.high_watermark,
            started_at=result.started_at,
            finished_at=result.finished_at,
        )
        for entry in result.entries:
            existing = session.execute(
                select(MailboxIdentity).where(
                    MailboxIdentity.organization_id == org.id,
                    func.lower(MailboxIdentity.address) == entry.mail.lower(),
                )
            ).scalar_one_or_none()
            if existing is None:
                session.add(
                    MailboxIdentity(
                        organization_id=org.id,
                        address=entry.mail,
                        display_name=entry.display_name,
                        aliases=list(entry.aliases),
                        department=entry.department,
                        title=entry.title,
                        directory_object_id=entry.object_id,
                        enabled=entry.enabled,
                        last_synced_at=utcnow(),
                    )
                )
                run.created += 1
            elif not existing.manual_override:
                existing.display_name = entry.display_name or existing.display_name
                existing.aliases = list(entry.aliases)
                existing.department = entry.department
                existing.title = entry.title
                existing.directory_object_id = entry.object_id
                existing.enabled = entry.enabled
                existing.last_synced_at = utcnow()
                run.updated += 1
        run.disabled = result.disabled
        session.add(run)

        # Protected identities follow directory group membership (ТЗ 1.0.1 §5).
        protected = sync_protected_identities(
            session, organization_id=org.id, entries=result.entries, rules=protected_rules
        )
        if protected.total or protected.disabled:
            record(
                session,
                action=AuditAction.DIRECTORY_SYNC,
                actor_email="system",
                actor_role="system",
                organization_id=org.id,
                object_type="protected_identities",
                object_id=run.id,
                detail={
                    "created": protected.created,
                    "updated": protected.updated,
                    "disabled": protected.disabled,
                    "groups_configured": len(protected_rules),
                },
            )
        record(
            session,
            action=AuditAction.DIRECTORY_SYNC,
            actor_email="system",
            actor_role="system",
            organization_id=org.id,
            object_type="directory_sync",
            object_id=run.id,
            outcome="success" if not result.errors else "partial",
            detail={
                "created": run.created,
                "updated": run.updated,
                "disabled": run.disabled,
                "incremental": run.incremental,
                "errors": result.errors[:5],
            },
        )
        return {
            "created": run.created,
            "updated": run.updated,
            "errors": result.errors,
            "protected_identities": {
                "created": protected.created,
                "updated": protected.updated,
                "disabled": protected.disabled,
            },
        }


@celery_app.task(name="msp.run_retention")
def run_retention() -> dict[str, Any]:
    """Delete expired content and keep the technical fact of deletion (ТЗ 27)."""
    settings = get_settings()
    storage = build_storage(settings)
    now = utcnow()
    summary: dict[str, int] = {}

    with session_scope() as session:
        # raw EML
        cutoff = now - timedelta(days=settings.retention_raw_eml_days)
        contents = (
            session.execute(
                select(MailContent)
                .join(MailMessage, MailMessage.id == MailContent.message_id)
                .where(
                    MailMessage.received_at < cutoff,
                    MailContent.raw_eml_key.is_not(None),
                    MailContent.raw_eml_purged_at.is_(None),
                )
                .limit(1000)
            )
            .scalars()
            .all()
        )
        for content in contents:
            try:
                storage.delete(content.raw_eml_key or "")
            except Exception as exc:  # noqa: BLE001
                logger.warning("retention.delete_failed", extra={"error": type(exc).__name__})
            content.raw_eml_key = None
            content.raw_eml_purged_at = now
        summary["raw_eml"] = len(contents)
        session.add(RetentionRun(category="raw_eml", deleted_count=len(contents), cutoff=cutoff))

        # attachments
        cutoff = now - timedelta(days=settings.retention_attachment_days)
        attachments = (
            session.execute(
                select(Attachment)
                .join(MailMessage, MailMessage.id == Attachment.message_id)
                .where(
                    MailMessage.received_at < cutoff,
                    Attachment.storage_key.is_not(None),
                    Attachment.purged_at.is_(None),
                )
                .limit(2000)
            )
            .scalars()
            .all()
        )
        kept_samples = 0
        sample_cutoff = now - timedelta(days=settings.retention_malicious_sample_days)
        for attachment in attachments:
            is_malicious_sample = bool((attachment.scan_result or {}).get("malicious"))
            message = session.get(MailMessage, attachment.message_id)
            if is_malicious_sample and message is not None and message.received_at >= sample_cutoff:
                # Confirmed malicious samples follow their own, longer policy (ТЗ 27).
                kept_samples += 1
                continue
            try:
                storage.delete(attachment.storage_key or "")
            except Exception as exc:  # noqa: BLE001
                logger.warning("retention.delete_failed", extra={"error": type(exc).__name__})
            attachment.storage_key = None
            attachment.purged_at = now
        summary["attachments"] = len(attachments) - kept_samples
        session.add(
            RetentionRun(
                category="attachments",
                deleted_count=summary["attachments"],
                cutoff=cutoff,
                detail={"kept_malicious_samples": kept_samples},
            )
        )

        # normalised bodies (metadata itself is kept longer)
        cutoff = now - timedelta(days=settings.retention_metadata_days)
        bodies = (
            session.execute(
                select(MailContent)
                .join(MailMessage, MailMessage.id == MailContent.message_id)
                .where(MailMessage.received_at < cutoff, MailContent.normalized_purged_at.is_(None))
                .limit(2000)
            )
            .scalars()
            .all()
        )
        for content in bodies:
            content.normalized_text = None
            content.sanitized_html = None
            content.normalized_purged_at = now
        summary["bodies"] = len(bodies)
        session.add(RetentionRun(category="bodies", deleted_count=len(bodies), cutoff=cutoff))

        # audit
        cutoff = now - timedelta(days=settings.retention_audit_days)
        deleted_audit = session.execute(delete(AuditEvent).where(AuditEvent.created_at < cutoff)).rowcount
        summary["audit"] = int(deleted_audit or 0)
        session.add(RetentionRun(category="audit", deleted_count=summary["audit"], cutoff=cutoff))

        # provider lookups follow the analysis retention
        cutoff = now - timedelta(days=settings.retention_analysis_days)
        deleted_lookups = session.execute(
            delete(ProviderLookup).where(ProviderLookup.fetched_at < cutoff)
        ).rowcount
        summary["provider_lookups"] = int(deleted_lookups or 0)

        record(
            session,
            action=AuditAction.RETENTION_RUN,
            actor_email="system",
            actor_role="system",
            object_type="retention",
            object_id=now.date().isoformat(),
            detail=summary,
        )
    return summary


@celery_app.task(name="msp.recheck_indicators")
def recheck_indicators() -> dict[str, Any]:
    """Re-check stored malicious verdicts so stale intelligence does not persist (ТЗ 13.4)."""
    hub = get_ti_hub()
    if not hub.configured:
        return {"skipped": "no provider configured"}
    rechecked = 0
    with session_scope() as session:
        stale_cutoff = utcnow() - timedelta(days=7)
        indicators = (
            session.execute(
                select(Indicator)
                .where(Indicator.worst_status == TIStatus.KNOWN_BAD, Indicator.last_seen >= stale_cutoff)
                .limit(100)
            )
            .scalars()
            .all()
        )
        for indicator in indicators:
            hub.cache.invalidate(hub.providers[0].provider_id, indicator.ioc_type, indicator.value)
            rechecked += 1
    return {"rechecked": rechecked}


@celery_app.task(name="msp.expire_exceptions")
def expire_exceptions() -> dict[str, Any]:
    """Report exceptions that have just expired so their owner is aware (ТЗ 15.3)."""
    now = utcnow()
    with session_scope() as session:
        expiring = (
            session.execute(
                select(DetectionException).where(
                    DetectionException.revoked_at.is_(None),
                    DetectionException.expires_at.is_not(None),
                    DetectionException.expires_at <= now,
                    DetectionException.expires_at > now - timedelta(hours=2),
                )
            )
            .scalars()
            .all()
        )
        for exception in expiring:
            _queue_notification(
                session,
                organization_id=exception.organization_id,
                event="exception_expired",
                subject="Истёк срок действия исключения детектирования",
                recipient=exception.owner_email,
                payload={
                    "exception_id": exception.id,
                    "value": exception.value,
                    "type": exception.exception_type.value,
                },
            )
        return {"expired": len(expiring)}


@celery_app.task(name="msp.send_notification")
def send_notification(notification_id: str) -> dict[str, Any]:
    """Deliver a queued notification (ТЗ 36). Malicious URLs are never sent as live links."""
    settings = get_settings()
    with session_scope() as session:
        notification = session.get(Notification, notification_id)
        if notification is None or notification.state != "pending":
            return {"skipped": "not pending"}
        if not settings.smtp_host or not notification.recipient:
            notification.state = "skipped"
            notification.error = "SMTP or recipient not configured"
            return {"skipped": notification.error}
        try:
            _send_email(settings, notification)
            notification.state = "sent"
            notification.sent_at = utcnow()
        except Exception as exc:  # noqa: BLE001
            logger.warning("worker.notification_failed", extra={"error": type(exc).__name__})
            notification.state = "failed"
            notification.error = type(exc).__name__
            return {"error": type(exc).__name__}
        return {"sent": notification.id}


def _defang(text: str) -> str:
    """Render URLs inert in notifications (ТЗ 36)."""
    return (
        text.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
        .replace("@", "[at]")
    )


def _send_email(settings, notification: Notification) -> None:  # type: ignore[no-untyped-def]
    import smtplib
    import ssl
    from email.message import EmailMessage

    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = notification.recipient
    message["Subject"] = notification.subject[:200]
    message.set_content(notification.body or notification.subject)

    context = ssl.create_default_context()
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as smtp:
        if settings.smtp_use_tls:
            smtp.starttls(context=context)
        if settings.smtp_user:
            smtp.login(settings.smtp_user, settings.smtp_password)
        smtp.send_message(message)


def _queue_notification(
    session,  # type: ignore[no-untyped-def]
    *,
    organization_id: str,
    event: str,
    subject: str,
    recipient: str,
    payload: dict[str, Any],
    body: str = "",
) -> Notification | None:
    if not recipient:
        return None
    notification = Notification(
        organization_id=organization_id,
        event=event,
        channel="email",
        recipient=recipient,
        subject=_defang(subject)[:500],
        body=_defang(body or subject),
        payload=payload,
        state="pending",
    )
    session.add(notification)
    session.flush()
    try:
        send_notification.delay(notification.id)
    except Exception as exc:  # noqa: BLE001 - broker problems must not fail the caller
        logger.warning("worker.notification_enqueue_failed", extra={"error": type(exc).__name__})
    return notification


@celery_app.task(name="msp.refresh_campaign")
def refresh_campaign(campaign_id: str) -> dict[str, Any]:
    """Recompute campaign aggregates after verdicts change."""
    with session_scope() as session:
        campaign = session.get(Campaign, campaign_id)
        if campaign is None:
            return {"skipped": "campaign not found"}
        from msp_api.db.models import CampaignMessage

        message_ids = (
            session.execute(
                select(CampaignMessage.message_id).where(CampaignMessage.campaign_id == campaign.id)
            )
            .scalars()
            .all()
        )
        distribution: dict[str, int] = {}
        for message_id in message_ids:
            result = session.execute(
                select(AnalysisResult).where(AnalysisResult.message_id == message_id)
            ).scalar_one_or_none()
            if result is not None:
                key = result.classification.value
                distribution[key] = distribution.get(key, 0) + 1
        campaign.verdict_distribution = distribution
        campaign.message_count = len(message_ids)
        campaign.confirmed_malicious = campaign.confirmed_malicious or distribution.get("MALICIOUS", 0) > 0
        return {"campaign_id": campaign.id, "messages": campaign.message_count}


@celery_app.task(name="msp.scan_attachments")
def scan_attachments(job_id: str) -> dict[str, Any]:
    settings = get_settings()
    with session_scope() as session:
        job = session.get(AnalysisJob, job_id)
        if job is None:
            return {"skipped": "job not found"}
        findings = _scan_attachments(session, job, settings)
        return {"job_id": job_id, "malicious": len(findings)}
