"""Durable intake for the security mailbox (ТЗ 1.0.1 §4.1).

The previous flow was ``FETCH -> mark Seen -> analyse``. A worker that died after the flag was
set lost the report: the message looked handled and was never fetched again. Nothing in the
mailbox recorded that it had not, in fact, been handled.

The flow implemented here makes the mailbox the *last* thing to change:

.. code-block:: text

    FETCH
      -> persist intake record        (the platform now knows the message exists)
      -> persist raw content          (the content survives a crash)
      -> create analysis job          (work is queued)
      -> commit
      -> acknowledge / move Processed (only now is the mailbox told)

A crash before the commit leaves the message untouched in the mailbox, so the next poll finds
it again. A crash after the commit but before the acknowledgement causes a re-fetch, which the
deduplication below turns into a no-op. Losing a report needs the database and the mailbox to
fail together; reprocessing one costs nothing.

Deduplication uses three keys because none is sufficient alone:

* **mailbox UID** — the cheapest, but unique only within one mailbox generation (UIDVALIDITY);
* **Message-ID of the reported message** — absent from some mail, and forgeable;
* **content SHA-256** — exact, but two people reporting the same phishing message legitimately
  produce identical content, and that should raise one incident, not two.

The first match wins, and a duplicate is linked to the original rather than dropped, so an
analyst can still see that three people reported the same message.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Any

from msp_contracts import (
    INTAKE_RESUMABLE,
    INTAKE_TERMINAL,
    AnalysisStatus,
    IntakeSource,
    IntakeState,
    JobState,
    ScanCompleteness,
)
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.base import utcnow
from ..db.models import AnalysisJob, IntakeRecord
from .storage import ObjectStorage, build_key

logger = logging.getLogger(__name__)

#: After this many failed attempts the message is dead-lettered instead of retried for ever.
MAX_INTAKE_RETRIES = 3


@dataclass
class IntakeOutcome:
    record: IntakeRecord
    created: bool
    duplicate_of: IntakeRecord | None = None
    #: True when the caller may acknowledge the message in the mailbox.
    acknowledgeable: bool = False
    job: AnalysisJob | None = None

    @property
    def is_duplicate(self) -> bool:
        return self.duplicate_of is not None


def find_duplicate(
    session: Session,
    *,
    organization_id: str,
    source_id: str,
    mailbox_uid: str,
    internet_message_id: str,
    content_sha256: str,
) -> IntakeRecord | None:
    """Look for a record of the same report, by any of the three identities."""
    identity_filters: list[Any] = []
    if mailbox_uid:
        identity_filters.append(
            (IntakeRecord.source_id == source_id) & (IntakeRecord.mailbox_uid == mailbox_uid)
        )
    if content_sha256:
        identity_filters.append(IntakeRecord.content_sha256 == content_sha256)
    if internet_message_id:
        identity_filters.append(IntakeRecord.internet_message_id == internet_message_id)
    if not identity_filters:
        return None
    return session.execute(
        select(IntakeRecord)
        .where(IntakeRecord.organization_id == organization_id, or_(*identity_filters))
        .order_by(IntakeRecord.fetched_at.asc())
        .limit(1)
    ).scalar_one_or_none()


def begin_intake(
    session: Session,
    settings: Settings,
    *,
    organization_id: str,
    source: IntakeSource,
    source_id: str,
    mailbox_uid: str,
    raw: bytes,
    internet_message_id: str = "",
    content_sha256: str = "",
    reported_by: str = "",
    oversized: bool = False,
    actual_size: int = 0,
    warnings: list[str] | None = None,
    storage: ObjectStorage | None = None,
) -> IntakeOutcome:
    """Record the message and store its content, before anything is acknowledged.

    Returns an outcome describing whether this is a new report, a duplicate, or a resumption of
    an intake that a previous worker left unfinished.
    """
    existing = find_duplicate(
        session,
        organization_id=organization_id,
        source_id=source_id,
        mailbox_uid=mailbox_uid,
        internet_message_id=internet_message_id,
        content_sha256=content_sha256,
    )
    if existing is not None:
        if existing.source_id == source_id and existing.mailbox_uid == mailbox_uid:
            # Literally the same mailbox item, fetched again because a previous run did not get
            # as far as acknowledging it. There is nothing new to record: the caller is told to
            # resume, or to acknowledge when the work was already finished. Inserting a
            # "duplicate" row here would collide with the uniqueness constraint that makes
            # concurrent polling safe in the first place.
            if existing.state in INTAKE_RESUMABLE:
                existing.retry_count += 1
                return IntakeOutcome(record=existing, created=False)
            return IntakeOutcome(
                record=existing,
                created=False,
                duplicate_of=existing if existing.state in INTAKE_TERMINAL else None,
                acknowledgeable=True,
            )
        return _record_duplicate(
            session,
            organization_id=organization_id,
            source=source,
            source_id=source_id,
            mailbox_uid=mailbox_uid,
            internet_message_id=internet_message_id,
            content_sha256=content_sha256,
            reported_by=reported_by,
            original=existing,
        )

    record = IntakeRecord(
        organization_id=organization_id,
        source=source,
        source_id=source_id[:320],
        mailbox_uid=mailbox_uid[:128],
        internet_message_id=internet_message_id[:998],
        content_sha256=content_sha256,
        reported_by=reported_by[:320],
        state=IntakeState.FETCHED,
        size_bytes=actual_size or len(raw),
        oversized=oversized,
        warnings=list(warnings or []),
    )
    session.add(record)
    try:
        session.flush()
    except IntegrityError:
        # Two workers polled the same mailbox at once. The unique constraint on
        # (organization, source, uid) is what makes that safe rather than merely unlikely.
        session.rollback()
        duplicate = find_duplicate(
            session,
            organization_id=organization_id,
            source_id=source_id,
            mailbox_uid=mailbox_uid,
            internet_message_id=internet_message_id,
            content_sha256=content_sha256,
        )
        if duplicate is None:
            raise
        return IntakeOutcome(record=duplicate, created=False)

    if raw and storage is not None:
        try:
            # The intake copy is raw RFC 822, so it shares the "eml" category and therefore the
            # raw-EML retention policy (ТЗ 27) rather than acquiring one of its own.
            key = build_key(
                "eml",
                content_sha256 or hashlib.sha256(raw).hexdigest(),
                organization_id=organization_id,
                extension="eml",
            )
            storage.put(key, raw, content_type="message/rfc822")
            record.raw_storage_key = key
            record.state = IntakeState.STORED
        except Exception as exc:  # noqa: BLE001 - a storage outage must not lose the record
            logger.warning("intake.raw_store_failed", extra={"error": type(exc).__name__})
            record.warnings = [*record.warnings, f"raw content not stored: {type(exc).__name__}"]
    elif oversized:
        # Nothing to store on purpose. The record carries the size so the analyst can see what
        # was refused and why (ТЗ 1.0.1 §4.2).
        record.state = IntakeState.STORED
    return IntakeOutcome(record=record, created=True)


def _record_duplicate(
    session: Session,
    *,
    organization_id: str,
    source: IntakeSource,
    source_id: str,
    mailbox_uid: str,
    internet_message_id: str,
    content_sha256: str,
    reported_by: str,
    original: IntakeRecord,
) -> IntakeOutcome:
    """Keep the fact of the repeat report without creating a second investigation.

    Several employees reporting the same phishing message is a useful signal — it is how a
    campaign becomes visible — so the repeat is recorded and linked, not discarded.
    """
    record = IntakeRecord(
        organization_id=organization_id,
        source=source,
        source_id=source_id[:320],
        mailbox_uid=mailbox_uid[:128],
        internet_message_id=internet_message_id[:998],
        content_sha256=content_sha256,
        reported_by=reported_by[:320],
        state=IntakeState.DUPLICATE,
        duplicate_of_id=original.id,
        analysis_job_id=original.analysis_job_id,
        acknowledged_at=utcnow(),
    )
    session.add(record)
    session.flush()
    return IntakeOutcome(record=record, created=True, duplicate_of=original, acknowledgeable=True)


def attach_job(record: IntakeRecord, job: AnalysisJob) -> None:
    """Link the analysis job. Only after this may the mailbox be acknowledged."""
    record.analysis_job_id = job.id
    record.state = IntakeState.JOB_CREATED


def mark_acknowledged(record: IntakeRecord) -> None:
    record.state = IntakeState.ACKNOWLEDGED
    record.acknowledged_at = utcnow()


def mark_failed(record: IntakeRecord, error: str) -> bool:
    """Record a failure and decide whether to retry.

    Returns True when the record was dead-lettered, which tells the caller to move the message
    to the Failed folder so it stops being re-fetched on every poll.
    """
    record.retry_count += 1
    record.last_error = error[:500]
    if record.retry_count >= MAX_INTAKE_RETRIES:
        record.state = IntakeState.DEAD_LETTER
        return True
    record.state = IntakeState.RETRY
    return False


def unscannable_job(
    session: Session,
    *,
    organization_id: str,
    record: IntakeRecord,
    reason: str,
) -> AnalysisJob:
    """Create a job for a message that was deliberately not analysed (ТЗ 1.0.1 §4.2).

    The job exists, and it is honest: its status is UNKNOWN, not LOW_RISK, and the reason is
    recorded as a warning. Nothing in the employee-facing projection may read as "проверено".
    """
    job = AnalysisJob(
        organization_id=organization_id,
        source=record.source,
        requester_mailbox=record.reported_by,
        is_report=True,
        state=JobState.PARTIAL,
        status=AnalysisStatus.UNKNOWN,
        scan_completeness=ScanCompleteness.UNSCANNABLE.value,
        idempotency_key=f"intake:{record.id}",
        error=None,
        warnings=[reason, *(record.warnings or [])],
        finished_at=utcnow(),
    )
    session.add(job)
    session.flush()
    attach_job(record, job)
    return job


def intake_stats(session: Session, organization_id: str) -> dict[str, Any]:
    """Counters behind the ``intake_*`` metrics (ТЗ 1.0.1 §4.1)."""
    rows = session.execute(
        select(IntakeRecord.state, func.count(IntakeRecord.id))
        .where(IntakeRecord.organization_id == organization_id)
        .group_by(IntakeRecord.state)
    ).all()
    by_state = {str(state.value if hasattr(state, "value") else state): int(count) for state, count in rows}
    return {
        "by_state": by_state,
        "success": by_state.get(IntakeState.ACKNOWLEDGED.value, 0),
        "retry": by_state.get(IntakeState.RETRY.value, 0),
        "failed": by_state.get(IntakeState.DEAD_LETTER.value, 0),
        "duplicates": by_state.get(IntakeState.DUPLICATE.value, 0),
        "in_flight": sum(by_state.get(state.value, 0) for state in INTAKE_RESUMABLE),
    }
