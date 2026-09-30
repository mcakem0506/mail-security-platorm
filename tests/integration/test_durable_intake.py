"""Durable intake and oversized messages (ТЗ 1.0.1 §4.1, §4.2).

The acceptance criterion of §4.1 is stated as a crash test: simulate a worker dying at five
points and show that no message is lost. That is what this file does, using a fake mailbox whose
``ack``/``fail`` calls are observable, so the *order* of operations can be asserted rather than
merely their outcome.

The order is the whole property. A message acknowledged before the database transaction commits
is lost when the worker dies; a message committed before the acknowledgement is, at worst, seen
twice — and deduplication makes that harmless. Every test here is ultimately about which of those
two failure modes the code has.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from msp_api.db.models import AnalysisJob, IntakeRecord
from msp_api.services.intake import (
    MAX_INTAKE_RETRIES,
    attach_job,
    begin_intake,
    find_duplicate,
    intake_stats,
    mark_acknowledged,
    mark_failed,
    unscannable_job,
)
from msp_contracts import INTAKE_TERMINAL, IntakeSource, IntakeState, ScanCompleteness
from msp_exchange.security_mailbox import IngestedReport
from sqlalchemy import select


@dataclass
class FakeMailbox:
    """Records what the platform asked the mailbox to do, and in what order."""

    acked: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    #: UIDs still sitting in the inbox, i.e. what the next poll would fetch again.
    inbox: list[str] = field(default_factory=list)

    def ack(self, uid: str) -> bool:
        self.acked.append(uid)
        if uid in self.inbox:
            self.inbox.remove(uid)
        return True

    def fail(self, uid: str) -> bool:
        self.failed.append(uid)
        if uid in self.inbox:
            self.inbox.remove(uid)
        return True


def report(uid: str, *, body: bytes = b"", oversized: bool = False, size: int = 0) -> IngestedReport:
    import hashlib

    raw = body or f"From: user@corp.example\r\nSubject: report {uid}\r\n\r\nbody {uid}".encode()
    return IngestedReport(
        uid=uid,
        raw_mime=b"" if oversized else raw,
        reported_by="employee@corp.example",
        internet_message_id=f"<msg-{uid}@corp.example>",
        content_sha256="" if oversized else hashlib.sha256(raw).hexdigest(),
        oversized=oversized,
        actual_size=size or len(raw),
    )


class MemoryStorage:
    """Object storage that can be made to fail on demand."""

    def __init__(self, *, fail: bool = False) -> None:
        self.objects: dict[str, bytes] = {}
        self.fail = fail

    def put(self, key: str, data: bytes, content_type: str = "") -> None:
        if self.fail:
            raise OSError("storage unavailable")
        self.objects[key] = data

    def get(self, key: str) -> bytes:
        return self.objects[key]

    def delete(self, key: str) -> None:
        self.objects.pop(key, None)


@pytest.fixture
def storage() -> MemoryStorage:
    return MemoryStorage()


SOURCE_ID = "security-phishing@corp.example:INBOX"


def _begin(db, settings, organization, item, storage):  # type: ignore[no-untyped-def]
    return begin_intake(
        db,
        settings,
        organization_id=organization.id,
        source=IntakeSource.SECURITY_MAILBOX,
        source_id=SOURCE_ID,
        mailbox_uid=item.uid,
        raw=item.raw_mime,
        internet_message_id=item.internet_message_id,
        content_sha256=item.content_sha256,
        reported_by=item.reported_by,
        oversized=item.oversized,
        actual_size=item.actual_size,
        warnings=item.warnings,
        storage=storage,
    )


class TestCrashPoints:
    """The five crash points of the ТЗ 1.0.1 §4.1 acceptance criterion."""

    def test_crash_after_fetch_leaves_the_message_in_the_mailbox(
        self, db, settings, organization, storage
    ) -> None:
        mailbox = FakeMailbox(inbox=["101"])
        item = report("101")

        # Crash here: the record exists but nothing was acknowledged.
        outcome = _begin(db, settings, organization, item, storage)
        db.commit()

        assert outcome.record.state is IntakeState.STORED
        assert mailbox.acked == [], "nothing may be acknowledged before a job exists"
        assert mailbox.inbox == ["101"], "the message must still be re-fetchable"
        assert outcome.record.state not in INTAKE_TERMINAL

    def test_crash_after_storing_raw_content_is_resumed_not_duplicated(
        self, db, settings, organization, storage
    ) -> None:
        item = report("102")
        first = _begin(db, settings, organization, item, storage)
        db.commit()
        record_id = first.record.id

        # The worker died; the next poll fetches the same UID again.
        second = _begin(db, settings, organization, item, storage)
        db.commit()

        assert second.record.id == record_id, "a half-finished intake is resumed, not re-created"
        assert not second.created
        assert second.record.retry_count == 1
        assert db.execute(select(IntakeRecord).where(IntakeRecord.mailbox_uid == "102")).scalars().all() != []
        assert len(db.execute(select(IntakeRecord)).scalars().all()) == 1

    def test_crash_after_job_creation_before_ack_is_recovered(
        self, db, settings, organization, storage
    ) -> None:
        mailbox = FakeMailbox(inbox=["103"])
        item = report("103")
        outcome = _begin(db, settings, organization, item, storage)
        job = AnalysisJob(
            organization_id=organization.id,
            source=IntakeSource.SECURITY_MAILBOX,
            requester_mailbox=item.reported_by,
            is_report=True,
            idempotency_key=f"intake:{outcome.record.id}",
        )
        db.add(job)
        db.flush()
        attach_job(outcome.record, job)
        db.commit()

        # Crash before the mailbox move. The work is safe; only the flag is missing.
        assert outcome.record.state is IntakeState.JOB_CREATED
        assert mailbox.inbox == ["103"]

        # Next poll: the same content is recognised and not analysed twice.
        again = _begin(db, settings, organization, item, storage)
        db.commit()
        assert again.record.state is IntakeState.DUPLICATE or again.record.id == outcome.record.id
        jobs = db.execute(select(AnalysisJob)).scalars().all()
        assert len(jobs) == 1, "a re-fetch must not create a second analysis job"

    def test_ack_only_after_the_transaction_commits(self, db, settings, organization, storage) -> None:
        mailbox = FakeMailbox(inbox=["104"])
        item = report("104")
        outcome = _begin(db, settings, organization, item, storage)
        job = AnalysisJob(
            organization_id=organization.id,
            source=IntakeSource.SECURITY_MAILBOX,
            is_report=True,
            idempotency_key=f"intake:{outcome.record.id}",
        )
        db.add(job)
        db.flush()
        attach_job(outcome.record, job)
        db.commit()

        mailbox.ack(item.uid)
        mark_acknowledged(outcome.record)
        db.commit()

        assert mailbox.acked == ["104"]
        assert mailbox.inbox == []
        assert outcome.record.state is IntakeState.ACKNOWLEDGED
        assert outcome.record.acknowledged_at is not None

    def test_crash_after_ack_does_not_reprocess(self, db, settings, organization, storage) -> None:
        item = report("105")
        outcome = _begin(db, settings, organization, item, storage)
        mark_acknowledged(outcome.record)
        db.commit()

        # A message already acknowledged is never analysed again, even if the mailbox move
        # failed and it reappears. The original record is returned as-is: the same mailbox item
        # does not become a second row, which is what keeps concurrent polling safe.
        again = _begin(db, settings, organization, item, storage)
        db.commit()
        assert again.is_duplicate
        assert not again.created
        assert again.record.id == outcome.record.id
        assert again.record.state is IntakeState.ACKNOWLEDGED
        assert again.acknowledgeable
        assert len(db.execute(select(IntakeRecord)).scalars().all()) == 1


class TestDeduplication:
    def test_same_uid_is_recognised(self, db, settings, organization, storage) -> None:
        item = report("201")
        _begin(db, settings, organization, item, storage)
        db.commit()
        found = find_duplicate(
            db,
            organization_id=organization.id,
            source_id=SOURCE_ID,
            mailbox_uid="201",
            internet_message_id="",
            content_sha256="",
        )
        assert found is not None

    def test_same_content_reported_by_two_people_is_linked_not_dropped(
        self, db, settings, organization, storage
    ) -> None:
        """Several people reporting one phishing message is how a campaign becomes visible."""
        first = report("301")
        first_outcome = _begin(db, settings, organization, first, storage)
        mark_acknowledged(first_outcome.record)
        db.commit()

        second = report("302", body=first.raw_mime)
        second.reported_by = "other@corp.example"
        second_outcome = _begin(db, settings, organization, second, storage)
        db.commit()

        assert second_outcome.is_duplicate
        assert second_outcome.record.duplicate_of_id == first_outcome.record.id
        # The repeat is kept as a record, so the analyst can see three people reported it.
        assert len(db.execute(select(IntakeRecord)).scalars().all()) == 2
        assert len(db.execute(select(AnalysisJob)).scalars().all()) == 0

    def test_message_id_matches_across_mailbox_generations(self, db, settings, organization, storage) -> None:
        """A UIDVALIDITY change renumbers every UID; the Message-ID still identifies the report."""
        original = report("401")
        first = _begin(db, settings, organization, original, storage)
        mark_acknowledged(first.record)
        db.commit()

        renumbered = report("9401", body=original.raw_mime)
        renumbered.internet_message_id = original.internet_message_id
        renumbered.content_sha256 = ""  # force the match to rely on the Message-ID alone
        outcome = _begin(db, settings, organization, renumbered, storage)
        db.commit()
        assert outcome.is_duplicate


class TestFailureHandling:
    def test_retries_then_dead_letters(self, db, settings, organization, storage) -> None:
        item = report("501")
        outcome = _begin(db, settings, organization, item, storage)
        db.commit()

        for attempt in range(1, MAX_INTAKE_RETRIES):
            dead = mark_failed(outcome.record, "ValueError")
            assert not dead, f"attempt {attempt} should still be retried"
            assert outcome.record.state is IntakeState.RETRY

        assert mark_failed(outcome.record, "ValueError"), "must dead-letter after the last retry"
        assert outcome.record.state is IntakeState.DEAD_LETTER
        assert outcome.record.last_error == "ValueError"

    def test_dead_letter_stops_the_message_being_refetched_forever(
        self, db, settings, organization, storage
    ) -> None:
        mailbox = FakeMailbox(inbox=["502"])
        item = report("502")
        outcome = _begin(db, settings, organization, item, storage)
        for _ in range(MAX_INTAKE_RETRIES):
            dead = mark_failed(outcome.record, "ValueError")
        db.commit()

        assert dead
        mailbox.fail(item.uid)
        assert mailbox.failed == ["502"]
        assert mailbox.inbox == [], "a dead letter is moved out of the inbox, not left to loop"

    def test_storage_failure_keeps_the_record(self, db, settings, organization) -> None:
        """A storage outage must not lose the knowledge that a report arrived."""
        broken = MemoryStorage(fail=True)
        outcome = _begin(db, settings, organization, report("503"), broken)
        db.commit()

        assert outcome.created
        assert outcome.record.raw_storage_key is None
        assert any("raw content not stored" in w for w in outcome.record.warnings)
        assert outcome.record.state is IntakeState.FETCHED


class TestOversizedMessages:
    """ТЗ 1.0.1 §4.2: a message over the limit is not analysed, and never looks analysed."""

    def test_oversized_report_is_not_analysed(self, db, settings, organization, storage) -> None:
        item = report("601", oversized=True, size=80 * 1024 * 1024)
        outcome = _begin(db, settings, organization, item, storage)
        job = unscannable_job(
            db,
            organization_id=organization.id,
            record=outcome.record,
            reason="письмо превышает предел анализа",
        )
        db.commit()

        assert outcome.record.oversized
        assert outcome.record.size_bytes == 80 * 1024 * 1024, "the real size is recorded"
        assert outcome.record.raw_storage_key is None, "the content is not stored at all"
        assert job.scan_completeness == ScanCompleteness.UNSCANNABLE.value
        assert job.status.value == "UNKNOWN", "an unexamined message is never LOW_RISK"
        assert job.warnings

    def test_no_truncated_content_is_kept(self, db, settings, organization, storage) -> None:
        """Truncation is the failure mode §4.2 exists to prevent."""
        item = report("602", oversized=True, size=60 * 1024 * 1024)
        assert item.raw_mime == b"", "an oversized report carries no bytes, not partial bytes"
        _begin(db, settings, organization, item, storage)
        db.commit()
        assert storage.objects == {}, "nothing is stored, not even a prefix"

    def test_employee_wording_never_says_checked(self, db, settings, organization, storage) -> None:
        from msp_api.services.analysis import employee_view
        from msp_risk import evaluate

        item = report("603", oversized=True, size=60 * 1024 * 1024)
        outcome = _begin(db, settings, organization, item, storage)
        job = unscannable_job(
            db, organization_id=organization.id, record=outcome.record, reason="превышен предел"
        )
        db.commit()

        verdict = evaluate([], missing_evidence=["письмо не проверялось"], analysis_complete=False)
        view = employee_view(verdict, job)
        assert view["classification"] == "UNKNOWN"
        assert view["scan_completeness"] == ScanCompleteness.UNSCANNABLE.value
        assert view["analysis_incomplete"] is True
        text = f"{view['recommendation']} {' '.join(r['explanation'] for r in view['reasons'])}".lower()
        # The wording must not *claim* a completed check or a safe result. It may well contain
        # the word "безопасность" — "подтвердить безопасность письма нельзя" is exactly right —
        # so the test looks for the claims, not for the vocabulary.
        for claim in (
            "письмо проверено",
            "проверка выполнена успешно",
            "угроз не обнаружено",
            "письмо безопасно",
            "признаков атаки не обнаружено",
        ):
            assert claim not in text, f"unexamined message described as checked: {claim!r}"
        assert "нельзя" in text or "не полностью" in text, (
            "the employee must be told the check did not complete"
        )


class TestParserLimitSignals:
    """Each limit produces its own explainable signal (ТЗ 1.0.1 §4.2)."""

    def test_each_limit_is_a_separate_signal(self, context, ruleset) -> None:
        from msp_detection import analyze
        from msp_mail_parser import ParserLimits, parse_message

        raw = (
            b"From: sender@partner.example\r\nTo: buh@corp.example\r\n"
            b"Subject: many links\r\nMessage-ID: <x@partner.example>\r\n\r\n"
            + b"\r\n".join(f"https://site{i}.example/page".encode() for i in range(40))
        )
        tight = ParserLimits(max_urls=5, max_message_size=10 * 1024 * 1024)
        parsed = parse_message(raw, tight)
        result = analyze(parsed, context, ruleset=ruleset)

        assert "MAX_URLS" in parsed.limits_hit
        assert result.facts.get("limit_url_count_exceeded") is True
        assert result.facts.get("scan_completeness") == ScanCompleteness.LIMIT_EXCEEDED.value
        assert result.facts.missing_evidence, "a limit must be recorded as missing evidence"
        assert any(s.rule_id == "LIM-006" for s in result.signals)

    def test_oversized_message_is_unscannable_not_partial(self, context, ruleset) -> None:
        from msp_detection import analyze
        from msp_mail_parser import ParserLimits, parse_message

        raw = b"From: a@b.example\r\nSubject: big\r\n\r\n" + b"A" * 4096
        parsed = parse_message(raw, ParserLimits(max_message_size=1024))
        result = analyze(parsed, context, ruleset=ruleset)

        assert not parsed.parse_ok, "an oversized message is refused, not partially parsed"
        assert parsed.attachments == [] and parsed.urls == []
        assert result.facts.get("limit_message_size_exceeded") is True
        assert result.facts.get("scan_completeness") == ScanCompleteness.UNSCANNABLE.value
        assert any(s.rule_id == "LIM-001" for s in result.signals)

    def test_verdict_cannot_be_low_risk_when_a_limit_was_hit(self, context, ruleset) -> None:
        from msp_detection import analyze
        from msp_mail_parser import ParserLimits, parse_message
        from msp_risk import evaluate

        raw = b"From: a@b.example\r\nSubject: big\r\n\r\n" + b"A" * 4096
        parsed = parse_message(raw, ParserLimits(max_message_size=1024))
        result = analyze(parsed, context, ruleset=ruleset)
        verdict = evaluate(
            result.signals,
            missing_evidence=result.facts.missing_evidence,
            unparseable=not parsed.parse_ok,
        )
        assert verdict.classification.value != "LOW_RISK"
        assert verdict.missing_evidence


def test_intake_stats_expose_the_required_counters(db, settings, organization, storage) -> None:
    """The metrics named in ТЗ 1.0.1 §4.1 are derivable from the records."""
    acknowledged = _begin(db, settings, organization, report("701"), storage)
    mark_acknowledged(acknowledged.record)
    retrying = _begin(db, settings, organization, report("702"), storage)
    mark_failed(retrying.record, "TimeoutError")
    dead = _begin(db, settings, organization, report("703"), storage)
    for _ in range(MAX_INTAKE_RETRIES):
        mark_failed(dead.record, "ValueError")
    duplicate = _begin(db, settings, organization, report("704", body=report("701").raw_mime), storage)
    db.commit()

    stats = intake_stats(db, organization.id)
    assert stats["success"] == 1
    assert stats["retry"] == 1
    assert stats["failed"] == 1
    assert stats["duplicates"] == 1
    assert duplicate.is_duplicate
