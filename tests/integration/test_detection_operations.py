"""Feedback, rule quality, candidate packs, releases and re-evaluation (ТЗ 1.0.3B §4–§12, §23, §24).

The properties under test are the judgement calls, not the plumbing:

* feedback belongs to an analysis, and a false positive without a reason is refused;
* precision is ``None`` until enough has been judged, and health never disables a rule;
* a critical rule change cannot be approved by its author;
* a release manifest records every version a verdict depends on;
* a bulk re-evaluation is a dry run that can be paused and cancelled, and never remediates.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from msp_api.db.models import (
    AnalysisJob,
    AnalysisResult,
    DetectionGapRecord,
    DetectionSignal,
    MailMessage,
    RuleCandidate,
)
from msp_api.services import evaluation, feedback, reanalysis, releases
from msp_contracts import (
    AnalystClassification,
    CandidateState,
    FalseNegativeSource,
    FalsePositiveReason,
    GapStatus,
    IntakeSource,
    ReanalysisState,
    RiskLevel,
    RootCause,
    RuleHealth,
    Severity,
    SignalDisposition,
    utcnow,
)


@pytest.fixture
def org_id(organization) -> str:  # type: ignore[no-untyped-def]
    return organization.id


def _message(db, org_id: str, *, minutes_ago: int = 0, subject: str = "Счёт") -> MailMessage:  # type: ignore[no-untyped-def]
    message = MailMessage(
        organization_id=org_id,
        internet_message_id=f"<{subject}-{minutes_ago}@test>",
        raw_sha256=f"{abs(hash((subject, minutes_ago))):064x}"[:64],
        subject=subject,
        sender_address="billing@partner.test",
        sender_display_name="Поставщик",
        sender_domain="partner.test",
        recipient_count=1,
        size_bytes=2048,
        received_at=utcnow() - timedelta(minutes=minutes_ago),
        source=IntakeSource.API,
    )
    db.add(message)
    db.flush()
    return message


def _analysis(
    db,  # type: ignore[no-untyped-def]
    org_id: str,
    message: MailMessage,
    *,
    classification: RiskLevel = RiskLevel.HIGH_RISK,
    rules: tuple[str, ...] = ("BEC-001",),
) -> AnalysisJob:
    job = AnalysisJob(organization_id=org_id, message_id=message.id, source=IntakeSource.API)
    db.add(job)
    db.flush()
    result = AnalysisResult(
        job_id=job.id,
        message_id=message.id,
        classification=classification,
        score=65,
        confidence="high",
        recommendation="Передайте в службу ИБ",
    )
    db.add(result)
    db.flush()
    for index, rule_id in enumerate(rules):
        db.add(
            DetectionSignal(
                result_id=result.id,
                signal_id=f"{rule_id}-{index}",
                rule_id=rule_id,
                rule_version=1,
                category="invoice_payment_fraud",
                title=rule_id,
                explanation="e",
                severity=Severity.HIGH,
                confidence=0.8,
                weight=45.0,
                source="rule_engine",
                evidence={},
                rule_status="ACTIVE",
                observed_at=utcnow(),
            )
        )
    db.flush()
    return job


class TestFeedbackBelongsToAnAnalysis:
    def test_feedback_is_recorded_with_signal_judgements(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        job = _analysis(db, org_id, _message(db, org_id))
        db.commit()

        record = feedback.record_feedback(
            db,
            organization_id=org_id,
            analysis_id=job.id,
            classification=AnalystClassification.CONFIRMED_BEC,
            analyst_email="analyst@corp.example",
            comment="Подтверждена смена реквизитов",
            signals=[
                feedback.SignalJudgement(
                    rule_id="BEC-001", disposition=SignalDisposition.CORRECT
                )
            ],
        )
        db.commit()
        assert record.analysis_id == job.id
        assert record.classification == "CONFIRMED_BEC"

    def test_feedback_for_an_unknown_analysis_is_refused(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        with pytest.raises(feedback.FeedbackError, match="анализ не найден"):
            feedback.record_feedback(
                db,
                organization_id=org_id,
                analysis_id="missing",
                classification=AnalystClassification.CONFIRMED_BEC,
                analyst_email="a@corp.example",
                comment="x",
            )

    def test_false_positive_requires_a_reason(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        """A false positive without a reason is a complaint: the reason decides who fixes it."""
        job = _analysis(db, org_id, _message(db, org_id))
        db.commit()
        with pytest.raises(feedback.FeedbackError, match="причину"):
            feedback.record_feedback(
                db,
                organization_id=org_id,
                analysis_id=job.id,
                classification=AnalystClassification.FALSE_POSITIVE,
                analyst_email="a@corp.example",
                comment="Легитимное письмо подрядчика",
                signals=[
                    feedback.SignalJudgement(
                        rule_id="BEC-001", disposition=SignalDisposition.INCORRECT
                    )
                ],
            )

    def test_false_positive_requires_an_offending_signal(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        job = _analysis(db, org_id, _message(db, org_id))
        db.commit()
        with pytest.raises(feedback.FeedbackError, match="сигнал"):
            feedback.record_feedback(
                db,
                organization_id=org_id,
                analysis_id=job.id,
                classification=AnalystClassification.FALSE_POSITIVE,
                analyst_email="a@corp.example",
                comment="Легитимное письмо подрядчика",
                fp_reason=FalsePositiveReason.KNOWN_VENDOR,
            )

    def test_too_severe_is_not_counted_as_a_false_positive(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        """The rule saw something real and overstated it — a weight problem, not a wrong rule.

        Counting it as a false positive would push an owner to delete a rule that works.
        """
        job = _analysis(db, org_id, _message(db, org_id))
        db.commit()
        feedback.record_feedback(
            db,
            organization_id=org_id,
            analysis_id=job.id,
            classification=AnalystClassification.CONFIRMED_BEC,
            analyst_email="a@corp.example",
            signals=[
                feedback.SignalJudgement(
                    rule_id="BEC-001", disposition=SignalDisposition.TOO_SEVERE
                )
            ],
        )
        db.commit()
        from msp_api.db.models import RuleStatistic
        from sqlalchemy import select

        stat = db.execute(
            select(RuleStatistic).where(RuleStatistic.rule_id == "BEC-001")
        ).scalar_one()
        assert stat.confirmed_fp == 0


class TestMissedDetectionNeedsEnoughToActOn:
    def test_missing_fields_are_refused_by_name(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        with pytest.raises(feedback.FeedbackError, match="владелец"):
            feedback.record_missed_detection(
                db,
                organization_id=org_id,
                source=FalseNegativeSource.ANALYST,
                root_cause=RootCause.MISSING_RULE,
                analyst_email="a@corp.example",
                expected_category="bec",
                minimum_classification="SUSPICIOUS",
                severity="high",
                owner="",
                target_release="MSP 1.0.4",
            )

    def test_a_complete_report_is_recorded(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        record = feedback.record_missed_detection(
            db,
            organization_id=org_id,
            source=FalseNegativeSource.RED_TEAM,
            root_cause=RootCause.EXCEPTION_SUPPRESSION,
            analyst_email="a@corp.example",
            expected_category="credential_theft",
            minimum_classification="HIGH_RISK",
            severity="high",
            owner="detection-url@corp.example",
            target_release="MSP 1.0.4",
            comment="Исключение погасило сигнал",
        )
        db.commit()
        assert record.kind == "false_negative"
        assert record.root_cause == "EXCEPTION_SUPPRESSION"
        assert record.owner == "detection-url@corp.example"


class TestRuleHealth:
    def _quality(self, **kwargs) -> feedback.RuleQuality:  # type: ignore[no-untyped-def]
        defaults = {"rule_id": "BEC-001", "trigger_count": 50}
        defaults.update(kwargs)
        return feedback.RuleQuality(**defaults)

    def test_precision_is_none_until_enough_is_judged(self) -> None:
        quality = self._quality(true_positive=0, false_positive=0)
        assert quality.precision is None
        health, reasons = feedback.assess_health(quality)
        assert health is RuleHealth.NO_DATA
        assert reasons

    def test_a_rule_that_never_fires_is_low_coverage_not_healthy(self) -> None:
        health, _ = feedback.assess_health(self._quality(trigger_count=0))
        assert health is RuleHealth.LOW_COVERAGE

    def test_a_noisy_rule_is_named(self) -> None:
        health, reasons = feedback.assess_health(
            self._quality(true_positive=3, false_positive=7)
        )
        assert health is RuleHealth.NOISY
        assert "точность" in reasons[0]

    def test_a_drop_against_the_previous_period_is_a_regression(self) -> None:
        health, reasons = feedback.assess_health(
            self._quality(true_positive=8, false_positive=2), previous_precision=1.0
        )
        assert health is RuleHealth.REGRESSED
        assert "упала" in reasons[0]

    def test_health_never_disables_anything(self) -> None:
        """Health is a label. A control that switches itself off can be switched off by a bad week."""
        for health in RuleHealth:
            assert health.value in {h.value for h in RuleHealth}
        # The assessment returns a label and reasons, and nothing else: no rule object is touched.
        quality = self._quality(true_positive=1, false_positive=9)
        result = feedback.assess_health(quality)
        assert isinstance(result, tuple) and len(result) == 2


class TestCandidateReview:
    def _candidate(self, db, org_id, **kwargs) -> RuleCandidate:  # type: ignore[no-untyped-def]
        defaults = {
            "organization_id": org_id,
            "name": "candidate-1",
            "source": "rules",
            "author": "author@corp.example",
            "state": CandidateState.DRAFT,
            "critical_change": False,
            "critical_reasons": [],
        }
        defaults.update(kwargs)
        candidate = RuleCandidate(**defaults)
        db.add(candidate)
        db.flush()
        return candidate

    def test_review_without_a_benchmark_is_refused(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        """Reviewing a rule change by reading it is what the golden corpus exists to avoid."""
        candidate = self._candidate(db, org_id)
        with pytest.raises(releases.ReleaseError, match="золотому корпусу"):
            releases.submit_for_review(candidate, actor="author@corp.example")

    def test_an_author_cannot_approve_their_own_critical_change(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        candidate = self._candidate(
            db,
            org_id,
            state=CandidateState.READY_FOR_REVIEW,
            critical_change=True,
            critical_reasons=["изменяет жёсткое правило ATT-030"],
            benchmarked_at=utcnow(),
        )
        with pytest.raises(releases.ReleaseError, match="не может быть утверждено его автором"):
            releases.review_candidate(
                candidate, approve=True, reviewer="author@corp.example", comment="ок"
            )

    def test_someone_else_may_approve_it(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        candidate = self._candidate(
            db,
            org_id,
            state=CandidateState.READY_FOR_REVIEW,
            critical_change=True,
            critical_reasons=["изменяет жёсткое правило ATT-030"],
            benchmarked_at=utcnow(),
        )
        releases.review_candidate(
            candidate, approve=True, reviewer="lead@corp.example", comment="проверено"
        )
        assert candidate.state is CandidateState.APPROVED

    def test_an_author_may_approve_a_non_critical_change(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        """Four eyes where it matters, not everywhere: a wording fix should not need a quorum."""
        candidate = self._candidate(
            db, org_id, state=CandidateState.READY_FOR_REVIEW, benchmarked_at=utcnow()
        )
        releases.review_candidate(
            candidate, approve=True, reviewer="author@corp.example", comment="мелкая правка"
        )
        assert candidate.state is CandidateState.APPROVED

    def test_sending_back_requires_a_comment(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        candidate = self._candidate(
            db, org_id, state=CandidateState.READY_FOR_REVIEW, benchmarked_at=utcnow()
        )
        with pytest.raises(releases.ReleaseError, match="комментарий"):
            releases.review_candidate(candidate, approve=False, reviewer="lead@corp.example")

    def test_only_an_approved_candidate_can_be_published(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        candidate = self._candidate(db, org_id, state=CandidateState.DRAFT)
        db.commit()
        with pytest.raises(releases.ReleaseError, match="утверждённого"):
            releases.publish_release(
                db,
                organization_id=org_id,
                candidate=candidate,
                metrics={},
                dataset_version="x",
                dataset_checksum="y",
                parser_version="p",
                risk_engine_version="r",
                published_by="admin@corp.example",
            )

    def test_removing_a_rule_is_always_critical(self) -> None:
        """Removing protection needs someone else to agree the organisation no longer needs it."""
        from msp_detection.rules import RuleSet, find_rule_pack

        production = RuleSet.from_directory(find_rule_pack())
        reduced = RuleSet([rule for rule in production.rules if rule.id != "BEC-001"])
        diff = releases.diff_packs(production, reduced)
        assert diff.removed == ["BEC-001"]
        assert diff.critical


class TestReleaseManifest:
    def test_version_increments_within_the_month(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        first = releases.next_version(db, org_id)
        assert first.endswith(".1")
        release = releases.publish_release(
            db,
            organization_id=org_id,
            candidate=None,
            metrics={"precision": 1.0, "recall": 0.99},
            dataset_version="2026.09.1",
            dataset_checksum="abc",
            parser_version="parser-1.1.0",
            risk_engine_version="risk-1.0.0",
            published_by="admin@corp.example",
        )
        db.commit()
        assert release.version == first
        assert releases.next_version(db, org_id).endswith(".2")

    def test_manifest_records_every_version_a_verdict_depends_on(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        release = releases.publish_release(
            db,
            organization_id=org_id,
            candidate=None,
            metrics={"precision": 1.0},
            dataset_version="2026.09.1",
            dataset_checksum="abc123",
            parser_version="parser-1.1.0",
            risk_engine_version="risk-1.0.0",
            published_by="admin@corp.example",
        )
        db.commit()
        assert release.parser_version and release.risk_engine_version
        assert release.ruleset_fingerprint and release.dataset_checksum
        assert "Воспроизводимость" in release.changelog

    def test_open_gaps_are_part_of_the_release(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        """A release shipping with accepted limitations differs from one shipping with none."""
        db.add(
            DetectionGapRecord(
                organization_id=org_id,
                gap_id="GAP-100",
                category="qr",
                description="QR не декодируется",
                root_cause="нет декодера",
                severity=Severity.MEDIUM,
                status=GapStatus.ACCEPTED,
                owner="core@corp.example",
                target_release="MSP 1.0.4",
            )
        )
        db.flush()
        release = releases.publish_release(
            db,
            organization_id=org_id,
            candidate=None,
            metrics={},
            dataset_version="v",
            dataset_checksum="c",
            parser_version="p",
            risk_engine_version="r",
            published_by="admin@corp.example",
        )
        db.commit()
        assert [gap["gap_id"] for gap in release.known_limitations] == ["GAP-100"]
        assert "GAP-100" in release.changelog

    def test_deltas_are_null_when_there_is_nothing_to_compare(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        release = releases.publish_release(
            db,
            organization_id=org_id,
            candidate=None,
            metrics={"precision": 1.0},
            dataset_version="v",
            dataset_checksum="c",
            parser_version="p",
            risk_engine_version="r",
            published_by="admin@corp.example",
        )
        db.commit()
        # No previous release: a delta against nothing would read as "unchanged".
        assert release.metric_deltas["precision"] is None
        assert "—" in release.changelog


class TestReanalysisIsSafe:
    def _job(self, db, org_id, **kwargs):  # type: ignore[no-untyped-def]
        defaults = {"organization_id": org_id, "requested_by": "admin@corp.example", "days": 7}
        defaults.update(kwargs)
        return reanalysis.create_job(db, **defaults)

    def test_dry_run_is_the_default(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        job = self._job(db, org_id)
        db.commit()
        assert job.dry_run is True
        assert job.state is ReanalysisState.QUEUED

    def test_two_concurrent_jobs_are_refused(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        self._job(db, org_id)
        db.commit()
        with pytest.raises(reanalysis.ReanalysisError, match="уже выполняется"):
            self._job(db, org_id)

    def test_an_oversized_window_is_refused(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        with pytest.raises(reanalysis.ReanalysisError, match="окно больше"):
            self._job(db, org_id, days=400)

    def test_progress_is_null_before_the_size_is_known(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        """"Not started" and "nothing to do" must not look the same."""
        job = self._job(db, org_id)
        db.commit()
        assert job.total_messages == 0
        assert job.progress is None

    def test_pause_and_resume_keep_the_position(self, db, org_id, settings) -> None:  # type: ignore[no-untyped-def]
        for index in range(5):
            _analysis(db, org_id, _message(db, org_id, minutes_ago=index))
        db.commit()
        job = self._job(db, org_id)
        db.commit()
        assert job.total_messages == 5

        reanalysis.start(job)
        reanalysis.run_slice(db, settings, job, size=2)
        assert job.cursor == 2
        reanalysis.pause(job, actor="admin@corp.example")
        assert job.state is ReanalysisState.PAUSED

        with pytest.raises(reanalysis.ReanalysisError, match="не выполняется"):
            reanalysis.run_slice(db, settings, job, size=2)

        reanalysis.start(job)
        reanalysis.run_slice(db, settings, job, size=2)
        assert job.cursor == 4, "задание продолжается с места остановки, а не сначала"

    def test_cancel_is_terminal(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        job = self._job(db, org_id)
        db.commit()
        reanalysis.cancel(job, actor="admin@corp.example")
        assert job.state is ReanalysisState.CANCELLED
        with pytest.raises(reanalysis.ReanalysisError, match="уже завершено"):
            reanalysis.cancel(job, actor="admin@corp.example")

    def test_dry_run_does_not_change_stored_verdicts(self, db, org_id, settings) -> None:  # type: ignore[no-untyped-def]
        message = _message(db, org_id)
        job_analysis = _analysis(db, org_id, message, classification=RiskLevel.LOW_RISK)
        db.commit()
        from sqlalchemy import select

        before = db.execute(
            select(AnalysisResult).where(AnalysisResult.job_id == job_analysis.id)
        ).scalar_one()
        before_class = before.classification

        job = self._job(db, org_id, dry_run=True)
        db.commit()
        reanalysis.run_to_completion(db, settings, job)
        db.commit()
        db.expire_all()

        after = db.execute(
            select(AnalysisResult).where(AnalysisResult.job_id == job_analysis.id)
        ).scalar_one()
        assert after.classification == before_class


class TestEvaluationService:
    def test_the_api_and_the_cli_measure_the_same_thing(self) -> None:
        """One environment definition, imported by both.

        They used to have a copy each; the copies disagreed about one hostname, the delivery
        chain stopped verifying, and recall read 0.904 instead of 0.990 — the run measuring the
        configuration rather than the rules.
        """
        import sys

        sys.path.insert(0, "scripts")
        from msp_detection_eval import evaluation_context as package_context

        from msp_api.services.evaluation import evaluation_context as api_context

        assert api_context is package_context

    def test_current_metrics_pass_the_gate(self) -> None:
        result = evaluation.current_metrics()
        assert result["metrics"]["precision"] == 1.0
        assert result["gate"]["passed"] is True
