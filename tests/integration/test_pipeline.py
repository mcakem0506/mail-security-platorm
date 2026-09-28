"""Integration tests for the full analysis pipeline (ТЗ 35, 41, 42)."""

from __future__ import annotations

import pytest
from fixtures.corpus import BY_NAME, CORPUS
from msp_api.db.models import (
    AnalysisJob,
    AnalysisResult,
    Attachment,
    Campaign,
    CampaignMessage,
    DetectionSignal,
    Indicator,
    MailMessage,
    ProviderLookup,
    RiskVerdictHistory,
)
from msp_api.services.analysis import (
    apply_enrichment,
    collect_ti_indicators,
    employee_view,
    run_local_analysis,
)
from msp_api.services.storage import FilesystemObjectStorage
from msp_contracts import (
    RISK_ORDER,
    AnalysisStatus,
    IntakeSource,
    IOCType,
    JobState,
    RiskLevel,
    TIState,
    TIStatus,
)
from msp_detection import EnrichmentInput
from msp_ti import PrivacyPolicy, ThreatIntelligenceHub, TICache
from msp_virustotal import MockVirusTotalProvider
from sqlalchemy import func, select


@pytest.fixture
def storage(storage_dir):  # type: ignore[no-untyped-def]
    return FilesystemObjectStorage(storage_dir)


def make_job(db, organization, *, source=IntakeSource.ADDIN, mailbox="buh@corp.example", report=False):  # type: ignore[no-untyped-def]
    job = AnalysisJob(
        organization_id=organization.id,
        source=source,
        requester_mailbox=mailbox,
        is_report=report,
    )
    db.add(job)
    db.flush()
    return job


class TestLocalStage:
    def test_local_analysis_persists_everything(self, db, organization, settings, storage) -> None:
        job = make_job(db, organization, report=True)
        outcome = run_local_analysis(
            db, settings, job=job, raw=BY_NAME["09_bank_details_change"].raw, storage=storage
        )
        db.commit()

        assert outcome.verdict.classification in {RiskLevel.HIGH_RISK, RiskLevel.MALICIOUS}
        assert job.state is JobState.PARTIAL, "local stage must not claim completion before enrichment"
        assert job.message_id

        message = db.get(MailMessage, job.message_id)
        assert message.sender_address
        assert message.campaign_fingerprint
        assert message.auth_summary  # authentication results were recorded

        result = db.execute(select(AnalysisResult).where(AnalysisResult.job_id == job.id)).scalar_one()
        signals = (
            db.execute(select(DetectionSignal).where(DetectionSignal.result_id == result.id)).scalars().all()
        )
        assert signals, "verdict must be backed by stored signals"
        assert all(s.explanation for s in signals)
        assert all(s.rule_id and s.rule_version for s in signals)

        indicators = db.execute(
            select(func.count()).select_from(Indicator).where(Indicator.organization_id == organization.id)
        ).scalar_one()
        assert indicators > 0

        history = (
            db.execute(select(RiskVerdictHistory).where(RiskVerdictHistory.message_id == job.message_id))
            .scalars()
            .all()
        )
        assert len(history) == 1

    def test_raw_message_stored_and_readable(self, db, organization, settings, storage) -> None:
        job = make_job(db, organization)
        outcome = run_local_analysis(
            db, settings, job=job, raw=BY_NAME["01_normal_internal"].raw, storage=storage
        )
        db.commit()
        content = outcome.message.content
        assert content is not None and content.raw_eml_key
        assert storage.get(content.raw_eml_key) == BY_NAME["01_normal_internal"].raw

    def test_attachments_stored_with_metadata(self, db, organization, settings, storage) -> None:
        job = make_job(db, organization)
        run_local_analysis(db, settings, job=job, raw=BY_NAME["12_double_extension"].raw, storage=storage)
        db.commit()
        attachments = (
            db.execute(select(Attachment).where(Attachment.message_id == job.message_id)).scalars().all()
        )
        assert attachments
        assert any("DOUBLE_EXTENSION" in (a.flags or []) for a in attachments)
        assert all(a.sha256 for a in attachments)

    def test_unparseable_message_does_not_break_the_pipeline(
        self, db, organization, settings, storage
    ) -> None:
        job = make_job(db, organization)
        outcome = run_local_analysis(db, settings, job=job, raw=b"not a message at all", storage=storage)
        db.commit()
        assert outcome.verdict.classification is not RiskLevel.LOW_RISK
        assert job.state is JobState.PARTIAL

    def test_performance_target_for_a_simple_message(self, db, organization, settings, storage) -> None:
        """ТЗ 35: local metadata analysis under 5s for an ordinary message."""
        job = make_job(db, organization)
        outcome = run_local_analysis(
            db, settings, job=job, raw=BY_NAME["02_normal_external"].raw, storage=storage
        )
        db.commit()
        assert outcome.duration_ms < 5000, f"local analysis took {outcome.duration_ms} ms"


class TestEnrichmentStage:
    def _hub(self, provider=None, **policy):  # type: ignore[no-untyped-def]
        return ThreatIntelligenceHub(
            [provider or MockVirusTotalProvider()],
            policy=PrivacyPolicy(corporate_domains=("corp.example",), **policy),
            cache=TICache(),
        )

    def test_enrichment_raises_verdict_and_records_lookups(self, db, organization, settings, storage) -> None:
        job = make_job(db, organization)
        outcome = run_local_analysis(
            db, settings, job=job, raw=BY_NAME["19_known_bad_indicator"].raw, storage=storage
        )
        db.commit()
        before = outcome.verdict.classification

        hub = self._hub()
        results = hub.enrich(collect_ti_indicators(outcome.detection))
        verdict = apply_enrichment(
            db,
            settings,
            job=job,
            parsed=outcome.parsed,
            detection=outcome.detection,
            enrichment=EnrichmentInput(ti_results=results, ti_configured=True),
        )
        db.commit()

        assert RISK_ORDER[verdict.classification] >= RISK_ORDER[before], "enrichment must not lower risk"
        assert verdict.classification is RiskLevel.MALICIOUS
        assert verdict.hard_signals
        assert job.state is JobState.COMPLETED
        assert job.ti_state is TIState.COMPLETED

        lookups = (
            db.execute(select(ProviderLookup).where(ProviderLookup.analysis_job_id == job.id)).scalars().all()
        )
        assert lookups
        for lookup in lookups:
            # Only the normalised shape is stored, never the raw provider payload (ТЗ 42.9).
            assert set(lookup.summary).issubset(
                {
                    "stats",
                    "reputation",
                    "times_submitted",
                    "mode",
                    "domain_age_days",
                    "recently_registered",
                    "meaningful_name",
                    "file_type",
                    "reason",
                }
            )

    def test_provider_outage_leaves_analysis_usable(self, db, organization, settings, storage) -> None:
        """ТЗ 42.10: a provider outage must not fail the core platform."""
        job = make_job(db, organization)
        outcome = run_local_analysis(
            db, settings, job=job, raw=BY_NAME["07_fake_microsoft_login"].raw, storage=storage
        )
        db.commit()

        broken = MockVirusTotalProvider(fail_rate=1.0)
        hub = self._hub(broken)
        results = hub.enrich(collect_ti_indicators(outcome.detection))
        # URLs are blocked by the privacy policy before reaching the provider; everything that
        # does reach it must report the outage rather than a clean answer.
        reached = [r for r in results if r.status is not TIStatus.POLICY_BLOCKED]
        assert reached and all(r.status is TIStatus.PROVIDER_UNAVAILABLE for r in reached)

        verdict = apply_enrichment(
            db,
            settings,
            job=job,
            parsed=outcome.parsed,
            detection=outcome.detection,
            enrichment=EnrichmentInput(ti_results=results, ti_configured=True),
        )
        db.commit()
        assert job.state is JobState.COMPLETED
        assert job.ti_state is TIState.PARTIAL
        assert verdict.classification is not RiskLevel.LOW_RISK
        assert verdict.missing_evidence

    def test_privacy_gate_blocks_corporate_indicators(self, db, organization, settings, storage) -> None:
        job = make_job(db, organization)
        outcome = run_local_analysis(
            db, settings, job=job, raw=BY_NAME["05_punycode_homoglyph"].raw, storage=storage
        )
        db.commit()
        hub = self._hub()
        indicators = collect_ti_indicators(outcome.detection)
        indicators.append(type(indicators[0])(ioc_type=IOCType.DOMAIN, value="corp.example", context="test"))
        results = hub.enrich(indicators)
        blocked = [r for r in results if r.status is TIStatus.POLICY_BLOCKED]
        assert blocked, "the corporate domain must not be sent to an external provider"
        assert any("corporate" in (r.summary.get("reason") or "") for r in blocked)

    def test_urls_are_not_sent_by_default(self, db, organization, settings, storage) -> None:
        job = make_job(db, organization)
        outcome = run_local_analysis(
            db, settings, job=job, raw=BY_NAME["07_fake_microsoft_login"].raw, storage=storage
        )
        db.commit()
        hub = self._hub()
        results = hub.enrich(collect_ti_indicators(outcome.detection))
        url_results = [r for r in results if r.ioc_type is IOCType.URL]
        assert url_results
        assert all(r.status is TIStatus.POLICY_BLOCKED for r in url_results)

    def test_cache_prevents_repeated_external_calls(self, db, organization, settings, storage) -> None:
        job = make_job(db, organization)
        outcome = run_local_analysis(
            db, settings, job=job, raw=BY_NAME["19_known_bad_indicator"].raw, storage=storage
        )
        db.commit()
        hub = self._hub()
        indicators = collect_ti_indicators(outcome.detection)
        hub.enrich(indicators)
        calls_after_first = hub.stats.external_calls
        hub.enrich(indicators)
        assert hub.stats.external_calls == calls_after_first
        assert hub.stats.served_from_cache > 0


class TestCampaignCorrelation:
    def test_same_campaign_groups_across_recipients(self, db, organization, settings, storage) -> None:
        """ТЗ 41.8: one campaign sent to several users is detected as one campaign."""
        fixtures = [f for f in CORPUS if f.name.startswith("16_campaign_")]
        assert len(fixtures) >= 3
        for fixture in fixtures:
            job = make_job(db, organization)
            run_local_analysis(db, settings, job=job, raw=fixture.raw, storage=storage)
        db.commit()

        campaigns = (
            db.execute(select(Campaign).where(Campaign.organization_id == organization.id)).scalars().all()
        )
        assert len(campaigns) == 1, f"expected one campaign, got {len(campaigns)}"
        campaign = campaigns[0]
        assert campaign.message_count == len(fixtures)
        links = db.execute(
            select(func.count())
            .select_from(CampaignMessage)
            .where(CampaignMessage.campaign_id == campaign.id)
        ).scalar_one()
        assert links == len(fixtures)

    def test_unrelated_messages_do_not_merge(self, db, organization, settings, storage) -> None:
        for name in ("01_normal_internal", "08_invoice_bec", "12_double_extension"):
            job = make_job(db, organization)
            run_local_analysis(db, settings, job=job, raw=BY_NAME[name].raw, storage=storage)
        db.commit()
        campaigns = (
            db.execute(select(Campaign).where(Campaign.organization_id == organization.id)).scalars().all()
        )
        assert len(campaigns) == 3, "unrelated messages must not be grouped together"


class TestEmployeeProjection:
    def test_employee_sees_limited_explainable_output(self, db, organization, settings, storage) -> None:
        job = make_job(db, organization, report=True)
        outcome = run_local_analysis(
            db, settings, job=job, raw=BY_NAME["09_bank_details_change"].raw, storage=storage
        )
        db.commit()
        view = employee_view(outcome.verdict, job)
        assert view["classification"] in {"HIGH_RISK", "MALICIOUS", "SUSPICIOUS"}
        assert 0 < len(view["reasons"]) <= 5
        assert view["recommendation"]
        assert view["reported_to_security"] is True
        serialised = str(view)
        for leaked in ("rule_id", "SND-", "BEC-", "evidence", "weight", "score"):
            assert leaked not in serialised, f"internal detail {leaked} leaked to the employee view"


class TestCorpusCoverage:
    @pytest.mark.parametrize("fixture", CORPUS, ids=lambda f: f.name)
    def test_every_fixture_analyses_without_error(self, db, organization, settings, storage, fixture) -> None:
        job = make_job(db, organization)
        outcome = run_local_analysis(db, settings, job=job, raw=fixture.raw, storage=storage)
        db.commit()
        assert job.status is not AnalysisStatus.ERROR
        assert outcome.verdict.classification in set(RiskLevel)
        if fixture.expect_min_level != "LOW_RISK":
            expected = RiskLevel(fixture.expect_min_level)
            actual = outcome.verdict.classification
            if expected is RiskLevel.UNKNOWN or fixture.requires_enrichment:
                assert actual is not RiskLevel.LOW_RISK, f"{fixture.name}: presented as clean"
            else:
                assert RISK_ORDER[actual] >= RISK_ORDER[expected], (
                    f"{fixture.name}: expected at least {expected.value}, got {actual.value}"
                )
        for fact in fixture.expect_facts:
            assert outcome.detection.facts.get(fact), f"{fixture.name}: missing fact {fact}"
