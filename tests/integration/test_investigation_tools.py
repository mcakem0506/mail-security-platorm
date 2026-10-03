"""Related search, evidence graph, campaign curation, reporting quality (§16, §30–§33).

The properties worth testing here are the judgement calls, not the plumbing:

* a related message always states *why* it is related;
* the evidence graph shows what the engine actually did, including what it could not see;
* a merge suggestion is a suggestion — nothing is merged until an analyst says so;
* a split is refused when it would empty the campaign, because that is a rename;
* the reporting-quality figures come back as ``None`` rather than 0% when nothing has been
  classified yet.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from msp_api.db.models import (
    AnalysisJob,
    AnalysisResult,
    Attachment,
    Campaign,
    CampaignMessage,
    DetectionSignal,
    Incident,
    IncidentClassification,
    IncidentMessage,
    MailMessage,
)
from msp_api.services import investigation
from msp_contracts import AnalystClassification, IntakeSource, RiskLevel, Severity, utcnow


@pytest.fixture
def org_id(organization) -> str:  # type: ignore[no-untyped-def]
    return organization.id


def _message(
    db,  # type: ignore[no-untyped-def]
    org_id: str,
    *,
    subject: str = "Счёт на оплату",
    sender: str = "billing@partner.test",
    domain: str = "partner.test",
    reply_to: str = "",
    campaign: str = "",
    reported_by: str | None = None,
    minutes_ago: int = 0,
) -> MailMessage:
    message = MailMessage(
        organization_id=org_id,
        internet_message_id=f"<{subject}-{sender}-{minutes_ago}@test>",
        raw_sha256=f"{abs(hash((subject, sender, minutes_ago))):064x}"[:64],
        subject=subject,
        sender_address=sender,
        sender_display_name="Поставщик",
        sender_domain=domain,
        reply_to_address=reply_to,
        recipient_count=1,
        size_bytes=2048,
        received_at=utcnow() - timedelta(minutes=minutes_ago),
        source=IntakeSource.API,
        campaign_fingerprint=campaign,
        reported_by=reported_by,
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
    missing: list[str] | None = None,
) -> tuple[AnalysisJob, AnalysisResult]:
    job = AnalysisJob(organization_id=org_id, message_id=message.id, source=IntakeSource.API)
    db.add(job)
    db.flush()
    result = AnalysisResult(
        job_id=job.id,
        message_id=message.id,
        classification=classification,
        score=70,
        confidence="high",
        recommendation="Передайте в службу ИБ",
        missing_evidence=missing or [],
    )
    db.add(result)
    db.flush()
    return job, result


class TestRelatedSearch:
    def test_every_related_message_states_the_relation(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        origin = _message(db, org_id, campaign="camp-1", reply_to="pay@attacker.test")
        _message(db, org_id, sender="billing@partner.test", minutes_ago=10)
        _message(db, org_id, sender="other@partner.test", minutes_ago=20)
        _message(
            db,
            org_id,
            subject="Выписка за квартал",
            sender="x@unrelated.test",
            domain="unrelated.test",
            minutes_ago=30,
        )
        db.commit()

        found = investigation.find_related(db, organization_id=org_id, message_id=origin.id)
        assert found, "связанные письма должны найтись"
        assert all(item.reasons for item in found), "связь без причины не является доказательством"
        assert all(item.message_id != origin.id for item in found), "само письмо в список не входит"
        senders = {item.sender_address for item in found}
        assert "x@unrelated.test" not in senders

    def test_a_shared_subject_alone_ranks_last(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        """Subject is the weakest relation: «Счёт на оплату» is half the corporate mail.

        It stays in the list — analysts ask for it — but a message linked only by subject must
        never outrank one linked by sender, attachment or campaign.
        """
        origin = _message(db, org_id, campaign="camp-7")
        _message(db, org_id, sender="billing@partner.test", campaign="camp-7", minutes_ago=5)
        subject_only = _message(
            db, org_id, sender="someone@elsewhere.test", domain="elsewhere.test", minutes_ago=9
        )
        db.commit()

        found = investigation.find_related(db, organization_id=org_id, message_id=origin.id)
        weak = next(item for item in found if item.message_id == subject_only.id)
        assert weak.reasons == ["та же тема"]
        assert found[-1].message_id == subject_only.id, (
            "связь только по теме не должна опережать связь по отправителю или кампании"
        )

    def test_shared_attachment_is_a_relation(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        first = _message(db, org_id, subject="Акт", minutes_ago=5)
        second = _message(db, org_id, subject="Акт-2", sender="other@else.test", domain="else.test")
        digest = "a" * 64
        for message in (first, second):
            db.add(
                Attachment(
                    message_id=message.id,
                    filename="akt.docx",
                    normalized_filename="akt.docx",
                    declared_mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    detected_type="ooxml",
                    extension="docx",
                    size_bytes=1024,
                    sha256=digest,
                )
            )
        db.commit()

        found = investigation.find_related(db, organization_id=org_id, message_id=second.id)
        match = next(item for item in found if item.message_id == first.id)
        assert "то же вложение" in match.reasons

    def test_messages_from_another_organization_are_never_returned(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        origin = _message(db, org_id)
        other = _message(db, "other-org", sender="billing@partner.test")
        db.commit()
        found = investigation.find_related(db, organization_id=org_id, message_id=origin.id)
        assert all(item.message_id != other.id for item in found)


class TestEvidenceGraph:
    def test_graph_shows_facts_rules_and_the_verdict(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        message = _message(db, org_id)
        job, result = _analysis(db, org_id, message)
        db.add(
            DetectionSignal(
                result_id=result.id,
                signal_id="sig-1",
                rule_id="BEC-001",
                rule_version=1,
                category="invoice_payment_fraud",
                title="Запрос смены реквизитов",
                explanation="Письмо просит сменить платёжные реквизиты",
                severity=Severity.HIGH,
                confidence=0.8,
                weight=45.0,
                source="rule",
                evidence={"intent_bank_details_change": True},
                observed_at=utcnow(),
            )
        )
        db.commit()

        graph = investigation.build_evidence_graph(db, job_id=job.id)
        assert graph is not None
        kinds = {node.kind for node in graph.nodes}
        assert {"message", "fact", "rule", "verdict"} <= kinds
        assert any(edge.kind == "contributed" for edge in graph.edges)
        # Every edge is labelled: an unlabelled edge is an assertion the analyst cannot check.
        assert all(edge.label for edge in graph.edges)

    def test_shadow_rule_is_drawn_as_contributing_nothing(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        message = _message(db, org_id)
        job, result = _analysis(db, org_id, message)
        db.add(
            DetectionSignal(
                result_id=result.id,
                signal_id="sig-shadow",
                rule_id="URL-032",
                rule_version=1,
                category="phishing_url",
                title="Теневое правило",
                explanation="Измеряется, но не влияет на вердикт",
                severity=Severity.HIGH,
                confidence=0.7,
                weight=0.0,
                source="rule",
                evidence={},
                shadow=True,
                observed_at=utcnow(),
            )
        )
        db.commit()

        graph = investigation.build_evidence_graph(db, job_id=job.id)
        assert graph is not None
        shadow_edges = [edge for edge in graph.edges if edge.kind == "shadow"]
        assert shadow_edges, "теневое правило должно быть видно на графе"
        assert "баллов не даёт" in shadow_edges[0].label

    def test_what_was_not_checked_is_part_of_the_graph(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        """ТЗ §3: what the platform could not see belongs in the explanation, not a footnote."""
        message = _message(db, org_id)
        job, _ = _analysis(db, org_id, message, missing=["Архив защищён паролем и не проверен"])
        db.commit()
        graph = investigation.build_evidence_graph(db, job_id=job.id)
        assert graph is not None
        assert any(node.kind == "missing" for node in graph.nodes)
        assert any(edge.kind == "limited" for edge in graph.edges)


class TestCampaignCuration:
    def _campaign(self, db, org_id, **kwargs):  # type: ignore[no-untyped-def]
        now = utcnow()
        campaign = Campaign(
            organization_id=org_id,
            fingerprint=kwargs.pop("fingerprint", "fp-1"),
            name=kwargs.pop("name", "Кампания"),
            first_seen=kwargs.pop("first_seen", now),
            last_seen=kwargs.pop("last_seen", now),
            message_count=kwargs.pop("message_count", 0),
            recipient_count=kwargs.pop("recipient_count", 0),
            reported_count=kwargs.pop("reported_count", 0),
            verdict_distribution=kwargs.pop("verdict_distribution", {}),
            indicators=kwargs.pop("indicators", []),
            subjects=kwargs.pop("subjects", []),
            senders=kwargs.pop("senders", []),
            **kwargs,
        )
        db.add(campaign)
        db.flush()
        return campaign

    def test_similar_campaigns_are_suggested_not_merged(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        left = self._campaign(
            db,
            org_id,
            fingerprint="fp-a",
            senders=["billing@attacker.test"],
            indicators=["attacker.test", "pay.attacker.test"],
            subjects=["счёт на оплату"],
        )
        right = self._campaign(
            db,
            org_id,
            fingerprint="fp-b",
            senders=["billing@attacker.test"],
            indicators=["attacker.test"],
            subjects=["счёт на оплату"],
        )
        db.commit()

        suggestions = investigation.suggest_merges(db, org_id)
        assert suggestions, "похожие кампании должны попасть в предложения"
        assert suggestions[0].reasons, "предложение без причины бесполезно"
        # Nothing happened to the campaigns themselves.
        db.expire_all()
        assert db.get(Campaign, left.id) is not None
        assert db.get(Campaign, right.id) is not None

    def test_campaigns_months_apart_are_not_suggested(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        now = utcnow()
        self._campaign(
            db,
            org_id,
            fingerprint="fp-old",
            senders=["a@x.test"],
            last_seen=now - timedelta(days=120),
        )
        self._campaign(db, org_id, fingerprint="fp-new", senders=["a@x.test"], last_seen=now)
        db.commit()
        assert investigation.suggest_merges(db, org_id) == []

    def test_merge_moves_messages_and_keeps_totals(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        target = self._campaign(db, org_id, fingerprint="fp-t", message_count=2, recipient_count=2)
        source = self._campaign(db, org_id, fingerprint="fp-s", message_count=1, recipient_count=1)
        message = _message(db, org_id)
        db.add(CampaignMessage(campaign_id=source.id, message_id=message.id))
        db.commit()

        merged = investigation.merge_campaigns(
            db, organization_id=org_id, target_id=target.id, source_id=source.id, actor="a@corp"
        )
        db.commit()
        assert merged is not None
        assert merged.message_count == 3
        assert db.get(Campaign, source.id) is None
        assert investigation.campaign_message_count(db, target.id) == 1

    def test_merging_a_campaign_into_itself_is_refused(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        campaign = self._campaign(db, org_id, fingerprint="fp-self")
        db.commit()
        assert (
            investigation.merge_campaigns(
                db,
                organization_id=org_id,
                target_id=campaign.id,
                source_id=campaign.id,
                actor="a@corp",
            )
            is None
        )

    def test_split_extracts_messages_into_a_new_campaign(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        campaign = self._campaign(db, org_id, fingerprint="fp-split", message_count=3, recipient_count=3)
        messages = [_message(db, org_id, minutes_ago=index) for index in range(3)]
        for message in messages:
            db.add(CampaignMessage(campaign_id=campaign.id, message_id=message.id))
        db.commit()

        created = investigation.split_campaign(
            db,
            organization_id=org_id,
            campaign_id=campaign.id,
            message_ids=[messages[0].id],
            name="Отдельная волна",
            actor="a@corp",
        )
        db.commit()
        assert created is not None
        assert created.message_count == 1
        assert investigation.campaign_message_count(db, created.id) == 1
        assert investigation.campaign_message_count(db, campaign.id) == 2

    def test_splitting_everything_out_is_refused(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        """Extracting every message is a rename, and would leave an empty campaign behind."""
        campaign = self._campaign(db, org_id, fingerprint="fp-all", message_count=2)
        messages = [_message(db, org_id, minutes_ago=index) for index in range(2)]
        for message in messages:
            db.add(CampaignMessage(campaign_id=campaign.id, message_id=message.id))
        db.commit()

        assert (
            investigation.split_campaign(
                db,
                organization_id=org_id,
                campaign_id=campaign.id,
                message_ids=[m.id for m in messages],
                name="Всё сразу",
                actor="a@corp",
            )
            is None
        )


class TestReportingQuality:
    def test_no_reports_is_reported_as_no_data(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        result = investigation.reporting_quality(db, org_id)
        assert result["total_reports"] == 0
        assert result["confirmation_rate"] is None

    def test_unclassified_reports_do_not_read_as_zero_percent(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        """A backlog nobody has judged must not look like a 0% confirmation rate."""
        _message(db, org_id, reported_by="user@corp.example")
        db.commit()
        result = investigation.reporting_quality(db, org_id)
        assert result["total_reports"] == 1
        assert result["confirmation_rate"] is None
        assert result["classified_reports"] == 0

    def test_confirmed_report_counts_and_credits_the_reporter(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        message = _message(db, org_id, reported_by="user@corp.example")
        _analysis(db, org_id, message, classification=RiskLevel.LOW_RISK)
        incident = Incident(
            organization_id=org_id,
            number=1,
            title="Фишинг",
            summary="Подтверждён",
            severity=Severity.HIGH,
        )
        db.add(incident)
        db.flush()
        db.add(IncidentMessage(incident_id=incident.id, message_id=message.id))
        db.add(
            IncidentClassification(
                organization_id=org_id,
                incident_id=incident.id,
                classification=AnalystClassification.CONFIRMED_PHISHING,
                analyst_email="analyst@corp.example",
            )
        )
        db.commit()

        result = investigation.reporting_quality(db, org_id)
        assert result["confirmed_threats"] == 1
        assert result["confirmation_rate"] == 1.0
        # The platform itself said LOW_RISK, so this report caught something it had missed —
        # the number that justifies the reporting button existing.
        assert result["reports_that_found_something_new"] == 1
        assert result["top_reporters"][0]["reporter"] == "user@corp.example"

    def test_result_carries_the_note_against_misreading_it(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        _message(db, org_id, reported_by="user@corp.example")
        db.commit()
        assert "не повод отговаривать" in investigation.reporting_quality(db, org_id)["note"]


class TestIncidentSpanningSeveralCampaigns:
    """An incident may group more than one wave (regression, found on a live stand).

    Both the queue and the timeline used to assume an incident touches at most one campaign.
    Grouping two waves into one investigation is an ordinary thing for an analyst to do, and it
    made the whole queue return 500 for everybody — not just that one row.
    """

    def _campaign(self, db, org_id, fingerprint, name, count):  # type: ignore[no-untyped-def]
        now = utcnow()
        campaign = Campaign(
            organization_id=org_id,
            fingerprint=fingerprint,
            name=name,
            first_seen=now - timedelta(hours=2),
            last_seen=now,
            message_count=count,
            recipient_count=count,
            reported_count=0,
            verdict_distribution={},
            indicators=[],
            subjects=[],
            senders=[],
        )
        db.add(campaign)
        db.flush()
        return campaign

    def _incident_over(self, db, org_id, messages):  # type: ignore[no-untyped-def]
        incident = Incident(
            organization_id=org_id,
            number=4242,
            title="Две волны в одном инциденте",
            summary="Аналитик объединил две кампании для разбора.",
            severity=Severity.HIGH,
        )
        db.add(incident)
        db.flush()
        for message in messages:
            db.add(IncidentMessage(incident_id=incident.id, message_id=message.id))
        db.flush()
        return incident

    def test_queue_handles_it_and_takes_the_widest_spread(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        from msp_api.services import triage

        small = self._campaign(db, org_id, "fp-small", "Малая волна", 3)
        large = self._campaign(db, org_id, "fp-large", "Большая волна", 17)
        first = _message(db, org_id, minutes_ago=30)
        second = _message(db, org_id, sender="other@partner.test", minutes_ago=20)
        db.add(CampaignMessage(campaign_id=small.id, message_id=first.id))
        db.add(CampaignMessage(campaign_id=large.id, message_id=second.id))
        incident = self._incident_over(db, org_id, [first, second])
        db.commit()

        context = triage.build_context(db, incident)
        assert context.campaign_size == 17, "для приоритета важен самый широкий охват"

        queue = triage.build_queue(db, org_id)
        assert any(entry.incident_id == incident.id for entry in queue)

    def test_timeline_mentions_every_campaign(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        from msp_api.services import triage

        first_campaign = self._campaign(db, org_id, "fp-a", "Первая волна", 2)
        second_campaign = self._campaign(db, org_id, "fp-b", "Вторая волна", 5)
        first = _message(db, org_id, minutes_ago=40)
        second = _message(db, org_id, sender="two@partner.test", minutes_ago=35)
        db.add(CampaignMessage(campaign_id=first_campaign.id, message_id=first.id))
        db.add(CampaignMessage(campaign_id=second_campaign.id, message_id=second.id))
        incident = self._incident_over(db, org_id, [first, second])
        db.commit()

        timeline = triage.build_timeline(db, incident)
        created = [entry for entry in timeline if entry["event"] == "campaign_created"]
        assert len(created) == 2, "обе кампании должны попасть в хронологию"
