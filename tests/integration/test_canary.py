"""Canary rollout of detection rules (ТЗ 1.0.3 §52).

The properties worth testing are the ones that make a canary useful rather than decorative:

* outside the scope the rule is **withheld, not switched off** — it still evaluates and is still
  recorded, which is what makes the untouched majority a control group;
* a hard rule outside the scope must not set a verdict floor, or the rollout would not be
  limited at all;
* membership is stable for a given mailbox, because a rule that treats the same person
  differently from one message to the next cannot be explained or measured;
* nothing happens at the review date by itself — an overdue rollout becomes visible, and a
  human decides.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from msp_api.db.models import (
    AnalysisJob,
    AnalysisResult,
    DetectionSignal,
    Incident,
    IncidentClassification,
    IncidentMessage,
    MailMessage,
    RuleCanary,
)
from msp_api.services import canary
from msp_contracts import (
    AnalystClassification,
    CanaryScope,
    CanaryState,
    IntakeSource,
    RiskLevel,
    RuleStatus,
    Severity,
    utcnow,
)
from msp_detection import AnalysisContext, analyze, default_ruleset
from msp_mail_parser import parse_message


@pytest.fixture
def org_id(organization) -> str:  # type: ignore[no-untyped-def]
    return organization.id


def _started(db, org_id: str, **kwargs) -> RuleCanary:  # type: ignore[no-untyped-def]
    defaults = {
        "rule_id": "ATT-001",
        "rule_status": RuleStatus.ACTIVE,
        "rule_version": 1,
        "scope": CanaryScope.MAILBOX,
        "scope_values": ["buh@corp.example"],
        "reason": "Проверяем на бухгалтерии перед включением всем",
        "created_by": "admin@corp.example",
    }
    defaults.update(kwargs)
    created = canary.start(db, organization_id=org_id, **defaults)
    db.commit()
    return created


class TestScopeMembership:
    def test_mailbox_scope(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        rollout = _started(db, org_id, scope_values=["buh@corp.example", "Finance@Corp.Example"])
        assert canary.in_scope(rollout, mailbox="buh@corp.example")
        # Case and surrounding spaces must not decide who is protected.
        assert canary.in_scope(rollout, mailbox="  FINANCE@corp.example ")
        assert not canary.in_scope(rollout, mailbox="dev@corp.example")

    def test_department_scope(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        rollout = _started(db, org_id, scope=CanaryScope.DEPARTMENT, scope_values=["Бухгалтерия"])
        assert canary.in_scope(rollout, mailbox="x@corp.example", department="бухгалтерия")
        assert not canary.in_scope(rollout, mailbox="x@corp.example", department="Разработка")

    def test_percent_scope_is_stable_for_a_mailbox(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        """The same person is always on the same side of the split."""
        rollout = _started(db, org_id, scope=CanaryScope.PERCENT, scope_values=[], percent=50)
        first = canary.in_scope(rollout, mailbox="someone@corp.example")
        for _ in range(20):
            assert canary.in_scope(rollout, mailbox="someone@corp.example") is first

    def test_percent_scope_splits_the_population(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        rollout = _started(db, org_id, scope=CanaryScope.PERCENT, scope_values=[], percent=50)
        mailboxes = [f"user{index}@corp.example" for index in range(200)]
        inside = sum(1 for m in mailboxes if canary.in_scope(rollout, mailbox=m))
        # A deterministic hash will not land on exactly half; it must land nowhere near 0 or all.
        assert 60 < inside < 140, inside

    def test_unknown_recipient_stays_outside(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        """With nothing to hash, the safe side is the one where the rule cannot decide."""
        rollout = _started(db, org_id, scope=CanaryScope.PERCENT, scope_values=[], percent=99)
        assert not canary.in_scope(rollout, mailbox="")


class TestStartingAndDeciding:
    def test_a_shadow_rule_cannot_be_canaried(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        """It already scores nothing everywhere; a 'rollout' would describe nothing."""
        with pytest.raises(canary.CanaryError, match="активному правилу"):
            canary.start(
                db,
                organization_id=org_id,
                rule_id="URL-032",
                rule_status=RuleStatus.SHADOW,
                rule_version=1,
                scope=CanaryScope.MAILBOX,
                scope_values=["buh@corp.example"],
                reason="Хочу проверить теневое правило",
                created_by="admin@corp.example",
            )

    def test_two_rollouts_of_one_rule_are_refused(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        _started(db, org_id)
        with pytest.raises(canary.CanaryError, match="уже идёт"):
            _started(db, org_id)

    @pytest.mark.parametrize("percent", [0, 100])
    def test_degenerate_percentages_are_refused(self, db, org_id, percent: int) -> None:  # type: ignore[no-untyped-def]
        """0% protects nobody while looking live; 100% is not a canary."""
        with pytest.raises(canary.CanaryError, match="процент"):
            _started(db, org_id, scope=CanaryScope.PERCENT, scope_values=[], percent=percent)

    def test_an_empty_scope_is_refused(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        with pytest.raises(canary.CanaryError, match="адрес или отдел"):
            _started(db, org_id, scope_values=[])

    def test_review_date_is_required_and_bounded(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        with pytest.raises(canary.CanaryError, match="от 1 до"):
            _started(db, org_id, days=90)
        rollout = _started(db, org_id, days=7)
        assert rollout.review_at > utcnow()

    def test_promotion_ends_the_rollout(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        rollout = _started(db, org_id)
        canary.decide(db, rollout, state=CanaryState.PROMOTED, decided_by="admin@corp.example", note="ok")
        db.commit()
        assert rollout.state is CanaryState.PROMOTED
        assert canary.active_for(db, organization_id=org_id, rule_id="ATT-001") is None
        # And the rule stops being withheld from anyone.
        assert canary.withheld_rules(db, organization_id=org_id, mailbox="dev@corp.example") == frozenset()

    def test_aborting_requires_a_reason(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        rollout = _started(db, org_id)
        with pytest.raises(canary.CanaryError, match="причина"):
            canary.decide(db, rollout, state=CanaryState.ABORTED, decided_by="admin@corp.example")

    def test_a_decided_rollout_cannot_be_decided_again(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        rollout = _started(db, org_id)
        canary.decide(db, rollout, state=CanaryState.PROMOTED, decided_by="a@corp.example")
        with pytest.raises(canary.CanaryError, match="уже завершён"):
            canary.decide(db, rollout, state=CanaryState.ABORTED, decided_by="a@corp.example", note="x")


class TestOverdueDoesNotResolveItself:
    def test_an_overdue_rollout_keeps_its_scope(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        """Lifting it would release an unreviewed rule; dropping it would switch off detection.

        Both are decisions, so the deadline only makes the rollout visible.
        """
        rollout = _started(db, org_id)
        rollout.review_at = utcnow() - timedelta(days=1)
        db.commit()

        assert rollout.overdue()
        assert rollout.active, "просроченный выпуск не завершается сам"
        still_withheld = canary.withheld_rules(db, organization_id=org_id, mailbox="dev@corp.example")
        assert "ATT-001" in still_withheld, "область действия сохраняется"
        assert [c.rule_id for c in canary.overdue(db, org_id)] == ["ATT-001"]
        assert canary.coverage_summary(db, org_id) == {
            "active_canaries": 1,
            "overdue_canaries": 1,
        }


class TestEngineWithholdsTheScore:
    """The core property: outside the scope the rule is measured but powerless."""

    RAW = (
        b"From: Attacker <a@attacker.test>\r\n"
        b"To: buh@corp.example\r\n"
        b"Subject: Test\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
        b"--b\r\nContent-Type: text/plain\r\n\r\ntext\r\n"
        b"--b\r\nContent-Type: application/x-msdownload\r\n"
        b'Content-Disposition: attachment; filename="invoice.exe"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"TVqQAAMAAAAEAAAA//8AALgAAAA=\r\n"
        b"--b--\r\n"
    )

    def _analyse(self, withheld: frozenset[str]):  # type: ignore[no-untyped-def]
        parsed = parse_message(self.RAW)
        context = AnalysisContext(
            organization_id="org",
            corporate_domains=("corp.example",),
            source=IntakeSource.API,
            withheld_rules=withheld,
        )
        return analyze(parsed, context, ruleset=default_ruleset())

    def test_inside_the_scope_the_rule_scores(self) -> None:
        result = self._analyse(frozenset())
        signal = next(s for s in result.signals if s.rule_id == "ATT-001")
        rule = default_ruleset().get("ATT-001")
        assert rule is not None
        assert signal.weight == rule.effective_weight
        assert signal.shadow is False
        assert signal.withheld_by is None
        # Whatever the rule says about being hard, inside the scope it is honoured.
        assert signal.hard is rule.hard

    def test_outside_the_scope_the_rule_is_recorded_but_powerless(self) -> None:
        result = self._analyse(frozenset({"ATT-001"}))
        signal = next(s for s in result.signals if s.rule_id == "ATT-001")
        assert signal.weight == 0.0, "вне области правило не даёт баллов"
        assert signal.shadow is True, "но остаётся измеримым"
        assert signal.withheld_by == "canary", "и видно, почему именно оно не сработало"
        assert signal.hard is False, "жёсткий сигнал не задаёт нижнюю границу вне области"

    def test_a_hard_rule_sets_no_floor_outside_the_scope(self) -> None:
        """The sharpest case: a hard signal pins the verdict, which is the whole influence
        a rollout is supposed to withhold from the people outside it."""
        hard_rules = [rule.id for rule in default_ruleset().rules if rule.hard]
        assert hard_rules, "в пакете должны быть жёсткие правила, иначе проверка бессмысленна"
        result = self._analyse(frozenset(hard_rules))
        assert all(not signal.hard for signal in result.signals if signal.rule_id in set(hard_rules))

    def test_the_verdict_differs_between_the_two_sides(self) -> None:
        """If the score were the same, the rollout would not be limiting anything."""
        from msp_risk import evaluate

        inside = evaluate(self._analyse(frozenset()).signals)
        outside = evaluate(self._analyse(frozenset({"ATT-001"})).signals)
        assert inside.score > outside.score

    def test_withholding_one_rule_does_not_touch_the_others(self) -> None:
        inside = self._analyse(frozenset())
        outside = self._analyse(frozenset({"ATT-001"}))
        other_inside = {s.rule_id for s in inside.signals if s.rule_id != "ATT-001" and not s.shadow}
        other_outside = {s.rule_id for s in outside.signals if s.rule_id != "ATT-001" and not s.shadow}
        assert other_inside == other_outside


class TestComparison:
    def _signal(
        self,
        db,  # type: ignore[no-untyped-def]
        org_id: str,
        *,
        withheld: str | None,
        classification: AnalystClassification | None,
        suffix: str,
    ) -> None:
        message = MailMessage(
            organization_id=org_id,
            internet_message_id=f"<{suffix}@test>",
            raw_sha256=f"{suffix:0>64}",
            subject="Тема",
            sender_address="a@attacker.test",
            sender_display_name="A",
            sender_domain="attacker.test",
            recipient_count=1,
            size_bytes=1024,
            received_at=utcnow(),
            source=IntakeSource.API,
        )
        db.add(message)
        db.flush()
        job = AnalysisJob(organization_id=org_id, message_id=message.id, source=IntakeSource.API)
        db.add(job)
        db.flush()
        result = AnalysisResult(
            job_id=job.id,
            message_id=message.id,
            classification=RiskLevel.HIGH_RISK,
            score=60,
            confidence="high",
            recommendation="x",
        )
        db.add(result)
        db.flush()
        db.add(
            DetectionSignal(
                result_id=result.id,
                signal_id=f"sig-{suffix}",
                rule_id="ATT-001",
                rule_version=1,
                category="malicious_attachment",
                title="Исполняемое вложение",
                explanation="e",
                severity=Severity.HIGH,
                confidence=0.85,
                weight=0.0 if withheld else 45.0,
                source="rule_engine",
                evidence={},
                shadow=bool(withheld),
                withheld_by=withheld,
                rule_status="ACTIVE",
                observed_at=utcnow(),
            )
        )
        if classification is not None:
            incident = Incident(
                organization_id=org_id,
                number=int(suffix) if suffix.isdigit() else 1,
                title=f"Инцидент {suffix}",
                summary="x",
                severity=Severity.HIGH,
            )
            db.add(incident)
            db.flush()
            db.add(IncidentMessage(incident_id=incident.id, message_id=message.id))
            db.add(
                IncidentClassification(
                    organization_id=org_id,
                    incident_id=incident.id,
                    classification=classification,
                    analyst_email="analyst@corp.example",
                )
            )
        db.flush()

    def test_inside_and_outside_are_counted_separately(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        rollout = _started(db, org_id)
        self._signal(
            db,
            org_id,
            withheld=None,
            classification=AnalystClassification.CONFIRMED_MALWARE,
            suffix="1",
        )
        self._signal(
            db,
            org_id,
            withheld=None,
            classification=AnalystClassification.FALSE_POSITIVE,
            suffix="2",
        )
        self._signal(db, org_id, withheld="canary", classification=None, suffix="3")
        self._signal(db, org_id, withheld="canary", classification=None, suffix="4")
        db.commit()

        comparison = canary.compare(db, rollout)
        assert comparison.inside_triggers == 2
        assert comparison.outside_triggers == 2
        assert comparison.inside_confirmed == 1
        assert comparison.inside_false_positives == 1
        assert comparison.inside_precision == 0.5

    def test_precision_is_null_until_something_is_judged(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        """An unjudged rollout has no precision; showing 100% would argue for promoting it."""
        rollout = _started(db, org_id)
        self._signal(db, org_id, withheld=None, classification=None, suffix="5")
        db.commit()

        comparison = canary.compare(db, rollout)
        assert comparison.inside_triggers == 1
        assert comparison.inside_precision is None
        assert comparison.ready_to_promote is False

    def test_promotion_is_not_recommended_on_silence(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        """'Nothing bad happened yet' is how an unproven rule reaches everybody."""
        rollout = _started(db, org_id)
        db.commit()
        assert canary.compare(db, rollout).ready_to_promote is False

    def test_promotion_is_recommended_once_the_evidence_exists(self, db, org_id) -> None:  # type: ignore[no-untyped-def]
        rollout = _started(db, org_id)
        for index in range(4):
            self._signal(
                db,
                org_id,
                withheld=None,
                classification=AnalystClassification.CONFIRMED_MALWARE,
                suffix=str(10 + index),
            )
        db.commit()
        comparison = canary.compare(db, rollout)
        assert comparison.inside_precision == 1.0
        assert comparison.ready_to_promote is True
