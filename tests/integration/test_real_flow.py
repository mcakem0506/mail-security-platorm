"""Набор валидации на реальном потоке (ТЗ 1.0.4 §8, §11–§14).

Проверяется то, из-за чего этот модуль вообще отличается от обычной очереди писем:

* одно письмо, пришедшее двумя путями, остаётся одной записью;
* доли без знаменателя возвращаются как ``None``, а не как ноль;
* recall назван оценкой, и в ответе это сказано машиночитаемо;
* нагрузка правила считается на тысячу писем и **не** превращается автоматически в состояние
  ``PRODUCTION_NOISY``;
* теневой режим выключает реагирование независимо от собственного флага реагирования.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from msp_api.db.models import ValidationMessage
from msp_api.services import real_flow
from msp_contracts import AnalystClassification, PiiStatus, PromotionState, RiskLevel, ValidationSource
from sqlalchemy import select

SERVICE = pathlib.Path("apps/api/msp_api/services/real_flow.py")


def _ingest(db, organization, **kwargs):  # type: ignore[no-untyped-def]
    request = real_flow.IngestRequest(
        organization_id=organization.id,
        source=kwargs.pop("source", ValidationSource.JOURNAL_COPY),
        message_fingerprint=kwargs.pop("message_fingerprint", "fp-0001"),
        **kwargs,
    )
    record, created = real_flow.ingest(db, request)
    db.commit()
    return record, created


class TestOneMessageStaysOneRecord:
    def test_the_same_message_from_two_sources_is_not_counted_twice(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Копия из журнала и пересылка сотрудника — это одно письмо.

        Если бы оно попадало в набор дважды, объём выборки был бы завышен ровно на долю писем,
        о которых сотрудники сообщают, то есть сильнее всего на самых интересных.
        """
        first, created_first = _ingest(
            db,
            organization,
            source=ValidationSource.JOURNAL_COPY,
            sampling_reasons=[real_flow.HIGH_RISK],
        )
        second, created_second = _ingest(
            db,
            organization,
            source=ValidationSource.SECURITY_MAILBOX,
            sampling_reasons=[real_flow.EMPLOYEE_REPORT],
        )

        assert created_first is True
        assert created_second is False, "дубликат узнаётся по отпечатку"
        assert first.id == second.id
        assert db.execute(select(ValidationMessage)).scalars().all() == [first]

    def test_the_second_arrival_adds_its_reason(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Причины складываются: письмо, о котором ещё и сообщил сотрудник, — другое письмо."""
        _ingest(db, organization, sampling_reasons=[real_flow.HIGH_RISK])
        record, _ = _ingest(
            db,
            organization,
            source=ValidationSource.SECURITY_MAILBOX,
            sampling_reasons=[real_flow.EMPLOYEE_REPORT, real_flow.HIGH_RISK],
        )
        assert record.sampling_reasons == [real_flow.HIGH_RISK, real_flow.EMPLOYEE_REPORT]

    def test_a_missing_platform_message_is_filled_in_later(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Из пересылки сотрудника письмо платформы неизвестно, из журнала — известно."""
        _ingest(db, organization, source=ValidationSource.SECURITY_MAILBOX)
        record, _ = _ingest(db, organization, message_id="msg-1")
        assert record.message_id == "msg-1"

    def test_a_record_without_a_fingerprint_is_refused(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        with pytest.raises(real_flow.RealFlowError):
            _ingest(db, organization, message_fingerprint="")

    def test_the_same_fingerprint_in_another_organization_is_another_message(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Набор валидации принадлежит организации: отпечатки разных организаций не пересекаются."""
        from msp_api.db.models import Organization

        other = Organization(id="org-other", name="Other", corporate_domains=["other.example"])
        db.add(other)
        db.commit()

        _ingest(db, organization)
        record, created = real_flow.ingest(
            db,
            real_flow.IngestRequest(
                organization_id=other.id,
                source=ValidationSource.JOURNAL_COPY,
                message_fingerprint="fp-0001",
            ),
        )
        db.commit()
        assert created is True
        assert record.organization_id == other.id


class TestWhatIsKnownAboutTheMessage:
    def test_a_raw_message_is_marked_raw(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        record, _ = _ingest(db, organization)
        assert record.anonymized is False
        assert record.pii_status is PiiStatus.RAW
        assert record.promotion_state is PromotionState.NOT_REQUESTED

    def test_automatic_anonymization_is_not_a_human_review(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """``ANONYMIZED`` — это «замены сделаны», а не «проверено, что ничего не осталось».

        Шаблон находит то, что описано шаблоном. Фамилию в середине фразы — нет. Признавать его
        работу за проверку значило бы выдавать его возможности за гарантию (ТЗ §9).
        """
        record, _ = _ingest(db, organization, anonymized=True, anonymization_report={"local_parts": 3})
        assert record.pii_status is PiiStatus.ANONYMIZED
        assert record.pii_status is not PiiStatus.REVIEWED
        assert record.anonymization_report == {"local_parts": 3}

    def test_there_is_no_expected_classification_by_default(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """На реальном потоке ожидаемого ответа нет, и выдумывать его нельзя (ТЗ §12)."""
        record, _ = _ingest(db, organization)
        assert record.expected_classification is None

    def test_an_unreviewed_message_is_not_a_correct_one(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        record, _ = _ingest(db, organization, production_verdict=RiskLevel.HIGH_RISK)
        assert record.analyst_classification is None, "«не разобрано» ≠ «верно»"

    def test_the_versions_of_everything_that_decided_are_kept(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Без них расхождение между прошлым и нынешним вердиктом необъяснимо (ТЗ §8)."""
        record, _ = _ingest(
            db,
            organization,
            ruleset_version="2026.10.1",
            parser_version="1.0.4",
            risk_engine_version="1.0.4",
        )
        assert (record.ruleset_version, record.parser_version, record.risk_engine_version) == (
            "2026.10.1",
            "1.0.4",
            "1.0.4",
        )


class TestReview:
    def test_a_review_without_an_author_is_refused(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        record, _ = _ingest(db, organization)
        with pytest.raises(real_flow.RealFlowError):
            real_flow.review(
                db,
                record=record,
                classification=AnalystClassification.FALSE_POSITIVE,
                analyst="   ",
            )

    def test_a_review_does_not_promote_anything(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Разбор фиксирует, что было. Продвижение в корпус — отдельное решение (ТЗ §10)."""
        record, _ = _ingest(db, organization)
        real_flow.review(
            db,
            record=record,
            classification=AnalystClassification.CONFIRMED_PHISHING,
            analyst="analyst@corp.example",
        )
        db.commit()
        assert record.promotion_state is PromotionState.NOT_REQUESTED
        assert record.pii_status is PiiStatus.RAW


class TestMetricsRefuseToInvent:
    def test_an_empty_set_reports_null_shares_not_zero(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Ноль читался бы как «ложных срабатываний нет». Их просто никто не считал."""
        result = real_flow.summary(db, organization.id)
        assert result["messages_total"] == 0
        assert result["precision"] is None
        assert result["recall_estimate"] is None

    def test_unreviewed_messages_give_no_precision(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        for index in range(5):
            _ingest(
                db,
                organization,
                message_fingerprint=f"fp-{index}",
                production_verdict=RiskLevel.HIGH_RISK,
            )
        result = real_flow.summary(db, organization.id)
        assert result["messages_total"] == 5
        assert result["reviewed_total"] == 0
        assert result["precision"] is None, "вердикты есть, подтверждений нет — знаменателя нет"

    def test_precision_counts_only_judged_messages(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        verdicts = [
            AnalystClassification.CONFIRMED_PHISHING,
            AnalystClassification.CONFIRMED_PHISHING,
            AnalystClassification.CONFIRMED_PHISHING,
            AnalystClassification.FALSE_POSITIVE,
            AnalystClassification.UNKNOWN,
        ]
        for index, classification in enumerate(verdicts):
            record, _ = _ingest(
                db,
                organization,
                message_fingerprint=f"fp-{index}",
                production_verdict=RiskLevel.HIGH_RISK,
            )
            real_flow.review(db, record=record, classification=classification, analyst="analyst@corp.example")
        db.commit()

        result = real_flow.summary(db, organization.id)
        assert result["true_positive"] == 3
        assert result["false_positive"] == 1
        assert result["unknown"] == 1
        assert result["precision"] == pytest.approx(0.75), "неопределённые в знаменатель не идут"

    def test_recall_says_about_itself_that_it_is_an_estimate(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Полной разметки реального потока не существует, и ответ это признаёт машиночитаемо."""
        record, _ = _ingest(db, organization, production_verdict=RiskLevel.LOW_RISK)
        real_flow.review(
            db,
            record=record,
            classification=AnalystClassification.CONFIRMED_PHISHING,
            analyst="analyst@corp.example",
        )
        db.commit()

        result = real_flow.summary(db, organization.id)
        assert result["false_negative"] == 1, "подтверждённая угроза с низким риском — промах"
        assert result["recall_is_estimate"] is True
        assert result["ground_truth_complete"] is False

    def test_unreviewed_high_risk_is_reported_as_a_debt(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Нельзя закрыть этап, не разобрав то, что платформа назвала опасным (ТЗ §21)."""
        _ingest(db, organization, message_fingerprint="a", production_verdict=RiskLevel.MALICIOUS)
        _ingest(db, organization, message_fingerprint="b", production_verdict=RiskLevel.LOW_RISK)
        result = real_flow.summary(db, organization.id)
        assert result["sample"]["high_risk_unreviewed"] == 1

    def test_the_sample_targets_are_stated_next_to_the_counts(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Иначе «проанализировано 40» нечем сравнить с тем, сколько нужно."""
        result = real_flow.summary(db, organization.id)
        assert result["sample"]["analyzed_target"] == real_flow.TARGET_ANALYZED
        assert result["sample"]["reviewed_target"] == real_flow.TARGET_REVIEWED


class TestRulePressure:
    def test_an_empty_set_produces_no_rows(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        assert real_flow.rule_pressure(db, organization.id) == []

    def test_pressure_is_measured_per_thousand_messages(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Абсолютное число срабатываний растёт вместе с объёмом почты и о правиле молчит."""
        for index in range(10):
            _ingest(
                db,
                organization,
                message_fingerprint=f"fp-{index}",
                triggered_rules=["SND-024"] if index < 4 else [],
            )
        rows = real_flow.rule_pressure(db, organization.id)
        assert rows[0]["rule_id"] == "SND-024"
        assert rows[0]["triggers"] == 4
        assert rows[0]["triggers_per_1000_messages"] == 400.0

    def test_one_noisy_sender_is_distinguished_from_many(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Правило, сработавшее сто раз на одном письме и на ста разных, требует разного."""
        for index in range(3):
            _ingest(
                db,
                organization,
                message_fingerprint=f"fp-{index}",
                triggered_rules=["SND-024", "SND-024"],
            )
        rows = real_flow.rule_pressure(db, organization.id)
        assert rows[0]["triggers"] == 6
        assert rows[0]["distinct_messages"] == 3

    def test_noisy_is_a_conclusion_a_human_draws(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """ТЗ §12: правило может получить ``PRODUCTION_NOISY``, но не отключается автоматически.

        Проверяется по исходнику, а не по поведению: отсутствие автоматики — это отсутствие
        кода, и поведенческий тест на него был бы тестом на то, чего не случилось.
        """
        tree = ast.parse(SERVICE.read_text(encoding="utf-8"))
        assigned_health = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and node.attr in ("health", "status")
            and isinstance(node.ctx, ast.Store)
        ]
        assert assigned_health == [], "состояние правила этот модуль не меняет"
        assert "PRODUCTION_NOISY" not in {
            node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
        }


class TestUncertainQueueIsSeparate:
    def test_an_unscannable_message_is_in_the_queue(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        _ingest(
            db,
            organization,
            message_fingerprint="locked",
            production_verdict=RiskLevel.LOW_RISK,
            unscannable_reasons=["ENCRYPTED_ARCHIVE"],
        )
        queue = real_flow.uncertain_queue(db, organization.id)
        assert [row["unscannable_reasons"] for row in queue] == [["ENCRYPTED_ARCHIVE"]]

    def test_a_high_risk_message_is_not_in_the_uncertain_queue(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """По нему есть вердикт, который можно подтвердить. Это другая работа (ТЗ §14)."""
        _ingest(db, organization, message_fingerprint="bad", production_verdict=RiskLevel.MALICIOUS)
        assert real_flow.uncertain_queue(db, organization.id) == []

    def test_a_reviewed_message_leaves_the_queue(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        record, _ = _ingest(
            db, organization, message_fingerprint="locked", unscannable_reasons=["PASSWORD_PROTECTED"]
        )
        assert len(real_flow.uncertain_queue(db, organization.id)) == 1
        real_flow.review(
            db,
            record=record,
            classification=AnalystClassification.UNKNOWN,
            analyst="analyst@corp.example",
        )
        db.commit()
        assert real_flow.uncertain_queue(db, organization.id) == []


class TestSampling:
    def test_both_reasons_are_listed_not_reduced_to_one(self) -> None:
        reasons = real_flow.sampling_reasons(verdict=RiskLevel.HIGH_RISK, reported_by_employee=True)
        assert reasons == [real_flow.HIGH_RISK, real_flow.EMPLOYEE_REPORT]

    def test_legitimate_mail_enters_the_sample_by_chance(self) -> None:
        """Против слепого пятна: ложное срабатывание, которого никто не заметил, иначе не попадёт
        в набор никогда (ТЗ §14)."""
        assert real_flow.sampling_reasons(verdict=RiskLevel.LOW_RISK, random_draw=0.001) == [
            real_flow.RANDOM_LEGITIMATE
        ]
        assert real_flow.sampling_reasons(verdict=RiskLevel.LOW_RISK, random_draw=0.9) == []

    def test_a_message_already_in_the_sample_is_not_counted_as_the_random_share(self) -> None:
        """Иначе случайная доля перестала бы быть случайной долей."""
        reasons = real_flow.sampling_reasons(verdict=RiskLevel.MALICIOUS, random_draw=0.0)
        assert real_flow.RANDOM_LEGITIMATE not in reasons

    def test_an_unscannable_message_is_uncertain_whatever_the_verdict(self) -> None:
        reasons = real_flow.sampling_reasons(verdict=RiskLevel.LOW_RISK, unscannable=True)
        assert reasons == [real_flow.UNCERTAIN]


class TestRawDataGoesFirst:
    def test_raw_retention_is_shorter_and_expiry_is_queryable(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """ТЗ §22: исходные данные удаляются раньше обезличенных метрик."""
        from datetime import timedelta

        from msp_contracts import utcnow

        record, _ = _ingest(db, organization, raw_retention_days=30)
        assert record.raw_retained_until is not None
        assert real_flow.expired_raw_records(db, organization.id) == []

        record.raw_retained_until = utcnow() - timedelta(days=1)
        db.commit()
        assert real_flow.expired_raw_records(db, organization.id) == [record]

    def test_an_already_anonymized_record_is_not_swept_again(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        from datetime import timedelta

        from msp_contracts import utcnow

        record, _ = _ingest(db, organization, anonymized=True, raw_retention_days=1)
        record.raw_retained_until = utcnow() - timedelta(days=5)
        db.commit()
        assert real_flow.expired_raw_records(db, organization.id) == []


class TestPromotionIsNeverAutomatic:
    def test_a_reviewed_but_raw_message_is_not_a_candidate(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        record, _ = _ingest(db, organization)
        real_flow.review(
            db,
            record=record,
            classification=AnalystClassification.CONFIRMED_PHISHING,
            analyst="analyst@corp.example",
        )
        db.commit()
        assert real_flow.promotion_candidates(db, organization.id) == []

    def test_a_candidate_is_only_a_proposal(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """«Можно предложить» — это не «продвинуть»: состояние остаётся прежним (ТЗ §10)."""
        record, _ = _ingest(db, organization, anonymized=True)
        record.pii_status = PiiStatus.REVIEWED
        real_flow.review(
            db,
            record=record,
            classification=AnalystClassification.CONFIRMED_PHISHING,
            analyst="analyst@corp.example",
        )
        db.commit()

        assert real_flow.promotion_candidates(db, organization.id) == [record]
        assert record.promotion_state is PromotionState.NOT_REQUESTED

    def test_the_source_of_each_message_is_countable(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Источник решает, что о письме известно: пересылка и копия из журнала несравнимы."""
        _ingest(db, organization, message_fingerprint="a", source=ValidationSource.JOURNAL_COPY)
        _ingest(db, organization, message_fingerprint="b", source=ValidationSource.JOURNAL_COPY)
        _ingest(db, organization, message_fingerprint="c", source=ValidationSource.SECURITY_MAILBOX)
        assert real_flow.count_by_source(db, organization.id) == {
            "JOURNAL_COPY": 2,
            "SECURITY_MAILBOX": 1,
        }


class TestNoisyRuleIsJudgedByAPerson:
    """ТЗ §12 и §20: правило может получить ``PRODUCTION_NOISY``, но не от платформы.

    До этого этапа у платформы была только вторая половина требования — автоматики нет. Первой
    не было вовсе: состояние, которое человек может присвоить, негде было хранить, и условие §20
    «production noisy rules reviewed» проверить было нечем.
    """

    def test_a_verdict_is_recorded_with_the_numbers_it_was_made_on(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Без чисел через полгода нельзя понять, относился ли вывод к нынешнему поведению."""
        from msp_contracts import RuleNoiseVerdict

        review = real_flow.review_rule_noise(
            db,
            organization_id=organization.id,
            rule_id="SND-024",
            verdict=RuleNoiseVerdict.PRODUCTION_NOISY,
            analyst="analyst@corp.example",
            note="срабатывает на рассылке подрядчика с 2019 года",
            pressure={
                "triggers_per_1000_messages": 42.0,
                "fp_per_1000_messages": 3.5,
                "distinct_messages": 17,
            },
        )
        db.commit()
        assert review.verdict is RuleNoiseVerdict.PRODUCTION_NOISY
        assert review.triggers_per_1000 == 42.0
        assert review.distinct_messages == 17

    def test_production_noisy_requires_an_explanation(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Состояние останется у правила надолго; «шумит» без причины нечем перепроверить."""
        from msp_contracts import RuleNoiseVerdict

        with pytest.raises(real_flow.RealFlowError, match="пояснения"):
            real_flow.review_rule_noise(
                db,
                organization_id=organization.id,
                rule_id="SND-024",
                verdict=RuleNoiseVerdict.PRODUCTION_NOISY,
                analyst="analyst@corp.example",
            )

    def test_an_acceptable_verdict_needs_no_explanation(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Проверка самой проверки: требование относится к состоянию, которое остаётся."""
        from msp_contracts import RuleNoiseVerdict

        review = real_flow.review_rule_noise(
            db,
            organization_id=organization.id,
            rule_id="URL-010",
            verdict=RuleNoiseVerdict.ACCEPTABLE,
            analyst="analyst@corp.example",
        )
        db.commit()
        assert review.verdict is RuleNoiseVerdict.ACCEPTABLE

    def test_a_second_verdict_replaces_the_first(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Вывод о правиле один: два вывода подряд — это изменение мнения, а не два мнения."""
        from msp_api.db.models import RealFlowRuleReview
        from msp_contracts import RuleNoiseVerdict
        from sqlalchemy import func

        for verdict, note in (
            (RuleNoiseVerdict.PRODUCTION_NOISY, "шумит"),
            (RuleNoiseVerdict.NEEDS_RULE_CHANGE, "нужна правка условия"),
        ):
            real_flow.review_rule_noise(
                db,
                organization_id=organization.id,
                rule_id="SND-024",
                verdict=verdict,
                analyst="analyst@corp.example",
                note=note,
            )
            db.commit()

        total = db.execute(select(func.count(RealFlowRuleReview.id))).scalar_one()
        assert total == 1
        assert real_flow.rule_noise_reviews(db, organization.id)[0]["verdict"] == "NEEDS_RULE_CHANGE"

    def test_reviewed_means_looked_at_not_judged_noisy(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Гейт спрашивает «разобрано ли», а не «признано ли шумным» (ТЗ §20)."""
        from msp_contracts import RuleNoiseVerdict

        real_flow.review_rule_noise(
            db,
            organization_id=organization.id,
            rule_id="URL-010",
            verdict=RuleNoiseVerdict.ACCEPTABLE,
            analyst="analyst@corp.example",
        )
        db.commit()
        assert real_flow.reviewed_noisy_rules(db, organization.id) == {"URL-010"}

    def test_the_verdict_does_not_disable_the_rule(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Отключение — отдельное изменение, проходящее ревью (1.0.3B §8).

        Проверяется по исходнику: отсутствие отключения — это отсутствие кода, и поведенческий
        тест на него был бы тестом на то, чего не случилось.
        """
        tree = ast.parse(SERVICE.read_text(encoding="utf-8"))
        names = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store)
        }
        assert "status" not in names
        assert "enabled" not in names
        assert "health" not in names


class TestAMissMustNameItsGap:
    """ТЗ §21: все известные пропуски задокументированы."""

    def test_a_miss_without_a_gap_is_listed_as_undocumented(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Пропуск без зарегистрированного пробела и есть незарегистрированный пробел."""
        record, _ = _ingest(db, organization, production_verdict=RiskLevel.LOW_RISK)
        real_flow.review(
            db,
            record=record,
            classification=AnalystClassification.CONFIRMED_PHISHING,
            analyst="analyst@corp.example",
        )
        db.commit()

        result = real_flow.summary(db, organization.id)
        assert result["false_negative"] == 1
        assert result["undocumented_false_negatives"] == [record.id]

    def test_naming_the_gap_documents_the_miss(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        record, _ = _ingest(db, organization, production_verdict=RiskLevel.LOW_RISK)
        real_flow.review(
            db,
            record=record,
            classification=AnalystClassification.CONFIRMED_PHISHING,
            analyst="analyst@corp.example",
            gap_id="GAP-003",
        )
        db.commit()

        result = real_flow.summary(db, organization.id)
        assert result["false_negative"] == 1, "пропуск остаётся пропуском"
        assert result["undocumented_false_negatives"] == []
        assert real_flow.as_dict(record)["gap_id"] == "GAP-003"

    def test_a_correct_verdict_is_not_a_miss_and_needs_no_gap(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Проверка самой проверки: список не должен наполняться чем попало."""
        record, _ = _ingest(db, organization, production_verdict=RiskLevel.MALICIOUS)
        real_flow.review(
            db,
            record=record,
            classification=AnalystClassification.CONFIRMED_PHISHING,
            analyst="analyst@corp.example",
        )
        db.commit()
        assert real_flow.summary(db, organization.id)["undocumented_false_negatives"] == []
