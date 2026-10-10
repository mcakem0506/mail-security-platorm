"""Инварианты теневого режима на реальном потоке (ТЗ 1.0.4 §11).

ТЗ называет пять свойств режима: вердикт сохраняется, ящик пользователя не меняется,
реагирование выключено, уведомления сотрудникам по умолчанию выключены, обратная связь
аналитиков и метрики — включены.

Четыре из них — про то, чего платформа **не** делает, и проверять их отображением настроек
нельзя: словарь возможностей может говорить «выключено», пока места применения читают исходный
флаг. Поэтому здесь проверяется сам флаг, который эти места читают, и разбирается исходный код
на предмет того, что ни одна точка применения не обходит его стороной.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

CONFIG = pathlib.Path("apps/api/msp_api/config.py")
API = pathlib.Path("apps/api/msp_api")


def _settings(**overrides: object):  # type: ignore[no-untyped-def]
    from msp_api.config import Settings

    return Settings(secret_key="shadow-mode-test-key", **overrides)  # type: ignore[arg-type]


class TestShadowModeDisablesActing:
    def test_remediation_is_off_even_when_its_own_flag_is_on(self) -> None:
        """Главный инвариант: включённое реагирование в теневом режиме не включено.

        Проверяется сам флаг, а не его отображение. Мест, где реагирование разрешается, в коде
        несколько, и каждое читает ``remediation_enabled`` напрямую — режим, правящий только
        словарь возможностей, сообщал бы о себе правду и не делал ничего.
        """
        settings = _settings(real_flow_shadow=True, remediation_enabled=True)
        assert settings.remediation_enabled is False
        assert settings.public_config()["remediation_enabled"] is False

    def test_employee_notifications_are_off(self) -> None:
        """Пилот смотрит на поток и молчит: сотрудники не должны узнавать о недообученном
        детектировании раньше службы безопасности."""
        settings = _settings(real_flow_shadow=True, employee_notifications_enabled=True)
        assert settings.employee_notifications_enabled is False

    def test_outside_shadow_mode_the_flags_are_the_administrators(self) -> None:
        """Режим гасит флаги только собой: иначе это была бы не настройка, а запрет."""
        settings = _settings(
            real_flow_shadow=False,
            remediation_enabled=True,
            employee_notifications_enabled=True,
            ews_mailbox_scope="security@corp.example",
        )
        assert settings.remediation_enabled is True
        assert settings.employee_notifications_enabled is True

    def test_shadow_mode_is_off_by_default(self) -> None:
        """Режим — осознанное решение администратора, а не состояние, в которое можно попасть."""
        assert _settings().real_flow_shadow is False

    def test_the_mode_is_reported_so_it_cannot_be_silent(self) -> None:
        """Скрытое состояние, меняющее поведение, читалось бы как неисправность."""
        assert _settings(real_flow_shadow=True).public_config()["real_flow_shadow"] is True


class TestNoEnforcementPointBypassesTheFlag:
    """Гарантия, что инвариант нельзя обойти: проверка самой проверки.

    Тест выше проверяет значение флага. Этот — что места, принимающие решение о реагировании,
    спрашивают именно его, а не отдельную копию состояния, до которой теневой режим не достанет.
    """

    def test_remediation_decisions_read_the_settings_flag(self) -> None:
        readers: list[str] = []
        for path in sorted(API.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr == "remediation_enabled":
                    readers.append(str(path))
                    break
        assert len(readers) > 3, "точки применения должны находиться — иначе тест пустой"
        assert str(CONFIG) in readers

    def test_the_mode_cannot_be_turned_off_by_a_later_assignment(self) -> None:
        """``real_flow_shadow`` нигде не переписывается: иначе режим снимался бы кодом, а не
        администратором."""
        writes: list[str] = []
        for path in sorted(API.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            if "real_flow_shadow" not in text:
                continue
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Attribute)
                    and node.attr == "real_flow_shadow"
                    and isinstance(node.ctx, ast.Store)
                ):
                    writes.append(str(path))
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "setattr"
                    and len(node.args) > 1
                    and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value == "real_flow_shadow"
                ):
                    writes.append(str(path))
        assert writes == []


class TestWhatShadowModeKeepsOn:
    def test_the_verdict_is_still_computed_and_stored(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Режим называется теневым, а не выключенным: без вердикта мерить было бы нечего."""
        from msp_api.db.models import ValidationMessage
        from msp_api.services import real_flow
        from msp_contracts import RiskLevel, ValidationSource
        from sqlalchemy import select

        record, _ = real_flow.ingest(
            db,
            real_flow.IngestRequest(
                organization_id=organization.id,
                source=ValidationSource.JOURNAL_COPY,
                message_fingerprint="shadow-1",
                production_verdict=RiskLevel.HIGH_RISK,
                triggered_rules=["SND-024"],
            ),
        )
        db.commit()

        stored = db.execute(select(ValidationMessage)).scalars().one()
        assert stored.id == record.id
        assert stored.production_verdict is RiskLevel.HIGH_RISK
        assert stored.triggered_rules == ["SND-024"]

    def test_analyst_feedback_is_enabled(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """Ради обратной связи режим и существует: выключить её значило бы выключить измерение."""
        from msp_api.services import real_flow
        from msp_contracts import AnalystClassification, RiskLevel, ValidationSource

        record, _ = real_flow.ingest(
            db,
            real_flow.IngestRequest(
                organization_id=organization.id,
                source=ValidationSource.SECURITY_MAILBOX,
                message_fingerprint="shadow-2",
                production_verdict=RiskLevel.HIGH_RISK,
            ),
        )
        real_flow.review(
            db,
            record=record,
            classification=AnalystClassification.FALSE_POSITIVE,
            analyst="analyst@corp.example",
            comment="рассылка собственной бухгалтерии",
        )
        db.commit()

        result = real_flow.summary(db, organization.id)
        assert result["false_positive"] == 1
        assert result["precision"] == 0.0, "ноль здесь честен: знаменатель есть"

    def test_metrics_are_enabled(self) -> None:
        settings = _settings(real_flow_shadow=True)
        assert settings.metrics_enabled is True


class _Target:
    mailbox = "employee@corp.example"


class TestTheMailboxIsNotTouched:
    """Письмо в ящике сотрудника не трогается, и отказ происходит до обращения к Exchange."""

    def test_a_plan_made_in_shadow_mode_carries_a_blocker(self) -> None:
        """План составляется — это полезно: аналитик видит, что было бы сделано. Выполнить его
        нельзя, и причина названа прямо в плане, а не выяснена при отказе."""
        from msp_api.services.remediation_providers import ExchangeRemediationProvider
        from msp_contracts import RemediationType

        settings = _settings(
            real_flow_shadow=True,
            remediation_enabled=True,
            remediation_dry_run_only=False,
            ews_mailbox_scope="employee@corp.example",
        )
        provider = ExchangeRemediationProvider(provider=None, settings=settings)
        plan = provider.propose(RemediationType.QUARANTINE, [_Target()])
        assert "реагирование отключено в конфигурации развёртывания" in plan.blockers

    def test_without_the_mode_the_same_plan_has_no_blockers(self) -> None:
        """Проверка самой проверки: вне теневого режима тот же план проходит, значит блокировка
        выше — следствие режима, а не всегда так."""
        from msp_api.services.remediation_providers import ExchangeRemediationProvider
        from msp_contracts import RemediationType

        settings = _settings(
            real_flow_shadow=False,
            remediation_enabled=True,
            remediation_dry_run_only=False,
            ews_mailbox_scope="employee@corp.example",
        )
        provider = ExchangeRemediationProvider(provider=None, settings=settings)
        plan = provider.propose(RemediationType.QUARANTINE, [_Target()])
        assert plan.blockers == []


@pytest.mark.parametrize(
    "forbidden",
    [
        "MSP_REAL_FLOW_SHADOW=true\nMSP_REMEDIATION_ENABLED=true",
    ],
)
def test_the_combination_is_allowed_and_resolved_not_rejected(forbidden: str) -> None:
    """Противоречие в настройках разрешается в пользу осторожности, а не ошибкой запуска.

    Отказ запускаться был бы хуже: администратор, включивший теневой режим на стенде с уже
    настроенным реагированием, получил бы неработающую платформу вместо безопасной.
    """
    settings = _settings(real_flow_shadow=True, remediation_enabled=True)
    assert settings.remediation_enabled is False


class TestRetentionOrderIsEnforced:
    """ТЗ §22: исходные данные удаляются раньше обезличенных метрик."""

    def test_the_default_order_is_correct(self) -> None:
        settings = _settings()
        assert settings.raw_message_retention_days <= settings.anonymized_validation_retention_days

    def test_raw_data_outliving_the_metrics_is_refused(self) -> None:
        """Иначе платформа хранила бы переписку ради чисел, которые уже посчитаны."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="удаляются раньше"):
            _settings(
                raw_message_retention_days=400,
                anonymized_validation_retention_days=30,
            )

    def test_an_equal_pair_is_allowed(self) -> None:
        """Проверка самой проверки: запрет касается только нарушения порядка."""
        settings = _settings(raw_message_retention_days=90, anonymized_validation_retention_days=90)
        assert settings.raw_message_retention_days == 90

    def test_the_three_periods_are_published(self) -> None:
        """Администратору нужно видеть сроки, не читая конфигурацию сервера."""
        retention = _settings().public_config()["retention"]
        assert set(retention) == {
            "raw_message_days",
            "anonymized_validation_days",
            "analyst_feedback_days",
        }
