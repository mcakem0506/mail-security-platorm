"""Шлюз готовности к MSP 1.1 (ТЗ 1.0.4 §18-§21, §29).

Этот гейт существует ради одного утверждения: готовность, выданная по отсутствию доказательств
обратного, — не готовность. Поэтому главные тесты здесь — про ``unknown``: непроверенное
условие обязано блокировать `READY` так же, как провал, и обязано отличаться от провала в
отчёте, потому что «мы не смотрели» и «мы посмотрели и плохо» требуют разного.

Второе, что проверяется подробно, — граница между блокирующим и необязательным. ТЗ §21 велит при
недоборе выборки отвечать ``READY_WITH_WARNINGS`` **с фактическим числом**, а не подделывать
готовность и не прятать недобор за отказом. Отличать недобор от пустоты при этом обязательно, и
за это отвечает отдельное обязательное условие: конвейер должен быть доказан хотя бы одним
письмом, прошедшим путь до разбора.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 - запускает собственный скрипт репозитория
import sys
from pathlib import Path

import pytest
from msp_api.services import gateway_readiness as policy

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "gateway_readiness.py"

#: «Не передано» против «передано как отсутствующее». ``None`` значит ровно «данных нет», и
#: путать его со значением по умолчанию нельзя — отсутствие данных здесь и есть предмет проверки.
DEFAULT = object()


def _full_summary(**overrides: object) -> dict[str, object]:
    """Сводка, при которой все обязательные условия по реальному потоку выполнены."""
    summary: dict[str, object] = {
        "messages_total": policy.MIN_ANALYZED,
        "reviewed_total": policy.MIN_REVIEWED,
        "precision": 0.97,
        "recall_is_estimate": True,
        "ground_truth_complete": False,
        "rule_pressure": [],
        "reviewed_noisy_rules": [],
        "undocumented_false_negatives": [],
        "sample": {
            "analyzed": policy.MIN_ANALYZED,
            "reviewed": policy.MIN_REVIEWED,
            "high_risk_unreviewed": 0,
        },
    }
    summary.update(overrides)
    return summary


def _ok_gaps() -> list[dict[str, object]]:
    """Реестр, при котором политика перехода §20 выполнена.

    Поимённо: GAP-001 закрыт, GAP-002 на подтверждении с причиной, GAP-003 и GAP-004 приняты с
    компенсирующими мерами.
    """
    return [
        {
            "gap_id": "GAP-001",
            "severity": "MEDIUM",
            "status": "RESOLVED",
            # Закрытый пробел без подтверждения на реальной почте даёт замечание: закрытие по
            # синтетическому корпусу — закрытие по случаям, которые мы сами придумали.
            "real_flow_validated_at": "2026-10-09T00:00:00+00:00",
        },
        {
            "gap_id": "GAP-002",
            "severity": "LOW",
            "status": "VALIDATION",
            "operational_reason": "живого материала с QR-кодами пока не поступало",
        },
        {
            "gap_id": "GAP-003",
            "severity": "MEDIUM",
            "status": "ACCEPTED",
            "compensating_controls": "вложение помечается непроверенным, вердикт не опускается",
        },
        {
            "gap_id": "GAP-004",
            "severity": "MEDIUM",
            "status": "ACCEPTED",
            "compensating_controls": "PDF помечается разобранным не полностью",
        },
    ]


def _ready(summary: object = DEFAULT, gaps: object = DEFAULT) -> policy.Readiness:
    readiness = policy.Readiness()
    readiness.extend(
        policy.real_flow_checks(_full_summary() if summary is DEFAULT else summary)  # type: ignore[arg-type]
    )
    readiness.extend(policy.gap_checks(_ok_gaps() if gaps is DEFAULT else gaps))  # type: ignore[arg-type]
    return readiness


def _keys(checks: list[policy.Check]) -> set[str]:
    return {check.key for check in checks}


class TestUnknownBlocksReadiness:
    def test_a_missing_summary_is_not_ready(self) -> None:
        """Платформа, про которую нечего сказать, в разрыв потока не идёт."""
        assert _ready(summary=None).decision == policy.NOT_READY

    def test_unknown_is_reported_as_unknown_not_as_failure(self) -> None:
        """«Мы не смотрели» и «мы посмотрели и плохо» требуют разного, и отчёт их различает."""
        checks = policy.real_flow_checks(None)
        assert {check.state for check in checks} == {policy.UNKNOWN}
        assert all(check.passed is None for check in checks)

    def test_an_unread_gap_registry_blocks(self) -> None:
        readiness = _ready(gaps=None)
        assert readiness.decision == policy.NOT_READY
        assert "critical_gaps_registered" in _keys(readiness.blocking)

    def test_an_empty_registry_is_not_the_same_as_an_unread_one(self) -> None:
        """На этой разнице скрипт однажды сообщил «пробелы зарегистрированы», не найдя ни одного."""
        assert policy.gap_checks([])[0].passed is True
        assert policy.gap_checks(None)[0].passed is None


class TestTheThreeDecisions:
    def test_everything_green_is_ready(self) -> None:
        """Проверка самой проверки: `READY` достижим, иначе остальные тесты ничего не значат."""
        readiness = _ready()
        assert readiness.decision == policy.READY, [c.key for c in readiness.blocking]

    def test_a_short_sample_is_a_warning_not_a_refusal(self) -> None:
        """ТЗ §21: при недоборе объёма — ``READY_WITH_WARNINGS`` с фактическим числом.

        Отказ, одинаковый для 480 писем из 500 и для нуля писем, скрывает различие между «почти
        набрали» и «не начинали». Первое — повод подождать, второе — повод проверить приём.
        """
        summary = _full_summary(
            messages_total=480,
            reviewed_total=95,
            sample={"analyzed": 480, "reviewed": 95, "high_risk_unreviewed": 0},
        )
        readiness = _ready(summary=summary)
        assert readiness.decision == policy.READY_WITH_WARNINGS
        assert _keys(readiness.warnings) == {"real_flow_sample", "real_flow_reviewed"}
        assert readiness.blocking == []

    def test_the_warning_carries_the_actual_sample_size(self) -> None:
        """«Не хватает» без числа не говорит, сколько ещё ждать."""
        summary = _full_summary(
            messages_total=480, sample={"analyzed": 480, "reviewed": 95, "high_risk_unreviewed": 0}
        )
        warnings = {check.key: check.value for check in _ready(summary=summary).warnings}
        assert warnings["real_flow_sample"] == 480
        assert warnings["real_flow_reviewed"] == 95

    def test_an_empty_pipeline_is_a_refusal_not_a_warning(self) -> None:
        """Ноль писем — не «мало данных», а «путь не пройден ни разу».

        Это и есть граница, отделяющая §21 от §20: недобор даёт замечание, пустота — отказ.
        """
        summary = _full_summary(
            messages_total=0,
            reviewed_total=0,
            precision=None,
            sample={"analyzed": 0, "reviewed": 0, "high_risk_unreviewed": 0},
        )
        readiness = _ready(summary=summary)
        assert readiness.decision == policy.NOT_READY
        assert "real_flow_pipeline_proven" in _keys(readiness.blocking)

    def test_an_optional_failure_is_ready_with_warnings(self) -> None:
        """Открытый критический пробел — замечание: он может быть принятым ограничением."""
        gaps = [
            *_ok_gaps(),
            {"gap_id": "GAP-010", "severity": "HIGH", "status": "OPEN"},
        ]
        readiness = _ready(gaps=gaps)
        assert readiness.decision == policy.READY_WITH_WARNINGS
        assert "critical_gaps_not_open" in _keys(readiness.warnings)
        assert readiness.blocking == []

    def test_a_required_failure_is_not_ready(self) -> None:
        assert _ready(summary=_full_summary(precision=None)).decision == policy.NOT_READY


class TestWhatTheGateRefusesToOverlook:
    def test_a_null_precision_blocks(self) -> None:
        """null означает отсутствие знаменателя: мерить ещё нечем, и это не «хорошо»."""
        readiness = _ready(summary=_full_summary(precision=None))
        assert "real_flow_precision_measured" in _keys(readiness.blocking)

    def test_recall_presented_as_a_measurement_blocks(self) -> None:
        """Если бы recall выдавался за измерение, гейт обязан это заметить: полной разметки
        реального потока не существует."""
        summary = _full_summary(recall_is_estimate=False, ground_truth_complete=True)
        readiness = _ready(summary=summary)
        assert readiness.decision == policy.NOT_READY
        assert "real_flow_recall_is_labelled_estimate" in _keys(readiness.blocking)

    def test_an_unreviewed_noisy_rule_blocks(self) -> None:
        """ТЗ §20: production noisy rules reviewed.

        Блокирует не шум, а **неразобранный** шум: вывод «правило шумит» делает человек, и пока
        он его не сделал, неизвестно, кампания это или дефект правила.
        """
        summary = _full_summary(rule_pressure=[{"rule_id": "SND-024", "fp_per_1000_messages": 4.0}])
        readiness = _ready(summary=summary)
        assert readiness.decision == policy.NOT_READY
        assert "real_flow_rule_noise_reviewed" in _keys(readiness.blocking)

    def test_a_reviewed_noisy_rule_does_not_block(self) -> None:
        """Проверка самой проверки: разобранный шум проходит, значит блокирует именно разбор."""
        summary = _full_summary(
            rule_pressure=[{"rule_id": "SND-024", "fp_per_1000_messages": 4.0}],
            reviewed_noisy_rules=["SND-024"],
        )
        assert _ready(summary=summary).decision == policy.READY

    def test_an_undocumented_false_negative_blocks(self) -> None:
        """ТЗ §21: all known FN documented.

        Пропуск без зарегистрированного пробела и есть незарегистрированный пробел, а его §29
        делает безусловным блокиратором.
        """
        summary = _full_summary(undocumented_false_negatives=["msg-17"])
        readiness = _ready(summary=summary)
        assert readiness.decision == policy.NOT_READY
        assert "known_false_negatives_documented" in _keys(readiness.blocking)

    def test_unreviewed_high_risk_is_a_warning_with_its_count(self) -> None:
        """Условие из §21, поэтому замечание, а не отказ — но с числом, а не молча."""
        summary = _full_summary(
            sample={
                "analyzed": policy.MIN_ANALYZED,
                "reviewed": policy.MIN_REVIEWED,
                "high_risk_unreviewed": 3,
            }
        )
        readiness = _ready(summary=summary)
        assert readiness.decision == policy.READY_WITH_WARNINGS
        warning = next(c for c in readiness.warnings if c.key == "real_flow_high_risk_reviewed")
        assert warning.value == 3

    def test_an_unregistered_critical_gap_blocks(self) -> None:
        """ТЗ §29: нельзя выдавать READY при незарегистрированном критическом пробеле."""
        gaps = [*_ok_gaps(), {"gap_id": "GAP-009", "severity": "CRITICAL", "status": ""}]
        readiness = _ready(gaps=gaps)
        assert readiness.decision == policy.NOT_READY
        blocking = {check.key: check.value for check in readiness.blocking}
        assert blocking["critical_gaps_registered"] == ["GAP-009"]

    def test_a_registered_critical_gap_does_not_block(self) -> None:
        """Регистрация не делает пробел безопасным — она делает его известным, а известное
        ограничение и неизвестная дыра различаются для того, кто ставит платформу в разрыв."""
        gaps = [*_ok_gaps(), {"gap_id": "GAP-009", "severity": "CRITICAL", "status": "ACCEPTED"}]
        assert _ready(gaps=gaps).decision == policy.READY


class TestTheNamedGapPolicy:
    """ТЗ §20 называет пробелы поимённо, и этого требования общее правило не покрывает."""

    def test_gap_001_must_be_resolved(self) -> None:
        """Этап брался закрыть GAP-001 кодом, поэтому `VALIDATION` для готовности не хватает."""
        gaps = [
            {"gap_id": "GAP-001", "severity": "MEDIUM", "status": "VALIDATION"},
            *_ok_gaps()[1:],
        ]
        readiness = _ready(gaps=gaps)
        assert readiness.decision == policy.NOT_READY
        blocking = {check.key: check.value for check in readiness.blocking}
        assert any("GAP-001" in item for item in blocking["gate_gaps_in_required_state"])

    def test_gap_002_may_stay_in_validation_with_a_reason(self) -> None:
        assert _ready().decision == policy.READY

    def test_gap_002_in_validation_without_a_reason_blocks(self) -> None:
        """«Ещё проверяем» без объяснения — не причина, а отсутствие решения."""
        gaps = [
            _ok_gaps()[0],
            {"gap_id": "GAP-002", "severity": "LOW", "status": "VALIDATION"},
            *_ok_gaps()[2:],
        ]
        readiness = _ready(gaps=gaps)
        assert readiness.decision == policy.NOT_READY
        assert "validation_gaps_have_operational_reason" in _keys(readiness.blocking)

    def test_an_accepted_gap_without_compensating_controls_blocks(self) -> None:
        """Принятый пробел без компенсирующей меры — это необъявленная дыра с номером."""
        gaps = [
            *_ok_gaps()[:2],
            {"gap_id": "GAP-003", "severity": "MEDIUM", "status": "ACCEPTED"},
            _ok_gaps()[3],
        ]
        readiness = _ready(gaps=gaps)
        assert readiness.decision == policy.NOT_READY
        blocking = {check.key: check.value for check in readiness.blocking}
        assert blocking["open_gaps_have_compensating_controls"] == ["GAP-003"]

    def test_a_gap_missing_from_the_registry_blocks(self) -> None:
        """Пробел, названный политикой и отсутствующий в реестре, — не «нет проблемы»."""
        readiness = _ready(gaps=_ok_gaps()[1:])
        assert readiness.decision == policy.NOT_READY
        blocking = {check.key: check.value for check in readiness.blocking}
        assert any("нет в реестре" in item for item in blocking["gate_gaps_in_required_state"])

    def test_the_policy_names_the_gaps_the_stage_took_on(self) -> None:
        """Проверка самой проверки: список не должен оказаться пустым после правки."""
        assert set(policy.GATE_GAP_POLICY) == {"GAP-001", "GAP-002", "GAP-003", "GAP-004"}
        assert policy.GATE_GAP_POLICY["GAP-001"] == frozenset({"RESOLVED"})


class TestTheAnswerStatesItsOwnLimits:
    def test_ready_says_what_it_does_not_mean(self) -> None:
        """Решение читают из API, и ограничение этого решения должно стоять там же."""
        body = _ready().as_dict()
        assert body["decision"] == policy.READY
        assert "inline-шлюз" in body["scope_note"]
        assert "MSP 1.1" in body["scope_note"]

    def test_the_thresholds_are_published_with_the_answer(self) -> None:
        """Иначе «500» нечем объяснить тому, кто читает отчёт через год."""
        thresholds = _ready().as_dict()["thresholds"]
        assert thresholds["min_analyzed"] == policy.MIN_ANALYZED
        assert thresholds["min_reviewed"] == policy.MIN_REVIEWED


class TestTheScriptAndTheServiceAgree:
    """Один источник порогов. Две копии расходились бы молча, а расхождение между «конвейер
    сказал готово» и «консоль показывает не готово» хуже любого из двух ответов."""

    def test_the_script_does_not_keep_its_own_thresholds(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        assert "from msp_api.services.gateway_readiness import" in text
        assert "MIN_ANALYZED = " not in text, "порог определён в сервисе, не в скрипте"
        assert "MIN_REVIEWED = " not in text

    def test_the_script_parses_the_published_gap_registry(self) -> None:
        """Реестр читается из документа, который публикуется и читается людьми."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import gateway_readiness as script

        gaps = script.read_gap_registry()
        assert gaps is not None, "реестр должен читаться, иначе условие по нему пустое"
        assert len(gaps) >= 4
        assert {gap["gap_id"] for gap in gaps} >= {"GAP-001", "GAP-002", "GAP-003", "GAP-004"}
        assert all(gap["status"] for gap in gaps), "у каждого пробела в документе есть статус"

    def test_the_glossary_table_is_not_read_as_a_gap(self) -> None:
        """В документе после реестра идёт глоссарий «## Статусы» с таблицей «Статус | Значение».
        Без границы раздела она переписывала статус последнего пробела пустым значением — и это
        проходило незамеченным по трём пробелам из четырёх."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import gateway_readiness as script

        gaps = {gap["gap_id"]: gap for gap in script.read_gap_registry() or []}
        assert gaps["GAP-004"]["status"] == "ACCEPTED"

    def test_the_script_reads_compensating_controls_and_reasons(self) -> None:
        """ТЗ §20 требует этих двух полей, и в документе они записаны прозой, а не таблицей."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import gateway_readiness as script

        gaps = {gap["gap_id"]: gap for gap in script.read_gap_registry() or []}
        assert gaps["GAP-003"]["compensating_controls"], "«Что защищает пока» должно читаться"
        assert gaps["GAP-004"]["compensating_controls"]
        assert gaps["GAP-002"]["operational_reason"], "причина статуса VALIDATION должна читаться"

    def test_the_repository_checks_find_their_files(self) -> None:
        """ТЗ §19: приёмка предыдущего этапа, выпуск правил, миграции, артефакты CI.

        Проверяется, что условия **находят** свои источники: условие, не нашедшее файл,
        возвращает ``unknown`` и блокирует — честно, но по неверному адресу, и это уже
        случалось с baseline.
        """
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import gateway_readiness as script

        checks = [
            *script.previous_stage_checks(),
            *script.release_checks(),
            *script.migration_checks(),
            *script.ci_checks(),
        ]
        unknown = [check.key for check in checks if check.passed is None]
        assert unknown == [], f"условия не нашли свои источники: {unknown}"
        failed = [check.key for check in checks if check.passed is False]
        assert failed == [], f"условия не выполнены: {failed}"

    def test_the_migration_check_would_notice_two_heads(self) -> None:
        """Иначе проверка выше проходила бы потому, что ничего не сравнивает."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import gateway_readiness as script

        check = script.migration_checks()[0]
        assert check.key == "migrations_single_head"
        assert isinstance(check.value, list)
        assert len(check.value) == 1

    @pytest.mark.slow
    def test_the_script_runs_and_refuses_without_a_real_flow_summary(self, tmp_path: Path) -> None:
        """Сквозной прогон: без сводки реального потока ответ — NOT_READY и код возврата 1."""
        out = tmp_path / "readiness.json"
        completed = subprocess.run(  # nosec B603 - fixed argv, no shell
            [sys.executable, str(SCRIPT), "--json", str(out)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            check=False,
        )
        assert completed.returncode == 1, completed.stderr
        body = json.loads(out.read_text(encoding="utf-8"))
        assert body["decision"] == policy.NOT_READY
        assert "real_flow_pipeline_proven" in body["blocking"]
        assert "regression_suite" in body["blocking"], "непроверенная регрессия блокирует"
        # Недобор выборки — замечание, а не блокировка (ТЗ §21).
        assert "real_flow_sample" in body["warnings"]

    @pytest.mark.slow
    def test_the_script_reports_the_current_gap_state_honestly(self, tmp_path: Path) -> None:
        """На текущем состоянии репозитория GAP-001 ещё `VALIDATION`, и гейт это говорит.

        Тест намеренно сверяется с живым документом: если GAP-001 когда-нибудь переведут в
        `RESOLVED`, он упадёт и заставит перечитать, подтверждено ли закрытие на реальной почте.
        """
        out = tmp_path / "readiness.json"
        subprocess.run(  # nosec B603 - fixed argv, no shell
            [sys.executable, str(SCRIPT), "--json", str(out)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            check=False,
        )
        body = json.loads(out.read_text(encoding="utf-8"))
        named = next(check for check in body["checks"] if check["key"] == "gate_gaps_in_required_state")
        assert named["state"] == "failed"
        assert any("GAP-001" in item for item in named["value"])


class TestTheTwoAbsoluteRefusals:
    """ТЗ §29: нельзя выдавать READY при провалившейся регрессии или незарегистрированном
    критическом пробеле. Остальные условия обсуждаемы, эти два — нет."""

    def test_a_failed_regression_blocks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Проверяется именно **провал**, а не отсутствие прогона.

        Непрогнанная регрессия даёт ``unknown`` и тоже блокирует, но это другое состояние, и
        тест на него не доказывает, что провал обрабатывается: провал идёт по другой ветке кода.
        """
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import gateway_readiness as script

        monkeypatch.setattr(script, "_run", lambda *a, **k: (1, "3 failed, 870 passed"))
        checks = script.test_checks(run_tests=True)
        assert len(checks) == 1
        assert checks[0].passed is False, "провал регрессии — не unknown, а failed"

        readiness = _ready()
        assert readiness.decision == policy.READY, "иначе проверка ниже ничего не значит"
        readiness.extend(checks)
        assert readiness.decision == policy.NOT_READY
        assert "regression_suite" in _keys(readiness.blocking)

    def test_a_passing_regression_does_not_block(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Проверка самой проверки: условие различает исход, а не всегда отказывает."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import gateway_readiness as script

        monkeypatch.setattr(script, "_run", lambda *a, **k: (0, "881 passed"))
        checks = script.test_checks(run_tests=True)
        assert checks[0].passed is True

        readiness = _ready()
        readiness.extend(checks)
        assert readiness.decision == policy.READY

    def test_a_regression_that_could_not_start_is_unknown_not_passed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Не запустившийся pytest — это «неизвестно», а не «всё хорошо»."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import gateway_readiness as script

        monkeypatch.setattr(script, "_run", lambda *a, **k: (None, ""))
        checks = script.test_checks(run_tests=True)
        assert checks[0].passed is None
        assert checks[0].state == policy.UNKNOWN

    def test_an_unregistered_critical_gap_blocks_even_with_everything_else_green(self) -> None:
        gaps = [*_ok_gaps(), {"gap_id": "GAP-100", "severity": "CRITICAL", "status": ""}]
        readiness = _ready(gaps=gaps)
        assert readiness.decision == policy.NOT_READY
        assert "critical_gaps_registered" in _keys(readiness.blocking)


class TestTheTwoRegistriesMustAgree:
    """Организация читает документ, инструменты читают YAML.

    Два источника с разными ответами про серьёзность и статус означают, что зелёный отчёт и
    прочитанный документ говорят разное. Сверка при появлении нашла именно это: у GAP-001
    серьёзность различалась.
    """

    def _script(self):  # type: ignore[no-untyped-def]
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import gateway_readiness as script

        return script

    def test_the_machine_registry_is_the_source(self) -> None:
        """Источник решения — структурный реестр, а не разбор прозы.

        Разбор прозы приходилось исправлять дважды, причём во второй раз незаметно для трёх
        пробелов из четырёх. Такой разбор не должен быть основанием решения.
        """
        gaps = self._script().read_gap_registry()
        assert gaps is not None
        assert {gap["gap_id"] for gap in gaps} == {"GAP-001", "GAP-002", "GAP-003", "GAP-004"}
        for gap in gaps:
            assert gap["status"], f"{gap['gap_id']}: статус обязателен"
            assert gap["compensating_controls"], f"{gap['gap_id']}: мера обязательна"

    def test_the_registries_agree_right_now(self) -> None:
        check = self._script().registry_agreement_checks()[0]
        assert check.passed is True, check.value

    def test_the_severity_is_read_as_the_current_one_not_the_previous(self) -> None:
        """«низкая (была средняя)» — это низкая.

        Перебор по таблице слов давал здесь прошлую серьёзность вместо нынешней, и сверка
        показывала расхождение там, где его не было. Берётся самое левое вхождение.
        """
        script = self._script()
        assert script._severity_from_russian("низкая (была средняя)") == "LOW"
        assert script._severity_from_russian("средняя") == "MEDIUM"
        assert script._severity_from_russian("критическая") == "CRITICAL"

    def test_a_disagreement_would_be_noticed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Проверка самой проверки: без этого «совпадает» значит только «ничего не сравнивали»."""
        script = self._script()
        monkeypatch.setattr(
            script,
            "read_published_gap_registry",
            lambda: [
                {"gap_id": "GAP-001", "severity": "CRITICAL", "status": "RESOLVED"},
                {"gap_id": "GAP-002", "severity": "LOW", "status": "VALIDATION"},
                {"gap_id": "GAP-003", "severity": "MEDIUM", "status": "ACCEPTED"},
                {"gap_id": "GAP-004", "severity": "MEDIUM", "status": "ACCEPTED"},
            ],
        )
        check = script.registry_agreement_checks()[0]
        assert check.passed is False
        assert any("GAP-001" in item for item in check.value)

    def test_a_gap_missing_from_the_document_is_a_disagreement(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Пробел, который есть в реестре и пропал из документа, перестаёт быть объявленным."""
        script = self._script()
        monkeypatch.setattr(
            script,
            "read_published_gap_registry",
            lambda: [{"gap_id": "GAP-001", "severity": "LOW", "status": "VALIDATION"}],
        )
        check = script.registry_agreement_checks()[0]
        assert check.passed is False
        assert any("нет в документе" in item for item in check.value)

    def test_an_unreadable_registry_is_unknown_not_agreement(self, monkeypatch: pytest.MonkeyPatch) -> None:
        script = self._script()
        monkeypatch.setattr(script, "read_gap_registry", lambda: None)
        check = script.registry_agreement_checks()[0]
        assert check.passed is None
        assert check.state == policy.UNKNOWN
