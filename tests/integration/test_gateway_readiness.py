"""Шлюз готовности к MSP 1.1 (ТЗ 1.0.4 §18-§21, §29).

Этот гейт существует ради одного утверждения: готовность, выданная по отсутствию доказательств
обратного, — не готовность. Поэтому главные тесты здесь — про ``unknown``: непроверенное
условие обязано блокировать `READY` так же, как провал, и обязано отличаться от провала в
отчёте, потому что «мы не смотрели» и «мы посмотрели и плохо» требуют разного.
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


def _full_summary(**overrides: object) -> dict[str, object]:
    """Сводка, при которой все обязательные условия по реальному потоку выполнены."""
    summary: dict[str, object] = {
        "messages_total": policy.MIN_ANALYZED,
        "reviewed_total": policy.MIN_REVIEWED,
        "precision": 0.97,
        "recall_is_estimate": True,
        "ground_truth_complete": False,
        "rule_pressure": [],
        "sample": {
            "analyzed": policy.MIN_ANALYZED,
            "reviewed": policy.MIN_REVIEWED,
            "high_risk_unreviewed": 0,
        },
    }
    summary.update(overrides)
    return summary


def _ok_gaps() -> list[dict[str, object]]:
    return [{"gap_id": "GAP-001", "severity": "MEDIUM", "status": "ACCEPTED"}]


#: «Не передано» против «передано как отсутствующее». ``None`` значит ровно «данных нет», и
#: путать его со значением по умолчанию нельзя — отсутствие данных здесь и есть предмет проверки.
DEFAULT = object()


def _ready(summary: object = DEFAULT, gaps: object = DEFAULT) -> policy.Readiness:
    readiness = policy.Readiness()
    readiness.extend(
        policy.real_flow_checks(_full_summary() if summary is DEFAULT else summary)  # type: ignore[arg-type]
    )
    readiness.extend(policy.gap_checks(_ok_gaps() if gaps is DEFAULT else gaps))  # type: ignore[arg-type]
    return readiness


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
        assert "critical_gaps_registered" in [c.key for c in readiness.blocking]

    def test_an_empty_registry_is_not_the_same_as_an_unread_one(self) -> None:
        """На этой разнице скрипт однажды сообщил «пробелы зарегистрированы», не найдя ни одного."""
        assert policy.gap_checks([])[0].passed is True
        assert policy.gap_checks(None)[0].passed is None


class TestTheThreeDecisions:
    def test_everything_green_is_ready(self) -> None:
        """Проверка самой проверки: `READY` достижим, иначе остальные тесты ничего не значат."""
        assert _ready().decision == policy.READY

    def test_an_optional_failure_is_ready_with_warnings(self) -> None:
        """Шум правила — повод для разбора человеком, а не для отказа (ТЗ §12)."""
        summary = _full_summary(rule_pressure=[{"rule_id": "SND-024", "fp_per_1000_messages": 4.0}])
        readiness = _ready(summary=summary)
        assert readiness.decision == policy.READY_WITH_WARNINGS
        assert [check.key for check in readiness.warnings] == ["real_flow_rule_noise"]
        assert readiness.blocking == []

    def test_a_required_failure_is_not_ready(self) -> None:
        readiness = _ready(
            summary=_full_summary(sample={"analyzed": 4, "reviewed": 2, "high_risk_unreviewed": 0})
        )
        assert readiness.decision == policy.NOT_READY
        assert "real_flow_sample" in readiness.blocking[0].key


class TestWhatTheGateRefusesToOverlook:
    def test_a_small_sample_is_not_enough(self) -> None:
        """Точность 1.000 на четырёх письмах не отличима от совпадения."""
        summary = _full_summary(
            precision=1.0, sample={"analyzed": 4, "reviewed": 4, "high_risk_unreviewed": 0}
        )
        assert _ready(summary=summary).decision == policy.NOT_READY

    def test_unreviewed_high_risk_blocks(self) -> None:
        """Непросмотренный высокий риск — неизвестный ответ на самый дорогой вопрос."""
        summary = _full_summary(
            sample={
                "analyzed": policy.MIN_ANALYZED,
                "reviewed": policy.MIN_REVIEWED,
                "high_risk_unreviewed": 1,
            }
        )
        readiness = _ready(summary=summary)
        assert readiness.decision == policy.NOT_READY
        assert "real_flow_high_risk_reviewed" in readiness.blocking[0].key

    def test_a_null_precision_blocks(self) -> None:
        """null означает отсутствие знаменателя: мерить ещё нечем, и это не «хорошо»."""
        assert _ready(summary=_full_summary(precision=None)).decision == policy.NOT_READY

    def test_recall_presented_as_a_measurement_blocks(self) -> None:
        """Если бы recall выдавался за измерение, гейт обязан это заметить: полной разметки
        реального потока не существует."""
        summary = _full_summary(recall_is_estimate=False, ground_truth_complete=True)
        readiness = _ready(summary=summary)
        assert readiness.decision == policy.NOT_READY
        assert "real_flow_recall_is_labelled_estimate" in [c.key for c in readiness.blocking]

    def test_an_unregistered_critical_gap_blocks(self) -> None:
        """ТЗ §29: нельзя выдавать READY при незарегистрированном критическом пробеле."""
        gaps = [{"gap_id": "GAP-009", "severity": "CRITICAL", "status": ""}]
        readiness = _ready(gaps=gaps)
        assert readiness.decision == policy.NOT_READY
        assert readiness.blocking[0].value == ["GAP-009"]

    def test_a_registered_critical_gap_does_not_block(self) -> None:
        """Регистрация не делает пробел безопасным — она делает его известным, а известное
        ограничение и неизвестная дыра различаются для того, кто ставит платформу в разрыв."""
        gaps = [{"gap_id": "GAP-009", "severity": "CRITICAL", "status": "ACCEPTED"}]
        assert _ready(gaps=gaps).decision == policy.READY

    def test_a_resolved_gap_without_real_mail_evidence_is_a_warning(self) -> None:
        """Закрытый по синтетическому корпусу — закрытый по случаям, которые мы сами придумали."""
        gaps = [{"gap_id": "GAP-001", "severity": "MEDIUM", "status": "RESOLVED"}]
        readiness = _ready(gaps=gaps)
        assert readiness.decision == policy.READY_WITH_WARNINGS
        assert "resolved_gaps_validated_on_real_mail" in [c.key for c in readiness.warnings]


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
        assert "real_flow_sample" in body["blocking"]
        assert "regression_suite" in body["blocking"], "непроверенная регрессия блокирует"

    @pytest.mark.slow
    def test_the_script_accepts_a_summary_and_changes_its_answer(self, tmp_path: Path) -> None:
        """Проверка самой проверки: отказ выше — следствие отсутствия данных, а не всегда так."""
        summary = tmp_path / "summary.json"
        summary.write_text(json.dumps(_full_summary()), encoding="utf-8")
        out = tmp_path / "readiness.json"
        subprocess.run(  # nosec B603 - fixed argv, no shell
            [
                sys.executable,
                str(SCRIPT),
                "--real-flow-summary",
                str(summary),
                "--json",
                str(out),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            check=False,
        )
        body = json.loads(out.read_text(encoding="utf-8"))
        assert "real_flow_sample" not in body["blocking"]
        # Регрессия всё ещё не запускалась, поэтому готовности нет — и это правильный ответ.
        assert body["decision"] == policy.NOT_READY
        assert body["blocking"] == ["regression_suite"]
