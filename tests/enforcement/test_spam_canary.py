"""Канарейка SPAM_REJECT на настоящем Postfix, Rspamd и службе принуждения (ТЗ 1.3 §24, §25, §67–§69, §72, §74–§76).

Порядок тестов существенен: стенд общий, а состояние контроля меняется шагами — от наблюдения к канарейке, выключателю,
откату и перебою панели. Каждый шаг проверяет реальный ответ SMTP, а не только решение в журнале.
"""

from __future__ import annotations

import contextlib
import time

import pytest
from msp_enforcement.model import ControlState  # noqa: F401 - состояния используются в сообщениях проверок

from .harness import (
    BASE,
    CANARY_RCPT,
    OTHER_RCPT,
    activate,
    decisions,
    make_ready,
    pause,
    rejected_text,
)

SPAM_THRESHOLD = {"reject_score": 12.0}  # письма корпуса категории phishing набирают около 13


def delivered(lab, message_id: str, timeout: float = 90.0):  # type: ignore[no-untyped-def]
    return lab.exchange1.wait_for(f"<{message_id}>", timeout=timeout) or lab.exchange2.wait_for(
        f"<{message_id}>", timeout=2
    )


def not_delivered(lab, message_id: str, wait: float = 12.0) -> bool:  # type: ignore[no-untyped-def]
    time.sleep(wait)
    return (
        lab.exchange1.wait_for(f"<{message_id}>", timeout=1) is None
        and lab.exchange2.wait_for(f"<{message_id}>", timeout=1) is None
    )


class TestSpamCanary:
    def test_1_before_activation_nothing_is_rejected(self, lab, admin) -> None:  # type: ignore[no-untyped-def]
        case = lab.case("phishing", 1)
        mid, result = lab.send_case(case, [CANARY_RCPT], unique="shadow")
        assert result.get("ok"), result
        assert delivered(lab, mid)
        # В наблюдении (SHADOW) контроль ничего не применяет: ни отказов, ни удержаний.
        applied = [
            d
            for d in decisions(admin)
            if d["applied_action"] in ("SMTP_REJECT", "SMTP_TEMPFAIL", "QUARANTINED")
        ]
        assert applied == []

    def test_2_a_canary_needs_a_ready_control_and_two_people(self, lab, admin, admin2) -> None:  # type: ignore[no-untyped-def]
        kind = "SPAM_REJECT"
        # Без подтверждённых проверок контроль не готов, и запрос отклоняется.
        early = admin.post(
            f"{BASE}/controls/{kind}/canary",
            {
                "action": "request",
                "scope": {"recipients": [CANARY_RCPT]},
                "justification": "преждевременная попытка",
            },
        )
        assert early.status_code == 409, early.text
        make_ready(lab, admin, kind)
        version = activate(
            lab, admin, admin2, kind, scope={"recipients": [CANARY_RCPT]}, thresholds=SPAM_THRESHOLD
        )
        assert admin.get(f"{BASE}/controls/{kind}").json()["state"] == "CANARY"
        status = lab.node_status()
        assert status["policy_version"] == version and status["status"] == "FRESH"
        assert status["kill_switch"] is False

    def test_3_a_canary_recipient_gets_a_generic_5xx_and_nothing_is_delivered(self, lab, admin) -> None:  # type: ignore[no-untyped-def]
        case = lab.case("phishing", 2)
        mid, result = lab.send_case(case, [CANARY_RCPT], unique="canary")
        assert result.get("ok") is False and result.get("stage") == "response", result
        assert str(result["code"]).startswith("5"), result
        text = rejected_text(result)
        assert "Message rejected by local policy" in text
        for leak in ("score", "BAYES", "rspamd", "RBL", "SPAM_", "MSP_", "policy v", "13"):
            assert leak not in text.replace("Message rejected by local policy", ""), text
        assert not_delivered(lab, mid)

    def test_4_every_applied_reject_has_evidence_policy_version_and_an_audit_event(self, lab, admin) -> None:  # type: ignore[no-untyped-def]
        current = admin.get(f"{BASE}/policies/current").json()
        lab.wait_until(
            lambda: any(
                d["applied_action"] == "SMTP_REJECT" for d in decisions(admin, control="SPAM_REJECT")
            ),
            timeout=60,
            what="применённый отказ дошёл до панели",
        )
        rejects = [d for d in decisions(admin, control="SPAM_REJECT") if d["applied_action"] == "SMTP_REJECT"]
        assert rejects
        for d in rejects:
            assert d["evidence_ids"] and d["policy_version"] == current["version"]
            assert d["policy_checksum"] == current["checksum"]
            assert d["suggested_action"] == "REJECT" and d["decision"] == "REJECT"
            assert d["reason_codes"] and d["latency_ms"] < 1500
        from msp_api.db.models import AuditEvent

        with lab.panel.database() as session:  # type: ignore[attr-defined]
            audited = (
                session.query(AuditEvent).filter(AuditEvent.action == "enforcement.decision_applied").all()
            )
        assert audited and all(e.detail["policy_version"] == current["version"] for e in audited)

    def test_5_a_non_canary_recipient_gets_only_the_suggestion(self, lab, admin) -> None:  # type: ignore[no-untyped-def]
        case = lab.case("phishing", 3)
        mid, result = lab.send_case(case, [OTHER_RCPT], unique="other")
        assert result.get("ok"), result
        assert delivered(lab, mid)
        lab.wait_until(
            lambda: any(
                d["applied_action"] == "OBSERVE_ONLY"
                and d["suggested_action"] == "REJECT"
                and d["reason_codes"]
                and "OUT_OF_CANARY_SCOPE" in d["reason_codes"]
                for d in decisions(admin, control="SPAM_REJECT")
            ),
            timeout=60,
            what="вне канарейки — только предложение",
        )

    def test_6_a_legitimate_canary_message_is_delivered(self, lab) -> None:  # type: ignore[no-untyped-def]
        case = lab.case("transactional", 1)
        mid, result = lab.send_case(case, [CANARY_RCPT], unique="legit")
        assert result.get("ok"), result
        assert delivered(lab, mid)

    def test_7_a_multi_recipient_message_is_not_rejected_for_a_partial_canary(self, lab) -> None:  # type: ignore[no-untyped-def]
        case = lab.case("phishing", 4)
        mid, result = lab.send_case(case, [CANARY_RCPT, OTHER_RCPT], unique="multi")
        assert result.get("ok"), result
        assert delivered(lab, mid)

    def test_8_a_retry_of_the_same_message_decides_the_same_way(self, lab) -> None:  # type: ignore[no-untyped-def]
        case = lab.case("phishing", 5)
        first = lab.send_case(case, [CANARY_RCPT], unique="retry")[1]
        second = lab.send_case(case, [CANARY_RCPT], unique="retry")[1]
        assert first.get("ok") is False and second.get("ok") is False
        assert str(first["code"]).startswith("5") and str(second["code"]).startswith("5")

    def test_9_the_gate_failing_open_never_blocks_mail(self, lab, admin) -> None:  # type: ignore[no-untyped-def]
        from tests.gateway.harness import docker

        docker("stop", "-t", "2", lab.enforcement_container)
        try:
            case = lab.case("phishing", 6)
            mid, result = lab.send_case(case, [CANARY_RCPT], unique="svcdown")
            assert result.get("ok"), result
            assert delivered(lab, mid, timeout=120)
        finally:
            docker("start", lab.enforcement_container)
            lab.wait_policy(admin.get(f"{BASE}/policies/current").json()["version"], timeout=90)

    def test_10_the_kill_switch_stops_rejects_within_the_propagation_slo(self, lab, admin, admin2) -> None:  # type: ignore[no-untyped-def]
        started = time.monotonic()
        assert (
            admin.post(f"{BASE}/kill-switch", {"reason": "лабораторная проверка выключателя"}).status_code
            == 200
        )
        lab.wait_kill_switch(True, timeout=20)
        propagation = time.monotonic() - started
        assert propagation < 20, f"распространение выключателя заняло {propagation:.1f} с"
        case = lab.case("phishing", 7)
        mid, result = lab.send_case(case, [CANARY_RCPT], unique="killed")
        assert result.get("ok"), result
        assert delivered(lab, mid)
        # Решение помечено обходом выключателем, предложение сохранено.
        lab.wait_until(
            lambda: any(
                d["applied_action"] == "BYPASS_KILL_SWITCH" and d["suggested_action"] == "REJECT"
                for d in decisions(admin, control="SPAM_REJECT")
            ),
            timeout=60,
            what="обход выключателем записан",
        )
        # Снять может только второй человек.
        assert (
            admin.post(f"{BASE}/kill-switch/clear", {"reason": "проверка завершена"}).json()["status"]
            == "CLEAR_REQUESTED"
        )
        assert (
            admin2.post(f"{BASE}/kill-switch/clear", {"reason": "подтверждаю"}).json()["status"] == "CLEARED"
        )
        lab.wait_kill_switch(False, timeout=20)
        _, again = lab.send_case(lab.case("phishing", 8), [CANARY_RCPT], unique="after-clear")
        assert again.get("ok") is False and str(again["code"]).startswith("5")

    def test_11_a_panel_outage_keeps_the_cached_policy_and_the_kill_switch_state(self, lab, admin) -> None:  # type: ignore[no-untyped-def]
        lab.panel.stop()  # type: ignore[attr-defined]
        try:
            time.sleep(6)  # узел успел заметить недоступность
            _, result = lab.send_case(lab.case("phishing", 9), [CANARY_RCPT], unique="panel-down")
            assert result.get("ok") is False and str(result["code"]).startswith("5"), result
            ok_mid, ok = lab.send_case(lab.case("transactional", 2), [CANARY_RCPT], unique="panel-down-legit")
            assert ok.get("ok"), ok
            assert delivered(lab, ok_mid)
            assert lab.node_status()["status"] in ("FRESH", "STALE")
        finally:
            lab.panel.restart()  # type: ignore[attr-defined]

    def test_12_a_local_bypass_works_without_the_control_plane(self, lab, admin) -> None:  # type: ignore[no-untyped-def]
        lab.panel.stop()  # type: ignore[attr-defined]
        try:
            lab.set_local_bypass(True)
            mid, result = lab.send_case(lab.case("phishing", 10), [CANARY_RCPT], unique="bypass")
            assert result.get("ok"), result
            assert delivered(lab, mid)
        finally:
            lab.set_local_bypass(False)
            lab.panel.restart()  # type: ignore[attr-defined]
        _, again = lab.send_case(lab.case("phishing", 11), [CANARY_RCPT], unique="bypass-off")
        assert again.get("ok") is False and str(again["code"]).startswith("5")

    def test_13_rollback_returns_to_the_previous_policy_checksum(self, lab, admin) -> None:  # type: ignore[no-untyped-def]
        history = admin.get(f"{BASE}/policies").json()["items"]
        shadow = next(p for p in history if p["current"] is False and p["version"] == "v1")
        response = admin.post(
            f"{BASE}/controls/SPAM_REJECT/rollback",
            {"to_version": shadow["version"], "reason": "ложные срабатывания"},
        )
        assert response.status_code == 200, response.text
        lab.wait_policy(shadow["version"])
        current = admin.get(f"{BASE}/policies/current").json()
        assert current["checksum"] == shadow["checksum"]
        assert lab.node_status()["checksum"] == shadow["checksum"]
        mid, result = lab.send_case(lab.case("phishing", 12), [CANARY_RCPT], unique="rolled-back")
        assert result.get("ok"), "после отката отказов нет"
        assert delivered(lab, mid)


@pytest.fixture(scope="module", autouse=True)
def _restore(enf, admin):  # type: ignore[no-untyped-def]
    yield
    with contextlib.suppress(Exception):  # возврат состояния не должен скрывать результат проверок
        pause(enf, admin, "SPAM_REJECT")
