"""Общий выключатель, перебой панели и локальный обход (ТЗ 1.3 §19, §20, §48, §74, §75).

Выключатель действует на следующем письме и не зависит от плоскости управления: узел помнит его состояние.
"""

from __future__ import annotations

import time

import pytest

from .harness import BASE, CANARY_RCPT, decisions, delivered

pytestmark = pytest.mark.usefixtures("canary_active")


class TestKillSwitch:
    def test_1_the_kill_switch_stops_rejects_within_the_propagation_slo(self, lab, admin, admin2) -> None:  # type: ignore[no-untyped-def]
        started = time.monotonic()
        assert (
            admin.post(f"{BASE}/kill-switch", {"reason": "лабораторная проверка выключателя"}).status_code
            == 200
        )
        lab.wait_kill_switch(True, timeout=20)
        propagation = time.monotonic() - started
        assert propagation < 20, f"распространение выключателя заняло {propagation:.1f} с"
        print(f"KILL_SWITCH_PROPAGATION_SECONDS {propagation:.2f}")
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

    def test_2_a_panel_outage_keeps_the_cached_policy_and_the_kill_switch_state(
        self, lab, admin, admin2
    ) -> None:  # type: ignore[no-untyped-def]
        assert (
            admin.post(f"{BASE}/kill-switch", {"reason": "проверка без плоскости управления"}).status_code
            == 200
        )
        lab.wait_kill_switch(True, timeout=20)
        lab.panel.stop()  # type: ignore[attr-defined]
        try:
            time.sleep(6)  # узел успел заметить недоступность
            mid, result = lab.send_case(lab.case("phishing", 9), [CANARY_RCPT], unique="panel-down-killed")
            assert result.get("ok"), "выключатель действует и без панели"
            assert delivered(lab, mid)
            assert lab.node_status()["kill_switch"] is True
        finally:
            lab.panel.restart()  # type: ignore[attr-defined]
        assert (
            admin.post(f"{BASE}/kill-switch/clear", {"reason": "запрос"}).json()["status"]
            == "CLEAR_REQUESTED"
        )
        assert (
            admin2.post(f"{BASE}/kill-switch/clear", {"reason": "подтверждаю"}).json()["status"] == "CLEARED"
        )
        lab.wait_kill_switch(False, timeout=30)

    def test_3_a_panel_outage_keeps_enforcing_with_the_cached_policy(self, lab) -> None:  # type: ignore[no-untyped-def]
        lab.panel.stop()  # type: ignore[attr-defined]
        try:
            time.sleep(6)
            _, result = lab.send_case(lab.case("phishing", 10), [CANARY_RCPT], unique="panel-down")
            assert result.get("ok") is False and str(result["code"]).startswith("5"), result
            ok_mid, ok = lab.send_case(lab.case("transactional", 2), [CANARY_RCPT], unique="panel-down-legit")
            assert ok.get("ok"), ok
            assert delivered(lab, ok_mid)
            assert lab.node_status()["status"] in ("FRESH", "STALE")
        finally:
            lab.panel.restart()  # type: ignore[attr-defined]

    def test_4_a_local_bypass_works_without_the_control_plane(self, lab) -> None:  # type: ignore[no-untyped-def]
        lab.panel.stop()  # type: ignore[attr-defined]
        try:
            lab.set_local_bypass(True)
            mid, result = lab.send_case(lab.case("phishing", 11), [CANARY_RCPT], unique="bypass")
            assert result.get("ok"), result
            assert delivered(lab, mid)
        finally:
            lab.set_local_bypass(False)
            lab.panel.restart()  # type: ignore[attr-defined]
        _, again = lab.send_case(lab.case("phishing", 12), [CANARY_RCPT], unique="bypass-off")
        assert again.get("ok") is False and str(again["code"]).startswith("5")

    def test_5_decisions_made_during_an_outage_reach_the_panel_afterwards(self, lab, admin) -> None:  # type: ignore[no-untyped-def]
        lab.wait_until(
            lambda: any(
                d["applied_action"] == "BYPASS_LOCAL" for d in decisions(admin, control="SPAM_REJECT")
            ),
            timeout=120,
            what="журнал решений, накопленный при перебое, дошёл до панели",
        )
