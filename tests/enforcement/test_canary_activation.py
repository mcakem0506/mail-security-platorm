"""Включение канарейки: наблюдение, готовность и два человека (ТЗ 1.3 §17, §24, §73).

До включения контроль ничего не применяет; запрос без готовности отклоняется; включают двое; узлы получают политику.
"""

from __future__ import annotations

import contextlib

import pytest

from .harness import BASE, CANARY_RCPT, activate, decisions, delivered, make_ready, pause


class TestCanaryActivation:
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
            lab, admin, admin2, kind, scope={"recipients": [CANARY_RCPT]}, thresholds={"reject_score": 12.0}
        )
        assert admin.get(f"{BASE}/controls/{kind}").json()["state"] == "CANARY"
        status = lab.node_status()
        assert status["policy_version"] == version and status["status"] == "FRESH"
        assert status["kill_switch"] is False

    def test_3_a_blocked_control_cannot_be_activated_on_the_running_stack(self, lab, admin) -> None:  # type: ignore[no-untyped-def]
        response = admin.post(
            f"{BASE}/controls/DMARC_REJECT/canary",
            {
                "action": "request",
                "scope": {"recipients": [CANARY_RCPT]},
                "justification": "попытка включить заблокированный",
            },
        )
        assert response.status_code == 409
        assert response.json()["detail"]["readiness"] == "BLOCKED_BY_GAP"
        view = admin.get(f"{BASE}/controls/DMARC_REJECT").json()
        assert view["state"] == "SHADOW" and view["blocking_gaps"] == ["GAP-006"]


@pytest.fixture(scope="module", autouse=True)
def _restore(enf, admin):  # type: ignore[no-untyped-def]
    yield
    with contextlib.suppress(Exception):  # возврат состояния не должен скрывать результат проверок
        pause(enf, admin, "SPAM_REJECT")
