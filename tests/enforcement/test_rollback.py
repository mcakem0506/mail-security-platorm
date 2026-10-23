"""Откат политики: узлы возвращаются к прежней контрольной сумме (ТЗ 1.3 §21, §76)."""

from __future__ import annotations

import pytest

from .harness import BASE, CANARY_RCPT, delivered

pytestmark = pytest.mark.usefixtures("canary_active")


def test_1_rollback_returns_to_the_previous_policy_checksum_and_stops_rejects(lab, admin) -> None:  # type: ignore[no-untyped-def]
    history = admin.get(f"{BASE}/policies").json()["items"]
    baseline = next(p for p in history if p["version"] == "v1")
    _, rejected = lab.send_case(lab.case("phishing", 1), [CANARY_RCPT], unique="before-rollback")
    assert rejected.get("ok") is False and str(rejected["code"]).startswith("5")
    response = admin.post(
        f"{BASE}/controls/SPAM_REJECT/rollback",
        {"to_version": baseline["version"], "reason": "ложные срабатывания"},
    )
    assert response.status_code == 200, response.text
    lab.wait_policy(baseline["version"])
    current = admin.get(f"{BASE}/policies/current").json()
    assert current["version"] == baseline["version"] and current["checksum"] == baseline["checksum"]
    assert lab.node_status()["checksum"] == baseline["checksum"]
    assert lab.node_status(lab.afterqueue_container)["checksum"] == baseline["checksum"]
    mid, result = lab.send_case(lab.case("phishing", 2), [CANARY_RCPT], unique="after-rollback")
    assert result.get("ok"), "после отката решений прежней версии больше нет"
    assert delivered(lab, mid)
    assert admin.get(f"{BASE}/controls/SPAM_REJECT").json()["state"] == "ROLLED_BACK"


def test_2_a_rolled_back_control_returns_only_through_shadow_and_a_new_two_person_request(
    lab, admin, admin2
) -> None:  # type: ignore[no-untyped-def]
    direct = admin.post(
        f"{BASE}/controls/SPAM_REJECT/canary",
        {
            "action": "request",
            "scope": {"recipients": [CANARY_RCPT]},
            "justification": "прямое включение после отката",
        },
    )
    assert direct.status_code == 409, "из ROLLED_BACK в канарейку напрямую нельзя"
    assert (
        admin.post(f"{BASE}/controls/SPAM_REJECT/shadow", {"reason": "вернуться в наблюдение"}).status_code
        == 200
    )
    assert admin.get(f"{BASE}/controls/SPAM_REJECT").json()["state"] == "SHADOW"
