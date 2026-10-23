"""Проверки безопасности принуждения на живом стенде (ТЗ 1.3 §57, §66, §67, §74, §85).

Подделанные заголовки не обходят принуждение; выключатель работает без плоскости управления; отчёт о действиях сканера
учитывает шлюз принуждения; перебой базы и анализа не останавливает почту.
"""

from __future__ import annotations

import contextlib
import json
import time

import pytest

from tests.gateway.harness import docker

from .harness import BASE, CANARY_RCPT, activate, decisions, make_ready, pause

THRESHOLD = {"reject_score": 12.0}


@pytest.fixture(scope="module")
def canary(enf, admin, admin2):  # type: ignore[no-untyped-def]
    make_ready(enf, admin, "SPAM_REJECT")
    activate(enf, admin, admin2, "SPAM_REJECT", scope={"recipients": [CANARY_RCPT]}, thresholds=THRESHOLD)
    yield
    with contextlib.suppress(Exception):
        pause(enf, admin, "SPAM_REJECT")


def send_spam(lab, unique: str, headers: str = ""):  # type: ignore[no-untyped-def]
    """Письмо категории phishing с добавленными заголовками; подпись пересчитывается после добавления."""
    import dataclasses

    from tests.spam.harness import OTHER_IP, SENDER_IP
    from tests.spam.zone import Zone

    from .harness import build_case, dns_for

    case = dataclasses.replace(
        lab.case("phishing", 1),
        id=f"SPC-PHIS-001-{unique}",
        extra_headers=tuple(tuple(line.split(": ", 1)) for line in headers.splitlines() if ": " in line),
    )
    zone = Zone("sc")
    lab.dns.reset()
    lab.dns.records(dns_for(case, zone, None))
    ip = SENDER_IP if case.context.client == "authorized" else OTHER_IP
    raw = build_case(case, zone, None)
    result = lab.smtp_from(ip, f"sender@{zone.domain}", [CANARY_RCPT], raw, helo=zone.helo)
    return f"{case.id.lower()}@corpus.example", result


class TestForgedEvidence:
    def test_forged_scanner_and_authentication_headers_do_not_bypass_enforcement(self, lab, canary) -> None:  # type: ignore[no-untyped-def]
        forged = (
            "X-Spam-Flag: NO\nX-Spam-Status: No, score=-50.0\nX-Spamd-Result: default: False [-50.00 / 15.00]\n"
            "X-Rspamd-Action: no action\nX-MSP-Enforcement-Bypass: 1\nX-Enforcement-Bypass: true\n"
            "Authentication-Results: gw.lab.example; spf=pass; dkim=pass; dmarc=pass\n"
        )
        mid, result = send_spam(lab, "forged", forged)
        assert result.get("ok") is False and str(result["code"]).startswith("5"), result

    def test_a_forged_header_cannot_raise_the_score_of_a_legitimate_message(self, lab, canary) -> None:  # type: ignore[no-untyped-def]
        from .harness import CANARY_RCPT as RCPT

        case = lab.case("transactional", 2)
        mid, result = lab.send_case(
            __import__("dataclasses").replace(case, extra_headers=(("X-Spam-Status", "Yes, score=99"),)),
            [RCPT],
            unique="forged-high",
        )
        assert result.get("ok"), result
        assert lab.exchange1.wait_for(f"<{mid}>", timeout=90) or lab.exchange2.wait_for(f"<{mid}>", timeout=2)


class TestWithoutControlPlane:
    def test_the_kill_switch_state_survives_a_panel_outage(self, lab, admin, canary) -> None:  # type: ignore[no-untyped-def]
        assert (
            admin.post(f"{BASE}/kill-switch", {"reason": "проверка без плоскости управления"}).status_code
            == 200
        )
        lab.wait_kill_switch(True, timeout=20)
        lab.panel.stop()  # type: ignore[attr-defined]
        try:
            time.sleep(5)
            mid, result = send_spam(lab, "nopanel")
            assert result.get("ok"), result
            assert lab.exchange1.wait_for(f"<{mid}>", timeout=90) or lab.exchange2.wait_for(
                f"<{mid}>", timeout=2
            )
            assert lab.node_status()["kill_switch"] is True
        finally:
            lab.panel.restart()  # type: ignore[attr-defined]

    def test_clearing_needs_the_second_person_and_enforcement_returns(
        self, lab, admin, admin2, canary
    ) -> None:  # type: ignore[no-untyped-def]
        # После перезапуска панели сессии в памяти теста остаются действительными (база та же).
        assert (
            admin.post(f"{BASE}/kill-switch/clear", {"reason": "проверка"}).json()["status"]
            == "CLEAR_REQUESTED"
        )
        assert (
            admin2.post(f"{BASE}/kill-switch/clear", {"reason": "подтверждаю"}).json()["status"] == "CLEARED"
        )
        lab.wait_kill_switch(False, timeout=30)
        _, result = send_spam(lab, "after-clear")
        assert result.get("ok") is False and str(result["code"]).startswith("5")


class TestEffectiveActionsReport:
    def test_the_gate_is_reported_as_an_approved_source_and_nothing_else_is_hidden(self, lab, canary) -> None:  # type: ignore[no-untyped-def]
        out = docker(
            "exec",
            lab.rspamd_container,
            "cat",
            "/var/lib/msp-rspamd/active/effective_actions_report.json",
            check=False,
        ).stdout
        report = json.loads(out)
        assert report["clean"] is True
        kinds = {s["kind"]: s["approved"] for s in report["sources"]}
        assert kinds.get("MSP_ENFORCEMENT_GATE") is True
        assert all(approved for approved in kinds.values()), kinds


class TestFailOpen:
    def test_decisions_are_still_recorded_after_the_panel_returns(self, lab, admin, canary) -> None:  # type: ignore[no-untyped-def]
        # Решения, принятые при недоступной панели, ждали в журнале узла и доставлены после возвращения связи.
        lab.wait_until(
            lambda: any(
                d["applied_action"] == "BYPASS_KILL_SWITCH" for d in decisions(admin, control="SPAM_REJECT")
            ),
            timeout=90,
            what="журнал решений дошёл до панели после перебоя",
        )
