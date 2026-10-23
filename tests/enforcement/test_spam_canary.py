"""Канарейка SPAM_REJECT на настоящем Postfix, Rspamd и службе принуждения (ТЗ 1.3 §24, §25, §67–§69, §72, §74).

Каждая проверка смотрит на реальный ответ SMTP и на то, дошло ли письмо до Exchange, а не только на журнал решений.
Контроль приводится в канарейку общей фикстурой тем же путём, что и в работе (готовность, запрос, согласование вторым человеком).
"""

from __future__ import annotations

import pytest

from tests.gateway.harness import docker

from .harness import (
    BASE,
    CANARY_RCPT,
    OTHER_RCPT,
    decisions,
    delivered,
    not_delivered,
    rejected_text,
)

pytestmark = pytest.mark.usefixtures("canary_active")


class TestSpamCanary:
    def test_1_a_canary_recipient_gets_a_generic_5xx_and_nothing_is_delivered(self, lab) -> None:  # type: ignore[no-untyped-def]
        case = lab.case("phishing", 2)
        mid, result = lab.send_case(case, [CANARY_RCPT], unique="canary")
        assert result.get("ok") is False and result.get("stage") == "response", result
        assert str(result["code"]).startswith("5"), result
        text = rejected_text(result)
        assert "Message rejected by local policy" in text
        for leak in ("score", "BAYES", "rspamd", "RBL", "SPAM_", "MSP_", "policy v", "13"):
            assert leak not in text.replace("Message rejected by local policy", ""), text
        assert not_delivered(lab, mid)

    def test_2_every_applied_reject_has_evidence_policy_version_and_an_audit_event(self, lab, admin) -> None:  # type: ignore[no-untyped-def]
        lab.send_case(lab.case("phishing", 3), [CANARY_RCPT], unique="evidence")
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
            assert d["evidence_ids"] and d["policy_version"]
            assert d["suggested_action"] == "REJECT" and d["decision"] == "REJECT"
            assert d["reason_codes"] and d["latency_ms"] < 1500
        assert any(d["policy_checksum"] == current["checksum"] for d in rejects)
        from msp_api.db.models import AuditEvent

        with lab.panel.database() as session:  # type: ignore[attr-defined]
            audited = (
                session.query(AuditEvent).filter(AuditEvent.action == "enforcement.decision_applied").all()
            )
        assert audited and all(e.detail["policy_version"] for e in audited)

    def test_3_a_non_canary_recipient_gets_only_the_suggestion(self, lab, admin) -> None:  # type: ignore[no-untyped-def]
        case = lab.case("phishing", 4)
        mid, result = lab.send_case(case, [OTHER_RCPT], unique="other")
        assert result.get("ok"), result
        assert delivered(lab, mid)
        lab.wait_until(
            lambda: any(
                d["applied_action"] == "OBSERVE_ONLY"
                and d["suggested_action"] == "REJECT"
                and "OUT_OF_CANARY_SCOPE" in d["reason_codes"]
                for d in decisions(admin, control="SPAM_REJECT")
            ),
            timeout=60,
            what="вне канарейки — только предложение",
        )

    def test_4_a_legitimate_canary_message_is_delivered(self, lab) -> None:  # type: ignore[no-untyped-def]
        case = lab.case("transactional", 1)
        mid, result = lab.send_case(case, [CANARY_RCPT], unique="legit")
        assert result.get("ok"), result
        assert delivered(lab, mid)

    def test_5_a_multi_recipient_message_is_not_rejected_for_a_partial_canary(self, lab) -> None:  # type: ignore[no-untyped-def]
        case = lab.case("phishing", 5)
        mid, result = lab.send_case(case, [CANARY_RCPT, OTHER_RCPT], unique="multi")
        assert result.get("ok"), result
        assert delivered(lab, mid)

    def test_6_a_retry_of_the_same_message_decides_the_same_way(self, lab) -> None:  # type: ignore[no-untyped-def]
        case = lab.case("phishing", 6)
        first = lab.send_case(case, [CANARY_RCPT], unique="retry")[1]
        second = lab.send_case(case, [CANARY_RCPT], unique="retry")[1]
        assert first.get("ok") is False and second.get("ok") is False
        assert str(first["code"]).startswith("5") and str(second["code"]).startswith("5")

    def test_7_the_gate_failing_open_never_blocks_mail(self, lab, admin) -> None:  # type: ignore[no-untyped-def]
        docker("stop", "-t", "2", lab.enforcement_container)
        try:
            case = lab.case("phishing", 7)
            mid, result = lab.send_case(case, [CANARY_RCPT], unique="svcdown")
            assert result.get("ok"), result
            assert delivered(lab, mid, timeout=120)
        finally:
            docker("start", lab.enforcement_container)
            lab.wait_policy(admin.get(f"{BASE}/policies/current").json()["version"], timeout=90)

    def test_8_the_afterqueue_alone_failing_still_delivers_mail(self, lab) -> None:  # type: ignore[no-untyped-def]
        """Послеочередной шлюз недоступен: Postfix откладывает письмо (451) и доставляет его, когда шлюз вернулся."""
        docker("stop", "-t", "2", lab.afterqueue_container)
        try:
            mid, result = lab.send_case(lab.case("transactional", 3), [CANARY_RCPT], unique="aqdown")
            assert result.get("ok"), "приём не зависит от послеочередного шлюза"
        finally:
            docker("start", lab.afterqueue_container)
        assert delivered(lab, mid, timeout=240), (
            "после возвращения шлюза письмо доставлено из очереди Postfix"
        )
