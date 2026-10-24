"""Карантин после очереди от письма до выпуска (ТЗ 1.3 §11, §12, §32–§36, §70, §74).

```
письмо → очередь Postfix → послеочередной шлюз → полный анализ MSP → решение QUARANTINE → хранилище карантина
→ письмо не у получателя → аналитик → выпуск → доверенная повторная подача → доставлено один раз
```
"""

from __future__ import annotations

import base64
import contextlib
import re
import time
from email.message import EmailMessage
from email.policy import SMTP
from unittest import mock

import httpx
import pytest
from fixtures import attachments as make

from tests.gateway.harness import REPO
from tests.spam.harness import SENDER_IP

from .harness import (
    BASE,
    CANARY_RCPT,
    POLICY_TOKEN,
    activate,
    decisions,
    make_ready,
    pause,
    wait_panel_quiet,
    wait_with_diagnostics,
)

NODE = "00000000000000000000000000000001"


def encrypted_mail(token: str, rcpt: str = CANARY_RCPT) -> tuple[str, bytes]:
    message_id = f"q-{token}@partner.example"
    msg = EmailMessage(policy=SMTP)
    msg["From"] = "partner@partner.example"
    msg["To"] = rcpt
    msg["Subject"] = f"Документы {token}"
    msg["Message-ID"] = f"<{message_id}>"
    msg["Date"] = "Mon, 12 Oct 2026 10:00:00 +0000"
    msg.set_content("Во вложении архив с паролем, пароль сообщу по телефону.")
    msg.add_attachment(
        make.make_7z({"invoice.txt": b"secret"}, password="s3cret"),
        maintype="application",
        subtype="x-7z-compressed",
        filename="documents.7z",
    )
    return message_id, msg.as_bytes()


def send(lab, raw: bytes, rcpt: str = CANARY_RCPT):  # type: ignore[no-untyped-def]
    return lab.smtp_from(SENDER_IP, "partner@partner.example", [rcpt], raw, helo="mail.partner.example")


def quarantine_items(admin, **params: str):  # type: ignore[no-untyped-def]
    return admin.get("/api/v1/quarantine", params={"limit": "100", **params}).json()


def node_post(lab, path: str, body: dict) -> httpx.Response:  # type: ignore[no-untyped-def]
    return httpx.post(
        f"http://127.0.0.1:{lab.panel.port}/api/v1/gateway-agent{path}",
        json=body,
        timeout=60,
        headers={"Authorization": f"Bearer {POLICY_TOKEN}"},
    )


def count_at(lab, message_id: str) -> int:  # type: ignore[no-untyped-def]
    return sum(ex.message_ids().count(f"<{message_id}>") for ex in (lab.exchange1, lab.exchange2))


class TestQuarantineEndToEnd:
    def test_1_a_released_item_proves_the_release_path_and_unlocks_the_control(
        self, lab, admin, analyst
    ) -> None:  # type: ignore[no-untyped-def]
        """Контроль QUARANTINE нельзя включить, пока выпуск не проверен: проверяем его на пробном письме."""
        message_id, raw = encrypted_mail("probe")
        stored = node_post(
            lab,
            "/quarantine",
            {
                "node_id": NODE,
                "transport_message_id": "QPROBE0001",
                "internet_message_id": message_id,
                "decision_ref": "probe:1",
                "sender": "partner@partner.example",
                "recipients": [CANARY_RCPT],
                "subject": "пробное",
                "reason_codes": ["ENCRYPTED_UNSCANNABLE"],
                "policy_version": "v1",
                "raw_b64": base64.b64encode(raw).decode(),
            },
        )
        assert stored.status_code == 200, stored.text
        item_id = stored.json()["id"]
        assert analyst.post(f"/api/v1/quarantine/{item_id}/release", {"action": "request"}).status_code == 200
        lab.wait_until(
            lambda: quarantine_items(admin, state="RELEASED")["total"] >= 1,
            timeout=90,
            what="узел повторно подал письмо и подтвердил выпуск",
        )
        assert lab.exchange1.wait_for(f"<{message_id}>", timeout=60) or lab.exchange2.wait_for(
            f"<{message_id}>", timeout=5
        )
        assert count_at(lab, message_id) == 1, "письмо должно быть доставлено один раз"

    def test_2_the_control_becomes_ready_and_is_activated_by_two_people(self, lab, admin, admin2) -> None:  # type: ignore[no-untyped-def]
        make_ready(lab, admin, "QUARANTINE")
        activate(lab, admin, admin2, "QUARANTINE", scope={"recipients": [CANARY_RCPT]})
        assert admin.get(f"{BASE}/controls/QUARANTINE").json()["state"] == "CANARY"

    def test_3_an_encrypted_archive_goes_to_quarantine_after_the_queue_and_not_to_exchange(
        self, lab, admin
    ) -> None:  # type: ignore[no-untyped-def]
        wait_panel_quiet(lab, quiet=8)
        message_id, raw = encrypted_mail("e2e1")
        result = send(lab, raw)
        # Письмо принято (250): отказывать после очереди нельзя (ТЗ §10).
        assert result.get("ok"), result
        wait_with_diagnostics(
            lab,
            lambda: any(i["internet_message_id"] == message_id for i in quarantine_items(admin)["items"]),
            timeout=120,
            what="письмо попало в карантин",
        )
        time.sleep(8)
        assert count_at(lab, message_id) == 0, "карантинное письмо не должно уйти получателю"
        item = next(i for i in quarantine_items(admin)["items"] if i["internet_message_id"] == message_id)
        assert item["state"] == "QUARANTINED" and "ENCRYPTED_UNSCANNABLE" in item["reason_codes"]
        assert item["recipients"] == [CANARY_RCPT] and item["policy_version"]
        # Решение: не reject, а QUARANTINE, со свидетельствами и версией политики.
        lab.wait_until(
            lambda: any(
                d["decision"] == "QUARANTINE"
                and d["applied_action"] == "QUARANTINED"
                and d["evidence_ids"]
                and d["policy_version"]
                for d in decisions(admin, control="QUARANTINE")
            ),
            timeout=60,
            what="решение о карантине записано",
        )

    def test_4_the_preview_is_safe_and_the_release_delivers_once_without_a_loop(
        self, lab, admin, analyst
    ) -> None:  # type: ignore[no-untyped-def]
        wait_panel_quiet(lab, quiet=8)
        message_id, raw = encrypted_mail("e2e2")
        assert send(lab, raw).get("ok")
        wait_with_diagnostics(
            lab,
            lambda: any(i["internet_message_id"] == message_id for i in quarantine_items(admin)["items"]),
            timeout=120,
            what="письмо попало в карантин",
        )
        item = next(i for i in quarantine_items(admin)["items"] if i["internet_message_id"] == message_id)
        preview = analyst.get(f"/api/v1/quarantine/{item['id']}/preview").json()
        assert (
            preview["active_content_removed"] is True and preview["attachments"][0]["name"] == "documents.7z"
        )
        assert (
            analyst.post(f"/api/v1/quarantine/{item['id']}/release", {"action": "request"}).status_code == 200
        )
        lab.wait_until(
            lambda: (
                next(i for i in quarantine_items(admin)["items"] if i["id"] == item["id"])["state"]
                == "RELEASED"
            ),
            timeout=90,
            what="выпуск подтверждён узлом",
        )
        assert lab.exchange1.wait_for(f"<{message_id}>", timeout=60) or lab.exchange2.wait_for(
            f"<{message_id}>", timeout=5
        )
        time.sleep(10)
        assert count_at(lab, message_id) == 1, (
            "выпущенное письмо доставлено один раз и не карантинится повторно"
        )
        after = next(i for i in quarantine_items(admin)["items"] if i["id"] == item["id"])
        assert after["delivered_count"] == 1
        assert quarantine_items(admin, state="QUARANTINED")["total"] == _others(admin, item["id"])

    def test_5_an_unreachable_panel_fails_open_and_the_mail_is_delivered(self, lab) -> None:  # type: ignore[no-untyped-def]
        message_id, raw = encrypted_mail("outage")
        lab.panel.stop()
        try:
            assert send(lab, raw).get("ok")
            assert lab.exchange1.wait_for(f"<{message_id}>", timeout=120) or lab.exchange2.wait_for(
                f"<{message_id}>", timeout=5
            ), "при недоступной панели письмо доставляется (открытый сбой)"
        finally:
            lab.panel.restart()  # type: ignore[attr-defined]

    def test_6_a_quarantine_store_failure_fails_open_and_is_counted(self, lab, admin) -> None:  # type: ignore[no-untyped-def]
        from msp_api.config import get_settings

        message_id, raw = encrypted_mail("nostore")
        with mock.patch.object(get_settings(), "quarantine_encryption_key", ""):
            assert send(lab, raw).get("ok")
            assert lab.exchange1.wait_for(f"<{message_id}>", timeout=120) or lab.exchange2.wait_for(
                f"<{message_id}>", timeout=5
            )
        assert not any(i["internet_message_id"] == message_id for i in quarantine_items(admin)["items"])

    def test_7_nothing_bounces_after_the_queue(self, lab) -> None:  # type: ignore[no-untyped-def]
        postfix = lab.postfix_log()
        assert "status=bounced" not in postfix, (
            "после 250 недоставленных уведомлений быть не должно (backscatter)"
        )
        assert "Command not implemented" not in postfix

    def test_8_the_afterqueue_service_never_sends_a_permanent_error(self, lab) -> None:  # type: ignore[no-untyped-def]
        source = (REPO / "packages" / "enforcement" / "msp_enforcement" / "afterqueue.py").read_text(
            encoding="utf-8"
        )
        codes = {int(c) for c in re.findall(r"return (\d{3}), \"", source)}
        assert codes <= {250, 451}, codes


def _others(admin, exclude: str) -> int:  # type: ignore[no-untyped-def]
    return sum(1 for i in quarantine_items(admin, state="QUARANTINED")["items"] if i["id"] != exclude)


@pytest.fixture(scope="module", autouse=True)
def _quiet_panel(enf):  # type: ignore[no-untyped-def]
    wait_panel_quiet(enf)


@pytest.fixture(scope="module", autouse=True)
def _restore(enf, admin):  # type: ignore[no-untyped-def]
    yield
    with contextlib.suppress(Exception):
        pause(enf, admin, "QUARANTINE")
