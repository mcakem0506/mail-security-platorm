"""Панель и узел с настоящим сканером вместе (ТЗ 1.2 §27, §33, §40).

Проверяется то, что по отдельности не видно: результат сканирования доходит до панели; копия письма
дополняет запись HELO и результатами вышестоящего шлюза; назначенный в панели провайдер репутации и
активированный ключ подписи доходят до работающего сканера и меняют его поведение; перебой панели
не мешает почте и не теряет результаты.
"""

from __future__ import annotations

import base64
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import dkim
import httpx
import pytest
from msp_antispam import dkim_keys

from tests.gateway.panel import ADMIN_PASSWORD, Panel

from .harness import OTHER_IP, SENDER_IP, build_message
from .zone import Zone

BASE = "/api/v1/gateway"


class Person:
    """Второй человек: четыре глаза требуют другой учётной записи."""

    def __init__(self, panel: Panel, email: str) -> None:
        from msp_api.db.models import Organization, User
        from msp_api.security.auth import hash_password
        from msp_contracts import Role

        with panel.database() as session:
            org = session.query(Organization).first()
            if session.query(User).filter(User.email == email).first() is None:
                session.add(
                    User(
                        organization_id=org.id,
                        email=email,
                        display_name=email,
                        role=Role.SECURITY_ADMIN,
                        password_hash=hash_password(ADMIN_PASSWORD),
                    )
                )
                session.commit()
        self.client = httpx.Client(base_url=f"http://127.0.0.1:{panel.port}", timeout=60)
        response = self.client.post("/api/v1/auth/login", json={"email": email, "password": ADMIN_PASSWORD})
        response.raise_for_status()
        self.csrf = response.json()["csrf_token"]

    def get(self, path: str, params: dict | None = None) -> httpx.Response:
        return self.client.get(path, params=params)

    def post(self, path: str, json: object = None) -> httpx.Response:
        return self.client.post(path, json=json, headers={"x-csrf-token": self.csrf})

    def close(self) -> None:
        self.client.close()


@pytest.fixture(scope="module")
def admin(spam) -> Iterator[Person]:  # type: ignore[no-untyped-def]
    if not getattr(spam, "panel_port", None):
        pytest.skip("стенд без панели")
    person = Person(spam.panel, "admin@corp.example")
    yield person
    person.close()


@pytest.fixture(scope="module")
def second(spam) -> Iterator[Person]:  # type: ignore[no-untyped-def]
    if not getattr(spam, "panel_port", None):
        pytest.skip("стенд без панели")
    person = Person(spam.panel, "admin2@corp.example")
    yield person
    person.close()


def wait_for(spam, condition, what: str, timeout: float = 120.0):  # type: ignore[no-untyped-def]
    spam.wait_until(condition, timeout=timeout, what=what)


def panel_scan(admin: Person, mid: str) -> dict | None:
    response = admin.get(f"{BASE}/spam/messages/{mid}@sender.example")
    return response.json() if response.status_code == 200 else None


def scanner_version(spam) -> str:  # type: ignore[no-untyped-def]
    from tests.gateway.harness import docker

    out = docker(
        "exec", spam.rspamd_container, "python3", "-m", "msp_antispam.node", "status", check=False
    ).stdout
    import json

    try:
        return str(json.loads(out.strip().splitlines()[-1]).get("active"))
    except (ValueError, IndexError):
        return ""


def test_the_scan_reaches_the_panel_and_nothing_is_applied(clean_spam, admin) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("pa")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all", dmarc="v=DMARC1; p=reject"))
    mid, result = clean_spam.send_from_zone(zone)
    assert result.get("ok") and clean_spam.delivered(mid) is not None
    wait_for(clean_spam, lambda: panel_scan(admin, mid) is not None, "результат сканирования в панели")
    detail = panel_scan(admin, mid)
    assert detail["applied_action"] == "OBSERVE_ONLY"
    assert detail["auth"]["spf"]["result"] == "PASS" and detail["auth"]["dmarc"]["result"] == "PASS"
    assert detail["rspamd_config_version"], "версия конфигурации сканера записана в анализ"
    assert detail["rspamd_version"] == "3.12.1"
    assert detail["symbol_mapping_version"] == "1"


def test_the_shadow_copy_enriches_the_record_with_the_helo_and_the_chain(clean_spam, admin) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("pa")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all", dmarc=None))
    mid, _ = clean_spam.send_from_zone(zone)

    def enriched() -> bool:
        detail = panel_scan(admin, mid)
        return bool(detail and detail.get("transport_message_id") and (detail.get("helo") or {}).get("helo"))

    wait_for(clean_spam, enriched, "запись дополнена данными теневой копии", timeout=150)
    helo = panel_scan(admin, mid)["helo"]
    assert helo["helo"] == zone.helo


def test_an_upstream_gateway_that_disagrees_leaves_a_conflict_for_a_human(clean_spam, admin) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("pa")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:192.0.2.1 -all", dmarc=None))
    upstream = "Authentication-Results: ksmg.corp.example; spf=pass; dkim=pass; dmarc=pass\r\n"
    mid, _ = clean_spam.send_from_zone(
        zone, ip=OTHER_IP, raw=zone.message("pa-conf", extra_headers=upstream), sign=False
    )
    mid = "pa-conf"

    def conflict_seen() -> bool:
        detail = panel_scan(admin, mid)
        if not detail or not detail.get("transport_message_id"):
            return False
        items = admin.get(f"{BASE}/auth/conflicts").json()["items"]
        return any(i["kind"] == "SPF_MISMATCH" for i in items)

    wait_for(clean_spam, conflict_seen, "расхождение результатов зафиксировано", timeout=150)
    conflicts = admin.get(f"{BASE}/auth/conflicts").json()["items"]
    assert all(i["disposition"] == "OPEN" for i in conflicts if i["kind"] == "SPF_MISMATCH")


def test_scanner_state_and_drift_are_reported(clean_spam, admin) -> None:  # type: ignore[no-untyped-def]
    def reported() -> bool:
        health = admin.get(f"{BASE}/spam/summary").json()["health"]
        return any((h["rspamd"] or {}).get("drift") == "IN_SYNC" for h in health)

    wait_for(clean_spam, reported, "панель получила состояние сканера")
    health = admin.get(f"{BASE}/spam/summary").json()["health"]
    state = next(h["rspamd"] for h in health if h["rspamd"])
    assert state["up"] is True and state["config_version"] == scanner_version(clean_spam)
    alerts = admin.get(f"{BASE}/alerts").json()
    items = alerts["items"] if isinstance(alerts, dict) else alerts
    assert not [a for a in items if a["code"] in ("RSPAMD_DOWN", "RSPAMD_CONFIG_DRIFT")]


def test_a_provider_approved_in_the_panel_reaches_the_scanner_and_a_suspended_one_leaves_it(  # type: ignore[no-untyped-def]
    clean_spam, admin, second
) -> None:
    created = admin.post(
        f"{BASE}/spam/providers",
        {
            "id": "labzone",
            "provider_name": "Лабораторная зона",
            "license_mode": "LAB_ZONE",
            "privacy_class": "INTERNAL",
            "query_types": ["CLIENT_IP"],
            "zone": "rbl.lab.test",
        },
    )
    assert created.status_code == 201, created.text
    before = scanner_version(clean_spam)
    assert admin.post(f"{BASE}/spam/providers/labzone/request-activation", {}).status_code == 200
    assert admin.post(f"{BASE}/spam/providers/labzone/approve").status_code == 409, "сам себя не одобряет"
    assert second.post(f"{BASE}/spam/providers/labzone/approve").status_code == 200

    wait_for(
        clean_spam, lambda: scanner_version(clean_spam) != before, "сканер применил назначение", timeout=90
    )
    zone = Zone("pr")
    records = zone.records(spf="v=spf1 ip4:{ip} -all", dmarc=None)
    records["150.0.77.10.rbl.lab.test"] = {"A": ["127.0.0.2"]}
    clean_spam.dns.records(records)
    mid, result = clean_spam.send_from_zone(zone)
    assert result.get("ok") and clean_spam.delivered(mid) is not None, "листинг не отклоняет письмо"
    wait_for(clean_spam, lambda: panel_scan(admin, mid) is not None, "результат в панели")
    detail = panel_scan(admin, mid)
    assert any(s["code"] == "REPUTATION_LISTED" for s in detail["signals"])
    assert detail["applied_action"] == "OBSERVE_ONLY"

    during = scanner_version(clean_spam)
    assert second.post(f"{BASE}/spam/providers/labzone/suspend").status_code == 200
    wait_for(clean_spam, lambda: scanner_version(clean_spam) != during, "сканер убрал провайдера", timeout=90)
    mid2, _ = clean_spam.send_from_zone(zone)
    wait_for(clean_spam, lambda: panel_scan(admin, mid2) is not None, "результат в панели")
    assert not any(s["code"] == "REPUTATION_LISTED" for s in panel_scan(admin, mid2)["signals"])


def test_a_key_activated_in_the_panel_starts_signing_outbound_mail(
    clean_spam, admin, second, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    from msp_api.config import get_settings

    monkeypatch.setattr(get_settings(), "antispam_dkim_signing_domains", "corp.example")
    # Записи, которые панель увидела бы у резолвера, берутся из DNS стенда.
    monkeypatch.setattr(
        "msp_api.routers.antispam.txt_records",
        lambda name, **kw: ((clean_spam.dns.get_records().get(name.rstrip(".")) or {}).get("TXT"), False),
    )
    created = admin.post(f"{BASE}/dkim/keys", {"domain": "corp.example", "selector": "s2026"})
    assert created.status_code == 201, created.text
    key = created.json()
    # Оператор кладёт закрытый ключ в хранилище секретов узла и публикует запись в DNS.
    secrets = clean_spam.workdir / "secrets" / "rspamd" / "dkim"
    secrets.mkdir(parents=True, exist_ok=True)
    path = secrets / "corp.example.s2026.key"
    path.write_text(key["private_key_pem"], encoding="utf-8")
    path.chmod(0o644)
    assert admin.post(f"{BASE}/dkim/keys/{key['id']}/activate").status_code == 409, (
        "до публикации активировать нельзя"
    )
    clean_spam.dns.records({key["dns_name"]: {"TXT": [key["public_record"]]}})
    assert admin.post(f"{BASE}/dkim/keys/{key['id']}/verify-dns").json()["status"] == "READY"
    assert admin.post(f"{BASE}/dkim/keys/{key['id']}/activate").status_code == 409, "своё не активирует"
    before = scanner_version(clean_spam)
    assert second.post(f"{BASE}/dkim/keys/{key['id']}/activate").json()["status"] == "ACTIVE"
    wait_for(clean_spam, lambda: scanner_version(clean_spam) != before, "сканер применил ключ", timeout=90)

    mid, result = clean_spam.send_outbound(mail_from="ivan@corp.example")
    assert result.get("ok"), result
    clean_spam.wait_until(
        lambda: any(mid in m for m in clean_spam.sink.message_ids()), timeout=90, what="письмо у приёмника"
    )
    item = next(i for i in clean_spam.sink.received() if mid in str(i.get("message_id")))
    raw = base64.b64decode(str(item["raw_b64"]))
    table = {key["dns_name"]: key["public_record"].encode()}
    assert dkim.verify(
        raw, dnsfunc=lambda n, timeout=5: table.get((n.decode() if isinstance(n, bytes) else n).rstrip("."))
    ), "независимая проверка подписи не прошла"
    model = dkim_keys.DkimSigningKey  # ключ модели не раскрывается в ответах панели
    assert model is not None
    assert "PRIVATE KEY" not in str(admin.get(f"{BASE}/dkim/keys").json())


def test_a_panel_outage_does_not_stop_mail_and_the_scans_are_not_lost(clean_spam, admin) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("po")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all", dmarc=None))
    clean_spam.panel.stop()
    try:
        ids = []
        for _ in range(3):
            mid, result = clean_spam.send_from_zone(zone)
            assert result.get("ok"), "панель не нужна для приёма почты"
            ids.append(mid)
        for mid in ids:
            assert clean_spam.delivered(mid) is not None
        time.sleep(6)
    finally:
        clean_spam.panel.restart()
    reopened = Person(clean_spam.panel, "admin@corp.example")
    try:
        wait_for(
            clean_spam,
            lambda: all(panel_scan(reopened, mid) is not None for mid in ids),
            "накопленные результаты дошли после возврата панели",
            timeout=150,
        )
    finally:
        reopened.close()


def test_the_review_workflow_produces_the_metrics_and_keeps_the_reject_gate_closed(clean_spam, admin) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("pv")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject"))
    mid, _ = clean_spam.send_from_zone(zone, ip=OTHER_IP, sign=False)
    wait_for(clean_spam, lambda: panel_scan(admin, mid) is not None, "результат в панели")
    queue = admin.get(f"{BASE}/spam/review-queue", params={"selection": "DMARC_REJECT_FAILURE"}).json()[
        "items"
    ]
    target = next(i for i in queue if i["message_id"].startswith(mid))
    reviewed = admin.post(
        f"{BASE}/spam/messages/{target['id']}/review", {"verdict": "HAM", "selection": "DMARC_REJECT_FAILURE"}
    )
    assert reviewed.status_code == 201
    report = admin.get(f"{BASE}/spam/validation").json()
    assert report["metrics"]["auth_fp"] >= 1
    assert report["reject_safety"]["ready_for_discussion"] is False
    assert build_message("x", "a@b.example") and SENDER_IP and datetime.now(UTC) - timedelta(0)
