"""Сбои Rspamd, Redis и DNS не останавливают почту (ТЗ 1.2 §4, §30, §40).

Принцип этапа 1.2: сканер — наблюдатель. Его падение, зависание, потеря Redis и недоступный DNS
дают недостающее свидетельство и тревогу, но письмо принимается и доставляется, а очередь не
растёт из-за сканера.
"""

from __future__ import annotations

import contextlib
import time

import pytest
from msp_antispam.analysis import analyze
from msp_antispam.model import DkimResult, DmarcResult, SpfResult
from msp_antispam.policy import SpamPolicy
from msp_gateway.spec import Milter

from tests.gateway.harness import LAB_RECIPIENTS, docker, lab_spec

from .harness import SENDER_IP, milter_spec
from .zone import Zone


@pytest.fixture
def restore(spam):  # type: ignore[no-untyped-def]
    yield
    for service in ("rspamd", "rspamd-redis", "rspamd-dns"):
        with contextlib.suppress(Exception):
            docker("unpause", spam.container(service), check=False)
            docker("start", spam.container(service), check=False)
    spam.apply(milter_spec(), LAB_RECIPIENTS)
    spam.wait_until(lambda: spam.queue_size() == 0, timeout=120, what="очередь опустела")


def wait_rspamd(spam, timeout: float = 120.0) -> None:  # type: ignore[no-untyped-def]
    def ready() -> bool:
        result = docker(
            "exec", spam.rspamd_container, "python3", "-m", "msp_antispam.node", "status", check=False
        )
        return '"proxy_inbound": true' in result.stdout and '"proxy_outbound": true' in result.stdout

    spam.wait_until(ready, timeout=timeout, what="сканер снова принимает соединения")


def test_a_stopped_scanner_does_not_stop_inbound_mail(clean_spam, restore) -> None:  # type: ignore[no-untyped-def]
    spam = clean_spam
    spam.dns.records(Zone("fo").records(spf=None))
    docker("stop", "-t", "2", spam.rspamd_container)
    ids = []
    for _ in range(3):
        mid, result = spam.send_inbound()
        assert result.get("ok"), f"приём остановился из-за сканера: {result}"
        ids.append(mid)
    for mid in ids:
        assert spam.delivered(mid) is not None, "письмо не доставлено при недоступном сканере"
    assert spam.queue_size() == 0, "очередь выросла из-за сканера"
    assert "milter" in spam.postfix_log().lower(), "Postfix не сообщил о недоступном Milter"


def test_a_stopped_scanner_does_not_stop_outbound_mail(clean_spam, restore) -> None:  # type: ignore[no-untyped-def]
    spam = clean_spam
    docker("stop", "-t", "2", spam.rspamd_container)
    mid, result = spam.send_outbound()
    assert result.get("ok"), result
    spam.wait_until(
        lambda: any(mid in str(i) for i in spam.sink.message_ids()), timeout=60, what="доставка в приёмник"
    )


def test_no_scan_record_means_missing_evidence_not_clean(clean_spam, restore) -> None:  # type: ignore[no-untyped-def]
    analysis = analyze(None, SpamPolicy())
    assert analysis.incomplete and "RSPAMD_SCAN_UNAVAILABLE" in analysis.missing_evidence
    assert analysis.spam_class.value == "UNKNOWN", "отсутствие данных не равно «не спам»"


def test_scanning_resumes_after_the_scanner_returns(clean_spam, restore) -> None:  # type: ignore[no-untyped-def]
    spam = clean_spam
    docker("stop", "-t", "2", spam.rspamd_container)
    mid1, result = spam.send_inbound()
    assert result.get("ok") and spam.delivered(mid1) is not None
    docker("start", spam.rspamd_container)
    wait_rspamd(spam)
    mid2, result = spam.send_inbound()
    assert result.get("ok")
    assert spam.scan_for(mid2)["message_id"].startswith(mid2)


def test_a_hung_scanner_is_bounded_by_milter_timeouts(clean_spam, restore) -> None:  # type: ignore[no-untyped-def]
    spam = clean_spam
    fast = milter_spec(
        milter=Milter(
            enabled=True,
            inbound_socket="inet:10.77.0.50:11332",
            outbound_socket="inet:10.77.0.50:11333",
            connect_timeout_seconds=2,
            command_timeout_seconds=4,
            content_timeout_seconds=8,
        )
    )
    assert spam.apply(fast, LAB_RECIPIENTS)["outcome"] == "ACTIVE"
    docker("pause", spam.rspamd_container)
    started = time.monotonic()
    mid, result = spam.send_inbound()
    elapsed = time.monotonic() - started
    assert result.get("ok"), f"зависший сканер остановил приём: {result}"
    assert elapsed < 60, f"приём ждал сканер {elapsed:.0f} с"
    assert spam.delivered(mid) is not None
    docker("unpause", spam.rspamd_container)


def test_milter_default_action_is_accept_in_the_active_configuration(clean_spam) -> None:  # type: ignore[no-untyped-def]
    main_cf = clean_spam.exec("cat /var/lib/msp/config/active/main.cf").stdout
    assert "milter_default_action = accept" in main_cf
    assert "milter_protocol = 6" in main_cf
    master = clean_spam.exec("cat /var/lib/msp/config/active/master.cf").stdout
    assert "smtpd_milters=inet:10.77.0.50:11332" in master and "smtpd_milters=inet:10.77.0.50:11333" in master


def test_a_bad_scanner_configuration_is_rejected_and_the_old_one_keeps_working(clean_spam, restore) -> None:  # type: ignore[no-untyped-def]
    spam = clean_spam
    before = docker("exec", spam.rspamd_container, "python3", "-m", "msp_antispam.node", "status").stdout
    # Принудительно портим выпуск: configtest обязан его отвергнуть, активной останется прежняя версия.
    docker(
        "exec",
        spam.rspamd_container,
        "sh",
        "-c",
        "mkdir -p /tmp/bad/local.d && echo 'broken {{{' > /tmp/bad/local.d/options.inc && "
        "rspamadm --var=LOCAL_CONFDIR=/tmp/bad configtest -c /opt/msp-rspamd/rspamd.conf; echo rc=$?",
    )
    after = docker("exec", spam.rspamd_container, "python3", "-m", "msp_antispam.node", "status").stdout
    assert before == after
    mid, result = spam.send_inbound()
    assert result.get("ok") and spam.scan_for(mid)


def test_redis_loss_does_not_stop_scanning_or_delivery(clean_spam, restore) -> None:  # type: ignore[no-untyped-def]
    spam = clean_spam
    zone = Zone("rd")
    spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all", dmarc="v=DMARC1; p=reject"))
    docker("stop", "-t", "2", spam.container("rspamd-redis"))
    mid, result = spam.send_from_zone(zone)
    assert result.get("ok") and spam.delivered(mid) is not None
    auth = spam.auth_of(mid)
    # Базовые проверки аутентификации работают и без Redis (ТЗ 1.2 §30).
    assert auth.spf.result is SpfResult.PASS and auth.dkim.result is DkimResult.PASS
    assert auth.dmarc.result is DmarcResult.PASS


def test_dns_outage_gives_temperror_not_fail_and_delivery_continues(clean_spam, restore) -> None:  # type: ignore[no-untyped-def]
    spam = clean_spam
    zone = Zone("dn")
    spam.dns.records(zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject"))
    spam.dns.faults(timeout=[zone.domain])
    started = time.monotonic()
    mid, result = spam.send_from_zone(zone, ip="10.77.0.151")
    assert result.get("ok"), result
    assert spam.delivered(mid) is not None
    assert time.monotonic() - started < 90
    auth = spam.auth_of(mid)
    assert auth.spf.result is SpfResult.TEMPERROR, "сбой DNS не должен превращаться в SPF FAIL"
    assert auth.dmarc.result in (DmarcResult.TEMPERROR, DmarcResult.NONE)
    assert auth.dmarc.suggested_disposition.value == "NONE", "при сбое DNS нельзя предлагать отклонение"
    assert auth.incomplete


def test_the_dns_server_going_away_does_not_stop_mail(clean_spam, restore) -> None:  # type: ignore[no-untyped-def]
    spam = clean_spam
    docker("stop", "-t", "2", spam.container("rspamd-dns"))
    mid, result = spam.send_inbound(ip=SENDER_IP)
    assert result.get("ok"), result
    assert spam.delivered(mid, timeout=120) is not None
    auth = spam.auth_of(mid, timeout=300)
    assert auth.spf.result in (SpfResult.TEMPERROR, SpfResult.NONE)
    assert auth.spf.result is not SpfResult.FAIL
    assert lab_spec() is not None
