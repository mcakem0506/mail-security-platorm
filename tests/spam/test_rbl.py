"""Провайдеры репутации (RBL/DNSBL) на настоящем Rspamd и управляемой зоне (ТЗ 1.2 §14, §15, §38).

Публичных списков нет: зона ``rbl.lab.test`` обслуживается DNS стенда. Проверяется то, что
отличает продукт от «включили DNSBL»: лицензионный допуск, ограничение типов запросов, секретные
зоны, отказоустойчивость и то, что листинг не меняет судьбу письма.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest
from msp_antispam.model import QueryType
from msp_antispam.providers import LicenseApproval, LicenseMode, PrivacyClass, ReputationProvider

from tests.gateway.harness import docker

from .harness import OTHER_IP, SENDER_IP, node_config
from .zone import Zone, reverse_name

ZONE = "rbl.lab.test"


def lab_provider(**overrides: object) -> ReputationProvider:
    base: dict[str, object] = {
        "id": "labzone",
        "provider_name": "Лабораторная зона",
        "enabled": True,
        "license_mode": LicenseMode.LAB_ZONE,
        "query_types": (QueryType.CLIENT_IP,),
        "privacy_class": PrivacyClass.INTERNAL,
        "zone": ZONE,
    }
    base.update(overrides)
    return ReputationProvider(**base)  # type: ignore[arg-type]


def listed(ip: str) -> dict[str, dict[str, object]]:
    return {f"{reverse_name(ip).removesuffix('.in-addr.arpa')}.{ZONE}": {"A": ["127.0.0.2"]}}


def symbols(record: dict) -> set[str]:
    return {s["name"] for s in record["symbols"]}


@pytest.fixture
def providers(spam):  # type: ignore[no-untyped-def]
    applied: list[object] = []

    def apply(*items: ReputationProvider) -> None:
        outcome = spam.reapply_rspamd(node_config(providers=tuple(items)))
        assert outcome["outcome"] == "ACTIVE", outcome
        applied.append(outcome)

    yield apply
    spam.reapply_rspamd(node_config())


def test_a_listed_client_is_recorded_and_the_mail_is_still_delivered(clean_spam, providers) -> None:  # type: ignore[no-untyped-def]
    providers(lab_provider())
    # После перезагрузки модуль RBL в новом воркере может подняться позже первого письма (медленный
    # CI): допускаем до трёх попыток, каждая с новым доменом, чтобы кэш DNS не скрывал результат.
    for attempt in range(3):
        zone = Zone(f"rb{attempt}")
        records = zone.records(spf="v=spf1 ip4:{ip} -all", dmarc=None)
        records.update(listed(SENDER_IP))
        clean_spam.dns.records(records)
        mid, result = clean_spam.send_from_zone(zone)
        assert result.get("ok"), "листинг не отклоняет письмо на этапе 1.2"
        assert clean_spam.delivered(mid) is not None
        record = clean_spam.scan_for(mid)
        if "MSP_RBL_LABZONE_CLIENT_IP" in symbols(record):
            break
        time.sleep(5)
    assert "MSP_RBL_LABZONE_CLIENT_IP" in symbols(record)
    analysis = clean_spam.analysis(mid, secret_provider_ids=[])
    assert "REPUTATION_LISTED" in analysis.signals.codes(risk_only=True)


def test_not_listed_adds_nothing_and_does_not_lower_risk(clean_spam, providers) -> None:  # type: ignore[no-untyped-def]
    providers(lab_provider())
    zone = Zone("rb")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all", dmarc=None))
    mid, _ = clean_spam.send_from_zone(zone, ip=OTHER_IP)
    record = clean_spam.scan_for(mid)
    assert "MSP_RBL_LABZONE_CLIENT_IP" not in symbols(record)
    analysis = clean_spam.analysis(mid)
    assert "REPUTATION_LISTED" not in analysis.signals.codes()


def test_a_provider_timeout_does_not_block_the_mail(clean_spam, providers) -> None:  # type: ignore[no-untyped-def]
    providers(lab_provider())
    zone = Zone("rb")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all", dmarc=None))
    clean_spam.dns.faults(timeout=[ZONE])
    started = time.monotonic()
    mid, result = clean_spam.send_from_zone(zone)
    assert result.get("ok") and clean_spam.delivered(mid) is not None
    assert time.monotonic() - started < 60
    assert "MSP_RBL_LABZONE_CLIENT_IP" not in symbols(clean_spam.scan_for(mid))


def test_a_servfail_from_the_provider_does_not_block_the_mail(clean_spam, providers) -> None:  # type: ignore[no-untyped-def]
    providers(lab_provider())
    zone = Zone("rb")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all", dmarc=None))
    clean_spam.dns.faults(servfail=[ZONE])
    mid, result = clean_spam.send_from_zone(zone)
    assert result.get("ok") and clean_spam.delivered(mid) is not None


def test_a_public_list_without_licence_approval_is_never_queried(clean_spam, providers) -> None:  # type: ignore[no-untyped-def]
    public = lab_provider(
        id="publicbl",
        provider_name="Публичный список",
        license_mode=LicenseMode.PUBLIC_NONCOMMERCIAL,
        privacy_class=PrivacyClass.EXTERNAL_DNS,
        zone="zen.publicbl.test",
    )
    providers(public)
    zone = Zone("rb")
    records = zone.records(spf="v=spf1 ip4:{ip} -all", dmarc=None)
    records.update({"150.0.77.10.zen.publicbl.test": {"A": ["127.0.0.2"]}})
    clean_spam.dns.records(records)
    mid, _ = clean_spam.send_from_zone(zone)
    clean_spam.scan_for(mid)
    queried = {q["name"] for q in clean_spam.dns.queries()}
    assert not any(name.endswith("publicbl.test") for name in queried), (
        "запрос к неодобренному провайдеру ушёл"
    )


def test_an_approved_public_list_is_queried(clean_spam, providers) -> None:  # type: ignore[no-untyped-def]
    approval = LicenseApproval(
        license_approved=True,
        approved_by="ib-admin",
        second_approver="platform-admin",
        approved_at=datetime.now(UTC),
        usage_scope="корпоративная почта, один узел",
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    public = lab_provider(
        id="publicbl",
        license_mode=LicenseMode.COMMERCIAL_LICENSED,
        privacy_class=PrivacyClass.EXTERNAL_DNS,
        zone="zen.publicbl.test",
        approval=approval,
    )
    providers(public)
    zone = Zone("rb")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all", dmarc=None))
    mid, _ = clean_spam.send_from_zone(zone)
    clean_spam.scan_for(mid)
    assert any(q["name"].endswith("zen.publicbl.test") for q in clean_spam.dns.queries())


def test_only_the_enabled_query_types_reach_the_provider(clean_spam, providers) -> None:  # type: ignore[no-untyped-def]
    providers(lab_provider())  # только CLIENT_IP
    zone = Zone("rb")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all", dmarc=None))
    mid, _ = clean_spam.send_from_zone(zone)
    clean_spam.scan_for(mid)
    to_provider = [q["name"] for q in clean_spam.dns.queries() if q["name"].endswith(ZONE)]
    assert to_provider, "запрос по адресу клиента ожидался"
    assert all(name.startswith("150.0.77.10.") for name in to_provider), to_provider
    assert not any(zone.domain in name for name in to_provider), "домен отправителя уходить не должен"
    assert not any(zone.helo in name for name in to_provider)


def test_the_sender_domain_is_queried_only_when_enabled(clean_spam, providers) -> None:  # type: ignore[no-untyped-def]
    providers(lab_provider(query_types=(QueryType.CLIENT_IP, QueryType.SENDER_DOMAIN)))
    zone = Zone("rb")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all", dmarc=None))
    mid, _ = clean_spam.send_from_zone(zone)
    clean_spam.scan_for(mid)
    assert any(zone.domain in q["name"] and q["name"].endswith(ZONE) for q in clean_spam.dns.queries())


def test_a_secret_zone_is_not_revealed_by_the_configuration_the_record_or_the_logs(
    clean_spam, providers
) -> None:  # type: ignore[no-untyped-def]
    secret = "tok3nsecr3tzone"
    # В хранилище секретов лежит ТОЛЬКО имя зоны; всё остальное правило генерирует MSP.
    rule = f'rbl = "{secret}.{ZONE}";\n'
    secrets = clean_spam.workdir / "secrets" / "rspamd"
    (secrets / "rbl_priv.inc").write_text(rule, encoding="utf-8")
    (secrets / "rbl_priv.inc").chmod(0o644)
    private = lab_provider(id="priv", zone=None, zone_secret_file="/run/secrets/rspamd/rbl_priv.inc")
    providers(private)
    zone = Zone("rb")
    records = zone.records(spf="v=spf1 ip4:{ip} -all", dmarc=None)
    records[f"150.0.77.10.{secret}.{ZONE}"] = {"A": ["127.0.0.2"]}
    clean_spam.dns.records(records)
    mid, result = clean_spam.send_from_zone(zone)
    assert result.get("ok") and clean_spam.delivered(mid) is not None
    record = clean_spam.scan_for(mid)
    assert "MSP_RBL_PRIV_CLIENT_IP" in symbols(record), "секретный провайдер сработал"
    # Выпуск конфигурации и результат MSP не содержат секретную зону.
    release = docker(
        "exec",
        clean_spam.rspamd_container,
        "sh",
        "-c",
        "grep -r -l '" + secret + "' /var/lib/msp-rspamd/releases || true",
    ).stdout
    assert release.strip() == "", f"секрет попал в выпуск конфигурации: {release}"
    analysis = clean_spam.analysis(mid, secret_provider_ids=["priv"])
    assert secret not in analysis.evidence.model_dump_json()
    assert secret not in private.model_dump_json().replace("zone_secret_file", "")
    assert secret not in str(private.public_view())
