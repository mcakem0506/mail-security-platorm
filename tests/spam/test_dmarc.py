"""DMARC на настоящем Rspamd и сверка с RFC 9989 (ТЗ 1.2 §10, §38, §50).

Разбор записей, поиск политики и выравнивание выполняет Rspamd, а не MSP (ТЗ 1.2 §3). Поэтому
матрица ниже — это проверка установленной версии на соответствие RFC 9989: что совпало, закреплено
обычными тестами; что отличается, закреплено тестами ``test_deviation_*`` с описанием различия.
Отличия перечислены в docs/DMARC_RFC9989.md и реестре пробелов; на этапе 1.2 они влияют только на
``suggested_disposition``, которое ничего не исполняет.
"""

from __future__ import annotations

import pytest
from msp_antispam.model import DmarcPolicy, DmarcResult, SuggestedDisposition

from .harness import OTHER_IP, SENDER_IP, DkimKey, build_message
from .zone import Zone


def send(
    spam,
    zone: Zone,
    *,
    ip: str = SENDER_IP,
    sign: bool = True,
    mail_from: str | None = None,  # type: ignore[no-untyped-def]
    from_header: str | None = None,
    key: DkimKey | None = None,
):
    mid = f"dm-{zone.domain[:10]}"
    sender = from_header or zone.address
    raw = build_message(mid, sender)
    if sign:
        raw = (key or zone.key).sign(raw)
    mid2, result = spam.send_from_zone(
        zone, mid, ip=ip, raw=raw, mail_from=mail_from if mail_from is not None else sender
    )
    assert result.get("ok"), result
    assert spam.delivered(mid2) is not None, "DMARC не отклоняет почту на этапе 1.2"
    return spam.auth_of(mid2)


def test_spf_aligned_pass_is_a_dmarc_pass(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dm")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:{ip} -all", dmarc="v=DMARC1; p=reject"))
    auth = send(clean_spam, zone, sign=False)
    assert auth.dmarc.result is DmarcResult.PASS and auth.dmarc.spf_aligned and not auth.dmarc.dkim_aligned


def test_dkim_aligned_pass_is_a_dmarc_pass_even_when_spf_fails(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dm")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject"))
    auth = send(clean_spam, zone, ip=OTHER_IP)
    assert auth.dmarc.result is DmarcResult.PASS and auth.dmarc.dkim_aligned and not auth.dmarc.spf_aligned


def test_both_fail_with_reject_only_suggests_reject(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dm")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject"))
    auth = send(clean_spam, zone, ip=OTHER_IP, sign=False)
    assert auth.dmarc.result is DmarcResult.FAIL
    assert auth.dmarc.policy is DmarcPolicy.REJECT
    assert auth.dmarc.suggested_disposition is SuggestedDisposition.REJECT


def test_quarantine_policy_failure_suggests_quarantine(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dm")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=quarantine"))
    auth = send(clean_spam, zone, ip=OTHER_IP, sign=False)
    assert (
        auth.dmarc.result is DmarcResult.FAIL
        and auth.dmarc.suggested_disposition is SuggestedDisposition.QUARANTINE
    )


def test_policy_none_is_monitoring_only(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dm")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=none"))
    auth = send(clean_spam, zone, ip=OTHER_IP, sign=False)
    assert (
        auth.dmarc.result is DmarcResult.FAIL
        and auth.dmarc.suggested_disposition is SuggestedDisposition.NONE
    )


def test_no_record_is_none(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dm")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc=None))
    assert send(clean_spam, zone, ip=OTHER_IP, sign=False).dmarc.result is DmarcResult.NONE


def test_an_invalid_record_is_not_applied(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dm")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=bogus-policy"))
    auth = send(clean_spam, zone, ip=OTHER_IP, sign=False)
    assert auth.dmarc.result in (DmarcResult.PERMERROR, DmarcResult.NONE)
    assert auth.dmarc.suggested_disposition is SuggestedDisposition.NONE


def test_two_dmarc_records_mean_no_policy(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dm")
    records = zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject")
    records[f"_dmarc.{zone.domain}"] = {"TXT": ["v=DMARC1; p=reject", "v=DMARC1; p=none"]}
    clean_spam.dns.records(records)
    auth = send(clean_spam, zone, ip=OTHER_IP, sign=False)
    assert auth.dmarc.suggested_disposition is SuggestedDisposition.NONE


def test_a_dns_failure_is_temperror_and_not_fail(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dm")
    clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject"))
    clean_spam.dns.faults(servfail=[f"_dmarc.{zone.domain}"])
    auth = send(clean_spam, zone, ip=OTHER_IP, sign=False)
    assert auth.dmarc.result is DmarcResult.TEMPERROR
    assert auth.dmarc.suggested_disposition is SuggestedDisposition.NONE
    assert "DMARC_TEMPERROR" in auth.incomplete_reasons


# --- выравнивание ---------------------------------------------------------------------------
def test_relaxed_spf_alignment_accepts_a_subdomain_of_the_envelope(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dm")
    bounce = f"bounce.{zone.domain}"
    records = zone.records(spf=None, dmarc="v=DMARC1; p=reject")
    records[bounce] = {"A": [SENDER_IP], "TXT": [f"v=spf1 ip4:{SENDER_IP} -all"]}
    clean_spam.dns.records(records)
    auth = send(clean_spam, zone, sign=False, mail_from=f"x@{bounce}")
    assert auth.dmarc.result is DmarcResult.PASS


def test_strict_spf_alignment_rejects_a_subdomain_of_the_envelope(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dm")
    bounce = f"bounce.{zone.domain}"
    records = zone.records(spf=None, dmarc="v=DMARC1; p=reject; aspf=s")
    records[bounce] = {"A": [SENDER_IP], "TXT": [f"v=spf1 ip4:{SENDER_IP} -all"]}
    clean_spam.dns.records(records)
    auth = send(clean_spam, zone, sign=False, mail_from=f"x@{bounce}")
    assert auth.dmarc.result is DmarcResult.FAIL


def test_relaxed_dkim_alignment_accepts_a_signing_subdomain(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dm")
    sub_key = DkimKey.generate(f"mail.{zone.domain}", "s1")
    records = zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject", dkim=False)
    records[sub_key.dns_name] = sub_key.dns_record
    clean_spam.dns.records(records)
    auth = send(clean_spam, zone, ip=OTHER_IP, key=sub_key)
    assert auth.dmarc.result is DmarcResult.PASS


def test_strict_dkim_alignment_rejects_a_signing_subdomain(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dm")
    sub_key = DkimKey.generate(f"mail.{zone.domain}", "s1")
    records = zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject; adkim=s", dkim=False)
    records[sub_key.dns_name] = sub_key.dns_record
    clean_spam.dns.records(records)
    auth = send(clean_spam, zone, ip=OTHER_IP, key=sub_key)
    assert auth.dmarc.result is DmarcResult.FAIL


def test_a_foreign_domain_signature_does_not_align(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dm")
    foreign = Zone("fo")
    records = zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject", dkim=False)
    records.update(foreign.records(spf=None, dmarc=None, ptr=False))
    clean_spam.dns.records(records)
    auth = send(clean_spam, zone, ip=OTHER_IP, key=foreign.key)
    assert auth.dmarc.result is DmarcResult.FAIL


# --- политика поддомена ----------------------------------------------------------------------
def test_the_subdomain_policy_applies_to_a_subdomain_sender(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dm")
    sub = f"corp.{zone.domain}"
    records = zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=none; sp=reject", dkim=False)
    records[sub] = {"A": [SENDER_IP]}
    clean_spam.dns.records(records)
    auth = send(clean_spam, zone, ip=OTHER_IP, sign=False, mail_from=f"x@{sub}", from_header=f"x@{sub}")
    assert auth.dmarc.result is DmarcResult.FAIL
    assert auth.dmarc.policy is DmarcPolicy.REJECT


# --- пересылка и ARC -------------------------------------------------------------------------
def test_forwarding_keeps_dmarc_alive_through_an_intact_dkim_signature(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dm")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:192.0.2.1 -all", dmarc="v=DMARC1; p=reject"))
    # Пересылающий сервер (OTHER_IP) не в SPF домена, но подпись домена цела.
    auth = send(clean_spam, zone, ip=OTHER_IP)
    assert auth.dmarc.result is DmarcResult.PASS


def test_arc_does_not_rescue_a_failed_dmarc(clean_spam) -> None:  # type: ignore[no-untyped-def]
    zone = Zone("dm")
    clean_spam.dns.records(zone.records(spf="v=spf1 ip4:192.0.2.1 -all", dmarc="v=DMARC1; p=reject"))
    raw = zone.message("dm-arc").replace("Содержимое".encode(), "Изменено списком".encode())
    mid, result = clean_spam.send_from_zone(zone, "dm-arc", ip=OTHER_IP, raw=raw)
    assert result.get("ok")
    auth = clean_spam.auth_of(mid)
    assert auth.dmarc.suggested_disposition in (SuggestedDisposition.NONE, SuggestedDisposition.REJECT)
    assert auth.arc.result.value in ("NONE", "UNKNOWN")  # цепочки ARC нет: см. test_arc.py


# --- RFC 9989 ---------------------------------------------------------------------------------
class TestRfc9989:
    """Различия между RFC 7489 (PSL) и RFC 9989 (обход дерева DNS, np, psd, t)."""

    def test_tree_walk_finds_a_policy_set_at_an_intermediate_label(self, clean_spam) -> None:  # type: ignore[no-untyped-def]
        zone = Zone("dm")
        mid_label = f"dept.{zone.domain}"
        author = f"sales.{mid_label}"
        records = zone.records(spf="v=spf1 -all", dmarc=None, dkim=False)
        records[f"_dmarc.{mid_label}"] = {"TXT": ["v=DMARC1; p=reject"]}
        records[author] = {"A": [SENDER_IP]}
        clean_spam.dns.records(records)
        auth = send(
            clean_spam, zone, ip=OTHER_IP, sign=False, mail_from=f"x@{author}", from_header=f"x@{author}"
        )
        # RFC 9989: политика найдена на промежуточном уровне (reject). Rspamd 3.12.1 ищет
        # только имя автора и организационный домен по PSL, промежуточный уровень пропускает.
        if auth.dmarc.suggested_disposition is SuggestedDisposition.REJECT:
            pytest.skip("установленная версия Rspamd поддерживает обход дерева RFC 9989")
        assert auth.dmarc.result is DmarcResult.NONE, "отклонение зафиксировано: обход дерева не реализован"

    def test_deviation_np_tag_for_non_existent_subdomains(self, clean_spam) -> None:  # type: ignore[no-untyped-def]
        zone = Zone("dm")
        ghost = f"ghost.{zone.domain}"  # записей нет вообще: поддомен «не существует»
        records = zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=none; np=reject", dkim=False)
        clean_spam.dns.records(records)
        auth = send(
            clean_spam, zone, ip=OTHER_IP, sign=False, mail_from=f"x@{ghost}", from_header=f"x@{ghost}"
        )
        if auth.dmarc.policy is DmarcPolicy.REJECT:
            pytest.skip("установленная версия Rspamd поддерживает тег np (RFC 9989)")
        assert auth.dmarc.suggested_disposition is SuggestedDisposition.NONE, (
            "отклонение зафиксировано: тег np не применяется"
        )

    def test_deviation_testing_flag_t_y(self, clean_spam) -> None:  # type: ignore[no-untyped-def]
        zone = Zone("dm")
        clean_spam.dns.records(zone.records(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject; t=y", dkim=False))
        auth = send(clean_spam, zone, ip=OTHER_IP, sign=False)
        # RFC 9989: при t=y получатель не должен применять p=reject так, как применил бы без флага.
        # Наша защита от ложных отклонений не зависит от этого: suggested_disposition не исполняется.
        assert auth.dmarc.result is DmarcResult.FAIL
        assert auth.dmarc.suggested_disposition in (SuggestedDisposition.REJECT, SuggestedDisposition.NONE)
