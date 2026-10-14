"""Модель топологии и генератор конфигурации (ТЗ 1.1 §13, §22, §29, §39, §64).

Два свойства, на которых стоит безопасность шлюза, и оба проверяются здесь:

* небезопасное состояние невыразимо в модели — нет поля, которым его можно было бы выставить;
* то, что сгенерировано, не может содержать директивы, которой генератор не писал.
"""

from __future__ import annotations

import pytest
from msp_gateway import render as render_module
from msp_gateway.bundle import MAIN_CF_PARAMETERS
from msp_gateway.render import Recipient, RenderError, render
from msp_gateway.spec import (
    Backpressure,
    DeploymentMode,
    Direction,
    GatewaySpec,
    InboundListener,
    InternalListener,
    InternalOwnedPolicy,
    Limits,
    Outbound,
    OutboundMode,
    RelayDomain,
    Route,
    Target,
    TlsPolicy,
    TlsProfile,
)
from msp_gateway.validation import ConfigValueError
from pydantic import ValidationError

REFUSED = (ValidationError, ConfigValueError)


def make_spec(**overrides: object) -> GatewaySpec:
    base: dict[str, object] = {
        "hostname": "gw.lab.example",
        "relay_domains": (RelayDomain(domain="corp.example", route="exchange"),),
        "routes": (
            Route(
                name="exchange",
                targets=(
                    Target(host="ex1", port=2526, priority=10),
                    Target(host="ex2", port=2526, priority=20),
                ),
            ),
        ),
        "internal": InternalListener(trusted_networks=("10.77.0.64/26",)),
        "outbound": Outbound(mode=OutboundMode.SINK, host="sink", port=2527),
    }
    base.update(overrides)
    return GatewaySpec(**base)  # type: ignore[arg-type]


def text(config: object, name: str) -> str:
    return config.files[name].decode()  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------------------------
# Небезопасное невыразимо
# ---------------------------------------------------------------------------------------------
class TestUnsafeStatesCannotBeExpressed:
    def test_a_typo_in_a_security_setting_is_an_error_not_a_silent_default(self) -> None:
        """Опечатка «trusted_netwroks» иначе давала бы шлюз без доверенных сетей, выглядящий настроенным."""
        with pytest.raises(REFUSED):
            InternalListener(trusted_netwroks=("10.0.0.0/8",))  # type: ignore[call-arg]

    def test_there_is_no_tls_policy_that_encrypts_without_verifying(self) -> None:
        """Шифрование без проверки защищает от пассивного наблюдателя, но не от подмены."""
        assert {p.value for p in TlsPolicy} == {"NONE", "OPPORTUNISTIC", "VERIFY"}

    def test_the_whole_internet_cannot_be_a_trusted_network(self) -> None:
        with pytest.raises(REFUSED):
            InternalListener(trusted_networks=("0.0.0.0/0",))

    def test_an_enabled_internal_listener_needs_sources(self) -> None:
        """Иначе шлюз либо недоступен для Exchange, либо (при ошибке генерации) открыт всем."""
        with pytest.raises(REFUSED):
            InternalListener(enabled=True, trusted_networks=())

    def test_internet_delivery_needs_an_explicit_acknowledgement(self) -> None:
        with pytest.raises(REFUSED):
            Outbound(mode=OutboundMode.INTERNET)
        assert Outbound(mode=OutboundMode.INTERNET, internet_delivery_acknowledged=True)

    def test_outbound_is_disabled_unless_chosen(self) -> None:
        assert Outbound().mode is OutboundMode.DISABLED

    @pytest.mark.parametrize("mode", [OutboundMode.SINK, OutboundMode.UPSTREAM])
    def test_a_sink_or_upstream_needs_an_address(self, mode: OutboundMode) -> None:
        with pytest.raises(REFUSED):
            Outbound(mode=mode)

    def test_a_loop_policy_rejects_by_default(self) -> None:
        assert (
            InternalListener(trusted_networks=("10.0.0.0/8",)).owned_domain_policy
            is InternalOwnedPolicy.REJECT_LOOP
        )


# ---------------------------------------------------------------------------------------------
# Перекрёстные проверки
# ---------------------------------------------------------------------------------------------
class TestCrossChecks:
    def test_a_domain_pointing_at_a_missing_route_is_refused(self) -> None:
        with pytest.raises(REFUSED):
            make_spec(relay_domains=(RelayDomain(domain="corp.example", route="nope"),))

    def test_an_inbound_domain_needs_a_route(self) -> None:
        with pytest.raises(REFUSED):
            make_spec(relay_domains=(RelayDomain(domain="corp.example"),))

    def test_a_duplicate_domain_is_refused(self) -> None:
        with pytest.raises(REFUSED):
            make_spec(
                relay_domains=(
                    RelayDomain(domain="corp.example", route="exchange"),
                    RelayDomain(domain="Corp.Example", route="exchange"),
                )
            )

    def test_a_target_pointing_at_the_gateway_itself_is_a_loop(self) -> None:
        """MSP → Exchange → MSP: самая простая петля — маршрут на собственный слушатель."""
        with pytest.raises(REFUSED):
            make_spec(routes=(Route(name="exchange", targets=(Target(host="gw.lab.example", port=25),)),))

    def test_a_target_on_localhost_is_a_loop(self) -> None:
        with pytest.raises(REFUSED):
            make_spec(routes=(Route(name="exchange", targets=(Target(host="localhost", port=2525),)),))

    def test_targets_on_other_hosts_are_fine(self) -> None:
        assert make_spec()

    def test_duplicate_priorities_make_the_fallback_order_undefined(self) -> None:
        with pytest.raises(REFUSED):
            Route(name="r", targets=(Target(host="a", priority=10), Target(host="b", priority=10)))

    def test_a_route_with_every_target_disabled_is_refused(self) -> None:
        with pytest.raises(REFUSED):
            Route(name="r", targets=(Target(host="a", enabled=False),))

    def test_fallback_targets_share_one_tls_policy(self) -> None:
        """Запасные цели делят настройки TLS транспорта: иначе запасной получит политику основного."""
        with pytest.raises(REFUSED):
            Route(
                name="r",
                targets=(
                    Target(host="a", priority=1, tls_policy=TlsPolicy.VERIFY),
                    Target(host="b", priority=2, tls_policy=TlsPolicy.OPPORTUNISTIC),
                ),
            )

    def test_the_required_profile_forbids_unverified_exchange_routes(self) -> None:
        with pytest.raises(REFUSED):
            make_spec(
                tls_profile=TlsProfile.REQUIRED,
                routes=(
                    Route(name="exchange", targets=(Target(host="ex1", tls_policy=TlsPolicy.OPPORTUNISTIC),)),
                ),
            )

    def test_a_pilot_requires_the_required_profile(self) -> None:
        with pytest.raises(REFUSED):
            make_spec(mode=DeploymentMode.GATEWAY_PILOT, tls_profile=TlsProfile.LAB)

    def test_outside_the_lab_queue_lifetime_is_not_short(self) -> None:
        """Короткий срок превращает кратковременный сбой Exchange в потерю почты."""
        with pytest.raises(REFUSED):
            make_spec(
                mode=DeploymentMode.GATEWAY_PILOT,
                tls_profile=TlsProfile.REQUIRED,
                maximal_queue_lifetime_seconds=600,
                routes=(Route(name="exchange", targets=(Target(host="ex1", tls_policy=TlsPolicy.VERIFY),)),),
            )

    def test_the_gateway_limit_may_not_be_below_exchanges(self) -> None:
        """Письмо, которое Exchange принял бы, а шлюз отверг, исчезает по вине промежуточного звена."""
        with pytest.raises(REFUSED):
            Limits(max_message_size=10 * 1024 * 1024, downstream_max_message_size=50 * 1024 * 1024)
        assert Limits(max_message_size=50 * 1024 * 1024, downstream_max_message_size=50 * 1024 * 1024)

    def test_backpressure_thresholds_must_be_ordered(self) -> None:
        with pytest.raises(REFUSED):
            Backpressure(disk_pressure_free_bytes=100, disk_critical_free_bytes=200)
        with pytest.raises(REFUSED):
            Backpressure(queue_pressure_messages=100, queue_critical_messages=50)

    def test_a_disabled_domain_does_not_need_a_route(self) -> None:
        assert make_spec(relay_domains=(RelayDomain(domain="corp.example", enabled=False),))

    def test_outbound_only_domains_are_not_received(self) -> None:
        spec = make_spec(
            relay_domains=(
                RelayDomain(domain="corp.example", route="exchange"),
                RelayDomain(domain="out.example", direction=Direction.OUTBOUND),
            )
        )
        assert spec.owned_domains() == ("corp.example",)


# ---------------------------------------------------------------------------------------------
# Генерация
# ---------------------------------------------------------------------------------------------
class TestRenderingIsDeterministic:
    def test_the_same_spec_gives_the_same_bytes(self) -> None:
        recipients = [Recipient("ivan@corp.example"), Recipient("olga@corp.example")]
        assert render(make_spec(), recipients).files == render(make_spec(), recipients).files

    def test_the_order_of_recipients_does_not_matter(self) -> None:
        a = [Recipient("ivan@corp.example"), Recipient("olga@corp.example")]
        assert render(make_spec(), a).checksum == render(make_spec(), list(reversed(a))).checksum

    def test_any_change_of_meaning_changes_the_checksum(self) -> None:
        """На этом держится обнаружение дрейфа: сумма — отпечаток смысла, а не текста."""
        base = render(make_spec()).checksum
        assert render(make_spec(hopcount_limit=21)).checksum != base
        assert render(make_spec(), [Recipient("x@corp.example")]).checksum != base
        assert render(make_spec(limits=Limits(max_recipients=7))).checksum != base

    def test_the_version_is_not_part_of_the_meaning(self) -> None:
        """Одна и та же конфигурация под разными номерами — не дрейф."""
        assert render(make_spec(), version=1).checksum == render(make_spec(), version=2).checksum


class TestTheGeneratedConfigIsSafe:
    def test_the_public_listener_has_no_trusted_networks(self) -> None:
        """На публичном порту permit_mynetworks не должен сработать, как бы ни был заполнен main.cf."""
        master = text(render(make_spec()), "master.cf")
        public = master.split("2525 inet")[0].split("25 inet")[1]
        assert "-o mynetworks=\n" in public
        assert "permit_mynetworks" not in public

    def test_the_public_listener_only_relays_to_owned_destinations(self) -> None:
        master = text(render(make_spec()), "master.cf")
        public = master.split("2525 inet")[0].split("25 inet")[1]
        assert "smtpd_relay_restrictions=reject_unauth_destination" in public

    def test_the_internal_listener_requires_starttls_and_rejects_strangers_at_connect(self) -> None:
        master = text(render(make_spec()), "master.cf")
        internal = master.split("2525 inet")[1].split("pickup unix")[0]
        assert "smtpd_tls_security_level=encrypt" in internal
        assert "smtpd_delay_reject=no" in internal
        assert "mynetworks=10.77.0.64/26" in internal

    def test_no_listener_trusts_everyone(self) -> None:
        for name in ("main.cf", "master.cf"):
            body = text(render(make_spec()), name)
            assert "0.0.0.0/0" not in body
            assert "mynetworks = 0.0.0.0" not in body

    def test_smtp_smuggling_protection_is_on(self) -> None:
        """Голый LF не нормализуется, а отвергается (ТЗ §63)."""
        assert "smtpd_forbid_bare_newline = reject" in text(render(make_spec()), "main.cf")

    def test_the_banner_does_not_name_the_version(self) -> None:
        assert "smtpd_banner = $myhostname ESMTP" in text(render(make_spec()), "main.cf")

    def test_local_delivery_is_disabled(self) -> None:
        main = text(render(make_spec()), "main.cf")
        assert "mydestination =\n" in main
        assert "local_transport = error:" in main

    def test_unknown_recipients_are_rejected_explicitly_so_freshness_can_come_first(self) -> None:
        main = text(render(make_spec()), "main.cf")
        assert "smtpd_reject_unlisted_recipient = no" in main
        assert "reject_unlisted_recipient" in main

    def test_a_disabled_outbound_has_no_outbound_transport_and_errors_by_default(self) -> None:
        config = render(make_spec(outbound=Outbound()))
        assert "default_transport = error:5.7.1" in text(config, "main.cf")
        assert "msp-outbound unix" not in text(config, "master.cf")

    def test_a_disabled_outbound_stops_relay_for_trusted_sources(self) -> None:
        """Отказ при приёме, а не при доставке: иначе шлюз принял бы письмо и потом разослал уведомление."""
        master = text(render(make_spec(outbound=Outbound())), "master.cf")
        assert "smtpd_relay_restrictions=reject_unauth_destination" in master.split("2525 inet")[1]

    def test_a_sink_route_is_in_the_default_transport(self) -> None:
        main = text(render(make_spec()), "main.cf")
        assert "default_transport = msp-outbound:[sink]:2527" in main

    def test_owned_domains_are_rejected_from_the_internal_listener_by_default(self) -> None:
        """Единственная причина, по которой Exchange отдаёт шлюзу наш же домен, — неверная маршрутизация."""
        config = render(make_spec())
        assert "REJECT 5.4.6" in text(config, "owned_domains")
        assert "owned_domains" in text(config, "main.cf")

    def test_the_loop_policy_can_be_relaxed_explicitly(self) -> None:
        config = render(
            make_spec(
                internal=InternalListener(
                    trusted_networks=("10.0.0.0/8",),
                    owned_domain_policy=InternalOwnedPolicy.ROUTE_TO_EXCHANGE,
                )
            )
        )
        assert "owned_domains" not in text(config, "main.cf").split("msp_out_recipient =")[1].splitlines()[0]

    def test_hop_count_is_limited(self) -> None:
        assert "hopcount_limit = 20" in text(render(make_spec()), "main.cf")

    def test_the_fallback_relay_follows_priority_not_declaration_order(self) -> None:
        spec = make_spec(
            routes=(
                Route(
                    name="exchange",
                    targets=(
                        Target(host="late", port=2526, priority=30),
                        Target(host="first", port=2526, priority=10),
                        Target(host="second", port=2526, priority=20),
                    ),
                ),
            )
        )
        config = render(spec)
        assert "corp.example msp-r-exchange:[first]:2526" in text(config, "transport")
        assert "smtp_fallback_relay=[second]:2526,[late]:2526" in text(config, "master.cf")

    def test_a_verified_route_checks_the_certificate_name(self) -> None:
        spec = make_spec(
            routes=(Route(name="exchange", targets=(Target(host="ex1", tls_policy=TlsPolicy.VERIFY),)),)
        )
        master = text(render(spec), "master.cf")
        assert "smtp_tls_security_level=verify" in master
        assert "smtp_tls_verify_cert_match=hostname" in master

    def test_recipient_aliases_are_in_the_map(self) -> None:
        config = render(make_spec(), [Recipient("ivan@corp.example", ("i.petrov@corp.example",))])
        recipients = text(config, "relay_recipients")
        assert "ivan@corp.example OK" in recipients
        assert "i.petrov@corp.example OK" in recipients

    def test_the_journal_gets_a_copy_per_listener(self) -> None:
        """Направление определяется слушателем, а не доменом отправителя (ТЗ §30)."""
        master = text(render(make_spec()), "master.cf")
        assert "always_bcc=journal-in@journal.msp.invalid" in master
        assert "always_bcc=journal-out@journal.msp.invalid" in master

    def test_the_journal_domain_is_in_a_zone_that_never_resolves(self) -> None:
        """Ошибка маршрутизации не должна отправить копию наружу."""
        assert render_module.JOURNAL_DOMAIN.endswith(".invalid")

    def test_the_shadow_can_be_switched_off(self) -> None:
        from msp_gateway.spec import Shadow

        master = text(render(make_spec(shadow=Shadow(enabled=False))), "master.cf")
        assert "always_bcc" not in master
        assert "msp-journal" not in text(render(make_spec(shadow=Shadow(enabled=False))), "transport")

    def test_the_journal_writer_runs_as_an_unprivileged_user_other_than_postfix(self) -> None:
        """Писатель выполняет код над письмом: у него не должно быть прав на очередь."""
        master = text(render(make_spec()), "master.cf")
        assert "user=mspjournal" in master
        assert "user=postfix" not in master

    def test_disabled_listeners_are_not_generated(self) -> None:
        master = text(render(make_spec(inbound=InboundListener(enabled=False))), "master.cf")
        assert "-o syslog_name=postfix-in" not in master

    def test_the_deployment_note_forbids_production_mx(self) -> None:
        manifest = render(make_spec()).manifest
        assert "NOT APPROVED FOR PRODUCTION MX" in str(manifest["deployment"])


class TestSecondLayerOfInjectionDefence:
    """Если шаблон когда-нибудь изменят так, что значение сможет протащить строку-директиву,
    белый список ловит это независимо от проверки полей."""

    def test_every_generated_key_is_whitelisted(self) -> None:
        main = text(render(make_spec()), "main.cf")
        for line in main.splitlines():
            if line and not line.startswith("#"):
                assert line.split(" =")[0] in MAIN_CF_PARAMETERS

    def test_an_unknown_directive_is_caught_even_if_the_field_check_is_bypassed(self) -> None:
        with pytest.raises(RenderError):
            render_module._assert_whitelisted("myhostname = a\nmynetworks_style = host\n")

    def test_an_injected_line_is_caught(self) -> None:
        with pytest.raises(RenderError):
            render_module._assert_whitelisted("myhostname = a\nrelay_domains = x\ninjected\n")

    def test_a_carriage_return_is_caught(self) -> None:
        with pytest.raises(RenderError):
            render_module._assert_whitelisted("myhostname = a\rb\n")

    def test_the_guard_actually_runs_during_rendering(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Проверка самой проверки: если бы render её не вызывал, тесты выше ничего не значили бы."""
        calls: list[str] = []
        original = render_module._assert_whitelisted
        monkeypatch.setattr(
            render_module, "_assert_whitelisted", lambda body: (calls.append(body), original(body))[1]
        )
        render(make_spec())
        assert calls


def test_the_manifest_carries_the_backpressure_thresholds() -> None:
    """Агент судит о давлении по порогам действующей конфигурации, поэтому они обязаны в ней быть."""
    from msp_gateway.spec import Backpressure

    config = render(spec())
    assert config.manifest["backpressure"] == Backpressure().model_dump()
