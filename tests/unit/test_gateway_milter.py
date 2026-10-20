"""Milter в конфигурации шлюза MSP 1.2: сбой сканера не должен останавливать транспорт (ТЗ 1.2 §4)."""

from __future__ import annotations

import pytest
from msp_gateway.bundle import BundleError, check_main_cf, check_master_cf
from msp_gateway.render import render_main_cf, render_master_cf
from msp_gateway.spec import (
    GatewaySpec,
    InboundListener,
    InternalListener,
    Milter,
    Outbound,
    OutboundMode,
    RelayDomain,
    Route,
    Target,
)
from pydantic import ValidationError

STATE = "/var/lib/msp/state"
CONFIG = "/var/lib/msp/config/active"


def spec(**milter: object) -> GatewaySpec:
    return GatewaySpec(
        hostname="gw.lab.example",
        relay_domains=(RelayDomain(domain="corp.example", route="exchange"),),
        routes=(Route(name="exchange", targets=(Target(host="exchange.lab.example", port=25),)),),
        inbound=InboundListener(),
        internal=InternalListener(trusted_networks=("10.77.0.64/26",)),
        outbound=Outbound(mode=OutboundMode.SINK, host="sink.lab.example", port=2527),
        milter=Milter(**milter) if milter else Milter(),
    )


def main_cf(s: GatewaySpec) -> str:
    return render_main_cf(s, config_dir=CONFIG, state_dir=STATE, log_file="/var/log/msp/postfix.log")


def master_cf(s: GatewaySpec) -> str:
    return render_master_cf(s, config_dir=CONFIG, state_dir=STATE)


ENABLED = {
    "enabled": True,
    "inbound_socket": "inet:10.77.0.50:11332",
    "outbound_socket": "inet:10.77.0.50:11333",
}


class TestSocketValidation:
    @pytest.mark.parametrize(
        "socket",
        ["inet:10.77.0.50:11332", "inet:127.0.0.1:11332", "inet:[::1]:11332", "unix:/run/rspamd/milter.sock"],
    )
    def test_ip_addresses_and_unix_paths_are_accepted(self, socket: str) -> None:
        Milter(enabled=True, inbound_socket=socket, outbound_socket=socket)

    @pytest.mark.parametrize(
        "socket",
        [
            "inet:rspamd:11332",  # имя: ошибка разрешения превращается в 421 для всей почты
            "inet:localhost:11332",
            "inet:10.77.0.50",
            "inet:10.77.0.50:99999",
            "inet:10.77.0.50:0",
            "inet:10.77.0.999:11332",
            "inet:10.77.0.50:11332,inet:10.77.0.51:11332",
            "inet:10.77.0.50:11332\nmynetworks = 0.0.0.0/0",
            "unix:relative/path",
            "unix:/run/../etc/passwd",
            "local:/run/x",
            "",
            "inet:10.77.0.50:11332;evil",
        ],
    )
    def test_everything_else_is_refused(self, socket: str) -> None:
        with pytest.raises((ValidationError, ValueError)):
            Milter(enabled=True, inbound_socket=socket)

    def test_the_default_action_is_not_a_setting(self) -> None:
        with pytest.raises(ValidationError):
            Milter(enabled=True, default_action="tempfail")  # type: ignore[call-arg]


class TestRendering:
    def test_disabled_by_default_and_nothing_is_emitted(self) -> None:
        s = spec()
        assert "milter" not in main_cf(s) and "milter" not in master_cf(s)

    def test_enabled_main_cf_pins_accept_and_protocol_six(self) -> None:
        text = main_cf(spec(**ENABLED))
        assert "milter_default_action = accept" in text and "milter_protocol = 6" in text
        assert "milter_command_timeout = 15s" in text

    def test_each_listener_uses_its_own_socket_and_direction_name(self) -> None:
        text = master_cf(spec(**ENABLED))
        inbound = text.split("postfix-in")[1].split("postfix-out")[0]
        outbound = text.split("postfix-out")[1]
        assert (
            "smtpd_milters=inet:10.77.0.50:11332" in inbound
            and "milter_macro_daemon_name=gw.lab.example" in inbound
        )
        assert (
            "smtpd_milters=inet:10.77.0.50:11333" in outbound
            and "milter_macro_daemon_name=gw.lab.example" in outbound
        )
        assert "11333" not in inbound and "11332" not in outbound

    def test_the_global_smtpd_milters_parameter_is_never_set(self) -> None:
        assert "smtpd_milters" not in main_cf(spec(**ENABLED))

    def test_rendered_files_pass_the_node_whitelist(self) -> None:
        s = spec(**ENABLED)
        check_main_cf(main_cf(s))
        check_master_cf(master_cf(s))


class TestNodeRefusesUnsafeMilterSettings:
    def test_tempfail_as_default_action_is_refused_even_with_a_valid_checksum(self) -> None:
        for value in ("tempfail", "reject", "quarantine"):
            with pytest.raises(BundleError):
                check_main_cf(f"milter_default_action = {value}\n")
        check_main_cf("milter_default_action = accept\n")

    def test_protocol_is_pinned(self) -> None:
        with pytest.raises(BundleError):
            check_main_cf("milter_protocol = 2\n")

    def test_global_milter_lists_stay_outside_the_whitelist(self) -> None:
        for name in ("smtpd_milters", "non_smtpd_milters", "milter_mail_macros"):
            with pytest.raises(BundleError):
                check_main_cf(f"{name} = inet:evil.example:1\n")

    @pytest.mark.parametrize(
        "option",
        [
            "-o smtpd_milters=inet:evil.example:11332",
            "-o smtpd_milters=inet:10.0.0.1:1,inet:10.0.0.2:2",
            "-o smtpd_milters=unix:../../etc/x",
            "-o milter_macro_daemon_name=bad name;x",
        ],
    )
    def test_per_listener_options_are_checked(self, option: str) -> None:
        base = "25 inet n - n - - smtpd\n"
        with pytest.raises(BundleError):
            check_master_cf(f"{base}  {option}\n")

    def test_valid_per_listener_options_pass(self) -> None:
        base = "25 inet n - n - - smtpd\n"
        check_master_cf(
            f"{base}  -o smtpd_milters=inet:10.0.0.1:11332\n  -o milter_macro_daemon_name=gw.lab.example\n"
        )


class TestPostscreenIsNotAvailable:
    """Postscreen только оценивается (ТЗ 1.2 §21): узел не примет его параметры и не сформирует их."""

    def test_node_rejects_postscreen_main_cf_parameters(self) -> None:
        for line in (
            "postscreen_greet_action = enforce",
            "postscreen_dnsbl_sites = lab.rbl.test*2",
            "postscreen_access_list = permit_mynetworks",
        ):
            with pytest.raises(BundleError):
                check_main_cf(line + "\n")

    def test_node_rejects_a_postscreen_service_in_master_cf(self) -> None:
        with pytest.raises(BundleError):
            check_master_cf("smtp inet n - n - 1 postscreen\n")

    def test_rendered_configuration_never_mentions_postscreen(self) -> None:
        s = spec()
        assert "postscreen" not in main_cf(s)
        assert "postscreen" not in render_master_cf(s, config_dir=CONFIG, state_dir=STATE)

    def test_the_spec_has_no_field_to_enable_it(self) -> None:
        with pytest.raises(ValidationError):
            GatewaySpec(
                hostname="gw.lab.example",
                relay_domains=(RelayDomain(domain="corp.example", route="exchange"),),
                routes=(Route(name="exchange", targets=(Target(host="exchange.lab.example", port=25),)),),
                inbound=InboundListener(),
                internal=InternalListener(trusted_networks=("10.77.0.64/26",)),
                outbound=Outbound(mode=OutboundMode.SINK, host="sink.lab.example", port=2527),
                postscreen_enabled=True,  # type: ignore[call-arg]
            )
