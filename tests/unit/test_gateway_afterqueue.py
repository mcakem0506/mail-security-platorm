"""Послеочередной шлюз в конфигурации узла (ТЗ 1.3 §11, §12, §35, §56): фильтр, повторная подача, проверка узла."""

from __future__ import annotations

import pytest
from msp_gateway.bundle import BundleError, check_master_cf
from msp_gateway.render import render_master_cf
from msp_gateway.spec import (
    AfterQueue,
    GatewaySpec,
    InboundListener,
    InternalListener,
    Outbound,
    OutboundMode,
    RelayDomain,
    Route,
    Target,
)
from pydantic import ValidationError

STATE = "/var/lib/msp/state"
CONFIG = "/var/lib/msp/config/active"


def spec(**aq: object) -> GatewaySpec:
    return GatewaySpec(
        hostname="gw.lab.example",
        relay_domains=(RelayDomain(domain="corp.example", route="exchange"),),
        routes=(Route(name="exchange", targets=(Target(host="exchange.lab.example", port=25),)),),
        inbound=InboundListener(),
        internal=InternalListener(trusted_networks=("10.77.0.64/26",)),
        outbound=Outbound(mode=OutboundMode.SINK, host="sink.lab.example", port=2527),
        afterqueue=AfterQueue(**aq) if aq else AfterQueue(),
    )


def master(s: GatewaySpec) -> str:
    return render_master_cf(s, config_dir=CONFIG, state_dir=STATE)


ON = {"enabled": True, "filter_host": "10.77.0.53", "reinject_host": "10.77.0.10"}


def test_disabled_by_default_and_nothing_is_rendered() -> None:
    text = master(spec())
    assert "content_filter" not in text and "postfix-reinject" not in text


def test_the_public_listener_gets_the_filter_and_the_internal_one_does_not_by_default() -> None:
    text = master(spec(**ON))
    inbound = text.split("\n25 inet")[0] if False else text
    assert "-o content_filter=smtp:[10.77.0.53]:10025" in inbound
    assert text.count("content_filter=smtp:[") == 1, "исходящий путь по умолчанию не фильтруется"


def test_the_outbound_filter_is_opt_in_and_uses_its_own_port() -> None:
    text = master(spec(**ON, outbound_filter_port=10027))
    assert (
        "content_filter=smtp:[10.77.0.53]:10027" in text and "content_filter=smtp:[10.77.0.53]:10025" in text
    )


def test_the_reinjection_listener_has_no_filter_no_scanner_and_trusts_only_the_filter() -> None:
    text = master(spec(**ON))
    block = text.split("10.77.0.10:10026 inet")[1].split("\n10.77.0.10:")[0].split("\nsmtp ")[0]
    for line in (
        "-o mynetworks=10.77.0.53/32",
        "-o content_filter=",
        "-o smtpd_milters=",
        "-o smtpd_client_restrictions=permit_mynetworks,reject",
        "-o smtpd_relay_restrictions=permit_mynetworks,reject",
    ):
        assert line in block, line


def test_the_rendered_master_cf_passes_the_node_whitelist() -> None:
    check_master_cf(master(spec(**ON, outbound_filter_port=10027)))


@pytest.mark.parametrize(
    "option",
    [
        "-o content_filter=smtp:evil.example:25",
        "-o content_filter=smtp:[10.0.0.1]:25;rm",
        "-o content_filter=pipe:/bin/sh",
        "-o content_filter=smtp:[10.0.0.1]:99999999",
        "-o content_filter=smtp:[not-an-ip]:10025",
    ],
)
def test_the_node_refuses_any_other_content_filter(option: str) -> None:
    text = f"smtp inet n - n - - smtpd\n  {option}\n"
    with pytest.raises(BundleError):
        check_master_cf(text)


def test_an_empty_content_filter_is_allowed_for_the_reinjection_listener() -> None:
    check_master_cf("10.0.0.1:10026 inet n - n - - smtpd\n  -o content_filter=\n")


@pytest.mark.parametrize("field", ["filter_host", "reinject_host"])
def test_hostnames_are_refused_like_milter_sockets(field: str) -> None:
    with pytest.raises(ValidationError):
        AfterQueue(**{field: "filter.lab.example"})


def test_the_listener_ports_must_differ_and_not_collide_with_smtp_listeners() -> None:
    with pytest.raises(ValueError):
        spec(**ON, filter_port=10026, reinject_port=10026)
    with pytest.raises(ValueError):
        spec(**ON, outbound_filter_port=10025)
    with pytest.raises(ValueError):
        spec(**ON, outbound_filter_port=2525, filter_port=10025)
