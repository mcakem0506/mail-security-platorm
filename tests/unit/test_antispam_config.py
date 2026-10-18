"""Конфигурация Rspamd, провайдеры репутации и выпуск (ТЗ 1.2 §14, §15, §27, §31)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from msp_antispam.model import QueryType, RblResult
from msp_antispam.node import _FATAL_LINE
from msp_antispam.providers import (
    LicenseApproval,
    LicenseMode,
    PrivacyClass,
    ProviderStatus,
    ReputationProvider,
    mask_query_hostname,
    normalize_dnsbl_answer,
    scrub_secret,
)
from msp_antispam.rspamd_config import (
    THIRD_PARTY_MODULES,
    BayesSettings,
    ConfigError,
    DkimSigning,
    ReleaseStore,
    RspamdNodeConfig,
    SigningDomain,
    Thresholds,
    apply_release,
    drift_state,
    render,
)
from pydantic import ValidationError

NOW = datetime(2026, 10, 18, tzinfo=UTC)


def provider(**overrides: object) -> ReputationProvider:
    base: dict[str, object] = {
        "id": "labzone",
        "provider_name": "Лабораторная зона",
        "enabled": True,
        "license_mode": LicenseMode.LAB_ZONE,
        "query_types": (QueryType.CLIENT_IP,),
        "privacy_class": PrivacyClass.INTERNAL,
        "zone": "rbl.lab.test",
    }
    base.update(overrides)
    return ReputationProvider(**base)  # type: ignore[arg-type]


def config(**overrides: object) -> RspamdNodeConfig:
    base: dict[str, object] = {"authserv_id": "gw.lab.example", "nameservers": ("10.77.0.51",)}
    base.update(overrides)
    return RspamdNodeConfig(**base)  # type: ignore[arg-type]


class TestLicenceGate:
    def test_a_public_list_without_approval_is_disabled_by_policy_even_if_enabled(self) -> None:
        p = provider(
            license_mode=LicenseMode.PUBLIC_NONCOMMERCIAL,
            privacy_class=PrivacyClass.EXTERNAL_DNS,
            zone="zen.example.org",
        )
        assert p.enabled and p.effective_status(NOW) is ProviderStatus.DISABLED_BY_POLICY
        assert not p.is_usable(NOW)

    def test_approval_requires_who_when_and_for_what(self) -> None:
        with pytest.raises(ValidationError):
            LicenseApproval(license_approved=True)
        with pytest.raises(ValidationError):
            LicenseApproval(
                license_approved=True,
                approved_by="alice",
                approved_at=NOW,
                usage_scope="x",
                second_approver="alice",
            )

    def test_an_approved_provider_is_usable_until_the_licence_expires(self) -> None:
        approval = LicenseApproval(
            license_approved=True,
            approved_by="alice",
            second_approver="bob",
            approved_at=NOW,
            usage_scope="корпоративная почта, один узел",
            expires_at=NOW + timedelta(days=30),
        )
        p = provider(
            license_mode=LicenseMode.COMMERCIAL_LICENSED,
            privacy_class=PrivacyClass.EXTERNAL_DNS,
            approval=approval,
        )
        assert p.effective_status(NOW) is ProviderStatus.ACTIVE
        assert p.effective_status(NOW + timedelta(days=31)) is ProviderStatus.LICENSE_EXPIRED

    def test_a_disabled_provider_stays_disabled(self) -> None:
        assert provider(enabled=False).effective_status(NOW) is ProviderStatus.DISABLED

    def test_no_query_types_means_nothing_to_ask(self) -> None:
        assert not provider(query_types=()).is_usable(NOW)

    def test_exactly_one_of_zone_and_secret_file(self) -> None:
        with pytest.raises(ValidationError):
            provider(zone=None)
        with pytest.raises(ValidationError):
            provider(zone="a.example", zone_secret_file="/run/secrets/rspamd/x.inc")

    def test_hostile_ids_and_zones_are_refused(self) -> None:
        for bad in (
            {"id": "Bad Id"},
            {"id": "x;y"},
            {"zone": "a b.example"},
            {"zone": 'x".example'},
            {"zone": "no-dot"},
        ):
            with pytest.raises(ValidationError):
                provider(**bad)


class TestSecretsAreNotRevealed:
    def test_the_public_view_hides_a_secret_zone(self) -> None:
        p = provider(zone=None, zone_secret_file="/run/secrets/rspamd/rbl_priv.inc")
        view = p.public_view()
        assert view["zone"] is None and view["has_secret_zone"] is True
        assert "secrets" not in str(view) and "rbl_priv" not in str(view)

    def test_query_hostnames_of_secret_zones_are_masked(self) -> None:
        p = provider(zone=None, zone_secret_file="/run/secrets/rspamd/rbl_priv.inc")
        masked = mask_query_hostname(
            "4.3.2.1.tok3n-s3cret.zones.example", p, secret_zone="tok3n-s3cret.zones.example"
        )
        assert "tok3n" not in masked and "s3cret" not in masked

    def test_public_zones_are_not_masked(self) -> None:
        assert mask_query_hostname("4.3.2.1.rbl.lab.test", provider()) == "4.3.2.1.rbl.lab.test"

    def test_secret_text_is_scrubbed_from_errors(self) -> None:
        assert "tok3n" not in scrub_secret("query 4.3.2.1.TOK3N.zones.example failed", ["tok3n"])

    def test_a_secret_zone_never_reaches_the_generated_configuration(self) -> None:
        rendered = render(
            config(
                providers=(
                    provider(id="priv", zone=None, zone_secret_file="/run/secrets/rspamd/rbl_priv.inc"),
                )
            )
        )
        text = rendered.files["override.d/rbl.conf"].decode()
        assert "/run/secrets/rspamd/rbl_priv.inc" in text
        assert "zones.example" not in text


class TestRblAnswers:
    @pytest.mark.parametrize(
        ("answer", "error", "expected"),
        [
            ("127.0.0.2", None, RblResult.LISTED),
            (None, None, RblResult.NOT_LISTED),
            (None, "query timed out", RblResult.TEMPERROR),
            (None, "SERVFAIL", RblResult.TEMPERROR),
            (None, "NXDOMAIN", RblResult.NXDOMAIN),
            (None, "refused", RblResult.PROVIDER_ERROR),
            ("127.255.255.254", None, RblResult.PROVIDER_ERROR),
            ("10.0.0.1", None, RblResult.PROVIDER_ERROR),
        ],
    )
    def test_normalisation(self, answer: str | None, error: str | None, expected: RblResult) -> None:
        assert normalize_dnsbl_answer(answer, error) is expected

    def test_disabled_lookup(self) -> None:
        assert normalize_dnsbl_answer("127.0.0.2", lookup_enabled=False) is RblResult.DISABLED


class TestRenderedConfiguration:
    def test_every_third_party_module_is_off_by_default(self) -> None:
        files = render(config()).files
        for name in THIRD_PARTY_MODULES:
            assert b"enabled = false;" in files[f"local.d/{name}.conf"], name

    def test_unapproved_providers_produce_no_dns_rule(self) -> None:
        p = provider(
            license_mode=LicenseMode.PUBLIC_NONCOMMERCIAL,
            privacy_class=PrivacyClass.EXTERNAL_DNS,
            zone="zen.example.org",
        )
        text = render(config(providers=(p,))).files["override.d/rbl.conf"].decode()
        assert "zen.example.org" not in text

    def test_approved_provider_query_types_are_enabled_one_by_one(self) -> None:
        p = provider(query_types=(QueryType.CLIENT_IP, QueryType.SENDER_DOMAIN))
        text = render(config(providers=(p,))).files["override.d/rbl.conf"].decode()
        assert "MSP_RBL_LABZONE_CLIENT_IP" in text and "MSP_RBL_LABZONE_SENDER_DOMAIN" in text
        assert "MSP_RBL_LABZONE_HELO" not in text

    def test_both_directions_have_their_own_proxy_and_settings(self) -> None:
        files = render(config()).files
        assert b'settings_id = "msp_inbound"' in files["local.d/worker-proxy-inbound.inc"]
        assert b'settings_id = "msp_outbound"' in files["local.d/worker-proxy-outbound.inc"]
        settings = files["local.d/settings.conf"].decode()
        assert "MSP_DIRECTION_INBOUND" in settings and "MSP_DIRECTION_OUTBOUND" in settings

    def test_milter_proxies_are_fail_open_and_do_not_discard_or_quarantine(self) -> None:
        for name in ("worker-proxy-inbound.inc", "worker-proxy-outbound.inc"):
            text = render(config()).files[f"local.d/{name}"].decode()
            assert "discard_on_reject = false" in text and "quarantine_on_reject = false" in text

    def test_no_scanner_headers_with_score_or_topology_are_published(self) -> None:
        text = render(config()).files["local.d/milter_headers.conf"].decode()
        assert "extended_spam_headers = false" in text
        assert "x-spamd-result" not in text.lower().replace('"x-spamd-result" = 0', "")
        assert "X-MSP-Scan-ID" in text

    def test_forged_scanner_headers_are_removed_at_the_border(self) -> None:
        text = render(config()).files["local.d/milter_headers.conf"].decode()
        for name in ("X-Spamd-Result", "X-Spam-Status", "X-Spam-Level", "X-Rspamd-Score"):
            assert f'"{name}" = 0' in text

    def test_private_networks_are_not_local_by_default(self) -> None:
        override = render(config()).files["override.d/options.inc"].decode()
        assert "10.0.0.0/8" not in override and "192.168" not in override
        assert '"127.0.0.0/8"' in override

    def test_the_controller_is_loopback_only_and_the_password_is_from_a_secret(self) -> None:
        text = render(config()).files["local.d/worker-controller.inc"].decode()
        assert 'secure_ip = "127.0.0.1"' in text and ".include(try=false)" in text
        assert "password =" not in text

    def test_dmarc_actions_and_reports_are_off(self) -> None:
        text = render(config()).files["local.d/dmarc.conf"].decode()
        assert "enabled = false" in text and "actions = {}" in text

    def test_bayes_is_off_without_training_and_autolearn_is_never_default(self) -> None:
        text = render(config()).files["local.d/statistic.conf"].decode()
        assert "enabled = false" in text and "autolearn = false" in text
        on = (
            render(config(redis={"host": "redis", "port": 6379}, bayes=BayesSettings(enabled=True)))
            .files["local.d/statistic.conf"]
            .decode()
        )
        assert "autolearn = false" in on and "min_learns = 200" in on

    def test_bayes_requires_a_hundred_samples_floor_and_redis(self) -> None:
        with pytest.raises(ValidationError):
            BayesSettings(enabled=True, min_learns=10)
        with pytest.raises((ConfigError, ValidationError)):
            config(bayes=BayesSettings(enabled=True))

    def test_greylisting_is_disabled_unless_asked(self) -> None:
        assert b"enabled = false" in render(config()).files["local.d/greylist.conf"]
        assert (
            b"enabled = true"
            in render(config(redis={"host": "redis"}, greylisting=True)).files["local.d/greylist.conf"]
        )

    def test_no_arbitrary_lua_or_ucl_can_come_from_the_model(self) -> None:
        for bad in ('x"; evil = 1; "', "a\nb", "a b"):
            with pytest.raises((ConfigError, ValidationError)):
                config(authserv_id=bad)
        with pytest.raises((ConfigError, ValidationError)):
            config(exporter_host="127.0.0.1\nrules {}")
        with pytest.raises(ValidationError):
            RspamdNodeConfig(authserv_id="gw.lab.example", lua="os.execute('x')")  # type: ignore[call-arg]

    def test_the_only_lua_is_the_reviewed_file_in_the_package(self) -> None:
        files = render(config()).files
        lua = [name for name in files if name.endswith(".lua")]
        assert lua == ["rspamd.local.lua"]
        text = files["rspamd.local.lua"].decode()
        for forbidden in ("os.execute", "io.popen", "io.open", 'require "socket"', "loadstring", "dofile"):
            assert forbidden not in text

    def test_the_checksum_follows_the_content(self) -> None:
        a, b = render(config()), render(config())
        assert a.checksum == b.checksum
        assert render(config(thresholds=Thresholds(reject=20))).checksum != a.checksum


class TestDkimSigningConfig:
    def sign(self, **overrides: object) -> DkimSigning:
        base: dict[str, object] = {
            "enabled": True,
            "sign_networks": ("10.77.0.64/26",),
            "domains": (
                SigningDomain(
                    domain="lab.example",
                    selector="s1",
                    private_key_file="/run/secrets/rspamd/dkim/lab.example.s1.key",
                ),
            ),
        }
        base.update(overrides)
        return DkimSigning(**base)  # type: ignore[arg-type]

    def test_only_trusted_networks_and_listed_domains_are_signed(self) -> None:
        files = render(config(dkim_signing=self.sign())).files
        conf = files["local.d/dkim_signing.conf"].decode()
        assert 'sign_networks = ["10.77.0.64/26"]' in conf
        assert "sign_authenticated = false" in conf and "sign_inbound = false" in conf
        assert "allow_hdrfrom_mismatch = false" in conf and "allow_hdrfrom_multiple = false" in conf
        assert "try_fallback = false" in conf
        assert files["maps.d/dkim_selectors.map"].decode() == "lab.example s1\n"

    def test_the_private_key_is_a_reference_not_content(self) -> None:
        files = render(config(dkim_signing=self.sign())).files
        assert (
            files["maps.d/dkim_keys.map"].decode()
            == "lab.example /run/secrets/rspamd/dkim/lab.example.s1.key\n"
        )
        assert all(b"PRIVATE KEY" not in blob for blob in files.values())

    def test_signing_without_trusted_networks_is_refused(self) -> None:
        with pytest.raises((ConfigError, ValidationError)):
            self.sign(sign_networks=())

    def test_an_everything_network_is_refused(self) -> None:
        for bad in ("0.0.0.0/0", "::/0", "10.0.0.0/0"):
            with pytest.raises((ConfigError, ValidationError)):
                self.sign(sign_networks=(bad,))

    def test_the_inbound_direction_is_not_signed(self) -> None:
        settings = render(config(dkim_signing=self.sign())).files["local.d/settings.conf"].decode()
        inbound = next(line for line in settings.splitlines() if line.startswith("msp_inbound"))
        assert 'symbols_disabled = ["DKIM_SIGNED"]' in inbound

    def test_disabled_by_default(self) -> None:
        assert render(config()).files["local.d/dkim_signing.conf"] == b"enabled = false;\n"


def _symlinks_supported() -> bool:
    """Узел работает на Linux. На Windows без особых прав ссылку не создать (WinError 1314) —
    свойство машины разработчика; в CI (Linux) условие ложно, и тесты выполняются."""
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        try:
            os.symlink("target", os.path.join(directory, "link"))
        except OSError:
            return False
    return True


@pytest.mark.skipif(
    not _symlinks_supported(), reason="символические ссылки недоступны; проверяется в CI на Linux"
)
class TestRelease:
    def run(self, tmp_path: Path, cfg: RspamdNodeConfig, *, configtest_ok: bool = True, healthy: bool = True):  # type: ignore[no-untyped-def]
        store = ReleaseStore(tmp_path)
        reloads: list[str] = []
        outcome = apply_release(
            store,
            cfg,
            configtest=lambda staged: (configtest_ok, "syntax OK" if configtest_ok else "syntax BAD"),
            reload=lambda: reloads.append(str(store.active_version())),
            healthcheck=lambda: healthy,
        )
        return store, outcome, reloads

    def test_a_good_release_becomes_active_and_is_intact(self, tmp_path: Path) -> None:
        store, outcome, reloads = self.run(tmp_path, config())
        assert outcome.outcome == "ACTIVE" and store.active_version() == outcome.config_version
        assert store.verify(outcome.config_version) and reloads

    def test_a_release_that_fails_configtest_is_never_activated(self, tmp_path: Path) -> None:
        store, outcome, reloads = self.run(tmp_path, config(), configtest_ok=False)
        assert outcome.outcome == "REJECTED" and store.active_version() is None and not reloads

    def test_an_unhealthy_release_is_rolled_back(self, tmp_path: Path) -> None:
        _, first, _ = self.run(tmp_path, config())
        again = ReleaseStore(tmp_path)
        outcome = apply_release(
            again,
            config(thresholds=Thresholds(reject=20)),
            configtest=lambda staged: (True, "syntax OK"),
            reload=lambda: None,
            healthcheck=lambda: False,
        )
        assert outcome.outcome == "ROLLED_BACK"
        assert again.active_version() == first.config_version

    def test_a_tampered_release_fails_verification(self, tmp_path: Path) -> None:
        store, outcome, _ = self.run(tmp_path, config())
        (store.releases / outcome.config_version / "local.d" / "actions.conf").write_text(
            "reject = 0;\n", encoding="utf-8"
        )
        assert not store.verify(outcome.config_version)

    def test_drift_states(self) -> None:
        assert drift_state("a", "a") == "IN_SYNC"
        assert drift_state("a", "b") == "DRIFTED"
        assert drift_state(None, "b") == "UNKNOWN" and drift_state("a", None) == "UNKNOWN"

    def test_scanner_init_failures_count_as_a_failed_configtest(self) -> None:
        for line in (
            "init of /usr/share/rspamd/plugins/dmarc.lua failed: attempt to index field",
            "cannot register delayed dependency ARC_SIGNED -> DMARC_CHECK",
            "No such formatter: foo - disabling",
        ):
            assert _FATAL_LINE.search(line), line
        assert not _FATAL_LINE.search("syntax OK")
