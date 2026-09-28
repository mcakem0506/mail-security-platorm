"""Hardening tests: SSRF surface, storage traversal, privacy gate, secret hygiene (ТЗ 38)."""

from __future__ import annotations

import pytest
from msp_api.services.storage import FilesystemObjectStorage, StorageError, build_key, validate_key
from msp_contracts import IOCType, TIStatus, VTMode
from msp_ti import PrivacyPolicy, ThreatIntelligenceHub, TICache
from msp_virustotal import MockVirusTotalProvider, VirusTotalConfig, VirusTotalConfigError, build_provider


class TestSsrfSurface:
    """The platform must not fetch URLs from mail by default (ТЗ 11.4, 49.5)."""

    def test_url_fetching_is_disabled_by_default(self, settings) -> None:
        assert settings.url_fetch_enabled is False

    def test_parser_performs_no_network_io(self, monkeypatch) -> None:
        """Parsing untrusted mail must not open a socket, whatever the content contains."""
        import socket

        from fixtures.corpus import BY_NAME
        from msp_mail_parser import parse_message

        def forbid(*args: object, **kwargs: object):  # type: ignore[no-untyped-def]
            raise AssertionError("the parser must not perform network I/O")

        monkeypatch.setattr(socket, "create_connection", forbid)
        monkeypatch.setattr(socket.socket, "connect", forbid)
        monkeypatch.setattr(socket, "getaddrinfo", forbid)

        for name in (
            "05_punycode_homoglyph",
            "07_fake_microsoft_login",
            "14_nested_archive",
            "15_malformed_mime",
        ):
            parsed = parse_message(BY_NAME[name].raw)
            assert parsed.sha256

    def test_domain_resolution_is_offline(self, monkeypatch) -> None:
        """The public suffix list is bundled: no DNS or HTTP lookup during domain analysis."""
        import socket

        monkeypatch.setattr(
            socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no DNS"))
        )
        from msp_mail_parser import split_domain

        assert split_domain("a.b.example.co.uk").registrable_ascii == "example.co.uk"

    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8000/api/v1/admin/audit",
            "http://[::1]:6379/",
            "http://10.0.0.1/internal",
            "http://192.168.1.1/admin",
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_FLUSHALL",
        ],
    )
    def test_internal_targets_are_parsed_but_never_fetched(self, url: str) -> None:
        """Internal and metadata endpoints are recorded as indicators, never requested."""
        from msp_mail_parser import normalize_url

        parsed = normalize_url(url)
        assert parsed.redacted  # analysable
        assert parsed.normalized  # normalised for correlation
        # Nothing in the parser can turn this into a request: it returns data only.


class TestPrivacyGate:
    @pytest.mark.parametrize(
        ("ioc_type", "value", "allowed"),
        [
            (IOCType.SHA256, "a" * 64, True),
            (IOCType.DOMAIN, "evil.test", True),
            (IOCType.DOMAIN, "corp.example", False),
            (IOCType.DOMAIN, "mail.corp.example", False),
            (IOCType.IPV4, "203.0.113.5", True),
            (IOCType.URL, "https://evil.test/", False),
            (IOCType.EMAIL, "someone@corp.example", False),
            (IOCType.EMAIL, "attacker@evil.test", False),
        ],
    )
    def test_default_policy(self, ioc_type: IOCType, value: str, allowed: bool) -> None:
        policy = PrivacyPolicy(corporate_domains=("corp.example",))
        result, reason = policy.check(ioc_type, value)
        assert result is allowed, f"{value}: {reason}"

    @pytest.mark.parametrize(
        "url",
        [
            "https://x.test/p?token=abc123",
            "https://x.test/p?session=zzz",
            "https://x.test/reset?email=user@corp.example",
            "https://x.test/?user=ivanov",
            "https://user@corp.example:pass@x.test/",
        ],
    )
    def test_urls_with_sensitive_parameters_are_blocked_even_when_urls_are_enabled(self, url: str) -> None:
        policy = PrivacyPolicy(allow_url=True, allow_url_path=True, corporate_domains=("corp.example",))
        allowed, reason = policy.check(IOCType.URL, url)
        assert allowed is False, f"{url} should be blocked"
        assert reason

    def test_host_only_sanitisation_strips_path_and_query(self) -> None:
        policy = PrivacyPolicy(allow_url=True)
        assert policy.sanitize_url("https://evil.test/login?token=x") == "https://evil.test"

    def test_blocked_lookup_is_never_reported_as_clean(self) -> None:
        hub = ThreatIntelligenceHub(
            [MockVirusTotalProvider()],
            policy=PrivacyPolicy(corporate_domains=("corp.example",)),
            cache=TICache(),
        )
        result = hub.lookup(hub.providers[0], IOCType.DOMAIN, "corp.example")
        assert result.status is TIStatus.POLICY_BLOCKED
        assert result.status is not TIStatus.NO_NEGATIVE_REPUTATION


class TestVirusTotalGate:
    def test_disabled_without_a_licence(self) -> None:
        provider = build_provider(VirusTotalConfig(mode=VTMode.DISABLED))
        health = provider.health()
        assert health.status == "disabled"
        assert "not configured" in (health.detail or "")

    def test_premium_requires_a_key(self) -> None:
        with pytest.raises(VirusTotalConfigError):
            VirusTotalConfig(mode=VTMode.PREMIUM).validate()

    def test_upload_requires_private_scanning(self) -> None:
        with pytest.raises(VirusTotalConfigError):
            VirusTotalConfig(mode=VTMode.PREMIUM, api_key="k", allow_file_upload=True).validate()

    def test_file_upload_is_refused(self) -> None:
        with pytest.raises(PermissionError):
            MockVirusTotalProvider().submit_file(b"data")

    def test_disabled_provider_returns_unavailable_not_safe(self) -> None:
        provider = build_provider(VirusTotalConfig(mode=VTMode.DISABLED))
        result = provider.lookup_domain("evil.test")
        assert result.status is TIStatus.PROVIDER_UNAVAILABLE

    def test_no_negative_reputation_is_distinct_from_safe(self) -> None:
        result = MockVirusTotalProvider().lookup_domain("ordinary.test")
        assert result.status is TIStatus.NO_NEGATIVE_REPUTATION
        assert "SAFE" not in {s.value for s in TIStatus}

    def test_api_key_never_appears_in_health_or_quota(self) -> None:
        provider = build_provider(VirusTotalConfig(mode=VTMode.PREMIUM, api_key="super-secret-key"))
        serialised = f"{provider.health().model_dump()}{provider.quota().model_dump()}"
        assert "super-secret-key" not in serialised


class TestStorageHardening:
    @pytest.mark.parametrize(
        "key",
        [
            "../../etc/passwd",
            "eml/../../../etc/shadow",
            "/absolute/path",
            "eml/org/../../../../root/.ssh/id_rsa",
            "",
            "eml/\x00null",
            "EML/UPPER",
        ],
    )
    def test_invalid_keys_are_rejected(self, key: str) -> None:
        with pytest.raises((ValueError, StorageError)):
            validate_key(key)

    def test_keys_are_derived_from_content_hashes_not_filenames(self) -> None:
        key = build_key("attachment", "b" * 64, organization_id="org-1", extension="exe")
        assert key.startswith("attachment/org-1/")
        assert key.endswith(f"{'b' * 64}.exe")

    @pytest.mark.parametrize("digest", ["not-a-hash", "", "../../x", "A" * 64])
    def test_build_key_requires_a_real_hash(self, digest: str) -> None:
        with pytest.raises(ValueError):
            build_key("eml", digest, organization_id="org-1")

    def test_unknown_category_rejected(self) -> None:
        with pytest.raises(ValueError):
            build_key("../escape", "c" * 64, organization_id="org-1")

    def test_traversal_cannot_escape_the_storage_root(self, tmp_path) -> None:
        storage = FilesystemObjectStorage(str(tmp_path))
        with pytest.raises((ValueError, StorageError)):
            storage.put("../escaped.bin", b"data")
        assert not (tmp_path.parent / "escaped.bin").exists()

    def test_organization_id_is_sanitised_into_the_key(self) -> None:
        key = build_key("eml", "d" * 64, organization_id="../../evil ORG!")
        assert ".." not in key
        assert " " not in key


class TestSecretHygiene:
    def test_public_config_exposes_no_secrets(self, settings) -> None:
        serialised = str(settings.public_config()).lower()
        for banned in ("secret", "password", "api_key", "apikey", "token", "bind_dn"):
            assert banned not in serialised

    def test_audit_redacts_secrets_and_bodies(self) -> None:
        from msp_api.security.audit import redact

        payload = {
            "api_key": "vt-key",
            "Authorization": "Bearer xyz",
            "nested": {"password": "p", "session_token": "s", "keep": 1},
            "body": "x" * 5000,
            "raw_eml": "y" * 100,
            "list": [{"secret": "s"}],
        }
        cleaned = redact(payload)
        serialised = str(cleaned)
        for leaked in ("vt-key", "Bearer xyz", "'p'", "'s'"):
            assert leaked not in serialised
        assert cleaned["nested"]["keep"] == 1
        assert "omitted" in cleaned["body"]

    def test_logging_formatter_redacts_forbidden_keys(self) -> None:
        import json
        import logging

        from msp_api.observability import JsonFormatter

        record = logging.LogRecord("t", logging.INFO, __file__, 1, "msg", None, None)
        record.password = "p@ssw0rd"  # type: ignore[attr-defined]
        record.api_key = "vt-key"  # type: ignore[attr-defined]
        record.provider = "virustotal"  # type: ignore[attr-defined]
        payload = json.loads(JsonFormatter().format(record))
        assert payload["password"] == "[redacted]"
        assert payload["api_key"] == "[redacted]"
        assert payload["provider"] == "virustotal"

    def test_production_config_rejects_unsafe_settings(self, monkeypatch) -> None:
        from msp_api.config import Settings

        monkeypatch.setenv("MSP_ENVIRONMENT", "production")
        monkeypatch.setenv("MSP_SECRET_KEY", "x" * 40)
        monkeypatch.setenv("MSP_COOKIE_SECURE", "false")
        with pytest.raises(ValueError, match="cookie_secure"):
            Settings(_env_file=None)

    def test_production_requires_a_secret_key(self, monkeypatch) -> None:
        from msp_api.config import Settings

        monkeypatch.setenv("MSP_ENVIRONMENT", "production")
        monkeypatch.delenv("MSP_SECRET_KEY", raising=False)
        monkeypatch.setenv("MSP_SECRET_KEY_FILE", "")
        with pytest.raises(ValueError, match="SECRET_KEY"):
            Settings(_env_file=None)

    def test_production_rejects_debug(self, monkeypatch) -> None:
        from msp_api.config import Settings

        monkeypatch.setenv("MSP_ENVIRONMENT", "production")
        monkeypatch.setenv("MSP_SECRET_KEY", "x" * 40)
        # Set the other production requirements so the debug check is what actually fails.
        monkeypatch.setenv("MSP_COOKIE_SECURE", "true")
        monkeypatch.setenv("MSP_DEBUG", "true")
        with pytest.raises(ValueError, match="debug"):
            Settings(_env_file=None)


class TestRemediationSafety:
    def test_mock_provider_refuses_execution_when_disabled(self) -> None:
        from msp_contracts import RemediationType
        from msp_exchange import ExchangeMessageRef, MockExchangeProvider, RemediationRequest

        provider = MockExchangeProvider(remediation_enabled=False)
        outcome = provider.request_remediation(
            RemediationRequest(
                action=RemediationType.DELETE,
                targets=[ExchangeMessageRef(mailbox="a@corp.example", item_id="1")],
                dry_run=False,
            )
        )
        assert outcome.executed is False
        assert outcome.errors

    def test_dry_run_changes_nothing(self) -> None:
        from msp_contracts import RemediationType
        from msp_exchange import MockExchangeProvider, RemediationRequest

        provider = MockExchangeProvider(remediation_enabled=True)
        ref = provider.add_message("a@corp.example", b"From: x@y.test\r\n\r\nbody")
        outcome = provider.request_remediation(
            RemediationRequest(action=RemediationType.DELETE, targets=[ref], dry_run=True)
        )
        assert outcome.executed is False
        assert provider.mailboxes["a@corp.example"], "dry-run must not delete anything"
        assert any("dry-run" in w for w in outcome.warnings)

    def test_ews_provider_never_executes_without_the_environment_inventory(self) -> None:
        from msp_contracts import RemediationType
        from msp_exchange import EwsConfig, OnPremEwsExchangeProvider, RemediationRequest

        provider = OnPremEwsExchangeProvider(EwsConfig())
        outcome = provider.request_remediation(
            RemediationRequest(action=RemediationType.DELETE, targets=[], dry_run=False)
        )
        assert outcome.executed is False
        assert outcome.errors
        assert provider.blockers(), "unresolved blockers must be reported (ТЗ 51)"

    def test_active_directory_provider_has_no_write_operations(self) -> None:
        """ТЗ 49.8: no AD write permissions in v1 — the module offers none."""
        from msp_ad import ActiveDirectoryProvider

        forbidden = {"add", "modify", "delete", "modify_dn", "write", "create", "update"}
        exposed = {name for name in dir(ActiveDirectoryProvider) if not name.startswith("_")}
        assert not (exposed & forbidden), f"write-capable methods exposed: {exposed & forbidden}"
