"""Active Directory authentication tests (ТЗ 24).

The directory is exercised through a fake ldap3 connection: these tests verify the platform's
behaviour — credential handling, role mapping, failure modes — not the LDAP library.
"""

from __future__ import annotations

from typing import Any

import pytest
from msp_ad import ActiveDirectoryAuthenticator, AdAuthConfig, AuthOutcome, parse_group_role_map
from msp_ad.auth import escape_filter_value
from msp_contracts import Role


class FakeEntry:
    def __init__(self, dn: str, attributes: dict[str, Any]) -> None:
        self.entry_dn = dn
        self._attributes = attributes
        for key, value in attributes.items():
            setattr(self, key, _FakeAttribute(value))

    def __contains__(self, item: str) -> bool:
        return item in self._attributes


class _FakeAttribute:
    def __init__(self, value: Any) -> None:
        self.value = value

    def __str__(self) -> str:
        return str(self.value)

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self.value if isinstance(self.value, list) else [self.value])


class FakeConnection:
    """Records what the platform sent, so the tests can assert on it."""

    def __init__(
        self,
        *,
        bind_results: dict[str, bool],
        entries: list[FakeEntry] | None = None,
        bind_error: str = "",
    ) -> None:
        self.bind_results = bind_results
        self.entries = entries or []
        self.bind_error = bind_error
        self.bound_as: list[tuple[str | None, str | None]] = []
        self.searches: list[dict[str, Any]] = []
        self.user: str | None = None
        self.password: str | None = None
        self.result = {"description": "invalidCredentials"}
        self.server = type(
            "S", (), {"info": type("I", (), {"naming_contexts": ["DC=corp,DC=example"], "other": {}})()}
        )()

    def bind(self) -> bool:
        self.bound_as.append((self.user, self.password))
        ok = self.bind_results.get(self.user or "", False)
        if not ok and self.bind_error:
            self.result = {"description": self.bind_error}
        return ok

    def unbind(self) -> None:
        return None

    def start_tls(self) -> bool:
        return True

    def search(self, **kwargs: Any) -> bool:
        self.searches.append(kwargs)
        return True


@pytest.fixture
def config() -> AdAuthConfig:
    return AdAuthConfig(
        server="dc.corp.example",
        bind_dn="CN=svc-msp,OU=Service,DC=corp,DC=example",
        bind_password="service-secret",
        base_dn="DC=corp,DC=example",
        group_role_map=parse_group_role_map(
            "CN=SOC Admins,OU=Groups,DC=corp,DC=example=security_admin;SOC Analysts=security_analyst"
        ),
        default_role="employee",
    )


def install(monkeypatch, authenticator: ActiveDirectoryAuthenticator, connection: FakeConnection):  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        authenticator, "_connect", lambda user, password, read_only=True: _bind(connection, user, password)
    )
    return connection


def _bind(connection: FakeConnection, user: str | None, password: str | None) -> FakeConnection:
    connection.user = user
    connection.password = password
    return connection


ANALYST_ENTRY = FakeEntry(
    "CN=Ivan Petrov,OU=Users,DC=corp,DC=example",
    {
        "displayName": "Иван Петров",
        "mail": "analyst@corp.example",
        "memberOf": ["CN=SOC Analysts,OU=Groups,DC=corp,DC=example"],
        "userAccountControl": 512,
    },
)


class TestAuthentication:
    def test_successful_login_maps_group_to_role(self, monkeypatch, config) -> None:
        authenticator = ActiveDirectoryAuthenticator(config)
        connection = FakeConnection(
            bind_results={config.bind_dn: True, ANALYST_ENTRY.entry_dn: True},
            entries=[ANALYST_ENTRY],
        )
        install(monkeypatch, authenticator, connection)

        result = authenticator.authenticate("analyst@corp.example", "user-password")
        assert result.outcome is AuthOutcome.SUCCESS
        assert result.email == "analyst@corp.example"
        assert result.role == Role.SECURITY_ANALYST.value
        assert result.display_name == "Иван Петров"

    def test_authentication_binds_as_the_user_not_the_service_account(self, monkeypatch, config) -> None:
        """The user's password is verified by the directory, never compared by the platform."""
        authenticator = ActiveDirectoryAuthenticator(config)
        connection = FakeConnection(
            bind_results={config.bind_dn: True, ANALYST_ENTRY.entry_dn: True},
            entries=[ANALYST_ENTRY],
        )
        install(monkeypatch, authenticator, connection)
        authenticator.authenticate("analyst@corp.example", "user-password")

        assert (ANALYST_ENTRY.entry_dn, "user-password") in connection.bound_as
        # The service account is never bound with the user's password.
        assert (config.bind_dn, "user-password") not in connection.bound_as

    def test_wrong_password_is_refused(self, monkeypatch, config) -> None:
        authenticator = ActiveDirectoryAuthenticator(config)
        connection = FakeConnection(
            bind_results={config.bind_dn: True},  # the user bind fails
            entries=[ANALYST_ENTRY],
        )
        install(monkeypatch, authenticator, connection)
        result = authenticator.authenticate("analyst@corp.example", "wrong")
        assert result.outcome is AuthOutcome.INVALID_CREDENTIALS
        assert not result.authenticated

    def test_empty_password_never_becomes_an_anonymous_bind(self, monkeypatch, config) -> None:
        """An empty password must be refused outright: many servers accept it as anonymous."""
        authenticator = ActiveDirectoryAuthenticator(config)
        connection = FakeConnection(bind_results={config.bind_dn: True}, entries=[ANALYST_ENTRY])
        install(monkeypatch, authenticator, connection)
        result = authenticator.authenticate("analyst@corp.example", "")
        assert result.outcome is AuthOutcome.INVALID_CREDENTIALS
        assert connection.bound_as == [], "no bind should have been attempted"

    def test_unknown_user(self, monkeypatch, config) -> None:
        authenticator = ActiveDirectoryAuthenticator(config)
        install(monkeypatch, authenticator, FakeConnection(bind_results={config.bind_dn: True}, entries=[]))
        assert authenticator.authenticate("nobody@corp.example", "x").outcome is AuthOutcome.USER_NOT_FOUND

    def test_disabled_account_is_refused_before_binding(self, monkeypatch, config) -> None:
        disabled = FakeEntry(
            "CN=Disabled,OU=Users,DC=corp,DC=example",
            {
                "displayName": "Disabled",
                "mail": "disabled@corp.example",
                "memberOf": [],
                "userAccountControl": 514,  # NORMAL_ACCOUNT | ACCOUNTDISABLE
            },
        )
        authenticator = ActiveDirectoryAuthenticator(config)
        connection = FakeConnection(
            bind_results={config.bind_dn: True, disabled.entry_dn: True}, entries=[disabled]
        )
        install(monkeypatch, authenticator, connection)
        result = authenticator.authenticate("disabled@corp.example", "password")
        assert result.outcome is AuthOutcome.ACCOUNT_DISABLED
        assert (disabled.entry_dn, "password") not in connection.bound_as

    def test_ambiguous_login_is_refused(self, monkeypatch, config) -> None:
        """Two matching entries must not be resolved by picking one."""
        second = FakeEntry(
            "CN=Other,OU=Users,DC=corp,DC=example",
            {
                "displayName": "Other",
                "mail": "analyst@corp.example",
                "memberOf": [],
                "userAccountControl": 512,
            },
        )
        authenticator = ActiveDirectoryAuthenticator(config)
        install(
            monkeypatch,
            authenticator,
            FakeConnection(bind_results={config.bind_dn: True}, entries=[ANALYST_ENTRY, second]),
        )
        assert authenticator.authenticate("analyst@corp.example", "x").outcome is AuthOutcome.USER_NOT_FOUND

    def test_directory_outage_denies_rather_than_allows(self, monkeypatch, config) -> None:
        authenticator = ActiveDirectoryAuthenticator(config)
        connection = FakeConnection(bind_results={})  # the service account bind fails
        install(monkeypatch, authenticator, connection)
        result = authenticator.authenticate("analyst@corp.example", "password")
        assert result.outcome is AuthOutcome.DIRECTORY_UNAVAILABLE
        assert not result.authenticated

    def test_account_state_is_read_from_the_bind_error(self, monkeypatch, config) -> None:
        """Without a service account the state is only visible in the bind error code."""
        direct = AdAuthConfig(
            server="dc.corp.example",
            user_principal_template="{login}",
            base_dn="DC=corp,DC=example",
        )
        authenticator = ActiveDirectoryAuthenticator(direct)
        connection = FakeConnection(bind_results={}, bind_error="80090308: data 533, v2580")
        install(monkeypatch, authenticator, connection)
        result = authenticator.authenticate("user@corp.example", "password")
        assert result.outcome is AuthOutcome.ACCOUNT_DISABLED


class TestRoleMapping:
    def test_first_match_wins(self, config) -> None:
        authenticator = ActiveDirectoryAuthenticator(config)
        both = (
            "CN=SOC Admins,OU=Groups,DC=corp,DC=example",
            "CN=SOC Analysts,OU=Groups,DC=corp,DC=example",
        )
        assert authenticator.map_role(both) == Role.SECURITY_ADMIN.value

    def test_group_can_be_written_as_cn_or_full_dn(self, config) -> None:
        authenticator = ActiveDirectoryAuthenticator(config)
        assert (
            authenticator.map_role(("CN=SOC Analysts,OU=Elsewhere,DC=corp,DC=example",)) == "security_analyst"
        )

    def test_unmapped_user_gets_the_default_role(self, config) -> None:
        authenticator = ActiveDirectoryAuthenticator(config)
        assert authenticator.map_role(("CN=Sales,DC=corp,DC=example",)) == "employee"

    def test_require_group_match_refuses_unmapped_users(self, config) -> None:
        from dataclasses import replace

        authenticator = ActiveDirectoryAuthenticator(replace(config, require_group_match=True))
        assert authenticator.map_role(("CN=Sales,DC=corp,DC=example",)) is None

    def test_unmapped_user_is_refused_when_required(self, monkeypatch, config) -> None:
        from dataclasses import replace

        sales = FakeEntry(
            "CN=Sales User,OU=Users,DC=corp,DC=example",
            {
                "displayName": "Sales",
                "mail": "sales@corp.example",
                "memberOf": ["CN=Sales,DC=corp,DC=example"],
                "userAccountControl": 512,
            },
        )
        authenticator = ActiveDirectoryAuthenticator(replace(config, require_group_match=True))
        install(
            monkeypatch,
            authenticator,
            FakeConnection(bind_results={config.bind_dn: True, sales.entry_dn: True}, entries=[sales]),
        )
        result = authenticator.authenticate("sales@corp.example", "password")
        assert result.outcome is AuthOutcome.NOT_AUTHORIZED


class TestFilterInjection:
    @pytest.mark.parametrize(
        ("raw", "expected_absent"),
        [
            ("a*)(objectClass=*", "*)("),
            ("x)(uid=admin", ")(uid="),
            ("a\\b", "\\b"),
        ],
    )
    def test_metacharacters_are_escaped(self, raw: str, expected_absent: str) -> None:
        assert expected_absent not in escape_filter_value(raw)

    def test_injection_attempt_does_not_change_the_filter_shape(self, monkeypatch, config) -> None:
        authenticator = ActiveDirectoryAuthenticator(config)
        connection = FakeConnection(bind_results={config.bind_dn: True}, entries=[])
        install(monkeypatch, authenticator, connection)
        authenticator.authenticate("*)(objectClass=*", "password")

        assert connection.searches
        search_filter = connection.searches[0]["search_filter"]
        # The injected parentheses are escaped, so the filter keeps its intended structure.
        assert "(objectClass=*))" not in search_filter
        assert r"\2a" in search_filter


class TestConfiguration:
    def test_missing_server_is_reported_not_raised(self) -> None:
        problems = AdAuthConfig().validate()
        assert any("server" in p for p in problems)

    def test_plain_ldap_is_reported_as_unsafe(self) -> None:
        problems = AdAuthConfig(
            server="dc.corp.example", use_ssl=False, start_tls=False, bind_dn="x"
        ).validate()
        assert any("clear text" in p for p in problems)

    def test_misconfiguration_denies_authentication(self) -> None:
        result = ActiveDirectoryAuthenticator(AdAuthConfig()).authenticate("a@b.c", "x")
        assert result.outcome is AuthOutcome.MISCONFIGURED

    def test_health_is_reportable_without_a_server(self) -> None:
        assert ActiveDirectoryAuthenticator(AdAuthConfig()).health()["status"] == "not_configured"


class TestProvisioning:
    def test_directory_user_gets_no_local_password(self, db, organization, settings) -> None:
        """ТЗ 28: the directory password must never be stored, not even as a hash."""
        from dataclasses import replace

        from msp_ad import AuthResult
        from msp_api.services.directory_auth import provision_user

        result = AuthResult(
            AuthOutcome.SUCCESS,
            email="analyst@corp.example",
            display_name="Иван Петров",
            distinguished_name=ANALYST_ENTRY.entry_dn,
            groups=("CN=SOC Analysts,OU=Groups,DC=corp,DC=example",),
            role="security_analyst",
        )
        user = provision_user(db, settings, result)
        db.commit()
        assert user is not None
        assert user.password_hash is None
        assert user.auth_source == "ldap"
        assert user.role is Role.SECURITY_ANALYST
        del replace

    def test_role_change_in_the_directory_is_applied_on_next_login(self, db, organization, settings) -> None:
        from msp_ad import AuthResult
        from msp_api.services.directory_auth import provision_user

        first = AuthResult(
            AuthOutcome.SUCCESS, email="person@corp.example", role="employee", display_name="Person"
        )
        user = provision_user(db, settings, first)
        db.commit()
        assert user is not None and user.role is Role.EMPLOYEE

        promoted = AuthResult(
            AuthOutcome.SUCCESS, email="person@corp.example", role="security_analyst", display_name="Person"
        )
        user = provision_user(db, settings, promoted)
        db.commit()
        assert user is not None and user.role is Role.SECURITY_ANALYST

    def test_unknown_role_falls_back_to_employee(self, db, organization, settings) -> None:
        from msp_ad import AuthResult
        from msp_api.services.directory_auth import provision_user

        user = provision_user(
            db,
            settings,
            AuthResult(AuthOutcome.SUCCESS, email="odd@corp.example", role="not-a-real-role"),
        )
        db.commit()
        assert user is not None and user.role is Role.EMPLOYEE

    def test_local_account_is_not_treated_as_directory_managed(self, db, organization) -> None:
        from msp_api.db.models import User
        from msp_api.services.directory_auth import is_directory_managed

        local = User(
            organization_id=organization.id,
            email="bootstrap@corp.example",
            role=Role.SECURITY_ADMIN,
            auth_source="local",
            password_hash="x",
        )
        assert is_directory_managed(local) is False
