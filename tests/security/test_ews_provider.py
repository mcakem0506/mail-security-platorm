"""EWS provider tests (ТЗ 7, 20, 51).

The provider is exercised against a fake exchangelib account, so these tests verify the
platform's own guarantees — scope enforcement, capability honesty, remediation gating — rather
than the behaviour of the EWS library.
"""

from __future__ import annotations

from typing import Any

import pytest
from msp_contracts import RemediationType
from msp_exchange import ExchangeCapability, ExchangeMessageRef, RemediationRequest
from msp_exchange.ews import (
    EwsAccessMode,
    EwsAuthMethod,
    EwsCapabilityReport,
    EwsConfig,
    MailboxOutOfScope,
    OnPremEwsExchangeProvider,
    mailbox_in_scope,
    normalise_mailbox,
)

SERVICE_ACCOUNT = "svc-msp@corp.example"


def configured(**overrides: Any) -> EwsConfig:
    base = {
        "endpoint": "https://mail.corp.example/EWS/Exchange.asmx",
        "autodiscover": False,
        "primary_smtp_address": SERVICE_ACCOUNT,
        "username": SERVICE_ACCOUNT,
        "password": "service-secret",
        "access_mode": EwsAccessMode.IMPERSONATION,
        "mailbox_scope": ("buh@corp.example", "ceo@corp.example"),
    }
    base.update(overrides)
    return EwsConfig(**base)  # type: ignore[arg-type]


def with_capabilities(provider: OnPremEwsExchangeProvider, *caps: ExchangeCapability) -> None:
    provider._report = EwsCapabilityReport(
        reachable=True,
        authenticated=True,
        server_version="Exchange 2019",
        capabilities=set(caps),
    )


class FakeItem:
    def __init__(
        self, item_id: str, subject: str = "Тест", mime: bytes = b"From: a@b.test\r\n\r\nbody"
    ) -> None:
        self.id = item_id
        self.subject = subject
        self.mime_content = mime
        self.message_id = f"<{item_id}@corp.example>"
        self.headers = []
        self.attachments = []
        self.moved_to: Any = None
        self.soft_deleted = False

    def move(self, folder: Any) -> None:
        self.moved_to = folder

    def soft_delete(self) -> None:
        self.soft_deleted = True


class FakeAccount:
    def __init__(self, mailbox: str, items: list[FakeItem] | None = None) -> None:
        self.primary_smtp_address = mailbox
        self.items = items or []
        self.inbox = self
        self.root = self
        self.msg_folder_root = object()

    def get(self, id: str) -> FakeItem:
        for item in self.items:
            if item.id == id:
                return item
        raise KeyError(id)

    def all(self):  # type: ignore[no-untyped-def]
        return self

    def filter(self, **kwargs: Any):  # type: ignore[no-untyped-def]
        message_id = kwargs.get("message_id")
        if message_id:
            return [i for i in self.items if i.message_id == message_id]
        return self

    def only(self, *fields: str):  # type: ignore[no-untyped-def]
        return self.items

    def walk(self):  # type: ignore[no-untyped-def]
        return []

    def __getitem__(self, item: Any) -> list[FakeItem]:
        return self.items


class TestScopeEnforcement:
    """The scope is the difference between a pilot and access to the whole organisation."""

    def test_own_mailbox_is_always_reachable(self) -> None:
        assert mailbox_in_scope(SERVICE_ACCOUNT, (), SERVICE_ACCOUNT) is True

    def test_mailbox_outside_scope_is_refused(self) -> None:
        provider = OnPremEwsExchangeProvider(configured(mailbox_scope=("buh@corp.example",)))
        with pytest.raises(MailboxOutOfScope):
            provider._account_for("ceo@corp.example")

    def test_domain_entry_covers_the_whole_domain(self) -> None:
        assert mailbox_in_scope("anyone@corp.example", ("@corp.example",)) is True
        assert mailbox_in_scope("anyone@other.example", ("@corp.example",)) is False

    def test_empty_scope_grants_nothing_beyond_the_service_account(self) -> None:
        assert mailbox_in_scope("ceo@corp.example", (), SERVICE_ACCOUNT) is False

    def test_scope_matching_is_case_insensitive(self) -> None:
        assert mailbox_in_scope("CEO@Corp.Example", ("ceo@corp.example",)) is True

    def test_delegation_refuses_other_mailboxes_clearly(self) -> None:
        """Delegation cannot open an arbitrary mailbox; say so instead of failing obscurely."""
        from msp_exchange import CapabilityUnavailable

        provider = OnPremEwsExchangeProvider(
            configured(access_mode=EwsAccessMode.DELEGATE, mailbox_scope=("ceo@corp.example",))
        )
        with pytest.raises(CapabilityUnavailable, match="impersonation"):
            provider._account_for("ceo@corp.example")

    def test_normalisation(self) -> None:
        assert normalise_mailbox("  CEO@Corp.Example ") == "ceo@corp.example"
        assert normalise_mailbox(None) == ""  # type: ignore[arg-type]


class TestCapabilityHonesty:
    """ТЗ 6.5: never claim a capability this deployment has not demonstrated."""

    def test_unconfigured_provider_reports_not_configured(self) -> None:
        provider = OnPremEwsExchangeProvider(EwsConfig())
        health = provider.health()
        assert health.status == "not_configured"
        assert "security mailbox" in (health.detail or "")

    def test_unconfigured_provider_lists_blockers(self) -> None:
        assert OnPremEwsExchangeProvider(EwsConfig()).blockers()

    def test_operations_refuse_without_a_verified_capability(self) -> None:
        from msp_exchange import CapabilityUnavailable

        provider = OnPremEwsExchangeProvider(configured())
        with_capabilities(provider)  # nothing verified
        ref = ExchangeMessageRef(mailbox=SERVICE_ACCOUNT, item_id="1")
        for call in (
            lambda: provider.get_message(ref),
            lambda: provider.get_message_headers(ref),
            lambda: provider.get_attachments(ref),
        ):
            with pytest.raises(CapabilityUnavailable):
                call()

    def test_reporting_always_points_at_the_security_mailbox(self) -> None:
        from msp_exchange import CapabilityUnavailable

        provider = OnPremEwsExchangeProvider(configured())
        with_capabilities(provider, ExchangeCapability.SUBMIT_REPORT)
        with pytest.raises(CapabilityUnavailable, match="security mailbox"):
            provider.submit_report(ExchangeMessageRef(mailbox=SERVICE_ACCOUNT), "user@corp.example")

    def test_search_without_scope_is_refused_rather_than_silently_empty(self) -> None:
        from msp_exchange import CapabilityUnavailable

        provider = OnPremEwsExchangeProvider(configured(mailbox_scope=()))
        with_capabilities(provider, ExchangeCapability.SEARCH)
        with pytest.raises(CapabilityUnavailable, match="scope"):
            provider.search_related_messages(sender="a@b.test")

    def test_tls_verification_off_is_reported_as_a_blocker(self) -> None:
        provider = OnPremEwsExchangeProvider(configured(verify_tls=False))
        assert any("TLS" in b for b in provider.blockers())

    def test_autodiscover_without_an_address_is_a_blocker(self) -> None:
        config = EwsConfig(autodiscover=True, username="svc", password="x")
        assert any("Autodiscover" in b for b in config.blockers())


class TestUniversality:
    """The module must fit any deployment, not one fixed environment."""

    def test_auth_preference_is_tried_in_order(self) -> None:
        provider = OnPremEwsExchangeProvider(
            configured(
                auth_method=EwsAuthMethod.AUTO,
                auth_preference=(EwsAuthMethod.KERBEROS, EwsAuthMethod.NTLM),
            )
        )
        candidates = provider._auth_candidates()
        assert len(candidates) == 2

    def test_a_single_auth_method_can_be_pinned(self) -> None:
        provider = OnPremEwsExchangeProvider(configured(auth_method=EwsAuthMethod.NTLM))
        assert len(provider._auth_candidates()) == 1

    def test_autodiscover_needs_no_endpoint(self) -> None:
        config = EwsConfig(autodiscover=True, primary_smtp_address=SERVICE_ACCOUNT, username=SERVICE_ACCOUNT)
        assert config.configured is True
        assert config.blockers() == []

    def test_explicit_endpoint_needs_no_autodiscover(self) -> None:
        config = EwsConfig(
            endpoint="https://mail.example/EWS/Exchange.asmx",
            autodiscover=False,
            username="svc",
            password="x",
        )
        assert config.configured is True

    def test_no_exchange_version_is_hard_coded(self) -> None:
        """2016 and 2019 must both work, so no executable code may depend on a version.

        Only literals in code are checked: docstrings and comments are allowed to name versions,
        since explaining the constraint is not the same as depending on it.
        """
        import ast
        import inspect

        from msp_exchange import ews

        tree = ast.parse(inspect.getsource(ews))
        docstrings = {
            node.body[0].value
            for node in ast.walk(tree)
            if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef)
            and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
        }
        offenders = [
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and node not in docstrings
            and isinstance(node.value, str)
            and any(version in node.value for version in ("2016", "2019", "15.1", "15.2"))
        ]
        assert not offenders, f"Exchange version referenced in code: {offenders}"


class TestRemediationGating:
    def _request(self, action: RemediationType, **kwargs: Any) -> RemediationRequest:
        defaults: dict[str, Any] = {
            "action": action,
            "targets": [ExchangeMessageRef(mailbox="buh@corp.example", item_id="1")],
            "dry_run": False,
            "approved_by": ["admin@corp.example"],
        }
        defaults.update(kwargs)
        return RemediationRequest(**defaults)

    def test_dry_run_changes_nothing_and_says_so(self) -> None:
        provider = OnPremEwsExchangeProvider(configured(remediation_account_enabled=True))
        outcome = provider.request_remediation(self._request(RemediationType.DELETE, dry_run=True))
        assert outcome.executed is False
        assert any("dry-run" in w for w in outcome.warnings)

    def test_execution_refused_while_remediation_is_disabled(self) -> None:
        provider = OnPremEwsExchangeProvider(configured(remediation_account_enabled=False))
        outcome = provider.request_remediation(self._request(RemediationType.DELETE))
        assert outcome.executed is False
        assert outcome.errors

    def test_execution_refused_without_an_approval(self) -> None:
        provider = OnPremEwsExchangeProvider(configured(remediation_account_enabled=True))
        with_capabilities(provider, ExchangeCapability.REMEDIATION)
        outcome = provider.request_remediation(self._request(RemediationType.DELETE, approved_by=[]))
        assert outcome.executed is False
        assert any("approval" in e for e in outcome.errors)

    def test_targets_outside_scope_are_refused_before_anything_runs(self) -> None:
        provider = OnPremEwsExchangeProvider(
            configured(remediation_account_enabled=True, mailbox_scope=("buh@corp.example",))
        )
        with_capabilities(provider, ExchangeCapability.REMEDIATION)
        outcome = provider.request_remediation(
            self._request(
                RemediationType.DELETE,
                targets=[
                    ExchangeMessageRef(mailbox="buh@corp.example", item_id="1"),
                    ExchangeMessageRef(mailbox="ceo@corp.example", item_id="2"),
                ],
            )
        )
        assert outcome.executed is False
        assert any("outside the granted scope" in e for e in outcome.errors)
        assert outcome.detail["out_of_scope"] == ["ceo@corp.example"]

    def test_quarantine_is_reported_as_reversible(self) -> None:
        provider = OnPremEwsExchangeProvider(configured(remediation_account_enabled=True))
        outcome = provider.request_remediation(self._request(RemediationType.QUARANTINE, dry_run=True))
        assert outcome.rollback_supported is True

    def test_delete_is_reported_as_irreversible(self) -> None:
        provider = OnPremEwsExchangeProvider(configured(remediation_account_enabled=True))
        outcome = provider.request_remediation(self._request(RemediationType.DELETE, dry_run=True))
        assert outcome.rollback_supported is False

    def test_unsupported_action_becomes_a_proposal_not_a_silent_success(self) -> None:
        provider = OnPremEwsExchangeProvider(configured(remediation_account_enabled=True))
        with_capabilities(provider, ExchangeCapability.REMEDIATION)
        outcome = provider.request_remediation(self._request(RemediationType.BLOCK_DOMAIN))
        assert outcome.executed is False
        assert any("proposal" in e for e in outcome.errors)

    def test_quarantine_moves_the_item(self, monkeypatch) -> None:
        provider = OnPremEwsExchangeProvider(configured(remediation_account_enabled=True))
        with_capabilities(provider, ExchangeCapability.REMEDIATION)
        item = FakeItem("1")
        account = FakeAccount("buh@corp.example", [item])
        monkeypatch.setattr(provider, "_account_for", lambda mailbox: account)
        monkeypatch.setattr(provider, "_ensure_quarantine_folder", lambda acc: "quarantine-folder")

        outcome = provider.request_remediation(self._request(RemediationType.QUARANTINE))
        assert outcome.executed is True
        assert item.moved_to == "quarantine-folder"
        assert item.soft_deleted is False, "quarantine must move, not delete"
        assert outcome.rollback_token

    def test_delete_uses_soft_delete(self, monkeypatch) -> None:
        """Soft delete keeps the item in Recoverable Items, so the action stays recoverable."""
        provider = OnPremEwsExchangeProvider(configured(remediation_account_enabled=True))
        with_capabilities(provider, ExchangeCapability.REMEDIATION)
        item = FakeItem("1")
        account = FakeAccount("buh@corp.example", [item])
        monkeypatch.setattr(provider, "_account_for", lambda mailbox: account)

        outcome = provider.request_remediation(self._request(RemediationType.DELETE))
        assert outcome.executed is True
        assert item.soft_deleted is True

    def test_one_failing_item_does_not_abort_the_rest(self, monkeypatch) -> None:
        provider = OnPremEwsExchangeProvider(configured(remediation_account_enabled=True))
        with_capabilities(provider, ExchangeCapability.REMEDIATION)
        good = FakeItem("2")
        account = FakeAccount("buh@corp.example", [good])
        monkeypatch.setattr(provider, "_account_for", lambda mailbox: account)

        outcome = provider.request_remediation(
            self._request(
                RemediationType.DELETE,
                targets=[
                    ExchangeMessageRef(mailbox="buh@corp.example", item_id="missing"),
                    ExchangeMessageRef(mailbox="buh@corp.example", item_id="2"),
                ],
            )
        )
        assert outcome.executed is True
        assert outcome.affected_messages == 1
        assert outcome.warnings


class TestMessageAccess:
    def test_get_message_returns_raw_mime(self, monkeypatch) -> None:
        provider = OnPremEwsExchangeProvider(configured())
        with_capabilities(provider, ExchangeCapability.GET_MESSAGE)
        item = FakeItem("1", mime=b"From: sender@corp.example\r\n\r\nbody")
        account = FakeAccount("buh@corp.example", [item])
        monkeypatch.setattr(provider, "_account_for", lambda mailbox: account)

        fetched = provider.get_message(ExchangeMessageRef(mailbox="buh@corp.example", item_id="1"))
        assert fetched.raw_mime.startswith(b"From: sender@corp.example")
        assert fetched.source == "onprem_ews"

    def test_message_is_found_by_internet_message_id(self, monkeypatch) -> None:
        provider = OnPremEwsExchangeProvider(configured())
        with_capabilities(provider, ExchangeCapability.GET_MESSAGE)
        item = FakeItem("1")
        account = FakeAccount("buh@corp.example", [item])
        monkeypatch.setattr(provider, "_account_for", lambda mailbox: account)

        fetched = provider.get_message(
            ExchangeMessageRef(mailbox="buh@corp.example", internet_message_id="1@corp.example")
        )
        assert fetched.raw_mime == item.mime_content

    def test_missing_message_raises_a_clear_error(self, monkeypatch) -> None:
        provider = OnPremEwsExchangeProvider(configured())
        with_capabilities(provider, ExchangeCapability.GET_MESSAGE)
        account = FakeAccount("buh@corp.example", [])
        monkeypatch.setattr(provider, "_account_for", lambda mailbox: account)

        with pytest.raises(KeyError):
            provider.get_message(ExchangeMessageRef(mailbox="buh@corp.example", internet_message_id="nope@x"))

    def test_reference_without_any_identifier_is_rejected(self, monkeypatch) -> None:
        provider = OnPremEwsExchangeProvider(configured())
        with_capabilities(provider, ExchangeCapability.GET_MESSAGE)
        monkeypatch.setattr(provider, "_account_for", lambda mailbox: FakeAccount("buh@corp.example", []))
        with pytest.raises(KeyError, match="item id"):
            provider.get_message(ExchangeMessageRef(mailbox="buh@corp.example"))
