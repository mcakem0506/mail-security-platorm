"""On-premises EWS provider (ТЗ 7).

This is a *universal* adapter, not a deployment-specific one. Nothing about the environment is
assumed:

* the endpoint is either configured or found via Autodiscover — no URL is hard-coded;
* the authentication method is negotiated from a configured preference list, because NTLM,
  Kerberos and Basic all occur in the field;
* the Exchange build is detected, not declared: 2016 and 2019 differ in what they accept, and the
  library negotiates the request version;
* access is either impersonation or delegation, whichever the organisation granted;
* capabilities are *probed* against the live server and reported honestly, so the platform never
  claims something this deployment cannot do (ТЗ 6.5).

Two safety properties are structural rather than configurable:

* **mailbox scope** — every operation is checked against an allowlist before it is attempted, so
  a scope granted for a pilot group cannot be used against the whole organisation by mistake;
* **remediation is refused unless explicitly enabled**, and a destructive action is refused
  outright while the deployment is in dry-run mode (ТЗ 2.5, 20).

``exchangelib`` is an optional dependency: the platform runs fully without it, and this module
reports ``not_configured`` instead of failing at import.
"""

from __future__ import annotations

import contextlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from msp_contracts import ProviderHealth, RemediationType, utcnow

from .base import (
    CapabilityUnavailable,
    ExchangeCapability,
    ExchangeMessageRef,
    FetchedMessage,
    RemediationOutcome,
    RemediationRequest,
)

logger = logging.getLogger(__name__)

# Blockers that remain until the organisation supplies the corresponding facts (ТЗ 51).
BLOCKERS: tuple[str, ...] = (
    "EWS endpoint not configured and Autodiscover disabled",
    "EWS authentication method not confirmed for this deployment",
    "Service account for EWS access not provisioned",
    "Mailbox access mode (impersonation or delegation) not decided",
)

_MAILBOX_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_QUARANTINE_FOLDER = "MSP Quarantine"


class EwsAuthMethod(StrEnum):
    """Authentication methods that occur in on-premises deployments."""

    AUTO = "auto"  # try the configured preference order
    NTLM = "ntlm"
    KERBEROS = "kerberos"
    BASIC = "basic"
    SSPI = "sspi"  # Windows integrated, only when the platform runs on Windows


class EwsAccessMode(StrEnum):
    IMPERSONATION = "impersonation"
    DELEGATE = "delegate"


@dataclass
class EwsConfig:
    # Either an explicit endpoint or Autodiscover. Autodiscover keeps the module universal.
    endpoint: str = ""
    autodiscover: bool = True
    primary_smtp_address: str = ""  # the service account's own mailbox, used for Autodiscover
    username: str = ""
    password: str = ""
    auth_method: EwsAuthMethod = EwsAuthMethod.AUTO
    auth_preference: tuple[EwsAuthMethod, ...] = (
        EwsAuthMethod.NTLM,
        EwsAuthMethod.KERBEROS,
        EwsAuthMethod.BASIC,
    )
    access_mode: EwsAccessMode = EwsAccessMode.DELEGATE
    verify_tls: bool = True
    ca_file: str | None = None
    timeout_seconds: float = 30.0
    max_search_results: int = 200
    # Mailboxes (or domains) this deployment may touch. Empty means "nothing beyond the service
    # account's own mailbox": a scope must be granted deliberately, never by default.
    mailbox_scope: tuple[str, ...] = ()
    remediation_account_enabled: bool = False
    quarantine_folder: str = _QUARANTINE_FOLDER

    @property
    def configured(self) -> bool:
        return bool(self.username and (self.endpoint or (self.autodiscover and self.primary_smtp_address)))

    def blockers(self) -> list[str]:
        problems: list[str] = []
        if not self.endpoint and not self.autodiscover:
            problems.append(BLOCKERS[0])
        if self.autodiscover and not self.primary_smtp_address and not self.endpoint:
            problems.append("Autodiscover requires the service account's primary SMTP address")
        if not self.username:
            problems.append(BLOCKERS[2])
        if not self.verify_tls:
            problems.append("TLS verification is disabled: not acceptable for production (ТЗ 44)")
        if (
            self.remediation_account_enabled
            and self.access_mode is EwsAccessMode.DELEGATE
            and not self.mailbox_scope
        ):
            problems.append("remediation in delegate mode requires an explicit mailbox scope")
        return problems


@dataclass
class EwsCapabilityReport:
    """What this deployment actually supports, established by probing."""

    reachable: bool = False
    authenticated: bool = False
    server_version: str = ""
    server_build: str = ""
    auth_method: str = ""
    endpoint: str = ""
    access_mode: str = ""
    capabilities: set[ExchangeCapability] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)
    checked_at: datetime = field(default_factory=utcnow)

    def as_dict(self) -> dict[str, Any]:
        return {
            "reachable": self.reachable,
            "authenticated": self.authenticated,
            "server_version": self.server_version,
            "server_build": self.server_build,
            "auth_method": self.auth_method,
            "endpoint": self.endpoint,
            "access_mode": self.access_mode,
            "capabilities": sorted(c.value for c in self.capabilities),
            "errors": self.errors,
            "checked_at": self.checked_at.isoformat(),
        }


class MailboxOutOfScope(PermissionError):
    """Raised when an operation targets a mailbox the deployment was not granted."""


def normalise_mailbox(address: str) -> str:
    return (address or "").strip().lower()


def mailbox_in_scope(address: str, scope: tuple[str, ...], own_mailbox: str = "") -> bool:
    """A mailbox is in scope when it is the service account's own, or matches the allowlist.

    An entry may be a full address or a domain (``@corp.example``), which keeps the check usable
    for both a small pilot group and a whole organisation.
    """
    address = normalise_mailbox(address)
    if not address:
        return False
    if own_mailbox and address == normalise_mailbox(own_mailbox):
        return True
    for entry in scope:
        entry = normalise_mailbox(entry)
        if not entry:
            continue
        if entry.startswith("@") and address.endswith(entry):
            return True
        if entry == address:
            return True
    return False


def _import_exchangelib():  # type: ignore[no-untyped-def]
    try:
        import exchangelib
    except ImportError as exc:  # pragma: no cover - exercised only without the optional package
        raise RuntimeError(
            "exchangelib is not installed: install the 'exchange' extra to enable EWS"
        ) from exc
    return exchangelib


class OnPremEwsExchangeProvider:
    """EWS adapter for on-premises Exchange 2016 and 2019.

    The provider is created cheaply and connects lazily, so an unreachable Exchange never blocks
    application start-up.
    """

    provider_id = "onprem_ews"

    def __init__(self, config: EwsConfig) -> None:
        self.config = config
        self._account: Any = None
        self._report: EwsCapabilityReport | None = None

    # -- configuration ------------------------------------------------------------------------
    def blockers(self) -> list[str]:
        problems = self.config.blockers()
        if self._report is not None and self._report.errors:
            problems.extend(self._report.errors)
        return problems

    def _auth_candidates(self) -> list[Any]:
        exchangelib = _import_exchangelib()
        mapping = {
            EwsAuthMethod.NTLM: exchangelib.NTLM,
            EwsAuthMethod.KERBEROS: exchangelib.GSSAPI,
            EwsAuthMethod.BASIC: exchangelib.BASIC,
            EwsAuthMethod.SSPI: exchangelib.SSPI,
        }
        if self.config.auth_method is not EwsAuthMethod.AUTO:
            return [mapping[self.config.auth_method]]
        return [mapping[method] for method in self.config.auth_preference if method in mapping]

    def _tls_context(self) -> None:
        """Apply the organisation's CA bundle, where one was provided.

        Without an internal CA a deployment may still trust an exported self-signed certificate;
        disabling verification altogether stays a lab-only option and is reported as a blocker.
        """
        exchangelib = _import_exchangelib()
        from exchangelib.protocol import BaseProtocol

        if self.config.ca_file:
            import os

            os.environ.setdefault("REQUESTS_CA_BUNDLE", self.config.ca_file)
        elif not self.config.verify_tls:
            logger.warning("ews.tls_verification_disabled")
            BaseProtocol.HTTP_ADAPTER_CLS = exchangelib.protocol.NoVerifyHTTPAdapter

    # -- connection ---------------------------------------------------------------------------
    def _connect(self) -> Any:
        if self._account is not None:
            return self._account
        exchangelib = _import_exchangelib()
        from exchangelib import DELEGATE, IMPERSONATION, Account, Configuration, Credentials

        if not self.config.configured:
            raise CapabilityUnavailable(
                ExchangeCapability.GET_MESSAGE, "EWS is not configured for this deployment"
            )

        self._tls_context()
        credentials = Credentials(username=self.config.username, password=self.config.password)
        access_type = IMPERSONATION if self.config.access_mode is EwsAccessMode.IMPERSONATION else DELEGATE
        smtp_address = self.config.primary_smtp_address or self.config.username

        last_error: Exception | None = None
        for auth_type in self._auth_candidates():
            try:
                if self.config.endpoint:
                    configuration = Configuration(
                        service_endpoint=self.config.endpoint,
                        credentials=credentials,
                        auth_type=auth_type,
                        retry_policy=exchangelib.FaultTolerance(max_wait=self.config.timeout_seconds),
                    )
                    account = Account(
                        primary_smtp_address=smtp_address,
                        config=configuration,
                        autodiscover=False,
                        access_type=access_type,
                    )
                else:
                    account = Account(
                        primary_smtp_address=smtp_address,
                        credentials=credentials,
                        autodiscover=True,
                        access_type=access_type,
                    )
                # Touch the account so an authentication failure surfaces here, not later.
                _ = account.root
                self._account = account
                logger.info(
                    "ews.connected",
                    extra={"auth": getattr(auth_type, "__name__", str(auth_type))},
                )
                return account
            except Exception as exc:  # noqa: BLE001 - try the next method in the preference list
                last_error = exc
                logger.info(
                    "ews.auth_attempt_failed",
                    extra={"auth": str(auth_type), "error": type(exc).__name__},
                )
        raise ConnectionError(
            f"EWS authentication failed for every configured method: {type(last_error).__name__}"
        ) from last_error

    def close(self) -> None:
        account = self._account
        self._account = None
        if account is not None:
            with contextlib.suppress(Exception):
                account.protocol.close()

    # -- discovery ----------------------------------------------------------------------------
    def discover(self) -> EwsCapabilityReport:
        """Probe the live server and report what it actually supports (ТЗ 6.5)."""
        report = EwsCapabilityReport(
            endpoint=self.config.endpoint or "(autodiscover)",
            access_mode=self.config.access_mode.value,
        )
        if not self.config.configured:
            report.errors.append("EWS is not configured")
            self._report = report
            return report

        try:
            account = self._connect()
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"{type(exc).__name__}: {str(exc)[:200]}")
            self._report = report
            return report

        report.reachable = True
        report.authenticated = True
        try:
            version = account.protocol.version
            report.server_version = str(getattr(version, "fullname", "") or version)
            report.server_build = str(getattr(version, "build", ""))
            report.auth_method = str(account.protocol.auth_type)
            report.endpoint = str(account.protocol.service_endpoint)
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"version probe failed: {type(exc).__name__}")

        # Probe each capability rather than inferring it from the server version.
        probes: tuple[tuple[ExchangeCapability, Any], ...] = (
            (ExchangeCapability.GET_MESSAGE, lambda: account.inbox.all().only("subject")[:1]),
            (
                ExchangeCapability.GET_HEADERS,
                lambda: account.inbox.all().only("subject", "datetime_received")[:1],
            ),
            (
                ExchangeCapability.SEARCH,
                lambda: account.inbox.filter(subject__contains="x").only("subject")[:1],
            ),
            (ExchangeCapability.GET_ATTACHMENTS, lambda: account.inbox.all().only("attachments")[:1]),
        )
        for capability, probe in probes:
            try:
                list(probe())
                report.capabilities.add(capability)
            except Exception as exc:  # noqa: BLE001
                report.errors.append(f"{capability.value}: {type(exc).__name__}")

        if self.config.remediation_account_enabled and ExchangeCapability.GET_MESSAGE in report.capabilities:
            report.capabilities.add(ExchangeCapability.REMEDIATION)

        self._report = report
        return report

    # -- interface ----------------------------------------------------------------------------
    def health(self) -> ProviderHealth:
        if not self.config.configured:
            return ProviderHealth(
                provider_id=self.provider_id,
                status="not_configured",
                detail="EWS not configured; the platform runs through the security mailbox",
            )
        report = self._report or self.discover()
        if not report.reachable:
            return ProviderHealth(
                provider_id=self.provider_id,
                status="unavailable",
                detail="; ".join(report.errors[:2]) or "not reachable",
            )
        blockers = self.blockers()
        return ProviderHealth(
            provider_id=self.provider_id,
            status="ok" if not blockers else "degraded",
            mode=f"{report.auth_method or self.config.auth_method.value}/{self.config.access_mode.value}",
            detail="; ".join(blockers[:2]) if blockers else report.server_version,
        )

    def capabilities(self) -> set[ExchangeCapability]:
        report = self._report or self.discover()
        return set(report.capabilities)

    def _require(self, capability: ExchangeCapability) -> None:
        if capability not in self.capabilities():
            raise CapabilityUnavailable(
                capability, "not available in this Exchange deployment; see docs/EXCHANGE_COMPATIBILITY.md"
            )

    def _account_for(self, mailbox: str) -> Any:
        """Return an account scoped to ``mailbox``, refusing anything outside the granted scope."""
        mailbox = normalise_mailbox(mailbox)
        own = normalise_mailbox(self.config.primary_smtp_address or self.config.username)
        if not mailbox or mailbox == own:
            return self._connect()
        if not mailbox_in_scope(mailbox, self.config.mailbox_scope, own):
            raise MailboxOutOfScope(f"mailbox {mailbox} is outside the scope granted to this deployment")
        if self.config.access_mode is not EwsAccessMode.IMPERSONATION:
            # Delegation reaches only mailboxes explicitly shared with the service account.
            # Opening an arbitrary mailbox needs impersonation; claiming otherwise would fail
            # later with a confusing Exchange error instead of a clear refusal here.
            raise CapabilityUnavailable(
                ExchangeCapability.GET_MESSAGE,
                "reading another mailbox requires impersonation; this deployment uses delegation",
            )

        from exchangelib import IMPERSONATION, Account, Configuration

        base = self._connect()
        if self.config.endpoint:
            configuration = Configuration(
                service_endpoint=self.config.endpoint,
                credentials=base.protocol.credentials,
                auth_type=base.protocol.auth_type,
            )
            return Account(
                primary_smtp_address=mailbox,
                config=configuration,
                autodiscover=False,
                access_type=IMPERSONATION,
            )
        return Account(
            primary_smtp_address=mailbox,
            credentials=base.protocol.credentials,
            autodiscover=True,
            access_type=IMPERSONATION,
        )

    def _find_item(self, ref: ExchangeMessageRef) -> Any:
        account = self._account_for(ref.mailbox)
        if ref.item_id:
            return account.inbox.get(id=ref.item_id)
        message_id = (ref.internet_message_id or ref.message_id or "").strip()
        if not message_id:
            raise KeyError("neither an item id nor a Message-ID was supplied")
        if not message_id.startswith("<"):
            message_id = f"<{message_id}>"
        found = list(account.inbox.filter(message_id=message_id)[:1])
        if not found:
            # The message may already have been moved out of the inbox.
            found = list(account.root.filter(message_id=message_id)[:1])
        if not found:
            raise KeyError(f"message {message_id} not found in {ref.mailbox}")
        return found[0]

    def get_message(self, ref: ExchangeMessageRef) -> FetchedMessage:
        self._require(ExchangeCapability.GET_MESSAGE)
        item = self._find_item(ref)
        raw = getattr(item, "mime_content", None)
        if raw is None:
            raise CapabilityUnavailable(
                ExchangeCapability.GET_MESSAGE, "the server did not return MIME content"
            )
        data = raw if isinstance(raw, bytes) else str(raw).encode("utf-8", "replace")
        return FetchedMessage(ref=ref, raw_mime=data, source=self.provider_id)

    def get_message_headers(self, ref: ExchangeMessageRef) -> dict[str, str]:
        self._require(ExchangeCapability.GET_HEADERS)
        item = self._find_item(ref)
        headers = getattr(item, "headers", None) or []
        return {str(h.name): str(h.value) for h in headers}

    def get_attachments(self, ref: ExchangeMessageRef) -> list[tuple[str, bytes]]:
        self._require(ExchangeCapability.GET_ATTACHMENTS)
        item = self._find_item(ref)
        out: list[tuple[str, bytes]] = []
        for attachment in getattr(item, "attachments", []) or []:
            content = getattr(attachment, "content", None)
            if isinstance(content, bytes):
                out.append((str(getattr(attachment, "name", "attachment")), content))
        return out

    def submit_report(self, ref: ExchangeMessageRef, reported_by: str, note: str = "") -> str:
        # Reporting goes through the security mailbox, which works on every deployment (ТЗ 7.2).
        raise CapabilityUnavailable(
            ExchangeCapability.SUBMIT_REPORT,
            "use the security mailbox for reporting: it needs no EWS capability",
        )

    def search_related_messages(
        self, *, sender: str = "", subject: str = "", message_id: str = "", limit: int = 100
    ) -> list[ExchangeMessageRef]:
        """Search the mailboxes this deployment is scoped to.

        A search without a scope would silently return only the service account's own mailbox,
        which looks like "nothing found" — so an empty scope is an explicit error instead.
        """
        self._require(ExchangeCapability.SEARCH)
        if not self.config.mailbox_scope:
            raise CapabilityUnavailable(
                ExchangeCapability.SEARCH,
                "no mailbox scope is configured: a cross-mailbox search would be misleading",
            )
        limit = max(1, min(limit, self.config.max_search_results))
        results: list[ExchangeMessageRef] = []
        for mailbox in self._scope_mailboxes():
            if len(results) >= limit:
                break
            try:
                account = self._account_for(mailbox)
            except (MailboxOutOfScope, CapabilityUnavailable) as exc:
                logger.info("ews.search_skipped", extra={"reason": type(exc).__name__})
                continue
            except Exception as exc:  # noqa: BLE001 - one unreachable mailbox must not stop the search
                logger.warning("ews.search_failed", extra={"error": type(exc).__name__})
                continue
            query = account.inbox.all()
            if message_id:
                normalised = message_id if message_id.startswith("<") else f"<{message_id}>"
                query = account.inbox.filter(message_id=normalised)
            elif sender:
                query = account.inbox.filter(sender__icontains=sender)
            elif subject:
                query = account.inbox.filter(subject__icontains=subject)
            try:
                for item in query.only("subject", "sender", "message_id", "datetime_received")[
                    : limit - len(results)
                ]:
                    results.append(
                        ExchangeMessageRef(
                            mailbox=mailbox,
                            item_id=str(getattr(item, "id", "")),
                            internet_message_id=str(getattr(item, "message_id", "") or ""),
                            subject=str(getattr(item, "subject", "") or ""),
                            sender=str(getattr(getattr(item, "sender", None), "email_address", "") or ""),
                            received_at=getattr(item, "datetime_received", None),
                        )
                    )
            except Exception as exc:  # noqa: BLE001
                logger.warning("ews.search_error", extra={"error": type(exc).__name__})
        return results

    def _scope_mailboxes(self) -> list[str]:
        """Concrete mailbox addresses from the scope; domain entries cannot be enumerated here."""
        out = []
        for entry in self.config.mailbox_scope:
            entry = normalise_mailbox(entry)
            if entry and _MAILBOX_RE.match(entry):
                out.append(entry)
        return out

    # -- remediation --------------------------------------------------------------------------
    def request_remediation(self, request: RemediationRequest) -> RemediationOutcome:
        """Execute or simulate a remediation action.

        Refuses to execute unless the deployment explicitly enabled remediation, every target is
        within scope, and the caller asked for a real run. Anything else produces a dry-run
        report (ТЗ 20.2).
        """
        mailboxes = sorted({normalise_mailbox(t.mailbox) for t in request.targets if t.mailbox})
        outcome = RemediationOutcome(
            action=request.action,
            dry_run=request.dry_run,
            affected_messages=len(request.targets),
            affected_mailboxes=mailboxes,
            rollback_supported=request.action is RemediationType.QUARANTINE,
        )

        own = normalise_mailbox(self.config.primary_smtp_address or self.config.username)
        out_of_scope = [
            mailbox for mailbox in mailboxes if not mailbox_in_scope(mailbox, self.config.mailbox_scope, own)
        ]
        if out_of_scope:
            outcome.errors.append(
                f"{len(out_of_scope)} mailbox(es) are outside the granted scope and were refused"
            )
            outcome.detail["out_of_scope"] = out_of_scope[:20]
            return outcome

        for blocker in self.blockers():
            outcome.warnings.append(f"blocker: {blocker}")

        if request.dry_run:
            outcome.warnings.append("dry-run: no changes were made in Exchange")
            outcome.detail["would_affect"] = len(request.targets)
            return outcome

        if not self.config.remediation_account_enabled:
            outcome.errors.append(
                "remediation is disabled for this deployment: enable it deliberately after the "
                "security acceptance (ТЗ 20)"
            )
            return outcome
        if not request.approved_by:
            outcome.errors.append("execution requires at least one recorded approval")
            return outcome

        try:
            self._require(ExchangeCapability.REMEDIATION)
        except CapabilityUnavailable as exc:
            outcome.errors.append(str(exc))
            return outcome

        handler = {
            RemediationType.QUARANTINE: self._quarantine,
            RemediationType.DELETE: self._delete,
            RemediationType.LOCATE: self._locate,
        }.get(request.action)
        if handler is None:
            outcome.errors.append(
                f"action '{request.action.value}' is prepared as a proposal but is not executed "
                "through EWS; apply it in Exchange with the recorded approval"
            )
            return outcome

        affected = 0
        for target in request.targets:
            try:
                handler(target)
                affected += 1
            except Exception as exc:  # noqa: BLE001 - one failure must not abort the rest
                logger.warning("ews.remediation_item_failed", extra={"error": type(exc).__name__})
                outcome.warnings.append(f"{target.mailbox}: {type(exc).__name__}")
        outcome.affected_messages = affected
        outcome.executed = affected > 0
        if request.action is RemediationType.QUARANTINE and outcome.executed:
            outcome.rollback_token = f"folder:{self.config.quarantine_folder}"
        return outcome

    def _quarantine(self, ref: ExchangeMessageRef) -> None:
        """Move the message to a dedicated folder. Reversible, and therefore preferred."""
        account = self._account_for(ref.mailbox)
        item = self._find_item(ref)
        folder = self._ensure_quarantine_folder(account)
        item.move(folder)

    def _delete(self, ref: ExchangeMessageRef) -> None:
        """Soft delete: the item goes to Recoverable Items, not to nothing."""
        item = self._find_item(ref)
        item.soft_delete()

    def _locate(self, ref: ExchangeMessageRef) -> None:
        self._find_item(ref)

    def _ensure_quarantine_folder(self, account: Any) -> Any:
        from exchangelib import Folder

        name = self.config.quarantine_folder
        existing = [f for f in account.root.walk() if f.name == name]
        if existing:
            return existing[0]
        folder = Folder(parent=account.msg_folder_root, name=name)
        folder.save()
        return folder


def build_provider(config: EwsConfig) -> OnPremEwsExchangeProvider:
    return OnPremEwsExchangeProvider(config)


def probe_environment(config: EwsConfig) -> dict[str, Any]:
    """Run a one-off capability probe. Used by the deployment checklist (ТЗ 44, 51)."""
    provider = OnPremEwsExchangeProvider(config)
    try:
        report = provider.discover()
        return {
            "configured": config.configured,
            "blockers": provider.blockers(),
            **report.as_dict(),
        }
    finally:
        provider.close()
