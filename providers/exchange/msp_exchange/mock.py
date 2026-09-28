"""In-memory Exchange provider for development, CI and pilot dry-runs (ТЗ 7)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from msp_contracts import ProviderHealth, RemediationType

from .base import (
    ExchangeCapability,
    ExchangeMessageRef,
    FetchedMessage,
    RemediationOutcome,
    RemediationRequest,
)


@dataclass
class MockExchangeProvider:
    """Backed by an in-memory mailbox map: mailbox -> {key: raw MIME}."""

    provider_id: str = "mock_exchange"
    mailboxes: dict[str, dict[str, bytes]] = field(default_factory=dict)
    reports: list[dict[str, str]] = field(default_factory=list)
    remediation_enabled: bool = False
    executed_actions: list[RemediationOutcome] = field(default_factory=list)

    def add_message(self, mailbox: str, raw: bytes, *, message_id: str = "", subject: str = "", sender: str = "") -> ExchangeMessageRef:
        key = message_id or f"mock-{uuid.uuid4().hex[:12]}"
        self.mailboxes.setdefault(mailbox.lower(), {})[key] = raw
        return ExchangeMessageRef(
            mailbox=mailbox.lower(),
            message_id=key,
            item_id=key,
            internet_message_id=key,
            subject=subject,
            sender=sender,
        )

    def health(self) -> ProviderHealth:
        return ProviderHealth(provider_id=self.provider_id, status="ok", mode="mock")

    def capabilities(self) -> set[ExchangeCapability]:
        caps = {
            ExchangeCapability.GET_MESSAGE,
            ExchangeCapability.GET_HEADERS,
            ExchangeCapability.GET_ATTACHMENTS,
            ExchangeCapability.SEARCH,
            ExchangeCapability.SUBMIT_REPORT,
        }
        if self.remediation_enabled:
            caps.add(ExchangeCapability.REMEDIATION)
        return caps

    def _raw(self, ref: ExchangeMessageRef) -> bytes:
        box = self.mailboxes.get(ref.mailbox.lower(), {})
        raw = box.get(ref.key())
        if raw is None:
            raise KeyError(f"message {ref.key()} not found in {ref.mailbox}")
        return raw

    def get_message(self, ref: ExchangeMessageRef) -> FetchedMessage:
        return FetchedMessage(ref=ref, raw_mime=self._raw(ref), source=self.provider_id)

    def get_message_headers(self, ref: ExchangeMessageRef) -> dict[str, str]:
        from email import message_from_bytes, policy

        msg = message_from_bytes(self._raw(ref).split(b"\r\n\r\n", 1)[0], policy=policy.compat32)
        return {str(k): str(v) for k, v in msg.items()}

    def get_attachments(self, ref: ExchangeMessageRef) -> list[tuple[str, bytes]]:
        from msp_mail_parser import parse_message

        parsed = parse_message(self._raw(ref))
        return [
            (a.meta.normalized_filename, a.content)
            for a in parsed.attachments
            if a.content is not None and a.meta.depth == 0
        ]

    def submit_report(self, ref: ExchangeMessageRef, reported_by: str, note: str = "") -> str:
        report_id = f"report-{uuid.uuid4().hex[:12]}"
        self.reports.append(
            {"report_id": report_id, "mailbox": ref.mailbox, "key": ref.key(), "by": reported_by, "note": note}
        )
        return report_id

    def search_related_messages(
        self, *, sender: str = "", subject: str = "", message_id: str = "", limit: int = 100
    ) -> list[ExchangeMessageRef]:
        from msp_mail_parser import parse_message

        out: list[ExchangeMessageRef] = []
        for mailbox, items in self.mailboxes.items():
            for key, raw in items.items():
                if len(out) >= limit:
                    return out
                parsed = parse_message(raw)
                if message_id and parsed.message_id.strip("<>") != message_id.strip("<>"):
                    continue
                if sender and (parsed.from_ is None or parsed.from_.address != sender.lower()):
                    continue
                if subject and subject.lower() not in parsed.subject.lower():
                    continue
                out.append(
                    ExchangeMessageRef(
                        mailbox=mailbox,
                        message_id=parsed.message_id,
                        item_id=key,
                        subject=parsed.subject,
                        sender=parsed.from_.address if parsed.from_ else "",
                    )
                )
        return out

    def request_remediation(self, request: RemediationRequest) -> RemediationOutcome:
        mailboxes = sorted({t.mailbox for t in request.targets})
        outcome = RemediationOutcome(
            action=request.action,
            dry_run=request.dry_run,
            affected_messages=len(request.targets),
            affected_mailboxes=mailboxes,
            rollback_supported=request.action is RemediationType.QUARANTINE,
        )
        if request.dry_run:
            outcome.warnings.append("dry-run: no changes were made in Exchange")
            return outcome
        if not self.remediation_enabled:
            outcome.errors.append("remediation account is disabled for this provider")
            return outcome
        if request.action in {RemediationType.DELETE, RemediationType.QUARANTINE}:
            for target in request.targets:
                self.mailboxes.get(target.mailbox, {}).pop(target.key(), None)
        outcome.executed = True
        if outcome.rollback_supported:
            outcome.rollback_token = f"rollback-{uuid.uuid4().hex[:12]}"
        self.executed_actions.append(outcome)
        return outcome
