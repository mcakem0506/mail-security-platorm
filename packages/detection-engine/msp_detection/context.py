"""Analysis context: organisation data, protected identities, policy and exceptions.

The context is assembled by the API/worker from the database and passed to the engines, so the
detection packages stay free of database and network dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from msp_contracts import ExceptionType, IntakeSource, ProtectedCategory, utcnow
from msp_mail_parser import split_domain, to_ascii

from .similarity import common_service_targets, name_tokens, skeleton


@dataclass(frozen=True)
class ProtectedIdentity:
    identity_id: str
    display_name: str
    email: str
    categories: tuple[ProtectedCategory, ...] = ()
    aliases: tuple[str, ...] = ()  # additional email addresses
    name_variants: tuple[str, ...] = ()  # additional canonical names
    approved_delegates: tuple[str, ...] = ()  # emails allowed to write on their behalf
    approved_external_systems: tuple[str, ...] = ()  # domains allowed to use this identity
    department: str = ""
    title: str = ""
    enabled: bool = True

    @property
    def all_emails(self) -> tuple[str, ...]:
        return (self.email, *self.aliases)

    @property
    def all_names(self) -> tuple[str, ...]:
        return (self.display_name, *self.name_variants)


@dataclass(frozen=True)
class DirectoryUser:
    email: str
    display_name: str
    aliases: tuple[str, ...] = ()
    department: str = ""
    title: str = ""
    enabled: bool = True


@dataclass(frozen=True)
class ActiveException:
    exception_id: str
    exception_type: ExceptionType
    value: str
    rule_id: str | None = None
    owner: str = ""
    reason: str = ""
    expires_at: datetime | None = None

    def is_active(self, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return True
        return (now or utcnow()) < self.expires_at


@dataclass
class DetectionPolicy:
    """Thresholds and toggles that tune detection without code changes."""

    suspicious_threshold: int = 25
    high_risk_threshold: int = 50
    malicious_threshold: int = 80
    treat_dmarc_fail_as_hard: bool = False
    url_fetch_enabled: bool = False
    semantic_analysis_enabled: bool = False
    lookalike_check_common_services: bool = True
    max_reasons_employee: int = 5


@dataclass
class SenderHistory:
    """What the platform has seen about this sender before (ТЗ 16.3)."""

    known_sender: bool = False
    first_seen: datetime | None = None
    message_count: int = 0
    distinct_recipients: int = 0
    previously_reported: int = 0
    previously_malicious: int = 0


@dataclass
class AnalysisContext:
    organization_id: str = "default"
    organization_name: str = ""
    corporate_domains: tuple[str, ...] = ()
    trusted_infrastructure_domains: tuple[str, ...] = ()
    # Gateways the organisation runs itself (ksmg, eop, spamassassin, virus_scanner). Only their
    # headers are trusted: any sender can claim their message was already scanned.
    trusted_gateways: tuple[str, ...] = ()
    protected_identities: tuple[ProtectedIdentity, ...] = ()
    directory_users: tuple[DirectoryUser, ...] = ()
    exceptions: tuple[ActiveException, ...] = ()
    policy: DetectionPolicy = field(default_factory=DetectionPolicy)
    source: IntakeSource = IntakeSource.ADDIN
    reported_by: str | None = None
    recipient_department: str = ""
    recipient_is_protected: bool = False
    sender_history: SenderHistory = field(default_factory=SenderHistory)
    now: datetime = field(default_factory=utcnow)

    # ---- derived lookups (built lazily and cached) -----------------------------------------
    def __post_init__(self) -> None:
        self._corp_ascii = {to_ascii(d) for d in self.corporate_domains if d}
        self._corp_targets: dict[str, str] = dict.fromkeys(self._corp_ascii, "organization")
        self._corp_labels: dict[str, str] = {}
        for d in self._corp_ascii:
            self._corp_labels.setdefault(split_domain(d).label, d)
        self._email_index: dict[str, ProtectedIdentity] = {}
        self._name_index: dict[str, list[ProtectedIdentity]] = {}
        for pi in self.protected_identities:
            if not pi.enabled:
                continue
            for email in pi.all_emails:
                if email:
                    self._email_index[email.lower()] = pi
            for name in pi.all_names:
                for key in {skeleton(name), " ".join(sorted(skeleton(t) for t in name_tokens(name)))}:
                    if key:
                        self._name_index.setdefault(key, []).append(pi)
        self._dir_email: dict[str, DirectoryUser] = {}
        self._dir_names: dict[str, list[DirectoryUser]] = {}
        for du in self.directory_users:
            self._dir_email[du.email.lower()] = du
            for alias in du.aliases:
                self._dir_email.setdefault(alias.lower(), du)
            key = " ".join(sorted(skeleton(t) for t in name_tokens(du.display_name)))
            if key:
                self._dir_names.setdefault(key, []).append(du)
        self._active_exceptions = tuple(e for e in self.exceptions if e.is_active(self.now))
        if self.policy.lookalike_check_common_services:
            svc_targets, svc_labels = common_service_targets()
        else:
            svc_targets, svc_labels = {}, {}
        self._service_targets = svc_targets
        self._service_labels = svc_labels

    # -- domains
    @property
    def corporate_domains_ascii(self) -> set[str]:
        return self._corp_ascii

    def is_corporate_domain(self, domain: str) -> bool:
        d = to_ascii(domain)
        return bool(d) and (d in self._corp_ascii or any(d.endswith("." + c) for c in self._corp_ascii))

    def is_internal_address(self, address: str) -> bool:
        return "@" in address and self.is_corporate_domain(address.rsplit("@", 1)[1])

    def is_trusted_infrastructure(self, domain: str) -> bool:
        d = to_ascii(domain)
        return any(d == t or d.endswith("." + t) for t in map(to_ascii, self.trusted_infrastructure_domains))

    @property
    def corporate_targets(self) -> dict[str, str]:
        return self._corp_targets

    @property
    def corporate_labels(self) -> dict[str, str]:
        return self._corp_labels

    @property
    def service_targets(self) -> dict[str, str]:
        return self._service_targets

    @property
    def service_labels(self) -> dict[str, str]:
        return self._service_labels

    # -- identities
    def protected_by_email(self, address: str) -> ProtectedIdentity | None:
        return self._email_index.get((address or "").lower())

    def protected_by_name(self, display_name: str) -> list[ProtectedIdentity]:
        if not display_name:
            return []
        direct = self._name_index.get(skeleton(display_name))
        if direct:
            return direct
        key = " ".join(sorted(skeleton(t) for t in name_tokens(display_name)))
        return self._name_index.get(key, [])

    def directory_by_email(self, address: str) -> DirectoryUser | None:
        return self._dir_email.get((address or "").lower())

    def directory_by_name(self, display_name: str) -> list[DirectoryUser]:
        key = " ".join(sorted(skeleton(t) for t in name_tokens(display_name)))
        return self._dir_names.get(key, [])

    # -- exceptions
    @property
    def active_exceptions(self) -> tuple[ActiveException, ...]:
        return self._active_exceptions

    def matching_exception(
        self, *, sender: str = "", domain: str = "", rule_id: str = ""
    ) -> ActiveException | None:
        sender = (sender or "").lower()
        domain = to_ascii(domain)
        sender_domain = sender.rsplit("@", 1)[1] if "@" in sender else ""
        for exc in self._active_exceptions:
            value = (exc.value or "").lower()
            match exc.exception_type:
                case ExceptionType.TRUSTED_SENDER if value == sender:
                    return exc
                case ExceptionType.TRUSTED_DOMAIN if value and (
                    domain == to_ascii(value)
                    or domain.endswith("." + to_ascii(value))
                    or sender_domain == to_ascii(value)
                ):
                    return exc
                case ExceptionType.TRUSTED_SENDER_DOMAIN_PAIR if value == f"{sender}|{domain}":
                    return exc
                case ExceptionType.APPROVED_DELEGATED_SERVICE | ExceptionType.APPROVED_MARKETING_PLATFORM if (
                    value in {sender, sender_domain, domain}
                ):
                    return exc
                case ExceptionType.RULE_SUPPRESSION if (
                    exc.rule_id
                    and rule_id == exc.rule_id
                    and (not value or value in {sender, sender_domain, domain})
                ):
                    return exc
                case ExceptionType.TEMPORARY if value in {sender, sender_domain, domain}:
                    return exc
                case _:
                    continue
        return None
