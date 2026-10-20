"""Сводный анализ одного письма: сканер + аутентификация + HELO + класс + сигналы (ТЗ 1.2 §6–§13, §26).

Единственное место, где результаты собираются вместе. Результат — данные для движка риска и для
консоли; действий над почтой здесь нет: ``applied_action`` всегда ``OBSERVE_ONLY``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .auth import authentication
from .classification import BulkSignals, SpamClassification, bulk_signals, classify
from .helo import helo_evidence, top_received
from .mapping import MappedSignals, SymbolMapping, apply_mapping
from .model import (
    AppliedAction,
    AuthEvidence,
    HeloEvidence,
    RspamdEvidence,
    SpamClass,
    SuggestedAction,
)
from .policy import RspamdActionPolicy, SpamPolicy
from .rspamd_result import parse_scan


@dataclass
class AntispamAnalysis:
    evidence: RspamdEvidence | None
    auth: AuthEvidence | None
    helo: HeloEvidence | None
    classification: SpamClassification
    bulk: BulkSignals
    signals: MappedSignals | None
    suggested_action: SuggestedAction
    applied_action: AppliedAction = AppliedAction.OBSERVE_ONLY
    #: Чего не хватило. Недоступный сканер — это недостающее свидетельство, а не «чисто».
    missing_evidence: list[str] = field(default_factory=list)
    symbol_mapping_version: str = ""
    incomplete: bool = False

    @property
    def spam_class(self) -> SpamClass:
        return self.classification.spam_class


def analyze(
    record: Mapping[str, Any] | None,
    policy: SpamPolicy,
    *,
    headers: Mapping[str, Iterable[str] | str] | None = None,
    received_headers: Iterable[str] = (),
    protected_domains: Iterable[str] = (),
    secret_provider_ids: Iterable[str] = (),
    mapping: SymbolMapping | None = None,
    client_is_trusted: bool = False,
    peername_lookup: bool = True,
    recipient_count: int = 0,
    known_bulk_domains: Iterable[str] = (),
) -> AntispamAnalysis:
    """Анализ по записи сканера. ``record=None`` — сканер письмо не видел (недоступен, пропустил)."""
    action_policy = RspamdActionPolicy(policy.mode)
    headers = headers or {}
    if record is None:
        return AntispamAnalysis(
            evidence=None,
            auth=None,
            helo=None,
            classification=classify(None, policy),
            bulk=BulkSignals(),
            signals=None,
            suggested_action=SuggestedAction.UNKNOWN,
            applied_action=action_policy.applied(SuggestedAction.UNKNOWN),
            missing_evidence=["RSPAMD_SCAN_UNAVAILABLE"],
            incomplete=True,
        )

    evidence = parse_scan(record, secret_provider_ids=secret_provider_ids)
    top = top_received(list(received_headers))
    helo_text, rdns = (top[0], top[1]) if top else ("", "")
    evidence.helo = helo_text or evidence.helo
    from_header = record.get("header_from") or _as_list(headers.get("from"))
    auth = authentication(evidence, from_header=from_header, helo=helo_text)
    helo = helo_evidence(
        helo_text,
        rdns=rdns,
        scan=evidence,
        protected_domains=protected_domains,
        client_is_trusted=client_is_trusted,
        peername_lookup=peername_lookup,
    )
    names = [s.name for s in evidence.symbols]
    sender_domain = auth.dmarc.from_domain
    bulk = bulk_signals(
        headers,
        names,
        recipient_count=recipient_count,
        sender_domain=sender_domain,
        known_bulk_domains=known_bulk_domains,
    )
    classification = classify(evidence, policy, bulk, auth)
    signals = apply_mapping(evidence, policy, mapping)
    missing: list[str] = []
    if auth.incomplete:
        missing.extend(auth.incomplete_reasons)
    if not top:
        missing.append("HELO_RECEIVED_UNAVAILABLE")
    return AntispamAnalysis(
        evidence=evidence,
        auth=auth,
        helo=helo,
        classification=classification,
        bulk=bulk,
        signals=signals,
        suggested_action=evidence.suggested_action,
        applied_action=action_policy.applied(evidence.suggested_action),
        missing_evidence=missing,
        symbol_mapping_version=signals.mapping_version,
        incomplete=bool(auth.incomplete_reasons and set(auth.incomplete_reasons) - {"AUTH_CHECKS_NOT_RUN"}),
    )


def _as_list(value: Iterable[str] | str | None) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)
