"""Класс спама и массовая рассылка (ТЗ 1.2 §13, §19).

Класс спама и вердикт безопасности — разные оси. ``SPAM + LOW_RISK`` (назойливая реклама без
вредоносной нагрузки) и ``NOT_SPAM + HIGH_RISK`` (аккуратное BEC-письмо без спам-признаков)
одинаково допустимы, поэтому здесь нет функции, сводящей их в одно число; интерфейс показывает оси
рядом.

Рассылка (``BULK``) отделена от вредоносного спама: легитимная рассылка с ``List-Unsubscribe``
не должна считаться спамом автоматически. Но признак рассылки не оправдывает письмо с очень
высокой оценкой — подпись «отписаться» подделывается легко.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from .model import ArcResult, AuthEvidence, DkimResult, RspamdEvidence, SpamClass
from .policy import SpamPolicy, class_for_score

#: Символы Rspamd, свидетельствующие о рассылке.
BULK_SYMBOLS = frozenset(
    {
        "HAS_LIST_UNSUB",
        "HAS_LIST_UNSUBSCRIBE",
        "PRECEDENCE_BULK",
        "MAILLIST",
        "BULK_HEADER",
        "FORGED_RECIPIENTS_MAILLIST",
        "LIST_UNSUBSCRIBE",
    }
)
LIST_HEADERS = ("list-id", "list-post", "list-help", "list-archive", "x-mailing-list", "x-mailman-version")


@dataclass
class BulkSignals:
    list_unsubscribe: bool = False
    list_headers: bool = False
    precedence_bulk: bool = False
    high_recipient_volume: bool = False
    known_bulk_infrastructure: bool = False
    template_similarity: bool = False
    reasons: list[str] = field(default_factory=list)

    @property
    def is_bulk(self) -> bool:
        return (
            self.list_unsubscribe
            or self.list_headers
            or self.precedence_bulk
            or self.known_bulk_infrastructure
            or (self.high_recipient_volume and self.template_similarity)
        )

    @property
    def is_mailing_list(self) -> bool:
        return self.list_headers


def bulk_signals(
    headers: Mapping[str, Iterable[str] | str],
    symbols: Iterable[str] = (),
    *,
    recipient_count: int = 0,
    sender_domain: str = "",
    known_bulk_domains: Iterable[str] = (),
    template_similarity: bool = False,
    volume_threshold: int = 50,
) -> BulkSignals:
    """Признаки рассылки по заголовкам письма и символам сканера."""
    lowered = {str(k).lower(): v for k, v in headers.items()}
    names = set(lowered)
    symbol_set = set(symbols)
    signals = BulkSignals(template_similarity=template_similarity)
    if "list-unsubscribe" in names or symbol_set & {
        "HAS_LIST_UNSUB",
        "HAS_LIST_UNSUBSCRIBE",
        "LIST_UNSUBSCRIBE",
    }:
        signals.list_unsubscribe = True
        signals.reasons.append("LIST_UNSUBSCRIBE")
    if names & set(LIST_HEADERS) or "MAILLIST" in symbol_set:
        signals.list_headers = True
        signals.reasons.append("MAILING_LIST_HEADERS")
    precedence = lowered.get("precedence", "")
    precedence_text = " ".join(precedence) if not isinstance(precedence, str) else precedence
    if precedence_text.strip().lower() in ("bulk", "list", "junk") or "PRECEDENCE_BULK" in symbol_set:
        signals.precedence_bulk = True
        signals.reasons.append("PRECEDENCE_BULK")
    if recipient_count >= volume_threshold:
        signals.high_recipient_volume = True
        signals.reasons.append("HIGH_RECIPIENT_VOLUME")
    domain = (sender_domain or "").lower()
    if domain and any(domain == d.lower() or domain.endswith("." + d.lower()) for d in known_bulk_domains):
        signals.known_bulk_infrastructure = True
        signals.reasons.append("KNOWN_BULK_INFRASTRUCTURE")
    if template_similarity:
        signals.reasons.append("TEMPLATE_SIMILARITY")
    return signals


@dataclass
class SpamClassification:
    spam_class: SpamClass
    reasons: list[str] = field(default_factory=list)
    #: Письмо похоже на пересылку или список рассылки: нарушение DKIM здесь ожидаемо (§19).
    forwarding_or_list_context: bool = False


def classify(
    evidence: RspamdEvidence | None,
    policy: SpamPolicy,
    bulk: BulkSignals | None = None,
    auth: AuthEvidence | None = None,
) -> SpamClassification:
    """Класс спама. Без записи сканера — ``UNKNOWN``, а не ``NOT_SPAM``: отсутствие данных не
    означает отсутствия спама."""
    if evidence is None:
        return SpamClassification(SpamClass.UNKNOWN, ["NO_SCAN_EVIDENCE"])
    base = class_for_score(evidence.score, policy.thresholds)
    reasons = [f"SCORE_{base.value}"]
    bulk = bulk or BulkSignals()
    context = False
    if auth is not None and (bulk.is_mailing_list or auth.arc.result is ArcResult.PASS):
        # Список рассылки и пересылка ломают подпись DKIM: сама по себе потеря подписи тут не признак спама.
        context = auth.dkim.result in (DkimResult.FAIL, DkimResult.NONE)
        if context:
            reasons.append("DKIM_BREAKAGE_EXPECTED_FOR_LIST_OR_FORWARD")
    if bulk.is_bulk and base in (SpamClass.NOT_SPAM, SpamClass.SUSPECTED_SPAM, SpamClass.SPAM):
        # Настоящий список рассылки не спам автоматически; чужая реклама с кнопкой «отписаться» при
        # высокой оценке остаётся спамом.
        if base is SpamClass.SPAM and not bulk.is_mailing_list:
            reasons.extend(bulk.reasons)
            return SpamClassification(SpamClass.SPAM, reasons, context)
        reasons.extend(bulk.reasons)
        return SpamClassification(SpamClass.BULK, reasons, context)
    return SpamClassification(base, reasons, context)
