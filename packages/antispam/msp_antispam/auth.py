"""Нормализация результатов SPF, DKIM, DMARC и ARC из символов Rspamd (ТЗ 1.2 §8–§12).

Сами проверки выполняет Rspamd. Здесь результат сводится к единому словарю состояний, а
недостающее свидетельство (сбой DNS, проверка не запускалась) остаётся недостающим свидетельством:
ни ``TEMPERROR``, ни «проверки не было» не превращаются в ``FAIL`` (ТЗ 1.2 §30).

Важные свойства:

* несколько подписей DKIM оцениваются по лучшей: одна неудачная не отменяет корректную
  выровненную (§9);
* неподдерживаемая или слабая подпись — отдельное свидетельство, не ``PASS`` (§9);
* для пустого отправителя (null sender) SPF оценивается по HELO (§8);
* ``SPF_FAIL`` повышает риск, но ничего не отклоняет (§8).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

from msp_mail_parser.domains import split_domain

from .model import (
    ArcEvidence,
    ArcResult,
    AuthEvidence,
    DkimEvidence,
    DkimResult,
    DkimSignatureEvidence,
    DmarcEvidence,
    DmarcPolicy,
    DmarcResult,
    RspamdEvidence,
    RspamdSymbol,
    SpfEvidence,
    SpfResult,
    SuggestedDisposition,
)

_SPF = {
    "R_SPF_ALLOW": SpfResult.PASS,
    "R_SPF_FAIL": SpfResult.FAIL,
    "R_SPF_SOFTFAIL": SpfResult.SOFTFAIL,
    "R_SPF_NEUTRAL": SpfResult.NEUTRAL,
    "R_SPF_NA": SpfResult.NONE,
    "R_SPF_DNSFAIL": SpfResult.TEMPERROR,
    "R_SPF_PERMFAIL": SpfResult.PERMERROR,
}
_DKIM = {
    "R_DKIM_ALLOW": DkimResult.PASS,
    "R_DKIM_REJECT": DkimResult.FAIL,
    "R_DKIM_NA": DkimResult.NONE,
    "R_DKIM_TEMPFAIL": DkimResult.TEMPERROR,
    "R_DKIM_PERMFAIL": DkimResult.PERMERROR,
}
_ARC = {
    "ARC_ALLOW": ArcResult.PASS,
    "ARC_REJECT": ArcResult.FAIL,
    "ARC_INVALID": ArcResult.FAIL,
    "ARC_NA": ArcResult.NONE,
    "ARC_DNSFAIL": ArcResult.UNKNOWN,
}
#: Результат DMARC: (результат, политика), политика — то, что сканер сообщил при провале.
_DMARC = {
    "DMARC_POLICY_ALLOW": (DmarcResult.PASS, None),
    "DMARC_POLICY_ALLOW_WITH_FAILURES": (DmarcResult.PASS, None),
    "DMARC_POLICY_REJECT": (DmarcResult.FAIL, DmarcPolicy.REJECT),
    "DMARC_POLICY_QUARANTINE": (DmarcResult.FAIL, DmarcPolicy.QUARANTINE),
    "DMARC_POLICY_SOFTFAIL": (DmarcResult.FAIL, DmarcPolicy.NONE),
    "DMARC_NA": (DmarcResult.NONE, None),
    "DMARC_DNSFAIL": (DmarcResult.TEMPERROR, None),
    "DMARC_BAD_POLICY": (DmarcResult.PERMERROR, None),
}

_WEAK_WORDS = ("algorithm", "weak", "short", "unsupported", "sha1", "insecure", "key size")
_TEMP_WORDS = ("dns", "timeout", "timed out", "servfail", "temporar")

_ADDRESS = re.compile(r"[\w.+%\-]+@([\w.\-]+)")


def domain_of(address: str) -> str:
    """Домен адреса в нижнем регистре, без проверок: пустая строка, если адреса нет."""
    match = _ADDRESS.search(address or "")
    return match.group(1).lower().rstrip(".") if match else ""


def organizational_domain(host: str) -> str:
    """Организационный домен по публичному списку суффиксов (из пакета разбора почты)."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    parts = split_domain(host)
    return (parts.registrable_ascii or parts.registrable or host).lower()


def aligned(left: str, right: str, *, strict: bool = False) -> bool:
    """Выравнивание идентификаторов DMARC: точное совпадение (strict) или общий организационный домен."""
    left = (left or "").lower().rstrip(".")
    right = (right or "").lower().rstrip(".")
    if not left or not right:
        return False
    if strict:
        return left == right
    return organizational_domain(left) == organizational_domain(right)


def _first(symbols: Iterable[RspamdSymbol], table: Mapping[str, object]) -> RspamdSymbol | None:
    # Порядок таблицы — порядок предпочтения: содержательный результат выше «нет данных».
    by_name = {s.name: s for s in symbols}
    for name in table:
        if name in by_name:
            return by_name[name]
    return None


def _lower_options(symbol: RspamdSymbol | None) -> str:
    return " ".join(symbol.options).lower() if symbol else ""


# ---------------------------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------------------------
def spf_evidence(evidence: RspamdEvidence, *, helo: str = "") -> tuple[SpfEvidence, bool]:
    """Результат SPF и признак «проверка запускалась»."""
    symbol = _first(evidence.symbols, _SPF)
    sender = evidence.envelope_from
    null_sender = not sender or sender in ("<>", "unknown")
    identity = (helo or evidence.helo).lower() if null_sender else domain_of(sender)
    base = SpfEvidence(
        identity=identity,
        identity_kind="HELO" if null_sender else "MAIL_FROM",
        client_ip=evidence.client_ip,
    )
    if symbol is None:
        return base, False
    result = _SPF[symbol.name]
    reason = "; ".join(symbol.options)[:200]
    error_class = ""
    if result is SpfResult.TEMPERROR:
        error_class = "DNS_TEMPORARY"
    elif result is SpfResult.PERMERROR:
        error_class = "RECORD_INVALID_OR_LIMIT"
    return base.model_copy(update={"result": result, "reason": reason, "error_class": error_class}), True


# ---------------------------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------------------------
def _split_signature(option: str) -> tuple[str, str]:
    """``domain:s=selector`` -> (domain, selector)."""
    domain, _, rest = option.partition(":")
    selector = ""
    for part in rest.split(","):
        part = part.strip()
        if part.startswith("s="):
            selector = part[2:]
    return domain.strip().lower(), selector


def dkim_evidence(evidence: RspamdEvidence, from_domain: str) -> tuple[DkimEvidence, bool]:
    ran = False
    signatures: dict[tuple[str, str], DkimSignatureEvidence] = {}

    def entry(domain: str, selector: str) -> DkimSignatureEvidence:
        key = (domain, selector)
        if key not in signatures:
            signatures[key] = DkimSignatureEvidence(domain=domain, selector=selector)
        return signatures[key]

    for symbol in evidence.symbols:
        if symbol.name not in _DKIM:
            continue
        ran = True
        result = _DKIM[symbol.name]
        if result is DkimResult.NONE:
            continue
        for option in symbol.options or [""]:
            domain, selector = _split_signature(option)
            sig = entry(domain, selector)
            weak = any(word in option.lower() for word in _WEAK_WORDS)
            if result is DkimResult.PASS and not weak:
                sig.result = DkimResult.PASS
                sig.key_state = "VERIFIED"
            elif weak:
                sig.result = DkimResult.PERMERROR
                sig.unsupported_or_weak = True
                sig.key_state = "UNSUPPORTED_OR_WEAK"
            elif result is DkimResult.FAIL:
                sig.result = DkimResult.FAIL
                sig.key_state = "SIGNATURE_MISMATCH"
            elif result is DkimResult.TEMPERROR:
                sig.result = DkimResult.TEMPERROR
                sig.key_state = "DNS_ERROR"
            else:
                sig.result = DkimResult.PERMERROR
                sig.key_state = "KEY_INVALID_OR_MISSING"
            sig.reason = option[:200]
            sig.aligned = bool(domain) and aligned(domain, from_domain)

    # Подписи, о которых сообщил только DKIM_TRACE (домен и знак «+/-»), дополняют список.
    for symbol in evidence.symbols:
        if symbol.name != "DKIM_TRACE":
            continue
        ran = True
        for option in symbol.options:
            domain, _, sign = option.partition(":")
            domain = domain.strip().lower()
            if not domain:
                continue
            known = [s for s in signatures.values() if s.domain == domain]
            if not known:
                sig = entry(domain, "")
                sig.result = DkimResult.PASS if sign.strip().startswith("+") else DkimResult.FAIL
                sig.aligned = aligned(domain, from_domain)

    ordered = sorted(signatures.values(), key=lambda s: (s.domain, s.selector))
    # Итог по лучшей подписи: выровненная корректная выше любой неудачной.
    if any(s.result is DkimResult.PASS and s.aligned for s in ordered) or any(
        s.result is DkimResult.PASS for s in ordered
    ):
        overall = DkimResult.PASS
    elif any(s.result is DkimResult.TEMPERROR for s in ordered):
        overall = DkimResult.TEMPERROR
    elif any(s.result is DkimResult.FAIL for s in ordered):
        overall = DkimResult.FAIL
    elif any(s.result is DkimResult.PERMERROR for s in ordered):
        overall = DkimResult.PERMERROR
    else:
        overall = DkimResult.NONE
    return DkimEvidence(result=overall, signatures=ordered[:16]), ran


# ---------------------------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------------------------
def dmarc_evidence(
    evidence: RspamdEvidence, from_domain: str, spf: SpfEvidence, dkim: DkimEvidence
) -> tuple[DmarcEvidence, bool]:
    symbol = _first(evidence.symbols, _DMARC)
    spf_aligned = spf.result is SpfResult.PASS and aligned(spf.identity, from_domain)
    dkim_aligned = any(s.result is DkimResult.PASS and s.aligned for s in dkim.signatures)
    base = DmarcEvidence(from_domain=from_domain, spf_aligned=spf_aligned, dkim_aligned=dkim_aligned)
    if symbol is None:
        return base.model_copy(update={"spf_aligned": None, "dkim_aligned": None}), False
    result, policy = _DMARC[symbol.name]
    options = symbol.options
    # Первый параметр — «домен» либо «домен : причина»; второй (если есть) — политика.
    head = options[0] if options else ""
    policy_domain, _, head_reason = head.partition(" : ")
    policy_domain = policy_domain.strip().lower()
    if policy is None and len(options) > 1:
        try:
            policy = DmarcPolicy(options[1].strip().lower())
        except ValueError:
            policy = None
    disposition = SuggestedDisposition.NONE
    if result is DmarcResult.FAIL and policy is DmarcPolicy.REJECT:
        disposition = SuggestedDisposition.REJECT
    elif result is DmarcResult.FAIL and policy is DmarcPolicy.QUARANTINE:
        disposition = SuggestedDisposition.QUARANTINE
    meta = {"symbol": symbol.name}
    reason = "; ".join(part for part in [head_reason.strip(), *options[2:]] if part)
    if reason:
        meta["reason"] = reason[:200]
    return (
        base.model_copy(
            update={
                "result": result,
                "policy": policy,
                "policy_domain": policy_domain,
                "suggested_disposition": disposition,
                "policy_meta": meta,
                "discovery": "SCANNER",
            }
        ),
        True,
    )


# ---------------------------------------------------------------------------------------------
# ARC
# ---------------------------------------------------------------------------------------------
def arc_evidence(evidence: RspamdEvidence) -> tuple[ArcEvidence, bool]:
    symbol = _first(evidence.symbols, _ARC)
    if symbol is None:
        return ArcEvidence(), False
    domains: list[str] = []
    for option in symbol.options:
        domain = option.partition(":")[0].strip().lower()
        if domain and domain not in domains:
            domains.append(domain)
    return ArcEvidence(result=_ARC[symbol.name], instances=len(domains), signing_domains=domains[:16]), True


# ---------------------------------------------------------------------------------------------
# Сводка
# ---------------------------------------------------------------------------------------------
def from_domain_of(header_from: Iterable[str] | str | None) -> str:
    """Домен единственного адреса в заголовке From. При нескольких различных — пустая строка:
    выравнивание по неоднозначному From не определено (ТЗ 1.2 §24)."""
    if header_from is None:
        return ""
    values = [header_from] if isinstance(header_from, str) else list(header_from)
    domains = {domain_of(value) for value in values if domain_of(value)}
    return domains.pop() if len(domains) == 1 else ""


def authentication(
    evidence: RspamdEvidence, *, from_header: Iterable[str] | str | None = None, helo: str = ""
) -> AuthEvidence:
    """Единое свидетельство аутентификации письма."""
    from_domain = from_domain_of(from_header)
    spf, spf_ran = spf_evidence(evidence, helo=helo)
    dkim, dkim_ran = dkim_evidence(evidence, from_domain)
    dmarc, dmarc_ran = dmarc_evidence(evidence, from_domain, spf, dkim)
    arc, arc_ran = arc_evidence(evidence)
    reasons: list[str] = []
    if spf.result is SpfResult.TEMPERROR:
        reasons.append("SPF_TEMPERROR")
    if dkim.result is DkimResult.TEMPERROR:
        reasons.append("DKIM_TEMPERROR")
    if dmarc.result is DmarcResult.TEMPERROR:
        reasons.append("DMARC_TEMPERROR")
    if arc.result is ArcResult.UNKNOWN and arc_ran:
        reasons.append("ARC_UNKNOWN")
    if not (spf_ran and dkim_ran and dmarc_ran):
        reasons.append("AUTH_CHECKS_NOT_RUN")
    return AuthEvidence(
        spf=spf, dkim=dkim, dmarc=dmarc, arc=arc, incomplete=bool(reasons), incomplete_reasons=reasons
    )
