"""Доверенный ``Authentication-Results`` (RFC 8601; ТЗ 1.2 §12).

Заголовок в письме — это текст, который мог написать кто угодно, в том числе от имени нашего
authserv-id. Поэтому доверие строится не на заголовке, а на записи сканера, пришедшей по
собственному каналу узла:

* доверенный ``Authentication-Results`` MSP **собирает сам** из записи сканера
  (``build_authentication_results``) и подаёт в движок обнаружения; заголовок из письма движку
  не передаётся никогда;
* заголовок с нашим authserv-id, пришедший в письме, сверяется с записью сканера. Расхождение
  или второй такой заголовок — признак подделки (``AuthResHeaderFinding``), а не доказательство;
* если записи сканера нет (сканер был недоступен), заголовок с нашим authserv-id не доверяется
  вовсе: именно в этот момент подделка и была бы незаметна.

Чужие authserv-id (вышестоящий шлюз) не удаляются и не доверяются здесь: их разбирает общая модель
доверия платформы по цепочке Received.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .model import AuthEvidence, DkimResult, DmarcResult, SpfResult

_RESINFO = re.compile(
    r"(?P<method>[a-zA-Z][a-zA-Z0-9\-]*)\s*=\s*(?P<result>[a-zA-Z]+)(?P<rest>(?:\s*\([^)]*\))?(?:\s+[\w.\-]+\.[\w.\-]+=(?:\"[^\"]*\"|[^;\s]+))*)"
)
_PROP = re.compile(r"(?P<key>[\w.\-]+\.[\w.\-]+)=(?P<value>\"[^\"]*\"|[^;\s]+)")

_RESULT_NAMES = {
    SpfResult.PASS: "pass",
    SpfResult.FAIL: "fail",
    SpfResult.SOFTFAIL: "softfail",
    SpfResult.NEUTRAL: "neutral",
    SpfResult.NONE: "none",
    SpfResult.TEMPERROR: "temperror",
    SpfResult.PERMERROR: "permerror",
}


@dataclass
class ParsedMethod:
    method: str
    result: str
    properties: dict[str, str] = field(default_factory=dict)


@dataclass
class ParsedAuthResults:
    authserv_id: str
    methods: list[ParsedMethod] = field(default_factory=list)

    def result_of(self, method: str) -> str | None:
        for item in self.methods:
            if item.method == method:
                return item.result
        return None


def parse_authentication_results(value: str) -> ParsedAuthResults | None:
    """Разобрать значение заголовка. ``None``, если authserv-id не распознан."""
    body = " ".join((value or "").split())
    # Допускается значение вместе с именем поля: так заголовок выглядит в тексте письма.
    body = re.sub(r"^authentication-results\s*:\s*", "", body, flags=re.IGNORECASE)
    if not body:
        return None
    head, _, tail = body.partition(";")
    tokens = head.strip().split()
    # authserv-id и необязательный номер версии (RFC 8601 §2.2); всё прочее — не заголовок.
    if not tokens or len(tokens) > 2 or (len(tokens) == 2 and not tokens[1].isdigit()):
        return None
    authserv = tokens[0].lower()
    if not re.fullmatch(r"[a-z0-9.\-]{1,253}", authserv):
        return None
    parsed = ParsedAuthResults(authserv_id=authserv)
    for chunk in tail.split(";"):
        match = _RESINFO.search(chunk.strip())
        if not match:
            continue
        properties = {
            m.group("key").lower(): m.group("value").strip('"') for m in _PROP.finditer(match.group("rest"))
        }
        parsed.methods.append(
            ParsedMethod(match.group("method").lower(), match.group("result").lower(), properties)
        )
    return parsed


def build_authentication_results(
    authserv_id: str, auth: AuthEvidence, *, smtp_mailfrom: str = "", header_from: str = ""
) -> str:
    """Доверенный заголовок, собранный из записи сканера."""
    parts = [authserv_id.lower()]
    spf = f"spf={_RESULT_NAMES.get(auth.spf.result, 'none')}"
    if smtp_mailfrom:
        spf += f" smtp.mailfrom={smtp_mailfrom}"
    parts.append(spf)
    if auth.dkim.signatures:
        for signature in auth.dkim.signatures:
            name = {DkimResult.PASS: "pass", DkimResult.FAIL: "fail", DkimResult.TEMPERROR: "temperror"}.get(
                signature.result, "permerror"
            )
            parts.append(f"dkim={name} header.d={signature.domain or 'unknown'}")
    else:
        parts.append("dkim=none")
    dmarc_name = {
        DmarcResult.PASS: "pass",
        DmarcResult.FAIL: "fail",
        DmarcResult.NONE: "none",
        DmarcResult.TEMPERROR: "temperror",
        DmarcResult.PERMERROR: "permerror",
    }[auth.dmarc.result]
    dmarc = f"dmarc={dmarc_name}"
    if header_from:
        dmarc += f" header.from={header_from}"
    parts.append(dmarc)
    return "; ".join(parts)


@dataclass
class AuthResHeaderFinding:
    """Что нашлось среди заголовков ``Authentication-Results`` письма."""

    ours: list[str] = field(default_factory=list)
    others: list[str] = field(default_factory=list)
    #: Подделка или расхождение: причины, понятные аналитику.
    anomalies: list[str] = field(default_factory=list)

    @property
    def tampered(self) -> bool:
        return bool(self.anomalies)


def inspect_headers(
    headers: list[str], our_authserv_id: str, scan_auth: AuthEvidence | None
) -> AuthResHeaderFinding:
    """Сверить заголовки письма с записью сканера.

    ``scan_auth`` — свидетельство из записи сканера или ``None``, если сканер письмо не видел.
    """
    finding = AuthResHeaderFinding()
    ours_id = our_authserv_id.lower()
    for raw in headers:
        parsed = parse_authentication_results(raw)
        if parsed is not None and parsed.authserv_id == ours_id:
            finding.ours.append(raw)
        else:
            finding.others.append(raw)
    if not finding.ours:
        return finding
    if scan_auth is None:
        finding.anomalies.append("OUR_AUTHSERV_ID_WITHOUT_SCAN_RECORD")
        return finding
    if len(finding.ours) > 1:
        finding.anomalies.append("DUPLICATE_OUR_AUTHSERV_ID")
    parsed = parse_authentication_results(finding.ours[0])
    if parsed is None:
        finding.anomalies.append("OUR_HEADER_UNPARSEABLE")
        return finding
    claimed_spf = parsed.result_of("spf")
    actual_spf = _RESULT_NAMES.get(scan_auth.spf.result)
    if claimed_spf and actual_spf and claimed_spf != actual_spf:
        finding.anomalies.append("SPF_MISMATCH_WITH_SCAN_RECORD")
    claimed_dmarc = parsed.result_of("dmarc")
    if claimed_dmarc and claimed_dmarc != scan_auth.dmarc.result.value.lower():
        finding.anomalies.append("DMARC_MISMATCH_WITH_SCAN_RECORD")
    return finding
