"""Конфликты результатов аутентификации: вышестоящий шлюз против MSP (ТЗ 1.2 §25, §41).

Если письмо уже прошло другой шлюз (KSMG и т.п.), у него есть собственные результаты SPF/DKIM/DMARC.
Расхождение с нашими не скрывается и не «разрешается» в чью-то пользу: оно записывается как
конфликт, и его рассматривает человек. Частая безобидная причина — разные адреса клиента:
вышестоящий шлюз проверял SPF по адресу настоящего отправителя, а мы видим адрес самого шлюза.

Чистый вердикт вышестоящего шлюза **не снижает** риск MSP.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from .authres import ParsedAuthResults
from .model import AuthEvidence, DkimResult, DmarcResult, SpfResult


class ConflictKind(StrEnum):
    SPF = "SPF_MISMATCH"
    DKIM = "DKIM_MISMATCH"
    DMARC = "DMARC_MISMATCH"
    CLIENT_IP = "CLIENT_IP_MISMATCH"
    AUTHSERV_ID = "AUTHSERV_ID_MISMATCH"


class Disposition(StrEnum):
    OPEN = "OPEN"
    EXPECTED = "EXPECTED"  # объяснено топологией (шлюз перед шлюзом)
    REAL_PROBLEM = "REAL_PROBLEM"
    FALSE_ALARM = "FALSE_ALARM"


@dataclass
class AuthenticationConflict:
    kind: ConflictKind
    upstream_value: str
    msp_value: str
    note: str = ""
    disposition: Disposition = Disposition.OPEN
    reviewed_by: str = ""


@dataclass
class ConflictReport:
    conflicts: list[AuthenticationConflict] = field(default_factory=list)

    @property
    def any(self) -> bool:
        return bool(self.conflicts)


_SPF = {
    SpfResult.PASS: "pass",
    SpfResult.FAIL: "fail",
    SpfResult.SOFTFAIL: "softfail",
    SpfResult.NEUTRAL: "neutral",
    SpfResult.NONE: "none",
    SpfResult.TEMPERROR: "temperror",
    SpfResult.PERMERROR: "permerror",
}


def _dkim_name(result: DkimResult) -> str:
    return {DkimResult.PASS: "pass", DkimResult.FAIL: "fail", DkimResult.NONE: "none"}.get(result, "error")


def _dmarc_name(result: DmarcResult) -> str:
    return {DmarcResult.PASS: "pass", DmarcResult.FAIL: "fail", DmarcResult.NONE: "none"}.get(result, "error")


def _comparable(value: str | None) -> str | None:
    if value is None:
        return None
    return "error" if value in ("temperror", "permerror") else value


def compare(
    upstream: ParsedAuthResults | None,
    msp: AuthEvidence,
    *,
    upstream_client_ip: str = "",
    msp_client_ip: str = "",
    expected_upstream_ids: tuple[str, ...] = (),
) -> ConflictReport:
    """Сравнить результаты вышестоящего шлюза с нашими. Без вышестоящих результатов конфликтов нет."""
    report = ConflictReport()
    if upstream is None:
        return report
    if expected_upstream_ids and upstream.authserv_id not in {e.lower() for e in expected_upstream_ids}:
        report.conflicts.append(
            AuthenticationConflict(
                ConflictKind.AUTHSERV_ID,
                upstream.authserv_id,
                "|".join(expected_upstream_ids),
                "authserv-id вышестоящих результатов не входит в модель доверия",
            )
        )
    checks = (
        (ConflictKind.SPF, _comparable(upstream.result_of("spf")), _comparable(_SPF[msp.spf.result])),
        (
            ConflictKind.DKIM,
            _comparable(upstream.result_of("dkim")),
            _comparable(_dkim_name(msp.dkim.result)),
        ),
        (
            ConflictKind.DMARC,
            _comparable(upstream.result_of("dmarc")),
            _comparable(_dmarc_name(msp.dmarc.result)),
        ),
    )
    for kind, theirs, ours in checks:
        if theirs is not None and ours is not None and theirs != ours:
            report.conflicts.append(AuthenticationConflict(kind, theirs, ours))
    if upstream_client_ip and msp_client_ip and upstream_client_ip != msp_client_ip:
        report.conflicts.append(
            AuthenticationConflict(
                ConflictKind.CLIENT_IP,
                upstream_client_ip,
                msp_client_ip,
                "разные адреса клиента: SPF у вышестоящего шлюза и у MSP проверялся по разным источникам",
            )
        )
        for conflict in report.conflicts:
            if conflict.kind is ConflictKind.SPF:
                conflict.note = "расхождение SPF объясняется разными адресами клиента"
    return report
