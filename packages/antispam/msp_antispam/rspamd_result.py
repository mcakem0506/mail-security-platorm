"""Разбор результата сканирования Rspamd в ``RspamdEvidence`` (ТЗ 1.2 §6, §7).

Источник — запись, которую сам сканер отправил приёмнику узла, а не заголовки письма. Заголовки
``X-Spamd-*`` могла написать любая сторона, поэтому читаются они только затем, чтобы
зафиксировать факт подделки (см. ``forged_scanner_headers``).

Вход не доверяется по размеру и форме: число символов, длина имён и параметров ограничены,
неожиданные типы пропускаются, а не приводят к исключению. Разбор не бросает исключение на любом
JSON-объекте — сбой разбора одного письма не должен останавливать приём остальных.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

from .model import Direction, RspamdEvidence, RspamdSymbol, SuggestedAction

MAX_SYMBOLS = 512
MAX_OPTIONS = 32
MAX_OPTION_LENGTH = 256
MAX_NAME_LENGTH = 128

_SYMBOL_NAME = re.compile(r"^[A-Za-z0-9_]{1,128}$")

_ACTIONS = {
    "no action": SuggestedAction.NO_ACTION,
    "greylist": SuggestedAction.GREYLIST,
    "add header": SuggestedAction.ADD_HEADER,
    "rewrite subject": SuggestedAction.REWRITE_SUBJECT,
    "soft reject": SuggestedAction.SOFT_REJECT,
    "reject": SuggestedAction.REJECT,
}

#: Символы, которыми правило настроек помечает направление письма.
DIRECTION_SYMBOLS = {
    "MSP_DIRECTION_INBOUND": Direction.INBOUND,
    "MSP_DIRECTION_OUTBOUND": Direction.OUTBOUND,
    "MSP_DIRECTION_INTERNAL_TEST": Direction.INTERNAL_TEST,
}

#: Заголовки сканера, которые не должны приходить в письме извне. Их наличие — признак подделки.
SCANNER_HEADERS = (
    "x-spamd-result",
    "x-spamd-bar",
    "x-spam-status",
    "x-spam",
    "x-spam-level",
    "x-spam-flag",
    "x-rspamd-score",
    "x-rspamd-action",
    "x-rspamd-server",
    "x-rspamd-queue-id",
)


def suggested_action(value: object) -> SuggestedAction:
    if isinstance(value, str):
        return _ACTIONS.get(value.strip().lower(), SuggestedAction.UNKNOWN)
    return SuggestedAction.UNKNOWN


def _number(value: object, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        number = float(value)
        if number != number or number in (float("inf"), float("-inf")):
            return default
        return number
    if isinstance(value, str):
        try:
            number = float(value)
        except ValueError:
            return default
        if number != number or number in (float("inf"), float("-inf")):
            return default
        return number
    return default


def _text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = "".join(ch if ch.isprintable() else " " for ch in value)
    return cleaned[:limit]


def _options(value: object) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    out: list[str] = []
    for item in value[:MAX_OPTIONS]:
        text = _text(str(item), MAX_OPTION_LENGTH)
        if text:
            out.append(text)
    return out


def _iter_symbols(raw: object) -> Iterable[Mapping[str, Any]]:
    """Символы приходят списком (приёмник узла) или словарём (HTTP-ответ сканера)."""
    if isinstance(raw, Mapping):
        for name, body in list(raw.items())[:MAX_SYMBOLS]:
            if isinstance(body, Mapping):
                yield {"name": name, **body}
    elif isinstance(raw, (list, tuple)):
        for body in raw[:MAX_SYMBOLS]:
            if isinstance(body, Mapping):
                yield body


def parse_symbols(raw: object, *, secret_provider_ids: Iterable[str] = ()) -> list[RspamdSymbol]:
    """Нормализованный список символов. Параметры символов секретных провайдеров отбрасываются:
    в них может оказаться имя запроса, а значит, и секретная зона (ТЗ 1.2 §15)."""
    hidden_prefixes = tuple(f"MSP_RBL_{pid.upper()}_" for pid in secret_provider_ids)
    symbols: list[RspamdSymbol] = []
    for body in _iter_symbols(raw):
        name = body.get("name")
        if not isinstance(name, str) or not _SYMBOL_NAME.match(name):
            continue
        group = body.get("group")
        groups = body.get("groups")
        if not isinstance(group, str) or not group:
            group = groups[0] if isinstance(groups, list) and groups and isinstance(groups[0], str) else ""
        options = [] if name.startswith(hidden_prefixes) else _options(body.get("options"))
        symbols.append(
            RspamdSymbol(
                name=name[:MAX_NAME_LENGTH],
                score=_number(body.get("score")),
                group=_text(group, 64),
                description=_text(body.get("description"), 512),
                options=options,
            )
        )
    return symbols


def direction_of(symbols: Iterable[RspamdSymbol]) -> tuple[Direction, bool]:
    """Направление и признак того, что оно известно. Без символа направление не угадывается."""
    for symbol in symbols:
        if symbol.name in DIRECTION_SYMBOLS:
            return DIRECTION_SYMBOLS[symbol.name], True
    return Direction.INBOUND, False


def parse_scan(
    record: Mapping[str, Any],
    *,
    secret_provider_ids: Iterable[str] = (),
    default_required_score: float = 0.0,
) -> RspamdEvidence:
    """Результат сканирования из записи приёмника или из ответа ``/checkv2``."""
    symbols = parse_symbols(record.get("symbols"), secret_provider_ids=secret_provider_ids)
    direction, _ = direction_of(symbols)
    msp = record.get("_msp") if isinstance(record.get("_msp"), Mapping) else {}
    groups = sorted({s.group for s in symbols if s.group})
    message_id = _text(record.get("message_id") or record.get("message-id"), 998).strip("<> ")
    qid = _text(record.get("qid"), 64).strip("<> ")
    envelope_from = _text(record.get("from"), 320)
    created = datetime.now(UTC)
    received_at = msp.get("received_at") if isinstance(msp, Mapping) else None
    if isinstance(received_at, (int, float)):
        created = datetime.fromtimestamp(float(received_at), UTC)
    time_ms = record.get("scan_time", record.get("time_real"))
    scan_ms = int(_number(time_ms)) if "scan_time" in record else int(_number(time_ms) * 1000)
    return RspamdEvidence(
        message_id=message_id,
        transport_message_id=qid if qid != "unknown" else "",
        scan_id=qid if qid != "unknown" else "",
        score=_number(record.get("score")),
        required_score=_number(record.get("required_score"), default_required_score),
        suggested_action=suggested_action(record.get("action")),
        symbols=symbols,
        groups=groups,
        scan_time_ms=max(0, scan_ms),
        rspamd_version=_text(msp.get("rspamd_version") if isinstance(msp, Mapping) else "", 32),
        config_version=_text(msp.get("config_version") if isinstance(msp, Mapping) else "", 64),
        direction=direction,
        client_ip=_text(record.get("ip"), 64) if record.get("ip") != "unknown" else "",
        envelope_from=envelope_from if envelope_from != "unknown" else "",
        helo=_text(msp.get("helo") if isinstance(msp, Mapping) else "", 255),
        created_at=created,
    )


def forged_scanner_headers(headers: Mapping[str, Any] | Iterable[str]) -> list[str]:
    """Заголовки сканера в письме извне. Не доказательство: только факт подделки (ТЗ 1.2 §7)."""
    names = headers.keys() if isinstance(headers, Mapping) else headers
    found = []
    for name in names:
        lowered = str(name).strip().lower()
        if lowered in SCANNER_HEADERS or lowered.startswith("x-spamd-"):
            found.append(lowered)
    return sorted(set(found))
