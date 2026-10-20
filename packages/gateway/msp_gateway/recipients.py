"""Справочник принимаемых получателей: загрузка, проверка, свежесть (ТЗ 1.1 §16, §51).

Шлюз принимает письма только тем, о ком знает. Иначе он принял бы почту для несуществующих
адресов и потом должен был бы *возвращать* её по подделанным адресам отправителей —
рассеяние (backscatter). Поэтому справочник — не удобство, а часть защиты, и ошибки с ним
дороже, чем кажется:

* **Пустой справочник нельзя принимать как рабочий.** Сбой выгрузки, который выдал ноль
  адресов, при слепом применении отверг бы всю корпоративную почту. Пустое обновление
  отклоняется, действующий справочник остаётся (last-known-good).
* **Резкое сокращение — тоже тревога.** Если адресов стало вдвое меньше, скорее сломалась
  выгрузка, чем уволилась половина компании. Такое обновление требует явного подтверждения.
* **Устаревший справочник не маскируется.** Возраст справочника — метрика и состояние
  (``FRESH`` / ``STALE_GRACE`` / ``STALE_HARD``); безнадёжно устаревший справочник закрывает
  приём временным отказом (4xx), а не открывает его для всех.
* **Один адрес — один смысл.** Псевдоним, совпадающий с чужим основным адресом, — конфликт:
  письмо ушло бы не туда, куда ожидал владелец адреса.

Только стандартная библиотека: модуль работает и на узле, и в панели.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from .validation import ConfigValueError, email_address

#: Предел числа адресов в одном справочнике: защита от выгрузки, которая вышла из-под контроля.
MAX_ENTRIES = 500_000
MAX_ALIASES = 200


class RecipientKind(StrEnum):
    USER = "USER"
    SHARED_MAILBOX = "SHARED_MAILBOX"
    GROUP = "GROUP"
    CONTACT = "CONTACT"
    RESOURCE = "RESOURCE"
    OTHER = "OTHER"


class RecipientSourceError(ValueError):
    """Источник справочника не принят целиком (в отличие от отдельных плохих строк)."""


@dataclass(frozen=True)
class RecipientEntry:
    address: str
    kind: RecipientKind = RecipientKind.USER
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class LoadResult:
    entries: tuple[RecipientEntry, ...]
    rejected: tuple[str, ...] = ()  # причины по отброшенным строкам, без значений адресов

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)


def _entry(address: object, kind: object, aliases: Iterable[object], where: str) -> RecipientEntry:
    if not isinstance(address, str):
        raise ConfigValueError(f"{where}: адрес не строка")
    try:
        main = email_address(address, "address")
        kind_value = (
            RecipientKind(str(kind).strip().upper()) if kind not in (None, "") else RecipientKind.USER
        )
        cleaned: list[str] = []
        for alias in aliases:
            if not isinstance(alias, str):
                raise ConfigValueError(f"{where}: псевдоним не строка")
            if alias.strip():
                cleaned.append(email_address(alias, "alias"))
    except ValueError as error:  # ConfigValueError — подкласс; RecipientKind тоже поднимает ValueError
        raise ConfigValueError(f"{where}: {type(error).__name__}") from error
    if len(cleaned) > MAX_ALIASES:
        raise ConfigValueError(f"{where}: слишком много псевдонимов")
    return RecipientEntry(main, kind_value, tuple(sorted(set(cleaned) - {main})))


def _finish(entries: list[RecipientEntry], rejected: list[str]) -> LoadResult:
    if len(entries) > MAX_ENTRIES:
        raise RecipientSourceError("слишком много адресов в источнике")
    return LoadResult(tuple(entries), tuple(rejected))


def load_csv(text: str) -> LoadResult:
    """CSV с колонками ``address[,kind[,aliases]]``; псевдонимы разделены ``;`` или ``|``."""
    entries: list[RecipientEntry] = []
    rejected: list[str] = []
    reader = csv.reader(io.StringIO(text))
    for number, row in enumerate(reader, start=1):
        if not row or not any(cell.strip() for cell in row):
            continue
        if number == 1 and row[0].strip().lower() in {"address", "email", "mail"}:
            continue
        aliases = list((row[2] if len(row) > 2 else "").replace("|", ";").split(";"))
        try:
            entries.append(_entry(row[0], row[1] if len(row) > 1 else None, aliases, f"строка {number}"))
        except ValueError as error:
            rejected.append(str(error))
    return _finish(entries, rejected)


def load_json(text: str) -> LoadResult:
    """JSON: список объектов ``{"address", "kind", "aliases"}`` или строк-адресов."""
    try:
        data = json.loads(text)
    except ValueError as error:
        raise RecipientSourceError("источник не является JSON") from error
    if isinstance(data, dict):
        data = data.get("recipients")
    if not isinstance(data, list):
        raise RecipientSourceError("ожидался список адресатов")
    entries: list[RecipientEntry] = []
    rejected: list[str] = []
    for number, item in enumerate(data, start=1):
        where = f"запись {number}"
        try:
            if isinstance(item, str):
                entries.append(_entry(item, None, (), where))
            elif isinstance(item, dict):
                aliases = item.get("aliases") or []
                if not isinstance(aliases, list):
                    raise ConfigValueError(f"{where}: псевдонимы не список")
                entries.append(_entry(item.get("address"), item.get("kind"), aliases, where))
            else:
                raise ConfigValueError(f"{where}: неожиданный тип записи")
        except ValueError as error:
            rejected.append(str(error))
    return _finish(entries, rejected)


def merge(entries: Iterable[RecipientEntry]) -> tuple[tuple[RecipientEntry, ...], tuple[str, ...]]:
    """Свести дубли и найти конфликты. Конфликтующие псевдонимы отбрасываются, а не угадываются."""
    by_address: dict[str, RecipientEntry] = {}
    for item in entries:
        known = by_address.get(item.address)
        if known is None:
            by_address[item.address] = item
        else:
            by_address[item.address] = RecipientEntry(
                item.address, known.kind, tuple(sorted(set(known.aliases) | set(item.aliases)))
            )
    conflicts: list[str] = []
    owner: dict[str, str] = {}
    result: list[RecipientEntry] = []
    for address in sorted(by_address):
        item = by_address[address]
        kept: list[str] = []
        for alias in item.aliases:
            if alias in by_address:
                conflicts.append("псевдоним совпадает с основным адресом другой записи")
            elif alias in owner and owner[alias] != address:
                conflicts.append("псевдоним принадлежит двум разным записям")
            else:
                owner[alias] = address
                kept.append(alias)
        result.append(RecipientEntry(address, item.kind, tuple(kept)))
    return tuple(result), tuple(conflicts)


def accepted_addresses(entries: Iterable[RecipientEntry]) -> list[str]:
    keys: set[str] = set()
    for item in entries:
        keys.add(item.address)
        keys.update(item.aliases)
    return sorted(keys)


def map_text(entries: Iterable[RecipientEntry]) -> str:
    """Содержимое карты ``relay_recipients``; одинаково для одних и тех же адресов (детерминированно)."""
    return "".join(f"{key} OK\n" for key in accepted_addresses(entries))


@dataclass(frozen=True)
class Snapshot:
    entries: tuple[RecipientEntry, ...]
    generated_at: datetime
    source_snapshot_at: datetime | None = None
    source: str = "static"
    warnings: tuple[str, ...] = field(default=())

    @property
    def count(self) -> int:
        return len(self.entries)

    @property
    def checksum(self) -> str:
        return hashlib.sha256(map_text(self.entries).encode()).hexdigest()

    def meta(self) -> dict[str, object]:
        """Метаданные свежести: именно они, а не время применения, определяют возраст справочника."""
        return {
            "generated_at": self.generated_at.isoformat(),
            "source_snapshot_at": self.source_snapshot_at.isoformat() if self.source_snapshot_at else None,
            "recipient_count": self.count,
            "checksum": self.checksum,
            "source": self.source,
        }


class UpdateRefused(Exception):
    """Обновление справочника отклонено; действующий справочник остаётся."""


def validate_update(
    new: Snapshot,
    previous: Snapshot | None,
    *,
    min_ratio: float = 0.5,
    confirm_shrink: bool = False,
) -> None:
    """Проверить, можно ли заменить действующий справочник новым (last-known-good, §16)."""
    if new.count == 0:
        raise UpdateRefused("новый справочник пуст: действующий сохранён")
    if (
        previous is not None
        and previous.count > 0
        and not confirm_shrink
        and new.count < previous.count * min_ratio
    ):
        raise UpdateRefused(
            f"справочник сократился с {previous.count} до {new.count}: "
            "подтвердите сокращение явно, если это не сбой выгрузки"
        )
    if previous is not None and new.generated_at < previous.generated_at:
        raise UpdateRefused("новый справочник старше действующего")
