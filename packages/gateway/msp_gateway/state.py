"""Изменяемое состояние узла: режим слива, свежесть справочника, давление (ТЗ 1.1 §16, §25, §26).

Это состояние отделено от версий конфигурации намеренно. Смена версии не должна сбрасывать
режим слива, а слив не должен требовать новой версии: оператор, который включил слив перед
обслуживанием, и агент, который в это время применил обновление, не должны мешать друг другу.

Механизм — файлы карт, которые Postfix читает при каждом соединении. Свой демон в SMTP-пути не
вводится: чем меньше собственного кода между клиентом и ответом ``250``, тем меньше мест, где
принятая почта может быть потеряна. Если эти файлы исчезнут или станут нечитаемыми, Postfix
откажет в соединении временно (4xx), а не примет почту без проверки.

Только стандартная библиотека: модуль работает на узле.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404 - вызывает фиксированные команды Postfix
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

STATE_DIR = Path(os.environ.get("MSP_STATE_DIR", "/var/lib/msp/state"))

#: Ответ новым соединениям в режиме слива. Временный (450): отправитель повторит позже, письмо
#: не теряется и не возвращается отправителю уведомлением о недоставке.
DRAIN_RULE = "/./ 450 4.3.2 Service temporarily unavailable, try again later (maintenance)\n"

#: Ответ на получателей, пока справочник устарел безвозвратно (ТЗ §16). Временный, а не
#: «принимаем всех»: молча принимать неизвестных получателей — значит порождать обратное
#: рассеяние (backscatter) на подделанные адреса отправителей.
STALE_RULE = "/./ 451 4.3.0 Recipient directory is not fresh, try again later\n"

_RELOAD_COMMAND = ["postfix", "reload"]  # фиксированная команда образа


class PressureState(StrEnum):
    NORMAL = "NORMAL"
    PRESSURE = "PRESSURE"
    CRITICAL = "CRITICAL"
    DRAINING = "DRAINING"


class RecipientFreshness(StrEnum):
    FRESH = "FRESH"
    STALE_GRACE = "STALE_GRACE"
    STALE_HARD = "STALE_HARD"


def _write_atomically(path: Path, content: str) -> None:
    """Подмена файла целиком: Postfix читает либо старое содержимое, либо новое, но не половину."""
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(content, encoding="utf-8")
    os.chmod(temp, 0o644)
    os.replace(temp, path)


def _reload() -> None:
    # Карты pcre читаются процессами smtpd при запуске; reload заставляет их перечитать.
    subprocess.run(_RELOAD_COMMAND, check=False, capture_output=True, timeout=30)  # noqa: S603  # nosec B603


def set_drain(enabled: bool, *, state_dir: Path = STATE_DIR, reload: bool = True) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    _write_atomically(state_dir / "drain.pcre", DRAIN_RULE if enabled else "")
    if reload:
        _reload()


def is_draining(state_dir: Path = STATE_DIR) -> bool:
    try:
        return bool((state_dir / "drain.pcre").read_text(encoding="utf-8").strip())
    except OSError:
        return False


def set_recipient_gate(
    freshness: RecipientFreshness, *, state_dir: Path = STATE_DIR, reload: bool = True
) -> None:
    """При устаревшем навсегда справочнике получатели временно отвергаются; иначе проверка свободна."""
    state_dir.mkdir(parents=True, exist_ok=True)
    _write_atomically(
        state_dir / "recipient_gate.pcre", STALE_RULE if freshness is RecipientFreshness.STALE_HARD else ""
    )
    if reload:
        _reload()


@dataclass(frozen=True)
class DiskReading:
    free_bytes: int
    total_bytes: int


def read_disk(path: str = "/var/spool/postfix") -> DiskReading:
    usage = shutil.disk_usage(path)
    return DiskReading(free_bytes=usage.free, total_bytes=usage.total)


def classify_pressure(
    *,
    free_bytes: int,
    queue_messages: int,
    draining: bool,
    disk_pressure_free_bytes: int,
    disk_critical_free_bytes: int,
    queue_pressure_messages: int,
    queue_critical_messages: int,
) -> PressureState:
    """Состояние давления (ТЗ §25).

    Слив важнее остального: оператор сам остановил приём, и называть это «давлением» значило бы
    скрывать, кто принял решение. Дальше — по худшему из двух показателей, диска и очереди:
    очередь в двадцать тысяч писем на свободном диске — такая же проблема, как нехватка места.
    """
    if draining:
        return PressureState.DRAINING
    if free_bytes <= disk_critical_free_bytes or queue_messages >= queue_critical_messages:
        return PressureState.CRITICAL
    if free_bytes <= disk_pressure_free_bytes or queue_messages >= queue_pressure_messages:
        return PressureState.PRESSURE
    return PressureState.NORMAL


def classify_freshness(
    *,
    age_seconds: float | None,
    fresh_seconds: float,
    grace_seconds: float,
) -> RecipientFreshness:
    """Свежесть справочника получателей (ТЗ §16).

    ``None`` — возраста нет вовсе (справочник ни разу не загружался). Это не «свежий» и не
    «устаревший в пределах допуска», а самое плохое состояние: принимать почту, не зная адресатов,
    нельзя.
    """
    if age_seconds is None:
        return RecipientFreshness.STALE_HARD
    if age_seconds <= fresh_seconds:
        return RecipientFreshness.FRESH
    if age_seconds <= fresh_seconds + grace_seconds:
        return RecipientFreshness.STALE_GRACE
    return RecipientFreshness.STALE_HARD
