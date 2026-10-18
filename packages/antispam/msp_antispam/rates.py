"""Аномалии частоты отправки (ТЗ 1.2 §18, §32).

Это только свидетельства. Ни одна аномалия, в том числе ``OUTBOUND_ACCOUNT_ANOMALY`` высокой
степени, ничего не блокирует: она попадает в тревогу и в карточку письма (§32).
"""

from __future__ import annotations

import statistics
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum


class AnomalyKind(StrEnum):
    RECIPIENTS_PER_SENDER = "RECIPIENTS_PER_SENDER"
    SENDERS_PER_IP = "SENDERS_PER_IP"
    DOMAIN_VOLUME_SPIKE = "DOMAIN_VOLUME_SPIKE"
    BURST_TO_MANY_RECIPIENTS = "BURST_TO_MANY_RECIPIENTS"
    OUTBOUND_ACCOUNT_ANOMALY = "OUTBOUND_ACCOUNT_ANOMALY"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class RateAnomaly:
    kind: AnomalyKind
    observed: float
    expected: float
    severity: Severity
    #: Всегда «наблюдать»: аномалия ничего не блокирует (ТЗ 1.2 §32).
    action: str = "OBSERVE_ONLY"


def _severity(observed: float, expected: float) -> Severity:
    ratio = observed / max(expected, 1.0)
    if ratio >= 20:
        return Severity.HIGH
    if ratio >= 8:
        return Severity.MEDIUM
    return Severity.LOW


def anomaly(
    kind: AnomalyKind,
    observed: float,
    history: Sequence[float],
    *,
    floor: float,
    sigma: float = 3.0,
    multiplier: float = 3.0,
    min_history: int = 5,
) -> RateAnomaly | None:
    """Аномалия, если значение превышает и абсолютный пол, и статистику собственной истории.

    При короткой истории (меньше ``min_history`` наблюдений) работает только абсолютный пол:
    выводы из двух точек были бы шумом.
    """
    if observed < floor:
        return None
    if len(history) < min_history:
        return RateAnomaly(kind, observed, floor, _severity(observed, floor))
    mean = statistics.fmean(history)
    spread = statistics.pstdev(history)
    limit = max(floor, mean + sigma * spread, multiplier * max(mean, 1.0))
    if observed <= limit:
        return None
    return RateAnomaly(kind, observed, mean, _severity(observed, max(mean, 1.0)))


def outbound_account_anomaly(
    recipients_per_hour: float, history: Sequence[float], *, spam_hits: int = 0
) -> RateAnomaly | None:
    """Возможная компрометация учётной записи: резкий рост числа получателей, особенно со спам-признаками."""
    found = anomaly(AnomalyKind.OUTBOUND_ACCOUNT_ANOMALY, recipients_per_hour, history, floor=100)
    if found is None:
        return None
    if spam_hits >= 3 and found.severity is not Severity.HIGH:
        return RateAnomaly(found.kind, found.observed, found.expected, Severity.HIGH)
    return found
