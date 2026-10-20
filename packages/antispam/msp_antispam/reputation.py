"""Локальная репутация источников и зрелость истории организации (ТЗ 1.2 §17, §18).

Основные свойства:

* **Репутация затухает.** Счётчики уменьшаются вдвое за период полураспада (по умолчанию 30 дней),
  поэтому старая безупречная история не гарантирует будущее, а давний инцидент не клеймит навсегда.
* **Хорошая история не отключает жёсткие сигналы.** Положительная репутация никогда не подавляет
  вредоносное вложение, BEC, имитацию домена и совпадение с TI: ``suppresses_hard_signals`` —
  константа ``False`` и проверяется тестом.
* **Нет оценки без объяснения.** Представление всегда возвращает причины словами.
* **«Отправитель не наблюдался» информативно только при зрелой истории** организации
  (урок MSP 1.0.4): в молодой установке почти все отправители новые, и сигнал был бы шумом.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum

HALF_LIFE_DAYS = 30.0
OBSERVATION_WINDOW_DAYS = 180


class Outcome(StrEnum):
    LEGITIMATE = "LEGITIMATE"
    SPAM = "SPAM"
    THREAT = "THREAT"
    UNKNOWN = "UNKNOWN"


class Analyst(StrEnum):
    LEGITIMATE = "LEGITIMATE"
    MALICIOUS = "MALICIOUS"


class Tier(StrEnum):
    UNKNOWN = "UNKNOWN"
    NEW = "NEW"
    ESTABLISHED = "ESTABLISHED"
    POOR = "POOR"
    HOSTILE = "HOSTILE"


def _aware(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def _decay_factor(then: datetime, now: datetime, half_life_days: float) -> float:
    days = max(0.0, (_aware(now) - _aware(then)).total_seconds() / 86400)
    return 0.5 ** (days / half_life_days)


@dataclass
class SourceIpReputation:
    ip: str
    first_seen: datetime
    last_seen: datetime
    message_count: float = 0.0
    threat_count: float = 0.0
    spam_count: float = 0.0
    legitimate_count: float = 0.0
    distinct_senders: int = 0
    distinct_domains: int = 0
    analyst_confirmed: Analyst | None = None

    def decayed(self, now: datetime, half_life_days: float = HALF_LIFE_DAYS) -> SourceIpReputation:
        factor = _decay_factor(self.last_seen, now, half_life_days)
        return SourceIpReputation(
            self.ip,
            self.first_seen,
            self.last_seen,
            self.message_count * factor,
            self.threat_count * factor,
            self.spam_count * factor,
            self.legitimate_count * factor,
            self.distinct_senders,
            self.distinct_domains,
            self.analyst_confirmed,
        )


@dataclass
class DomainReputation:
    domain: str
    first_seen: datetime
    last_seen: datetime
    message_count: float = 0.0
    threat_count: float = 0.0
    spam_count: float = 0.0
    legitimate_count: float = 0.0
    auth_pass_count: float = 0.0
    analyst_confirmed: Analyst | None = None

    @property
    def authentication_pass_rate(self) -> float | None:
        return None if self.message_count < 1 else min(1.0, self.auth_pass_count / self.message_count)

    def decayed(self, now: datetime, half_life_days: float = HALF_LIFE_DAYS) -> DomainReputation:
        factor = _decay_factor(self.last_seen, now, half_life_days)
        return DomainReputation(
            self.domain,
            self.first_seen,
            self.last_seen,
            self.message_count * factor,
            self.threat_count * factor,
            self.spam_count * factor,
            self.legitimate_count * factor,
            self.auth_pass_count * factor,
            self.analyst_confirmed,
        )


def observe_ip(
    rep: SourceIpReputation | None,
    ip: str,
    outcome: Outcome,
    *,
    new_sender: bool,
    new_domain: bool,
    now: datetime,
    half_life_days: float = HALF_LIFE_DAYS,
) -> SourceIpReputation:
    """Учесть одно письмо. Вычисление идёт с затуханием, а не по накопленной сумме за всё время."""
    current = rep.decayed(now, half_life_days) if rep else SourceIpReputation(ip, now, now)
    current.last_seen = now
    current.message_count += 1
    if outcome is Outcome.THREAT:
        current.threat_count += 1
    elif outcome is Outcome.SPAM:
        current.spam_count += 1
    elif outcome is Outcome.LEGITIMATE:
        current.legitimate_count += 1
    current.distinct_senders += 1 if new_sender else 0
    current.distinct_domains += 1 if new_domain else 0
    return current


def observe_domain(
    rep: DomainReputation | None,
    domain: str,
    outcome: Outcome,
    *,
    authenticated: bool,
    now: datetime,
    half_life_days: float = HALF_LIFE_DAYS,
) -> DomainReputation:
    current = rep.decayed(now, half_life_days) if rep else DomainReputation(domain, now, now)
    current.last_seen = now
    current.message_count += 1
    if authenticated:
        current.auth_pass_count += 1
    if outcome is Outcome.THREAT:
        current.threat_count += 1
    elif outcome is Outcome.SPAM:
        current.spam_count += 1
    elif outcome is Outcome.LEGITIMATE:
        current.legitimate_count += 1
    return current


@dataclass
class ReputationView:
    tier: Tier
    #: Числовая оценка 0..100 всегда сопровождается причинами; без них её показывать нельзя.
    score: int
    explanations: list[str] = field(default_factory=list)
    #: Положительная история никогда не подавляет жёсткие сигналы (§17).
    suppresses_hard_signals: bool = False
    in_window: bool = True


def _view(
    *,
    first: datetime,
    last: datetime,
    total: float,
    threat: float,
    spam: float,
    legit: float,
    confirmed: Analyst | None,
    now: datetime,
    label: str,
) -> ReputationView:
    explanations: list[str] = []
    in_window = (_aware(now) - _aware(last)) <= timedelta(days=OBSERVATION_WINDOW_DAYS)
    if confirmed is Analyst.MALICIOUS:
        return ReputationView(
            Tier.HOSTILE, 0, [f"{label}: аналитик подтвердил вредоносность"], False, in_window
        )
    if confirmed is Analyst.LEGITIMATE:
        explanations.append(f"{label}: аналитик подтвердил легитимность (жёсткие сигналы это не отменяет)")
    if not in_window:
        return ReputationView(
            Tier.UNKNOWN,
            50,
            [*explanations, f"{label}: последнее наблюдение вне окна {OBSERVATION_WINDOW_DAYS} дн."],
            False,
            False,
        )
    if total < 3:
        explanations.append(f"{label}: наблюдений мало ({total:.1f}) — вывод о репутации не делается")
        return ReputationView(Tier.NEW, 50, explanations, False, True)
    bad_share = (threat + spam) / total
    age_days = (_aware(now) - _aware(first)).days
    if threat >= 1 and bad_share >= 0.3:
        explanations.append(f"{label}: доля угроз и спама {bad_share:.0%} при {total:.0f} учтённых письмах")
        return ReputationView(
            Tier.HOSTILE if threat / total >= 0.5 else Tier.POOR, 10, explanations, False, True
        )
    if bad_share >= 0.3:
        explanations.append(f"{label}: доля спама {bad_share:.0%}")
        return ReputationView(Tier.POOR, 25, explanations, False, True)
    if legit / total >= 0.8 and age_days >= 14:
        explanations.append(
            f"{label}: {legit:.0f} из {total:.0f} учтённых писем легитимны, наблюдается {age_days} дн."
        )
        return ReputationView(Tier.ESTABLISHED, 80, explanations, False, True)
    explanations.append(f"{label}: смешанная история ({total:.0f} писем)")
    return ReputationView(Tier.NEW, 55, explanations, False, True)


def view_ip(rep: SourceIpReputation | None, now: datetime) -> ReputationView:
    if rep is None:
        return ReputationView(Tier.UNKNOWN, 50, ["IP: адрес ещё не наблюдался"], False, True)
    d = rep.decayed(now)
    return _view(
        first=rep.first_seen,
        last=rep.last_seen,
        total=d.message_count,
        threat=d.threat_count,
        spam=d.spam_count,
        legit=d.legitimate_count,
        confirmed=rep.analyst_confirmed,
        now=now,
        label="IP",
    )


def view_domain(rep: DomainReputation | None, now: datetime) -> ReputationView:
    if rep is None:
        return ReputationView(Tier.UNKNOWN, 50, ["Домен: ещё не наблюдался"], False, True)
    d = rep.decayed(now)
    return _view(
        first=rep.first_seen,
        last=rep.last_seen,
        total=d.message_count,
        threat=d.threat_count,
        spam=d.spam_count,
        legit=d.legitimate_count,
        confirmed=rep.analyst_confirmed,
        now=now,
        label="Домен",
    )


# ---------------------------------------------------------------------------------------------
# Зрелость истории организации
# ---------------------------------------------------------------------------------------------
class Maturity(StrEnum):
    IMMATURE = "IMMATURE"
    DEVELOPING = "DEVELOPING"
    MATURE = "MATURE"


@dataclass
class OrganizationObservationMaturity:
    first_message_at: datetime | None
    total_messages: int
    distinct_senders: int

    def level(self, now: datetime, *, mature_days: int = 30, mature_messages: int = 500) -> Maturity:
        if self.first_message_at is None or self.total_messages < 50:
            return Maturity.IMMATURE
        age = (_aware(now) - _aware(self.first_message_at)).days
        if age >= mature_days and self.total_messages >= mature_messages:
            return Maturity.MATURE
        return Maturity.DEVELOPING

    def sender_not_observed_is_informative(self, now: datetime) -> bool:
        """«Отправитель не наблюдался» — сигнал только при зрелой истории (урок MSP 1.0.4)."""
        return self.level(now) is Maturity.MATURE
