"""Политика спама, режим действий и симулятор кандидата (ТЗ 1.2 §6, §28).

Что здесь зафиксировано жёстко и не настраивается:

* ``enforcement_enabled`` на этапе 1.2 всегда ``False``: модель отказывается создаваться с
  ``True``. Состояния ``ACTIVE_ENFORCING`` не существует;
* реальное действие MTA — ``OBSERVE_ONLY`` при любом режиме и любом предложении сканера;
* кандидат проходит ``DRAFT → SHADOW → VALIDATION → APPROVED → ACTIVE_SHADOW``, и одобряет его
  не тот, кто его правил (четыре глаза, §34).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .model import ActionMode, AppliedAction, SpamClass, SuggestedAction


class PolicyError(ValueError):
    pass


class CandidateState(StrEnum):
    DRAFT = "DRAFT"
    SHADOW = "SHADOW"
    VALIDATION = "VALIDATION"
    APPROVED = "APPROVED"
    ACTIVE_SHADOW = "ACTIVE_SHADOW"


_ORDER = [
    CandidateState.DRAFT,
    CandidateState.SHADOW,
    CandidateState.VALIDATION,
    CandidateState.APPROVED,
    CandidateState.ACTIVE_SHADOW,
]


class SpamThresholds(BaseModel):
    """Пороги оценки Rspamd, по которым MSP относит письмо к классу и предлагает действие."""

    model_config = ConfigDict(extra="forbid")

    suspected: float = Field(default=4.0, ge=0, le=100)
    spam: float = Field(default=6.0, ge=0, le=100)
    high_confidence: float = Field(default=12.0, ge=0, le=100)
    #: Оценка, с которой гипотетическое действие кандидата — «отклонить». Только гипотеза.
    suggest_reject: float = Field(default=15.0, ge=0, le=100)

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if not (self.suspected <= self.spam <= self.high_confidence <= self.suggest_reject):
            raise PolicyError(
                "пороги должны возрастать: suspected <= spam <= high_confidence <= suggest_reject"
            )
        return self


ENABLED_MODULES = frozenset(
    {
        "spf",
        "dkim",
        "dmarc",
        "arc",
        "hfilter",
        "reputation_dns",
        "bayes",
        "greylisting",
        "rate_anomalies",
        "bulk",
    }
)


class SpamPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str = "default"
    mode: ActionMode = ActionMode.SHADOW
    thresholds: SpamThresholds = SpamThresholds()
    enabled_modules: tuple[str, ...] = ("spf", "dkim", "dmarc", "arc", "hfilter", "bulk")
    rbl_provider_ids: tuple[str, ...] = ()
    bayes_enabled: bool = False
    greylisting_enabled: bool = False
    #: На этапе 1.2 всегда False (§28).
    enforcement_enabled: bool = False
    version: int = Field(default=1, ge=1)
    state: CandidateState = CandidateState.DRAFT
    edited_by: str = ""
    approved_by: str = ""

    @model_validator(mode="after")
    def _invariants(self) -> Self:
        if self.enforcement_enabled:
            raise PolicyError("enforcement_enabled=true недопустимо на этапе MSP 1.2")
        unknown = set(self.enabled_modules) - ENABLED_MODULES
        if unknown:
            raise PolicyError("неизвестный модуль в enabled_modules")
        if self.greylisting_enabled and "greylisting" not in self.enabled_modules:
            raise PolicyError("greylisting_enabled требует модуль greylisting")
        if self.bayes_enabled and "bayes" not in self.enabled_modules:
            raise PolicyError("bayes_enabled требует модуль bayes")
        if self.state in (CandidateState.APPROVED, CandidateState.ACTIVE_SHADOW):
            if not self.approved_by:
                raise PolicyError("одобренный кандидат должен иметь утверждающего")
            if self.approved_by == self.edited_by:
                raise PolicyError("кандидата не может одобрить тот, кто его правил")
        return self

    def transition(self, target: CandidateState, *, actor: str) -> SpamPolicy:
        """Следующее состояние. Назад и через ступень нельзя; ``ACTIVE_ENFORCING`` отсутствует."""
        current = _ORDER.index(self.state)
        wanted = _ORDER.index(target)
        if wanted != current + 1:
            raise PolicyError("переход допустим только к следующему состоянию")
        update: dict[str, object] = {"state": target}
        if target is CandidateState.APPROVED:
            if actor == self.edited_by:
                raise PolicyError("кандидата не может одобрить тот, кто его правил")
            update["approved_by"] = actor
        return SpamPolicy.model_validate({**self.model_dump(), **update})


class RspamdActionPolicy:
    """Что MTA делает с предложением сканера. Единственный ответ — наблюдать."""

    def __init__(self, mode: ActionMode = ActionMode.SHADOW) -> None:
        self.mode = mode

    def applied(self, suggested: SuggestedAction) -> AppliedAction:
        # Ни одно предложение (включая REJECT и SOFT_REJECT) не исполняется на этапе 1.2.
        del suggested
        return AppliedAction.OBSERVE_ONLY

    @property
    def header_marking_allowed(self) -> bool:
        """Разрешён ли только непрозрачный идентификатор сканирования (X-MSP-Scan-ID)."""
        return self.mode is ActionMode.PILOT_HEADER_ONLY or self.mode is ActionMode.SHADOW


def hypothetical_action(
    score: float, thresholds: SpamThresholds, *, greylist_at: float = 4.0
) -> SuggestedAction:
    """Действие, которое предложил бы кандидат при этой оценке. Только гипотеза для симулятора."""
    if score >= thresholds.suggest_reject:
        return SuggestedAction.REJECT
    if score >= thresholds.spam:
        return SuggestedAction.ADD_HEADER
    if score >= greylist_at:
        return SuggestedAction.GREYLIST
    return SuggestedAction.NO_ACTION


class SimulationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: float
    symbols: tuple[str, ...] = ()
    auth_summary: dict[str, str] = Field(default_factory=dict)
    reputation_listed: bool = False
    current_suggested_action: SuggestedAction = SuggestedAction.UNKNOWN
    msp_spam_class: SpamClass = SpamClass.UNKNOWN
    msp_security_verdict: str = "UNKNOWN"


class SimulationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: float
    symbols: tuple[str, ...]
    auth_summary: dict[str, str]
    reputation_listed: bool
    current_suggested_action: SuggestedAction
    candidate_spam_class: SpamClass
    msp_security_verdict: str
    hypothetical_action: SuggestedAction
    #: Всегда OBSERVE_ONLY: симулятор не меняет ничего в потоке почты.
    applied_action: AppliedAction = AppliedAction.OBSERVE_ONLY
    changed_vs_current: bool


def class_for_score(score: float, thresholds: SpamThresholds) -> SpamClass:
    if score >= thresholds.high_confidence:
        return SpamClass.HIGH_CONFIDENCE_SPAM
    if score >= thresholds.spam:
        return SpamClass.SPAM
    if score >= thresholds.suspected:
        return SpamClass.SUSPECTED_SPAM
    return SpamClass.NOT_SPAM


def simulate(candidate: SpamPolicy, sample: SimulationInput) -> SimulationResult:
    """Применить кандидата к одной записи и показать, что изменилось бы. Поток не затрагивается."""
    hypo = hypothetical_action(sample.score, candidate.thresholds, greylist_at=candidate.thresholds.suspected)
    spam_class = class_for_score(sample.score, candidate.thresholds)
    if sample.msp_spam_class is SpamClass.BULK and spam_class in (
        SpamClass.NOT_SPAM,
        SpamClass.SUSPECTED_SPAM,
    ):
        spam_class = SpamClass.BULK
    return SimulationResult(
        score=sample.score,
        symbols=sample.symbols,
        auth_summary=dict(sample.auth_summary),
        reputation_listed=sample.reputation_listed,
        current_suggested_action=sample.current_suggested_action,
        candidate_spam_class=spam_class,
        msp_security_verdict=sample.msp_security_verdict,
        hypothetical_action=hypo,
        changed_vs_current=hypo != sample.current_suggested_action,
    )
