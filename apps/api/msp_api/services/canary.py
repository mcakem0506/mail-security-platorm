"""Canary deployment of detection rules (ТЗ 1.0.3 §52).

A rule that has passed the gate and a week of shadow mode is still unproven in one specific
sense: nobody has seen what it does to the people who have to act on its verdicts. A canary
answers that by letting the rule decide for part of the organisation while the rest carries on
unchanged.

Three properties make the mechanism worth having rather than merely present:

* **Outside the scope the rule is not switched off — it is withheld.** It evaluates, it is
  recorded, it contributes nothing. The untouched majority is therefore a control group
  measured by the same code on the same mail, and the comparison costs nothing extra.
* **Membership is stable.** A given mailbox is always on the same side of the split, so a rule
  cannot treat the same person differently from one message to the next. An unstable split
  would make both the comparison and the explanation worthless.
* **A canary has an end date, and nothing happens at that date by itself.** Lifting the scope
  automatically would release an unreviewed rule to everybody; dropping it automatically would
  silently switch off detection. Both are decisions, so the only thing the deadline does is
  make an overdue rollout visible.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from msp_contracts import CanaryScope, CanaryState, RuleStatus, utcnow
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db.models import (
    AnalysisJob,
    AnalysisResult,
    DetectionSignal,
    Incident,
    IncidentClassification,
    IncidentMessage,
    RuleCanary,
)

logger = logging.getLogger(__name__)

#: Longest a rollout may run before it has to be decided. Not a technical limit: a rule that has
#: been "being rolled out" for a month is a rule where half the organisation is protected and
#: half is not, and nobody is treating that as a problem.
MAX_CANARY_DAYS = 30
DEFAULT_CANARY_DAYS = 7


# ---------------------------------------------------------------------------------------------
# Scope membership
# ---------------------------------------------------------------------------------------------
def _bucket(mailbox: str) -> int:
    """Stable 0–99 bucket for a mailbox.

    Hashing the address rather than the message is what keeps a recipient on one side of the
    split for the whole rollout. SHA-256 is used because it is already a dependency and because
    Python's ``hash`` is salted per process — the same mailbox would land in different buckets
    on different workers, which is the one thing this must never do.
    """
    digest = hashlib.sha256(mailbox.strip().lower().encode("utf-8")).digest()
    return digest[0] % 100


def in_scope(canary: RuleCanary, *, mailbox: str, department: str = "") -> bool:
    """Whether this recipient is inside the rollout."""
    match canary.scope:
        case CanaryScope.MAILBOX:
            wanted = {str(v).strip().lower() for v in (canary.scope_values or []) if v}
            return bool(mailbox) and mailbox.strip().lower() in wanted
        case CanaryScope.DEPARTMENT:
            wanted = {str(v).strip().lower() for v in (canary.scope_values or []) if v}
            return bool(department) and department.strip().lower() in wanted
        case CanaryScope.PERCENT:
            if not mailbox:
                # No recipient to hash: stay outside, because the safe side of an unknown is the
                # one where the rule cannot change a verdict.
                return False
            return _bucket(mailbox) < max(0, min(100, canary.percent))
    return False


def withheld_rules(
    session: Session,
    *,
    organization_id: str,
    mailbox: str = "",
    department: str = "",
) -> frozenset[str]:
    """Rules that are mid-rollout and do not apply to this recipient.

    Returned as a plain set for :class:`msp_detection.AnalysisContext`: the detection engine
    must not reach into the database, and a rule must not know who it applies to.
    """
    canaries = (
        session.execute(
            select(RuleCanary).where(
                RuleCanary.organization_id == organization_id,
                RuleCanary.state == CanaryState.ACTIVE,
            )
        )
        .scalars()
        .all()
    )
    return frozenset(
        canary.rule_id for canary in canaries if not in_scope(canary, mailbox=mailbox, department=department)
    )


# ---------------------------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------------------------
class CanaryError(ValueError):
    """A rollout that cannot be started or decided, with the reason in the message."""


def start(
    session: Session,
    *,
    organization_id: str,
    rule_id: str,
    rule_status: RuleStatus,
    rule_version: int,
    scope: CanaryScope,
    scope_values: list[str] | None = None,
    percent: int = 0,
    days: int = DEFAULT_CANARY_DAYS,
    reason: str,
    created_by: str,
) -> RuleCanary:
    """Begin a rollout. Refuses the cases that would make it meaningless."""
    if rule_status is not RuleStatus.ACTIVE:
        # A SHADOW rule already scores nothing anywhere, so "limiting" it would describe a
        # restriction that does not exist and would read on the dashboard as a live rollout.
        raise CanaryError(
            "канареечный выпуск применим только к активному правилу: "
            f"{rule_id} сейчас в состоянии {rule_status.value}"
        )
    existing = active_for(session, organization_id=organization_id, rule_id=rule_id)
    if existing is not None:
        raise CanaryError(f"для правила {rule_id} уже идёт канареечный выпуск")
    if not 1 <= days <= MAX_CANARY_DAYS:
        raise CanaryError(f"срок канареечного выпуска — от 1 до {MAX_CANARY_DAYS} дней")

    values = [str(v).strip() for v in (scope_values or []) if str(v).strip()]
    if scope is CanaryScope.PERCENT:
        if not 1 <= percent <= 99:
            # 100% is not a canary, and 0% is a rule that protects nobody while looking live.
            raise CanaryError("доля для канареечного выпуска — от 1 до 99 процентов")
        values = []
    else:
        if not values:
            raise CanaryError("для этой области нужно указать хотя бы один адрес или отдел")
        percent = 0

    canary = RuleCanary(
        organization_id=organization_id,
        rule_id=rule_id,
        rule_version=rule_version,
        scope=scope,
        scope_values=values,
        percent=percent,
        state=CanaryState.ACTIVE,
        review_at=utcnow() + timedelta(days=days),
        reason=reason[:4000],
        created_by=created_by,
    )
    session.add(canary)
    logger.info(
        "canary.started",
        extra={"rule_id": rule_id, "scope": scope.value, "days": days},
    )
    return canary


def active_for(session: Session, *, organization_id: str, rule_id: str) -> RuleCanary | None:
    return session.execute(
        select(RuleCanary).where(
            RuleCanary.organization_id == organization_id,
            RuleCanary.rule_id == rule_id,
            RuleCanary.state == CanaryState.ACTIVE,
        )
    ).scalar_one_or_none()


def decide(
    session: Session,
    canary: RuleCanary,
    *,
    state: CanaryState,
    decided_by: str,
    note: str = "",
) -> RuleCanary:
    """Promote or abort a rollout.

    Promotion lifts the scope so the rule applies to everyone. Aborting lifts it too — the rule
    stops being limited — but the expectation is that the same change moves it to DEGRADED or
    SHADOW in the rule pack, which is a reviewed commit. Leaving a bad rule permanently limited
    to a few mailboxes would be the worst of both: unreviewed, unmeasured, and still deciding
    for someone.
    """
    if not canary.active:
        raise CanaryError("этот канареечный выпуск уже завершён")
    if state is CanaryState.ACTIVE:
        raise CanaryError("решение должно быть PROMOTED или ABORTED")
    if state is CanaryState.ABORTED and not note.strip():
        raise CanaryError("при откате требуется причина")
    canary.state = state
    canary.decided_by = decided_by
    canary.decided_at = utcnow()
    canary.decision_note = note[:4000]
    logger.info("canary.decided", extra={"rule_id": canary.rule_id, "state": state.value})
    return canary


def overdue(session: Session, organization_id: str) -> list[RuleCanary]:
    """Rollouts past their review date — the only thing the deadline actually does."""
    now = utcnow()
    return list(
        session.execute(
            select(RuleCanary).where(
                RuleCanary.organization_id == organization_id,
                RuleCanary.state == CanaryState.ACTIVE,
                RuleCanary.review_at < now,
            )
        )
        .scalars()
        .all()
    )


# ---------------------------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------------------------
@dataclass
class CanaryComparison:
    """What the rule did inside the rollout against what it would have done outside."""

    rule_id: str
    state: str
    scope: str
    scope_values: list[str] = field(default_factory=list)
    percent: int = 0
    review_at: str = ""
    overdue: bool = False
    #: Signals that counted, because the recipient was inside the scope.
    inside_triggers: int = 0
    #: Signals withheld because the recipient was outside it. The control group.
    outside_triggers: int = 0
    #: Of the signals that counted, how many landed on an incident an analyst later called
    #: harmless. This is the number that decides whether the rollout goes further.
    inside_false_positives: int = 0
    outside_false_positives: int = 0
    inside_confirmed: int = 0
    outside_confirmed: int = 0

    @property
    def inside_precision(self) -> float | None:
        judged = self.inside_confirmed + self.inside_false_positives
        return (self.inside_confirmed / judged) if judged else None

    @property
    def outside_precision(self) -> float | None:
        judged = self.outside_confirmed + self.outside_false_positives
        return (self.outside_confirmed / judged) if judged else None

    @property
    def ready_to_promote(self) -> bool:
        """Whether the evidence supports widening the rollout.

        Deliberately conservative, and deliberately not automatic: this answers "is there a
        reason to look", and a person still decides. No judgement at all is returned until the
        rule has fired inside the scope and an analyst has classified some of it — promoting on
        the strength of "nothing bad happened yet" is how an unproven rule reaches everybody.
        """
        if self.inside_triggers == 0:
            return False
        judged = self.inside_confirmed + self.inside_false_positives
        if judged < 3:
            return False
        return (self.inside_precision or 0.0) >= 0.7

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "state": self.state,
            "scope": self.scope,
            "scope_values": self.scope_values,
            "percent": self.percent,
            "review_at": self.review_at,
            "overdue": self.overdue,
            "inside_triggers": self.inside_triggers,
            "outside_triggers": self.outside_triggers,
            "inside_confirmed": self.inside_confirmed,
            "inside_false_positives": self.inside_false_positives,
            "outside_confirmed": self.outside_confirmed,
            "outside_false_positives": self.outside_false_positives,
            "inside_precision": self.inside_precision,
            "outside_precision": self.outside_precision,
            "ready_to_promote": self.ready_to_promote,
        }


def compare(session: Session, canary: RuleCanary) -> CanaryComparison:
    """Measure a rollout against the recipients it did not reach."""
    comparison = CanaryComparison(
        rule_id=canary.rule_id,
        state=canary.state.value,
        scope=canary.scope.value,
        scope_values=[str(v) for v in (canary.scope_values or [])],
        percent=canary.percent,
        review_at=canary.review_at.isoformat(),
        overdue=canary.overdue(),
    )

    rows = session.execute(
        select(DetectionSignal.withheld_by, AnalysisResult.message_id)
        .join(AnalysisResult, AnalysisResult.id == DetectionSignal.result_id)
        .join(AnalysisJob, AnalysisJob.id == AnalysisResult.job_id)
        .where(
            AnalysisJob.organization_id == canary.organization_id,
            DetectionSignal.rule_id == canary.rule_id,
            DetectionSignal.observed_at >= canary.created_at,
            DetectionSignal.suppressed.is_(False),
        )
    ).all()
    if not rows:
        return comparison

    message_ids = {message_id for _withheld, message_id in rows if message_id}
    verdicts = _analyst_verdicts(session, canary.organization_id, message_ids)

    from msp_contracts import CONFIRMED_BENIGN, CONFIRMED_THREAT

    for withheld_by, message_id in rows:
        inside = withheld_by != "canary"
        if inside:
            comparison.inside_triggers += 1
        else:
            comparison.outside_triggers += 1
        verdict = verdicts.get(message_id or "")
        if verdict is None:
            continue
        if verdict in {c.value for c in CONFIRMED_BENIGN}:
            if inside:
                comparison.inside_false_positives += 1
            else:
                comparison.outside_false_positives += 1
        elif verdict in {c.value for c in CONFIRMED_THREAT}:
            if inside:
                comparison.inside_confirmed += 1
            else:
                comparison.outside_confirmed += 1
    return comparison


def _analyst_verdicts(session: Session, organization_id: str, message_ids: set[str]) -> dict[str, str]:
    """Latest analyst classification per message, via the incident that contains it."""
    if not message_ids:
        return {}
    rows = session.execute(
        select(
            IncidentMessage.message_id,
            IncidentClassification.classification,
            IncidentClassification.created_at,
        )
        .join(Incident, Incident.id == IncidentMessage.incident_id)
        .join(IncidentClassification, IncidentClassification.incident_id == Incident.id)
        .where(
            Incident.organization_id == organization_id,
            IncidentMessage.message_id.in_(message_ids),
        )
        .order_by(IncidentClassification.created_at)
    ).all()
    out: dict[str, str] = {}
    for message_id, classification, _created in rows:
        out[message_id] = classification.value if hasattr(classification, "value") else str(classification)
    return out


def list_canaries(
    session: Session, organization_id: str, *, include_decided: bool = False
) -> list[CanaryComparison]:
    query = select(RuleCanary).where(RuleCanary.organization_id == organization_id)
    if not include_decided:
        query = query.where(RuleCanary.state == CanaryState.ACTIVE)
    canaries = session.execute(query.order_by(RuleCanary.created_at.desc())).scalars().all()
    return [compare(session, canary) for canary in canaries]


def coverage_summary(session: Session, organization_id: str) -> dict[str, Any]:
    """One line for the quality dashboard: how much of detection is mid-rollout."""
    active = int(
        session.execute(
            select(func.count(RuleCanary.id)).where(
                RuleCanary.organization_id == organization_id,
                RuleCanary.state == CanaryState.ACTIVE,
            )
        ).scalar_one()
        or 0
    )
    return {
        "active_canaries": active,
        "overdue_canaries": len(overdue(session, organization_id)),
    }
