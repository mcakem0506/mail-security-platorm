"""Rule simulation, replay and the feedback loop (ТЗ 1.0.3 §13, §14, §23, §26, §49, §50).

Everything here shares one rule: **nothing changes a stored verdict as a side effect**. A
simulation, a replay and a bulk re-evaluation all produce a *new* record and leave the original
alone. Overwriting would destroy the only evidence of what the platform actually told people at
the time, which is precisely what an investigation needs months later — and it would let a rule
change silently rewrite history.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from msp_contracts import (
    RISK_ORDER,
    AnalystClassification,
    EngineVersions,
    FalseNegativeSource,
    GapStatus,
    RiskLevel,
    RootCause,
    Severity,
    utcnow,
)
from msp_detection import ENGINE_VERSION, analyze
from msp_detection.rules import RuleSet, find_rule_pack
from msp_mail_parser import parse_message
from msp_risk import RISK_ENGINE_VERSION, RiskThresholds, evaluate
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.models import (
    AnalysisJob,
    AnalysisResult,
    AnalysisRevision,
    DetectionFeedback,
    DetectionGapRecord,
    DetectionSignal,
    Incident,
    IncidentClassification,
    MailContent,
    MailMessage,
    ReevaluationRun,
    RuleStatistic,
)
from .analysis import build_context, get_ruleset, parser_limits
from .storage import build_storage

logger = logging.getLogger(__name__)

#: Version of the MIME parser, recorded with every analysis so a verdict stays reproducible.
PARSER_VERSION = "parser-1.1.0"


def engine_versions(settings: Settings, ruleset: RuleSet | None = None) -> EngineVersions:
    """Everything needed to reproduce a verdict later (ТЗ 1.0.3 §48)."""
    rules = ruleset or get_ruleset()
    return EngineVersions(
        ruleset_version=rules.version_fingerprint[:200],
        risk_engine_version=RISK_ENGINE_VERSION,
        parser_version=PARSER_VERSION,
        ti_policy_version=_ti_policy_version(settings),
    )


def _ti_policy_version(settings: Settings) -> str:
    """A short fingerprint of the privacy policy in force.

    Recorded because the policy decides what could be looked up at all: a verdict reached while
    URL lookups were disabled is not comparable with one reached after they were enabled.
    """
    flags = (
        settings.ti_allow_hash,
        settings.ti_allow_domain,
        settings.ti_allow_ip,
        settings.ti_allow_url,
        settings.ti_allow_url_path,
        settings.ti_allow_sender_email,
        settings.ti_allow_internal_domains,
    )
    return "ti-" + "".join("1" if flag else "0" for flag in flags)


def load_raw_message(session: Session, settings: Settings, message_id: str) -> bytes | None:
    """Fetch the stored raw message, if retention has not removed it yet."""
    content = session.execute(
        select(MailContent).where(MailContent.message_id == message_id)
    ).scalar_one_or_none()
    if content is None or not content.raw_eml_key:
        return None
    try:
        return build_storage(settings).get(content.raw_eml_key)
    except Exception as exc:  # noqa: BLE001 - a missing object is a retention fact, not an error
        logger.info("replay.raw_unavailable", extra={"error": type(exc).__name__})
        return None


# ---------------------------------------------------------------------------------------------
# Rule simulation and before/after comparison (ТЗ 1.0.3 §13, §14)
# ---------------------------------------------------------------------------------------------
@dataclass
class SignalView:
    rule_id: str
    rule_version: int
    title: str
    category: str
    severity: str
    weight: float
    confidence: float
    shadow: bool
    suppressed: bool
    condition: str | None
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "weight": self.weight,
            "confidence": self.confidence,
            "shadow": self.shadow,
            "suppressed": self.suppressed,
            "condition": self.condition,
            "evidence": self.evidence,
        }


@dataclass
class SimulationResult:
    """What a rule set would produce for one message, without touching the stored verdict."""

    message_id: str
    classification: RiskLevel
    score: int
    signals: list[SignalView] = field(default_factory=list)
    matched_facts: dict[str, Any] = field(default_factory=dict)
    missing_evidence: list[str] = field(default_factory=list)
    ruleset_fingerprint: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "classification": self.classification.value,
            "score": self.score,
            "signals": [s.as_dict() for s in self.signals],
            "matched_facts": self.matched_facts,
            "missing_evidence": self.missing_evidence,
            "ruleset_fingerprint": self.ruleset_fingerprint[:200],
        }


def _view(signal: Any) -> SignalView:
    return SignalView(
        rule_id=signal.rule_id or "",
        rule_version=signal.rule_version or 1,
        title=signal.title,
        category=signal.category,
        severity=signal.severity.value,
        weight=signal.weight,
        confidence=signal.confidence,
        shadow=signal.shadow,
        suppressed=signal.suppressed,
        condition=signal.rule_condition,
        evidence=dict(signal.evidence),
    )


def simulate(
    session: Session,
    settings: Settings,
    *,
    message_id: str,
    ruleset: RuleSet | None = None,
    rule_id: str | None = None,
) -> SimulationResult | None:
    """Run a rule set against a stored message without changing anything (ТЗ 1.0.3 §13).

    When ``rule_id`` is given the result is narrowed to that rule, which is what an engineer
    wants while tuning one condition; the verdict is still computed from the whole set, because
    a rule's effect depends on what else fired.
    """
    raw = load_raw_message(session, settings, message_id)
    if raw is None:
        return None
    message = session.get(MailMessage, message_id)
    if message is None:
        return None

    rules = ruleset or get_ruleset()
    parsed = parse_message(raw, parser_limits(settings))
    context = build_context(
        session,
        settings,
        organization_id=message.organization_id,
        source=message.source,
        recipient_mailbox=message.source_mailbox,
        sender_address=message.sender_address,
        exclude_message_id=message.id,
        parsed=parsed,
    )
    detection = analyze(parsed, context, ruleset=rules)
    verdict = evaluate(
        detection.signals,
        missing_evidence=detection.facts.missing_evidence,
        thresholds=RiskThresholds(
            settings.suspicious_threshold, settings.high_risk_threshold, settings.malicious_threshold
        ),
        analysis_complete=False,
        content_encrypted=parsed.encrypted,
        unparseable=not parsed.parse_ok,
        versions=engine_versions(settings, rules),
    )
    signals = [_view(s) for s in detection.signals]
    if rule_id:
        signals = [s for s in signals if s.rule_id == rule_id]
    return SimulationResult(
        message_id=message_id,
        classification=verdict.classification,
        score=verdict.score,
        signals=signals,
        matched_facts={k: v for k, v in detection.facts.truthy().items() if k != "subject"},
        missing_evidence=list(verdict.missing_evidence),
        ruleset_fingerprint=rules.version_fingerprint,
    )


@dataclass
class Comparison:
    """Current rules against candidate rules (ТЗ 1.0.3 §14)."""

    message_id: str
    current: SimulationResult
    candidate: SimulationResult

    @property
    def verdict_changed(self) -> bool:
        return self.current.classification is not self.candidate.classification

    @property
    def newly_detected(self) -> list[str]:
        before = {s.rule_id for s in self.current.signals if not s.shadow and not s.suppressed}
        after = {s.rule_id for s in self.candidate.signals if not s.shadow and not s.suppressed}
        return sorted(after - before)

    @property
    def newly_missed(self) -> list[str]:
        before = {s.rule_id for s in self.current.signals if not s.shadow and not s.suppressed}
        after = {s.rule_id for s in self.candidate.signals if not s.shadow and not s.suppressed}
        return sorted(before - after)

    def as_dict(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "verdict_changed": self.verdict_changed,
            "current": {
                "classification": self.current.classification.value,
                "score": self.current.score,
            },
            "candidate": {
                "classification": self.candidate.classification.value,
                "score": self.candidate.score,
            },
            "newly_detected": self.newly_detected,
            "newly_missed": self.newly_missed,
            "escalated": RISK_ORDER[self.candidate.classification] > RISK_ORDER[self.current.classification],
            "de_escalated": RISK_ORDER[self.candidate.classification]
            < RISK_ORDER[self.current.classification],
        }


def compare(
    session: Session, settings: Settings, *, message_id: str, candidate_path: str | Path
) -> Comparison | None:
    """Compare the deployed rules against a candidate pack for one message."""
    current = simulate(session, settings, message_id=message_id)
    if current is None:
        return None
    candidate_rules = RuleSet.from_directory(candidate_path)
    candidate = simulate(session, settings, message_id=message_id, ruleset=candidate_rules)
    if candidate is None:
        return None
    return Comparison(message_id=message_id, current=current, candidate=candidate)


# ---------------------------------------------------------------------------------------------
# Replay (ТЗ 1.0.3 §49)
# ---------------------------------------------------------------------------------------------
def replay(
    session: Session,
    settings: Settings,
    *,
    job_id: str,
    requested_by: str,
    apply: bool = False,
) -> AnalysisRevision | None:
    """Re-run one analysis with the current engine, as a new revision.

    The original analysis is never overwritten. ``apply`` only controls whether the *current*
    verdict is updated as well; either way the revision records both sides so the change is
    reviewable.
    """
    job = session.get(AnalysisJob, job_id)
    if job is None or job.message_id is None:
        return None
    previous = session.execute(
        select(AnalysisResult).where(AnalysisResult.job_id == job.id)
    ).scalar_one_or_none()
    if previous is None:
        return None

    simulation = simulate(session, settings, message_id=job.message_id)
    if simulation is None:
        return None

    before_rules = {
        row
        for row in session.execute(
            select(DetectionSignal.rule_id).where(
                DetectionSignal.result_id == previous.id,
                DetectionSignal.suppressed.is_(False),
                DetectionSignal.shadow.is_(False),
            )
        )
        .scalars()
        .all()
        if row
    }
    after_rules = {s.rule_id for s in simulation.signals if s.rule_id and not s.shadow and not s.suppressed}

    revision_number = session.execute(
        select(AnalysisRevision)
        .where(AnalysisRevision.analysis_job_id == job.id)
        .order_by(AnalysisRevision.revision.desc())
        .limit(1)
    ).scalar_one_or_none()
    revision = AnalysisRevision(
        organization_id=job.organization_id,
        analysis_job_id=job.id,
        message_id=job.message_id,
        revision=(revision_number.revision + 1) if revision_number else 1,
        dry_run=not apply,
        original_classification=previous.classification.value,
        new_classification=simulation.classification.value,
        original_score=previous.score,
        new_score=simulation.score,
        added_rules=sorted(after_rules - before_rules),
        removed_rules=sorted(before_rules - after_rules),
        versions=engine_versions(settings).model_dump(mode="json"),
        requested_by=requested_by,
    )
    session.add(revision)
    return revision


# ---------------------------------------------------------------------------------------------
# Historical re-evaluation (ТЗ 1.0.3 §50)
# ---------------------------------------------------------------------------------------------
def reevaluate(
    session: Session,
    settings: Settings,
    *,
    organization_id: str,
    days: int = 7,
    requested_by: str,
    dry_run: bool = True,
    limit: int = 2000,
) -> ReevaluationRun:
    """Re-run recent analyses with the current rules. Dry-run by default (ТЗ 1.0.3 §50).

    A rule released to catch a live campaign is worth nothing if it only applies to tomorrow's
    mail. This answers "what would we have said about the last week", and says so as a
    proposal rather than silently rewriting a week of verdicts.
    """
    cutoff = utcnow() - timedelta(days=days)
    run = ReevaluationRun(
        organization_id=organization_id,
        window_days=days,
        dry_run=dry_run,
        ruleset_fingerprint=get_ruleset().version_fingerprint[:4000],
        requested_by=requested_by,
    )
    session.add(run)
    session.flush()

    jobs = (
        session.execute(
            select(AnalysisJob)
            .where(
                AnalysisJob.organization_id == organization_id,
                AnalysisJob.created_at >= cutoff,
                AnalysisJob.message_id.is_not(None),
            )
            .limit(limit)
        )
        .scalars()
        .all()
    )

    campaigns: set[str] = set()
    users: set[str] = set()
    sample: list[dict[str, Any]] = []

    for job in jobs:
        previous = session.execute(
            select(AnalysisResult).where(AnalysisResult.job_id == job.id)
        ).scalar_one_or_none()
        if previous is None:
            continue
        simulation = simulate(session, settings, message_id=job.message_id or "")
        if simulation is None:
            continue
        run.messages_examined += 1
        if simulation.classification is previous.classification:
            continue

        run.verdict_changed += 1
        escalated = RISK_ORDER[simulation.classification] > RISK_ORDER[previous.classification]
        if escalated:
            run.newly_suspicious += 1
        else:
            run.newly_cleared += 1

        message = session.get(MailMessage, job.message_id)
        if message is not None:
            if message.campaign_fingerprint:
                campaigns.add(message.campaign_fingerprint)
            if message.reported_by:
                users.add(message.reported_by)
        if len(sample) < 50:
            sample.append(
                {
                    "message_id": job.message_id,
                    "subject": (message.subject if message else "")[:120],
                    "before": previous.classification.value,
                    "after": simulation.classification.value,
                    "escalated": escalated,
                }
            )

        if not dry_run:
            previous.classification = simulation.classification
            previous.score = simulation.score

    run.affected_campaigns = sorted(campaigns)[:100]
    run.affected_users = sorted(users)[:100]
    run.sample = sample
    run.finished_at = utcnow()
    return run


# ---------------------------------------------------------------------------------------------
# Feedback loop (ТЗ 1.0.3 §22, §23, §26)
# ---------------------------------------------------------------------------------------------
def classify_incident(
    session: Session,
    *,
    incident: Incident,
    classification: AnalystClassification,
    analyst_email: str,
    analyst_id: str | None = None,
    comment: str = "",
    offending_rules: list[str] | None = None,
    offending_signals: list[str] | None = None,
    confidence: str = "high",
) -> IncidentClassification:
    """Record an analyst's verdict and feed it back into rule quality (ТЗ 1.0.3 §22, §23).

    The classification is what every quality metric is computed from, so it is stored as its own
    record with its own history: an analyst changing their mind is information, not a correction
    to be overwritten.
    """
    previous = session.execute(
        select(IncidentClassification)
        .where(IncidentClassification.incident_id == incident.id)
        .order_by(IncidentClassification.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    record = IncidentClassification(
        organization_id=incident.organization_id,
        incident_id=incident.id,
        classification=classification,
        previous_classification=previous.classification.value if previous else None,
        analyst_id=analyst_id,
        analyst_email=analyst_email,
        confidence=confidence,
        comment=comment[:4000],
        offending_rules=list(offending_rules or []),
        offending_signals=list(offending_signals or []),
    )
    session.add(record)
    session.flush()

    _apply_to_rule_statistics(session, incident, record)

    if classification is AnalystClassification.FALSE_POSITIVE:
        for rule_id in offending_rules or []:
            session.add(
                DetectionFeedback(
                    organization_id=incident.organization_id,
                    kind="false_positive",
                    incident_id=incident.id,
                    rule_id=rule_id,
                    analyst_email=analyst_email,
                    comment=comment[:4000],
                )
            )
    return record


def _apply_to_rule_statistics(session: Session, incident: Incident, record: IncidentClassification) -> None:
    """Attribute the analyst's verdict to the rules that produced it.

    When the analyst named the offending rules, only those are counted as wrong; otherwise the
    verdict applies to every rule that fired. Naming them is better data, which is why the
    console asks for it.
    """
    from msp_contracts import CONFIRMED_BENIGN, CONFIRMED_THREAT
    from sqlalchemy import select as sa_select

    from ..db.models import IncidentMessage

    if record.classification in CONFIRMED_THREAT:
        field_name = "confirmed_tp"
    elif record.classification in CONFIRMED_BENIGN:
        field_name = "confirmed_fp"
    else:
        return

    message_ids = (
        session.execute(
            sa_select(IncidentMessage.message_id).where(IncidentMessage.incident_id == incident.id)
        )
        .scalars()
        .all()
    )
    if not message_ids:
        return

    rule_ids: list[str] = list(record.offending_rules or [])
    if not rule_ids:
        rule_ids = [
            row
            for row in session.execute(
                sa_select(DetectionSignal.rule_id)
                .join(AnalysisResult, AnalysisResult.id == DetectionSignal.result_id)
                .where(
                    AnalysisResult.message_id.in_(message_ids),
                    DetectionSignal.rule_id.is_not(None),
                    DetectionSignal.suppressed.is_(False),
                    DetectionSignal.shadow.is_(False),
                )
                .distinct()
            )
            .scalars()
            .all()
            if row
        ]

    now = utcnow()
    for rule_id in rule_ids:
        stat = session.execute(
            select(RuleStatistic).where(
                RuleStatistic.organization_id == incident.organization_id,
                RuleStatistic.rule_id == rule_id,
            )
        ).scalar_one_or_none()
        if stat is None:
            stat = RuleStatistic(organization_id=incident.organization_id, rule_id=rule_id)
            session.add(stat)
            session.flush()
        setattr(stat, field_name, getattr(stat, field_name) + 1)
        if field_name == "confirmed_fp":
            from ..db.models import RuleRegistryEntry

            entry = session.execute(
                select(RuleRegistryEntry).where(
                    RuleRegistryEntry.organization_id == incident.organization_id,
                    RuleRegistryEntry.rule_id == rule_id,
                )
            ).scalar_one_or_none()
            if entry is not None:
                entry.last_false_positive_at = now


def record_false_negative(
    session: Session,
    *,
    organization_id: str,
    message_id: str | None,
    incident_id: str | None,
    analyst_email: str,
    source: FalseNegativeSource,
    root_cause: RootCause,
    expected_detection: str = "",
    missing_fact: str = "",
    comment: str = "",
    gap_id: str | None = None,
) -> DetectionFeedback:
    """Record a miss somebody found (ТЗ 1.0.3 §26).

    The platform cannot discover its own false negatives, so every one of these means a human
    or another system noticed something it did not. Naming the layer that failed matters: a
    miss caused by a parser limit is fixed somewhere completely different from one caused by a
    rule that never fired.
    """
    feedback = DetectionFeedback(
        organization_id=organization_id,
        kind="false_negative",
        message_id=message_id,
        incident_id=incident_id,
        analyst_email=analyst_email,
        source=source.value,
        root_cause=root_cause.value,
        expected_detection=expected_detection[:255],
        missing_fact=missing_fact[:255],
        comment=comment[:4000],
        gap_id=gap_id,
    )
    session.add(feedback)
    return feedback


# ---------------------------------------------------------------------------------------------
# Detection gap registry (ТЗ 1.0.3 §27)
# ---------------------------------------------------------------------------------------------
def sync_gap_registry(session: Session, organization_id: str, *, path: str | Path | None = None) -> int:
    """Load the gap registry from its YAML file into the database.

    The file is the source of truth, because a gap is reviewed in a pull request alongside the
    code that caused it. The table exists so the console can show gaps next to the misses that
    fall into them.
    """
    import yaml

    source = Path(path) if path else _default_gap_path()
    if not source.is_file():
        return 0
    payload = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    loaded = 0
    for entry in payload.get("gaps", []) or []:
        gap_id = str(entry.get("id", "")).strip()
        if not gap_id:
            continue
        record = session.execute(
            select(DetectionGapRecord).where(
                DetectionGapRecord.organization_id == organization_id,
                DetectionGapRecord.gap_id == gap_id,
            )
        ).scalar_one_or_none()
        if record is None:
            record = DetectionGapRecord(organization_id=organization_id, gap_id=gap_id)
            session.add(record)
        record.category = str(entry.get("category", ""))[:64]
        record.description = str(entry.get("description", ""))
        record.root_cause = str(entry.get("root_cause", ""))
        try:
            record.severity = Severity(str(entry.get("severity", "medium")).lower())
        except ValueError:
            record.severity = Severity.MEDIUM
        try:
            record.status = GapStatus(str(entry.get("status", "OPEN")).upper())
        except ValueError:
            record.status = GapStatus.OPEN
        record.owner = str(entry.get("owner", ""))[:320]
        record.target_release = str(entry.get("target_release", ""))[:32]
        record.examples = [str(e) for e in (entry.get("examples") or [])]
        record.mitigation = str(entry.get("mitigation", ""))
        record.planned_fix = str(entry.get("planned_fix", ""))
        loaded += 1
    return loaded


def _default_gap_path() -> Path:
    for candidate in (
        Path("/app/datasets/detection_gaps.yaml"),
        Path(__file__).resolve().parents[4] / "datasets" / "detection_gaps.yaml",
    ):
        if candidate.is_file():
            return candidate
    return Path("datasets/detection_gaps.yaml")


def sync_rule_registry(session: Session, organization_id: str) -> int:
    """Mirror the rule pack into the registry so ownership and status are queryable."""
    from ..db.models import RuleRegistryEntry

    ruleset = get_ruleset()
    now = utcnow()
    count = 0
    for rule in ruleset.rules:
        entry = session.execute(
            select(RuleRegistryEntry).where(
                RuleRegistryEntry.organization_id == organization_id,
                RuleRegistryEntry.rule_id == rule.id,
            )
        ).scalar_one_or_none()
        if entry is None:
            entry = RuleRegistryEntry(organization_id=organization_id, rule_id=rule.id)
            session.add(entry)
            entry.last_status_change = now
        elif entry.status != rule.status.value:
            entry.last_status_change = now
        entry.rule_version = rule.version
        entry.status = rule.status.value
        entry.owner = rule.owner
        entry.category = rule.category
        entry.severity = rule.severity.value
        entry.scenarios = list(rule.scenarios)
        count += 1
    return count


def rule_pack_path() -> Path:
    return find_rule_pack()


ENGINE_VERSION_INFO = {
    "detection_engine": ENGINE_VERSION,
    "risk_engine": RISK_ENGINE_VERSION,
    "parser": PARSER_VERSION,
}
