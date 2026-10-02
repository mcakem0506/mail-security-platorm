"""Candidate rule packs, review and detection releases (ТЗ 1.0.3B §10–§12, §24).

A candidate is a **pointer** to a rule pack — a directory in the deployment or a Git reference —
not a copy of its rules in the database. Rules are data that go through code review, and a pack
stored in a table could be published without anyone reading the diff. What lives here is the
review: who proposed it, what the benchmark said, who looked at it, and whether it may ship.

Publishing therefore records a decision and produces a release manifest; the pack itself reaches
production by deployment. That is what keeps the reviewed artefact and the running artefact the
same thing, which is the property every other guarantee in this stage rests on.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess  # nosec B404 - reads the current commit for the manifest, fixed argv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from msp_contracts import CandidateState, Severity, utcnow
from msp_detection.rules import Rule, RuleSet, find_rule_pack
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import DetectionGapRecord, DetectionRelease, RuleCandidate
from ..observability import detection_gap_open, detection_release_info

logger = logging.getLogger(__name__)

#: Release versions are vYYYY.MM.N — the month a release shipped is part of its identity, and N
#: counts within that month.
VERSION_RE = re.compile(r"^v(\d{4})\.(\d{2})\.(\d+)$")

#: Rule properties whose mistakes are expensive enough that the author may not approve their own
#: change (ТЗ 1.0.3B §12). Hard signals pin a verdict; the categories below are the ones where a
#: miss costs money or an account.
CRITICAL_CATEGORIES: frozenset[str] = frozenset(
    {
        "malicious_attachment",
        "suspicious_attachment",
        "credential_harvesting",
        "credential_theft",
        "invoice_payment_fraud",
        "executive_impersonation",
        "corporate_identity_impersonation",
        "vendor_impersonation",
    }
)


class ReleaseError(ValueError):
    """A candidate or release operation that cannot proceed, with the reason."""


# ---------------------------------------------------------------------------------------------
# Candidate packs
# ---------------------------------------------------------------------------------------------
@dataclass
class PackDiff:
    """What a candidate changes relative to the pack in production."""

    added: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    critical_reasons: list[str] = field(default_factory=list)

    @property
    def critical(self) -> bool:
        return bool(self.critical_reasons)

    def as_dict(self) -> dict[str, Any]:
        return {
            "added": self.added,
            "changed": self.changed,
            "removed": self.removed,
            "critical": self.critical,
            "critical_reasons": self.critical_reasons,
        }


def _critical_reason(rule: Rule, verb: str) -> str | None:
    if rule.hard:
        return f"{verb} жёсткое правило {rule.id}"
    if rule.category in CRITICAL_CATEGORIES:
        return f"{verb} правило {rule.id} категории {rule.category}"
    if rule.severity is Severity.CRITICAL:
        return f"{verb} правило {rule.id} критической серьёзности"
    return None


def diff_packs(production: RuleSet, candidate: RuleSet) -> PackDiff:
    """Compare two packs and decide whether the change needs a second pair of eyes."""
    before = {rule.id: rule for rule in production.rules}
    after = {rule.id: rule for rule in candidate.rules}
    diff = PackDiff()

    for rule_id, rule in sorted(after.items()):
        previous = before.get(rule_id)
        if previous is None:
            diff.added.append(rule_id)
            reason = _critical_reason(rule, "добавляет")
            if reason:
                diff.critical_reasons.append(reason)
            continue
        if (
            previous.version != rule.version
            or previous.status is not rule.status
            or previous.effective_weight != rule.effective_weight
            or previous.conditions.render() != rule.conditions.render()
            or previous.severity is not rule.severity
        ):
            diff.changed.append(rule_id)
            reason = _critical_reason(rule, "изменяет") or _critical_reason(previous, "изменяет")
            if reason:
                diff.critical_reasons.append(reason)

    for rule_id in sorted(before):
        if rule_id not in after:
            diff.removed.append(rule_id)
            # Removing protection is critical whatever the rule looked like: the reviewer needs
            # to agree that the organisation no longer needs it.
            diff.critical_reasons.append(f"удаляет правило {rule_id}")

    return diff


def load_pack(source: str, kind: str = "path") -> RuleSet:
    """Load a candidate pack from its source."""
    if kind != "path":
        raise ReleaseError(f"источник пакета '{kind}' пока не поддерживается")
    path = Path(source)
    if not path.is_dir():
        raise ReleaseError(f"каталог с правилами не найден: {source}")
    return RuleSet.from_directory(path)


def create_candidate(
    session: Session,
    *,
    organization_id: str,
    name: str,
    source: str,
    description: str = "",
    source_kind: str = "path",
    author: str,
) -> RuleCandidate:
    """Register a candidate pack and validate it immediately.

    Validation at creation is deliberate: a candidate that does not load is not a proposal, and
    discovering that at review time wastes the reviewer rather than the author.
    """
    existing = session.execute(
        select(RuleCandidate).where(
            RuleCandidate.organization_id == organization_id, RuleCandidate.name == name
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ReleaseError(f"кандидат с именем «{name}» уже существует")

    candidate = RuleCandidate(
        organization_id=organization_id,
        name=name[:128],
        description=description[:4000],
        source=source[:512],
        source_kind=source_kind,
        author=author,
        state=CandidateState.DRAFT,
    )
    session.add(candidate)
    session.flush()
    validate_candidate(session, candidate)
    return candidate


def validate_candidate(session: Session, candidate: RuleCandidate) -> PackDiff:
    """Load the pack, diff it against production and record what it changes."""
    production = RuleSet.from_directory(find_rule_pack())
    pack = load_pack(candidate.source, candidate.source_kind)

    problems = _validate_pack(pack)
    if problems:
        raise ReleaseError("пакет правил не прошёл проверку: " + "; ".join(problems[:5]))

    diff = diff_packs(production, pack)
    candidate.ruleset_fingerprint = pack.version_fingerprint
    candidate.base_fingerprint = production.version_fingerprint
    candidate.added_rules = diff.added
    candidate.changed_rules = diff.changed
    candidate.removed_rules = diff.removed
    candidate.critical_change = diff.critical
    candidate.critical_reasons = diff.critical_reasons
    _ = session
    return diff


def _validate_pack(pack: RuleSet) -> list[str]:
    """Checks a pack must pass before anyone spends review time on it."""
    from msp_detection.vocabulary import unknown_condition_keys

    problems: list[str] = []
    if not pack.rules:
        problems.append("пакет не содержит правил")
    unknown = unknown_condition_keys(pack)
    for rule_id, keys in sorted(unknown.items()):
        problems.append(f"{rule_id}: условия ссылаются на неизвестные факты {sorted(keys)}")
    for rule in pack.rules:
        if rule.status.value == "ACTIVE" and not rule.owner:
            problems.append(f"{rule.id}: активное правило без владельца")
    return problems


def submit_for_review(candidate: RuleCandidate, *, actor: str) -> RuleCandidate:
    if not candidate.open_for_changes:
        raise ReleaseError("кандидат уже отправлен на ревью или завершён")
    if not candidate.benchmarked_at:
        # Review without a benchmark asks a person to judge a rule change by reading it, which
        # is exactly what the golden corpus exists to avoid.
        raise ReleaseError("перед ревью кандидат должен быть прогнан по золотому корпусу")
    candidate.state = CandidateState.READY_FOR_REVIEW
    candidate.author = candidate.author or actor
    return candidate


def review_candidate(
    candidate: RuleCandidate,
    *,
    approve: bool,
    reviewer: str,
    comment: str = "",
) -> RuleCandidate:
    """Approve a candidate or send it back (ТЗ 1.0.3B §12).

    Self-approval is refused for a change that touches a hard signal, malware, credential theft,
    impersonation of a protected identity or payment fraud. Those are the rules whose mistakes
    are expensive in both directions, and "the author read it twice" is not a review.
    """
    if candidate.state is not CandidateState.READY_FOR_REVIEW:
        raise ReleaseError("кандидат не находится на ревью")
    if not approve and not comment.strip():
        raise ReleaseError("при возврате на доработку требуется комментарий")
    if (
        approve
        and candidate.critical_change
        and reviewer.strip().lower() == (candidate.author or "").strip().lower()
    ):
        raise ReleaseError(
            "критическое изменение не может быть утверждено его автором: "
            + "; ".join(candidate.critical_reasons[:3])
        )
    candidate.state = CandidateState.APPROVED if approve else CandidateState.CHANGES_REQUESTED
    candidate.reviewer = reviewer
    candidate.review_comment = comment[:4000]
    candidate.reviewed_at = utcnow()
    return candidate


def reject_candidate(candidate: RuleCandidate, *, reviewer: str, comment: str) -> RuleCandidate:
    if candidate.state in {CandidateState.PUBLISHED, CandidateState.REJECTED}:
        raise ReleaseError("кандидат уже завершён")
    if not comment.strip():
        raise ReleaseError("при отклонении требуется причина")
    candidate.state = CandidateState.REJECTED
    candidate.reviewer = reviewer
    candidate.review_comment = comment[:4000]
    candidate.reviewed_at = utcnow()
    return candidate


# ---------------------------------------------------------------------------------------------
# Releases
# ---------------------------------------------------------------------------------------------
def next_version(session: Session, organization_id: str, *, now: Any = None) -> str:
    """The next vYYYY.MM.N for this month."""
    moment = now or utcnow()
    prefix = f"v{moment.year:04d}.{moment.month:02d}."
    existing = (
        session.execute(
            select(DetectionRelease.version).where(
                DetectionRelease.organization_id == organization_id,
                DetectionRelease.version.like(f"{prefix}%"),
            )
        )
        .scalars()
        .all()
    )
    highest = 0
    for version in existing:
        match = VERSION_RE.match(str(version))
        if match:
            highest = max(highest, int(match.group(3)))
    return f"{prefix}{highest + 1}"


def _commit_sha() -> str:
    """The commit this deployment was built from.

    Read from the environment first: a runtime image has no git and no repository, so asking git
    there returns nothing and the manifest loses the one field that ties a release to a diff.
    The build stamps ``MSP_COMMIT_SHA``; the git call is the fallback for running from a checkout.
    """
    stamped = os.environ.get("MSP_COMMIT_SHA", "").strip()
    if stamped:
        return stamped[:64]
    git = shutil.which("git")
    if git is None:
        return ""
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell
            [git, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=30, check=False
        )
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""


def publish_release(
    session: Session,
    *,
    organization_id: str,
    candidate: RuleCandidate | None,
    metrics: dict[str, Any],
    dataset_version: str,
    dataset_checksum: str,
    parser_version: str,
    risk_engine_version: str,
    published_by: str,
    gate_result: dict[str, Any] | None = None,
) -> DetectionRelease:
    """Publish a release manifest (ТЗ 1.0.3B §24).

    The manifest records every version a verdict depends on, not only the rules: the same rules
    on a different parser are not the same detection, and a release that cannot be reproduced is
    a release nobody can investigate against.
    """
    if candidate is not None and candidate.state is not CandidateState.APPROVED:
        raise ReleaseError("публиковать можно только утверждённого кандидата")

    pack = (
        load_pack(candidate.source, candidate.source_kind)
        if candidate is not None
        else RuleSet.from_directory(find_rule_pack())
    )
    previous = session.execute(
        select(DetectionRelease)
        .where(DetectionRelease.organization_id == organization_id)
        .order_by(DetectionRelease.published_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    gaps = (
        session.execute(
            select(DetectionGapRecord).where(
                DetectionGapRecord.organization_id == organization_id,
                DetectionGapRecord.status.not_in(["RESOLVED", "WONT_FIX"]),
            )
        )
        .scalars()
        .all()
    )

    diff = (
        PackDiff(
            added=list(candidate.added_rules or []),
            changed=list(candidate.changed_rules or []),
            removed=list(candidate.removed_rules or []),
        )
        if candidate is not None
        else PackDiff()
    )

    release = DetectionRelease(
        organization_id=organization_id,
        version=next_version(session, organization_id),
        ruleset_fingerprint=pack.version_fingerprint,
        parser_version=parser_version,
        risk_engine_version=risk_engine_version,
        commit_sha=_commit_sha(),
        candidate_id=candidate.id if candidate else None,
        approved_by=candidate.reviewer if candidate else "",
        dataset_version=dataset_version,
        dataset_checksum=dataset_checksum,
        new_rules=diff.added,
        changed_rules=diff.changed,
        removed_rules=diff.removed,
        metrics=metrics,
        gate_result=gate_result or {},
        known_limitations=[
            {
                "gap_id": gap.gap_id,
                "severity": gap.severity.value,
                "status": gap.status.value,
                "owner": gap.owner,
                "target_release": gap.target_release,
                "description": gap.description[:300],
            }
            for gap in gaps
        ],
        metric_deltas=_deltas(previous.metrics if previous else {}, metrics),
        published_by=published_by,
    )
    release.changelog = render_notes(release, previous)
    session.add(release)
    session.flush()

    if candidate is not None:
        candidate.state = CandidateState.PUBLISHED
        candidate.published_at = utcnow()
        candidate.release_id = release.id

    detection_release_info.labels(
        release.version,
        release.dataset_version,
        release.parser_version,
        release.risk_engine_version,
    ).set(1)
    severities: dict[str, int] = {}
    for gap in gaps:
        severities[gap.severity.value] = severities.get(gap.severity.value, 0) + 1
    for severity, count in severities.items():
        detection_gap_open.labels(severity).set(count)
    logger.info("release.published", extra={"version": release.version})
    return release


def _deltas(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Metric changes against the previous release.

    A metric missing on either side yields ``None`` rather than a delta against zero: "it did
    not exist before" and "it dropped to zero" are different facts.
    """
    out: dict[str, Any] = {}
    for key in ("precision", "recall", "f1", "false_positive_rate", "coverage"):
        old, new = before.get(key), after.get(key)
        if isinstance(old, (int, float)) and isinstance(new, (int, float)):
            out[key] = round(new - old, 4)
        else:
            out[key] = None
    latency_before = (before.get("latency_ms") or {}).get("p95")
    latency_after = (after.get("latency_ms") or {}).get("p95")
    out["latency_p95_ms"] = (
        round(latency_after - latency_before, 2)
        if isinstance(latency_before, (int, float)) and isinstance(latency_after, (int, float))
        else None
    )
    return out


def render_notes(release: DetectionRelease, previous: DetectionRelease | None) -> str:
    """Release notes generated from the manifest, not typed by hand.

    Hand-written notes drift from what shipped; these cannot, because they are produced from the
    same record the release is published with.
    """
    lines = [f"# Релиз детектирования {release.version}", ""]
    if previous is not None:
        lines.append(f"Предыдущий релиз: {previous.version} от {previous.published_at:%Y-%m-%d}.")
        lines.append("")

    for title, rules in (
        ("Новые правила", release.new_rules),
        ("Изменённые правила", release.changed_rules),
        ("Удалённые правила", release.removed_rules),
    ):
        if rules:
            lines += [f"## {title}", "", *[f"- `{rule_id}`" for rule_id in rules], ""]

    deltas = release.metric_deltas or {}
    if deltas:
        lines += ["## Изменение метрик", "", "| Метрика | Δ |", "|---|---:|"]
        for key, value in deltas.items():
            lines.append(f"| {key} | {'—' if value is None else f'{value:+}'} |")
        lines += ["", "`—` означает, что метрику не с чем сравнить, а не что она не изменилась.", ""]

    if release.known_limitations:
        lines += ["## Известные пробелы в этом релизе", ""]
        for gap in release.known_limitations:
            lines.append(
                f"- **{gap['gap_id']}** ({gap['severity']}, {gap['status']}) — "
                f"{gap['description']} · владелец {gap['owner']}, релиз {gap['target_release']}"
            )
        lines.append("")
    else:
        lines += ["## Известные пробелы в этом релизе", "", "Открытых пробелов нет.", ""]

    lines += [
        "## Воспроизводимость",
        "",
        f"- пакет правил: `{release.ruleset_fingerprint[:64]}…`",
        f"- парсер: `{release.parser_version}`",
        f"- движок риска: `{release.risk_engine_version}`",
        f"- датасет: `{release.dataset_version}` (`{release.dataset_checksum[:16]}…`)",
        f"- коммит: `{release.commit_sha[:12] or 'неизвестен'}`",
        "",
    ]
    return "\n".join(lines)
