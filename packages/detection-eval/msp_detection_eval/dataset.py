"""Golden dataset: cases, versioning and governance (ТЗ 1.0.3 §4.1, §5, §6).

A detection engine can only be measured against messages whose correct answer is known. That
set is the most valuable artefact this phase produces and the easiest one to corrupt: one
mislabelled case quietly moves every metric computed from it, and nothing about the number on
the dashboard reveals that it happened.

So the dataset is treated as a governed object rather than a folder:

* it is **versioned**, and old versions are immutable — a metric from last month means nothing
  if the set it was computed on has since changed;
* it carries a **checksum** over its cases, so a silent edit is detectable;
* every case records **where its label came from** and how confident that label is, because a
  label from a confirmed incident and a label from someone's guess are not the same evidence;
* it records **PII status and approval**, because real mail can only be used under a policy.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from msp_contracts import RiskLevel, utcnow


class DatasetCategory(StrEnum):
    """The golden corpus layout of ТЗ 1.0.3 §5."""

    LEGITIMATE = "legitimate"
    SPAM = "spam"
    PHISHING = "phishing"
    BEC = "bec"
    IMPERSONATION = "impersonation"
    CREDENTIAL_THEFT = "credential_theft"
    MALICIOUS_ATTACHMENT = "malicious_attachment"
    LOOKALIKE = "lookalike"
    QR_PHISHING = "qr_phishing"
    HTML_SMUGGLING = "html_smuggling"
    INVOICE_FRAUD = "invoice_fraud"
    PAYROLL_FRAUD = "payroll_fraud"
    SUPPLIER_FRAUD = "supplier_fraud"
    INTERNAL_ABUSE = "internal_abuse"
    MALFORMED = "malformed"


#: Categories whose messages must NOT be flagged. Everything else is expected to be caught.
BENIGN_CATEGORIES: frozenset[DatasetCategory] = frozenset({DatasetCategory.LEGITIMATE})
#: Spam is unwanted, not an attack: it must not be escalated to an attack verdict, but flagging
#: it as suspicious is not a false positive either. It is scored on its own.
AMBIGUOUS_CATEGORIES: frozenset[DatasetCategory] = frozenset({DatasetCategory.SPAM})


class CaseSource(StrEnum):
    """Where a case came from (ТЗ 1.0.3 §5.1)."""

    SYNTHETIC = "synthetic"
    ANONYMISED_REAL = "anonymised_real"
    CONFIRMED_INCIDENT = "confirmed_incident"
    PHISHING_SIMULATION = "phishing_simulation"
    PUBLIC_DATASET = "public_dataset"
    RED_TEAM = "red_team"


class PiiStatus(StrEnum):
    NONE = "none"  # synthetic, contains no real personal data
    ANONYMISED = "anonymised"
    CONTAINS_PII = "contains_pii"  # permitted only under an approved policy


class ApprovalStatus(StrEnum):
    DRAFT = "draft"
    APPROVED = "approved"
    RETIRED = "retired"


@dataclass
class EvaluationCase:
    """One message with a known correct answer (ТЗ 1.0.3 §4.1)."""

    id: str
    dataset_id: str
    category: DatasetCategory
    #: How to obtain the message bytes. ``fixture:<name>`` for the built-in corpus,
    #: ``file:<relative path>`` for a stored sample.
    message_reference: str
    expected_classification: RiskLevel
    expected_categories: list[str] = field(default_factory=list)
    #: Rules that must fire. A case with none asserts only the classification.
    expected_rules: list[str] = field(default_factory=list)
    #: Rules that must NOT fire. This is how a known false positive is pinned down so it
    #: cannot come back unnoticed.
    forbidden_rules: list[str] = field(default_factory=list)
    severity: str = "medium"
    source: CaseSource = CaseSource.SYNTHETIC
    #: How much the label itself can be trusted. A low-confidence label should not be allowed
    #: to fail a release on its own.
    confidence: float = 1.0
    labels: list[str] = field(default_factory=list)
    #: Threat scenarios this case exercises (ТЗ 1.0.3 §28).
    scenarios: list[str] = field(default_factory=list)
    notes: str = ""
    #: Enrichment is a separate stage; a case that needs it must say so, or local analysis
    #: will be judged for not knowing something it could not know yet.
    requires_enrichment: bool = False
    #: A registered DetectionGap this case is known to fall into. A miss with a gap is an
    #: accepted limitation; a miss without one is a regression (ТЗ 1.0.3 §27, §60). It is a
    #: reference, not an excuse: the gap has an owner, a severity and a target release.
    known_gap: str = ""

    @property
    def is_benign(self) -> bool:
        return self.category in BENIGN_CATEGORIES

    @property
    def is_ambiguous(self) -> bool:
        return self.category in AMBIGUOUS_CATEGORIES

    def fingerprint(self) -> str:
        """Stable hash of the case's assertions, used for the dataset checksum."""
        payload = json.dumps(
            {
                "id": self.id,
                "category": self.category.value,
                "message_reference": self.message_reference,
                "expected_classification": self.expected_classification.value,
                "expected_rules": sorted(self.expected_rules),
                "forbidden_rules": sorted(self.forbidden_rules),
                "requires_enrichment": self.requires_enrichment,
                "known_gap": self.known_gap,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["category"] = self.category.value
        data["expected_classification"] = self.expected_classification.value
        data["source"] = self.source.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvaluationCase:
        return cls(
            id=str(data["id"]),
            dataset_id=str(data.get("dataset_id", "")),
            category=DatasetCategory(str(data["category"])),
            message_reference=str(data["message_reference"]),
            expected_classification=RiskLevel(str(data["expected_classification"])),
            expected_categories=[str(c) for c in data.get("expected_categories", [])],
            expected_rules=[str(r) for r in data.get("expected_rules", [])],
            forbidden_rules=[str(r) for r in data.get("forbidden_rules", [])],
            severity=str(data.get("severity", "medium")),
            source=CaseSource(str(data.get("source", "synthetic"))),
            confidence=float(data.get("confidence", 1.0)),
            labels=[str(x) for x in data.get("labels", [])],
            scenarios=[str(s) for s in data.get("scenarios", [])],
            notes=str(data.get("notes", "")),
            requires_enrichment=bool(data.get("requires_enrichment", False)),
            known_gap=str(data.get("known_gap", "")),
        )


@dataclass
class Dataset:
    """A versioned, governed collection of cases (ТЗ 1.0.3 §6)."""

    id: str
    version: str
    cases: list[EvaluationCase] = field(default_factory=list)
    created_at: datetime = field(default_factory=utcnow)
    owner: str = ""
    source: str = "synthetic"
    pii_status: PiiStatus = PiiStatus.NONE
    approval_status: ApprovalStatus = ApprovalStatus.DRAFT
    changelog: list[str] = field(default_factory=list)
    notes: str = ""

    # -- governance ----------------------------------------------------------------------------
    @property
    def sample_count(self) -> int:
        return len(self.cases)

    def class_distribution(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for case in self.cases:
            counts[case.category.value] = counts.get(case.category.value, 0) + 1
        return dict(sorted(counts.items()))

    def checksum(self) -> str:
        """Hash over every case, so an edit to a stored dataset is detectable.

        Computed from the cases' assertions rather than from the file bytes: reformatting the
        file should not invalidate a metric, while changing a single expected verdict must.
        """
        digest = hashlib.sha256()
        for case in sorted(self.cases, key=lambda c: c.id):
            digest.update(case.fingerprint().encode("ascii"))
        return digest.hexdigest()

    def governance(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "created_at": self.created_at.isoformat(),
            "owner": self.owner,
            "source": self.source,
            "sample_count": self.sample_count,
            "class_distribution": self.class_distribution(),
            "pii_status": self.pii_status.value,
            "approval_status": self.approval_status.value,
            "checksum": self.checksum(),
        }

    def validate(self) -> list[str]:
        """Problems that make the dataset unfit to measure against."""
        problems: list[str] = []
        seen: set[str] = set()
        for case in self.cases:
            if case.id in seen:
                problems.append(f"duplicate case id: {case.id}")
            seen.add(case.id)
            if not case.message_reference:
                problems.append(f"{case.id}: no message reference")
            if not 0.0 <= case.confidence <= 1.0:
                problems.append(f"{case.id}: label confidence must be within 0..1")
            overlap = set(case.expected_rules) & set(case.forbidden_rules)
            if overlap:
                problems.append(f"{case.id}: rules both expected and forbidden: {sorted(overlap)}")
            if case.is_benign and case.expected_classification not in {
                RiskLevel.LOW_RISK,
                RiskLevel.UNKNOWN,
            }:
                problems.append(
                    f"{case.id}: a legitimate case cannot expect {case.expected_classification.value}"
                )
        if self.pii_status is PiiStatus.CONTAINS_PII and self.approval_status is not (
            ApprovalStatus.APPROVED
        ):
            problems.append(
                "dataset contains personal data but is not approved: real mail may only be "
                "used under an approved policy (ТЗ 1.0.3 §5.1)"
            )
        return problems

    # -- io ---------------------------------------------------------------------------------------
    def by_category(self, category: DatasetCategory) -> list[EvaluationCase]:
        return [case for case in self.cases if case.category is category]

    def __iter__(self) -> Iterator[EvaluationCase]:
        return iter(self.cases)

    def __len__(self) -> int:
        return len(self.cases)

    def to_json(self) -> str:
        return json.dumps(
            {
                "dataset": self.governance(),
                "changelog": self.changelog,
                "notes": self.notes,
                "cases": [case.as_dict() for case in self.cases],
            },
            ensure_ascii=False,
            indent=2,
        )

    def write(self, path: str | Path) -> Path:
        """Write the dataset, refusing to overwrite a different version in place.

        Immutability of historical versions is the property that makes a stored metric mean
        anything later (ТЗ 1.0.3 §6).
        """
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            existing = json.loads(target.read_text(encoding="utf-8"))
            previous = existing.get("dataset", {})
            if previous.get("version") != self.version and previous.get("checksum") != (self.checksum()):
                raise ValueError(
                    f"{target} already holds version {previous.get('version')}; publish a new "
                    "version instead of overwriting a historical one"
                )
        target.write_text(self.to_json(), encoding="utf-8")
        return target

    @classmethod
    def load(cls, path: str | Path) -> Dataset:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        meta = payload.get("dataset", {})
        dataset = cls(
            id=str(meta.get("id", "")),
            version=str(meta.get("version", "")),
            cases=[EvaluationCase.from_dict(c) for c in payload.get("cases", [])],
            created_at=datetime.fromisoformat(meta["created_at"]) if meta.get("created_at") else utcnow(),
            owner=str(meta.get("owner", "")),
            source=str(meta.get("source", "synthetic")),
            pii_status=PiiStatus(str(meta.get("pii_status", "none"))),
            approval_status=ApprovalStatus(str(meta.get("approval_status", "draft"))),
            changelog=[str(c) for c in payload.get("changelog", [])],
            notes=str(payload.get("notes", "")),
        )
        stored = str(meta.get("checksum", ""))
        if stored and stored != dataset.checksum():
            raise ValueError(
                f"{path}: checksum mismatch. The dataset was edited without publishing a new "
                "version, so metrics computed from it cannot be compared with earlier runs."
            )
        return dataset

    @classmethod
    def from_cases(cls, cases: Iterable[EvaluationCase], **meta: Any) -> Dataset:
        return cls(cases=list(cases), **meta)
