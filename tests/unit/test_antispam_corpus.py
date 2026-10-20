"""Синтетический корпус спама и оценка по записям сканера (ТЗ 1.2 §39)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from msp_antispam import corpus

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "rspamd"


def test_the_corpus_is_deterministic() -> None:
    first = corpus.generate_cases()
    second = corpus.generate_cases()
    assert corpus.corpus_checksum(first) == corpus.corpus_checksum(second)
    assert len({c.id for c in first}) == len(first), "идентификаторы примеров должны быть уникальны"


def test_every_required_category_is_present() -> None:
    present = {c.category for c in corpus.generate_cases()}
    assert set(corpus.CATEGORIES) <= present


def test_gtube_is_a_smoke_check_and_not_a_quality_sample() -> None:
    smoke = [c for c in corpus.generate_cases() if c.label == corpus.SMOKE]
    assert len(smoke) == 1
    assert corpus.GTUBE in smoke[0].body


def test_cases_survive_a_roundtrip() -> None:
    for case in corpus.generate_cases(per_category=2):
        assert corpus.case_from_dict(json.loads(json.dumps(corpus.case_to_dict(case)))) == case


def test_a_message_is_valid_rfc5322_with_one_from() -> None:
    for case in corpus.generate_cases(per_category=2):
        text = case.eml(domain="corpus.example")
        assert text.count("\r\nFrom: ") == 0 and text.startswith("From: ")
        assert "\r\n\r\n" in text


def test_no_record_means_missing_not_clean() -> None:
    cases = corpus.generate_cases(per_category=2)
    report = corpus.evaluate(cases, {})
    assert report.scored == 0
    assert len(report.missing_records) == len(cases)
    assert report.spam_precision is None and report.spam_recall is None
    assert report.smoke_ok is False


def test_a_recorded_scan_is_scored() -> None:
    record = json.loads((FIXTURES / "all_pass.json").read_text(encoding="utf-8"))
    cases = [c for c in corpus.generate_cases(per_category=1) if c.label == corpus.HAM][:1]
    report = corpus.evaluate(cases, {cases[0].id: record})
    assert report.scored == 1
    assert report.missing_records == []


# --- гейт регрессии по записанному корпусу (scripts/evaluate_spam.py) -------------------------
def _gate(*args: str) -> subprocess.CompletedProcess[str]:
    root = Path(__file__).resolve().parents[2]
    return subprocess.run(
        [sys.executable, str(root / "scripts" / "evaluate_spam.py"), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        check=False,
    )


def test_the_recorded_corpus_passes_the_gate() -> None:
    assert _gate("--gate").returncode == 0


def test_recorded_corpus_matches_the_generator() -> None:
    root = Path(__file__).resolve().parents[2]
    recorded = json.loads((root / "datasets" / "spam" / "cases.json").read_text(encoding="utf-8"))
    cases = [corpus.case_from_dict(item) for item in recorded]
    assert corpus.corpus_checksum(cases) == corpus.corpus_checksum(corpus.generate_cases())


def test_no_legitimate_example_is_classified_as_spam() -> None:
    root = Path(__file__).resolve().parents[2]
    cases = [
        corpus.case_from_dict(i)
        for i in json.loads((root / "datasets" / "spam" / "cases.json").read_text(encoding="utf-8"))
    ]
    records = json.loads((root / "datasets" / "spam" / "records.json").read_text(encoding="utf-8"))["records"]
    report = corpus.evaluate(cases, records)
    assert report.ham_flagged_as_spam == []
    assert report.missing_records == []
