"""Критические проверки принуждения не проходят «до зелёного» повторами (AGENTS.md §9, ТЗ 1.3 §78, §86)."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

REQUIRED_JOBS = {
    "enforcement-policy-tests",
    "enforcement-gap-guards",
    "enforcement-canary-tests",
    "enforcement-killswitch-tests",
    "enforcement-rollback-tests",
    "smtp-action-tests",
    "quarantine-tests",
    "quarantine-release-loop-tests",
    "credential-scope-tests",
    "rspamd-effective-actions-audit",
    "enforcement-load-smoke",
    "pilot-readiness-tests",
    "pilot-real-flow-intake-tests",
}


def test_all_blocking_enforcement_jobs_exist() -> None:
    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    assert set(jobs) >= REQUIRED_JOBS, REQUIRED_JOBS - set(jobs)


def test_no_job_retries_tests_until_they_pass() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert not re.search(r"--reruns|rerunfailures|nick-fields/retry|retry-on", text, re.IGNORECASE)


def test_live_enforcement_jobs_do_not_continue_on_error() -> None:
    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    for name in REQUIRED_JOBS:
        job = jobs[name]
        assert job.get("continue-on-error") is not True, name
        assert all(step.get("continue-on-error") is not True for step in job["steps"]), name


def test_no_rerun_plugin_is_configured() -> None:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "rerunfailures" not in text and "pytest-retry" not in text and "flaky" not in text
