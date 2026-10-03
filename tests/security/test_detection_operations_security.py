"""Security properties of detection operations (ТЗ 1.0.3B §43).

Eleven checks the stage names explicitly. They share a shape: each one asserts that a power
exists only where it was granted, and that a convenience never silently becomes an authority —
feedback does not create exceptions, a replay does not rewrite history, a rule file cannot run
code, and a model cannot settle a verdict.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml
from msp_api.db.models import DetectionException, RuleCandidate
from msp_api.security.rbac import Permission, can_approve_exception, permissions_for
from msp_api.services import feedback, releases
from msp_contracts import (
    AnalystClassification,
    CandidateState,
    FalsePositiveReason,
    Role,
    SignalDisposition,
    utcnow,
)
from msp_detection.rules import RuleSet, find_rule_pack
from msp_detection.semantic import build_provider

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


class TestPermissionsAreNotImplied:
    def test_publishing_is_not_granted_to_an_analyst(self) -> None:
        """Publishing decides what the whole organisation is protected by (§39)."""
        analyst = permissions_for(Role.SECURITY_ANALYST)
        assert Permission.PUBLISH_RULES not in analyst
        assert Permission.REVIEW_RULES not in analyst
        assert Permission.MANAGE_CANARY not in analyst
        assert Permission.EXECUTE_REPLAY not in analyst

    def test_an_analyst_may_still_propose_and_simulate(self) -> None:
        """Four eyes where it matters, not a ticket for every edit."""
        analyst = permissions_for(Role.SECURITY_ANALYST)
        assert Permission.EDIT_RULES in analyst
        assert Permission.SIMULATE_DETECTION in analyst
        assert Permission.CLASSIFY_INCIDENT in analyst

    def test_an_employee_sees_no_detection_internals(self) -> None:
        employee = permissions_for(Role.EMPLOYEE)
        internal = {
            Permission.VIEW_DETECTION_QUALITY,
            Permission.SIMULATE_DETECTION,
            Permission.EDIT_RULES,
            Permission.REVIEW_RULES,
            Permission.PUBLISH_RULES,
            Permission.MANAGE_DETECTION_RULES,
        }
        assert not (employee & internal)


class TestSelfApproval:
    def _candidate(self, **kwargs) -> RuleCandidate:  # type: ignore[no-untyped-def]
        defaults = {
            "organization_id": "org",
            "name": "candidate",
            "source": "rules",
            "author": "author@corp.example",
            "state": CandidateState.READY_FOR_REVIEW,
            "critical_change": True,
            "critical_reasons": ["изменяет жёсткое правило ATT-030"],
            "benchmarked_at": utcnow(),
        }
        defaults.update(kwargs)
        return RuleCandidate(**defaults)

    def test_author_cannot_approve_a_critical_change(self) -> None:
        with pytest.raises(releases.ReleaseError, match="автором"):
            releases.review_candidate(
                self._candidate(), approve=True, reviewer="author@corp.example", comment="ок"
            )

    def test_case_and_spacing_do_not_defeat_the_check(self) -> None:
        """A check defeated by a capital letter is not a check."""
        with pytest.raises(releases.ReleaseError, match="автором"):
            releases.review_candidate(
                self._candidate(),
                approve=True,
                reviewer="  Author@Corp.Example ",
                comment="ок",
            )

    def test_exception_author_cannot_approve_their_own(self) -> None:
        allowed, reason = can_approve_exception(
            role=Role.SECURITY_ADMIN,
            approver_id="u1",
            approver_email="admin@corp.example",
            created_by="admin@corp.example",
        )
        assert allowed is False
        assert "сам" in reason


class TestFeedbackIsNotAuthority:
    def test_feedback_does_not_create_an_exception(self, db, organization) -> None:  # type: ignore[no-untyped-def]
        """An exception is the one control that makes the platform deliberately blind.

        It needs an owner, a review date and a second approver — none of which a click on
        "false positive" provides.
        """
        from msp_api.db.models import AnalysisJob, AnalysisResult, MailMessage
        from msp_contracts import IntakeSource, RiskLevel
        from sqlalchemy import select

        message = MailMessage(
            organization_id=organization.id,
            internet_message_id="<fb@test>",
            raw_sha256="f" * 64,
            subject="Счёт",
            sender_address="billing@partner.test",
            sender_display_name="Поставщик",
            sender_domain="partner.test",
            recipient_count=1,
            size_bytes=1024,
            received_at=utcnow(),
            source=IntakeSource.API,
        )
        db.add(message)
        db.flush()
        job = AnalysisJob(organization_id=organization.id, message_id=message.id, source=IntakeSource.API)
        db.add(job)
        db.flush()
        db.add(
            AnalysisResult(
                job_id=job.id,
                message_id=message.id,
                classification=RiskLevel.HIGH_RISK,
                score=60,
                confidence="high",
                recommendation="x",
            )
        )
        db.commit()

        before = db.execute(select(DetectionException)).scalars().all()
        feedback.record_feedback(
            db,
            organization_id=organization.id,
            analysis_id=job.id,
            classification=AnalystClassification.FALSE_POSITIVE,
            analyst_email="analyst@corp.example",
            comment="Легитимный подрядчик",
            fp_reason=FalsePositiveReason.KNOWN_VENDOR,
            signals=[feedback.SignalJudgement(rule_id="BEC-014", disposition=SignalDisposition.INCORRECT)],
        )
        db.commit()
        after = db.execute(select(DetectionException)).scalars().all()
        assert len(after) == len(before), "обратная связь не создаёт исключений"


class TestRuleFilesCannotRunCode:
    def test_no_executable_yaml_tags_in_the_pack(self) -> None:
        forbidden = ("!!python/", "!!binary", "tag:yaml.org,2002:python")
        offenders = [
            f"{path}: {marker}"
            for path in (REPO_ROOT / "rules").rglob("*.yaml")
            for marker in forbidden
            if marker in path.read_text(encoding="utf-8")
        ]
        assert offenders == []

    def test_an_executable_tag_is_refused_by_the_loader(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """The loader must refuse it, not merely the pack happen not to contain one."""
        evil = tmp_path / "evil.yaml"
        evil.write_text(
            "ruleset: evil\nrules: !!python/object/apply:os.system ['echo pwned']\n",
            encoding="utf-8",
        )
        with pytest.raises((yaml.YAMLError, ValueError, TypeError)):
            RuleSet.from_directory(tmp_path)

    def test_a_condition_cannot_name_an_unknown_fact(self) -> None:
        """A rule that references something the engine never sets would never fire — and would
        look like coverage on every dashboard."""
        from msp_detection.vocabulary import unknown_condition_keys

        assert unknown_condition_keys(RuleSet.from_directory(find_rule_pack())) == {}


class TestSemanticProviderIsNotAVerdict:
    def test_disabled_by_default(self) -> None:
        assert build_provider().available() is False

    def test_an_external_model_cannot_be_enabled_by_name(self) -> None:
        for name in ("openai", "gpt-4", "anthropic", "https://api.example/v1"):
            assert build_provider(name).provider_id == "disabled"


class TestReplayAndReanalysisAreBounded:
    def test_replay_creates_a_revision_rather_than_overwriting(self) -> None:
        """Checked by reading the code path: ``replay`` only ever adds an AnalysisRevision.

        The stored result is updated solely when the caller passes ``apply``; the behaviour is
        exercised end to end in tests/e2e, and this test guards the shape of the function so a
        future refactor cannot quietly turn the default into an overwrite.
        """
        import inspect

        from msp_api.services import detection_ops

        source = inspect.getsource(detection_ops.replay)
        assert "AnalysisRevision(" in source
        assert "if apply" in source or "apply:" in source

    def test_a_reanalysis_job_never_notifies_or_remediates(self) -> None:
        """Checked over the syntax tree, not the text.

        A substring search also matches the comment that promises not to do it — which is how
        the first version of this test failed on the module's own docstring. What matters is
        what the code imports and calls.
        """
        import ast
        import pathlib as _pathlib

        source = _pathlib.Path("apps/api/msp_api/services/reanalysis.py").read_text(encoding="utf-8")
        tree = ast.parse(source)

        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.update(alias.name for alias in node.names)
                imported.add(node.module or "")
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)

        called: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    called.add(func.id)
                elif isinstance(func, ast.Attribute):
                    called.add(func.attr)

        forbidden = {"Notification", "RemediationAction", "notifications", "remediation"}
        assert not (imported & forbidden), f"импортирует {imported & forbidden}"
        assert not (called & forbidden), f"вызывает {called & forbidden}"

    def test_a_graph_query_is_bounded(self) -> None:
        from msp_api.services.investigation_graph import MAX_EDGES, MAX_NODES

        assert 0 < MAX_NODES <= 1000
        assert 0 < MAX_EDGES <= 2000
