"""The six end-to-end paths the stage names (ТЗ 1.0.3B §44).

Each walks a whole loop over HTTP, because the interesting failures live between the parts: a
feedback record that never reaches rule statistics, a candidate that cannot be reviewed because
the benchmark was never stored, a re-evaluation that quietly applies itself. Unit tests do not
see any of those.
"""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient
from fixtures.corpus import BY_NAME
from msp_contracts import Role


@pytest.fixture
def client(engine, storage_dir, monkeypatch):  # type: ignore[no-untyped-def]
    from msp_api import deps
    from msp_api.config import get_settings
    from msp_api.db.session import get_session
    from msp_api.main import create_app
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=engine, expire_on_commit=False)

    def override_session():  # type: ignore[no-untyped-def]
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    deps.reset_provider_cache()
    monkeypatch.setattr(deps, "_redis_client", lambda: None)
    deps.reset_rate_limiter()

    app = create_app(get_settings())
    app.dependency_overrides[get_session] = override_session
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    deps.reset_provider_cache()


@pytest.fixture
def people(engine, organization):  # type: ignore[no-untyped-def]
    from msp_api.db.models import User
    from msp_api.security.auth import hash_password
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    password = "Operations-Test-Password-7"
    accounts = {
        "employee": ("user@corp.example", Role.EMPLOYEE),
        "analyst": ("analyst@corp.example", Role.SECURITY_ANALYST),
        "admin": ("admin@corp.example", Role.SECURITY_ADMIN),
        "lead": ("lead@corp.example", Role.SECURITY_ADMIN),
    }
    created: dict[str, dict[str, str]] = {}
    with factory() as session:
        for key, (email, role) in accounts.items():
            user = User(
                organization_id=organization.id,
                email=email,
                display_name=key,
                role=role,
                password_hash=hash_password(password),
            )
            session.add(user)
            session.flush()
            created[key] = {"id": user.id, "email": email, "password": password}
        session.commit()
    return created


class Actor:
    def __init__(self, client: TestClient, email: str, password: str) -> None:
        self.client = client
        response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert response.status_code == 200, response.text
        self.csrf = response.json()["csrf_token"]
        self.email = email

    def get(self, path: str, **kwargs):  # type: ignore[no-untyped-def]
        return self.client.get(path, **kwargs)

    def post(self, path: str, json=None, **kwargs):  # type: ignore[no-untyped-def]
        return self.client.post(path, json=json, headers={"x-csrf-token": self.csrf}, **kwargs)

    def logout(self) -> None:
        self.client.post("/api/v1/auth/logout", headers={"x-csrf-token": self.csrf})
        self.client.cookies.clear()


def _report(client: TestClient, people, name: str = "09_bank_details_change") -> str:
    """An employee reports a corpus message; returns the analysis id."""
    employee = Actor(client, people["employee"]["email"], people["employee"]["password"])
    submitted = employee.post(
        "/api/v1/analysis",
        json={
            "raw_eml_base64": base64.b64encode(BY_NAME[name].raw).decode(),
            "report_as_phishing": True,
        },
    )
    assert submitted.status_code == 202, submitted.text
    employee.logout()
    return submitted.json()["job_id"]


class TestScenario1FalsePositiveToTuning:
    """FP → feedback → candidate → simulation (§44.1)."""

    def test_the_loop_closes(self, client, people, db) -> None:  # type: ignore[no-untyped-def]
        analysis_id = _report(client, people)
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])

        detail = analyst.get(f"/api/v1/analysis/{analysis_id}/detail").json()
        offending = next(s["rule_id"] for s in detail["signals"] if s["rule_id"])

        # A false positive without a reason is refused: the reason decides who fixes it.
        refused = analyst.post(
            f"/api/v1/analysis/{analysis_id}/feedback",
            json={
                "classification": "FALSE_POSITIVE",
                "comment": "Легитимное письмо подрядчика",
                "signals": [{"rule_id": offending, "disposition": "INCORRECT"}],
            },
        )
        assert refused.status_code == 400

        accepted = analyst.post(
            f"/api/v1/analysis/{analysis_id}/feedback",
            json={
                "classification": "FALSE_POSITIVE",
                "comment": "Легитимное письмо подрядчика, подтверждено по телефону",
                "fp_reason": "KNOWN_VENDOR",
                "signals": [{"rule_id": offending, "disposition": "INCORRECT"}],
            },
        )
        assert accepted.status_code == 200, accepted.text

        # The judgement reaches rule quality.
        quality = analyst.get("/api/v1/detection/rules/quality").json()
        row = next(item for item in quality if item["rule_id"] == offending)
        assert row["false_positive"] >= 1

        # And the analyst can simulate the rule against the same message without changing it.
        message_id = detail["message_id"]
        simulated = analyst.post(
            "/api/v1/detection/simulate", json={"message_id": message_id, "rule_id": offending}
        )
        assert simulated.status_code == 200, simulated.text
        assert [s["rule_id"] for s in simulated.json()["signals"]] == [offending]

        from msp_api.db.models import AuditEvent
        from sqlalchemy import select

        assert "detection.feedback" in set(db.execute(select(AuditEvent.action)).scalars().all())


class TestScenario2MissedDetectionToGap:
    """FN → gap → golden case → candidate → regression (§44.2)."""

    def test_a_miss_needs_enough_to_act_on_and_lands_in_the_registry(self, client, people) -> None:  # type: ignore[no-untyped-def]
        analysis_id = _report(client, people)
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])

        incomplete = analyst.post(
            "/api/v1/detection/missed-detections",
            json={
                "source": "ANALYST",
                "root_cause": "MISSING_RULE",
                "expected_category": "bec",
                "minimum_classification": "HIGH_RISK",
                "severity": "high",
                "owner": "",
                "target_release": "MSP 1.0.4",
                "analysis_id": analysis_id,
            },
        )
        assert incomplete.status_code == 422, "без владельца запись не принимается"

        reported = analyst.post(
            "/api/v1/detection/missed-detections",
            json={
                "source": "RED_TEAM",
                "root_cause": "EXCEPTION_SUPPRESSION",
                "expected_category": "credential_theft",
                "minimum_classification": "HIGH_RISK",
                "severity": "high",
                "owner": "detection-url@corp.example",
                "target_release": "MSP 1.0.4",
                "analysis_id": analysis_id,
                "comment": "Исключение погасило сигнал",
            },
        )
        assert reported.status_code == 200, reported.text
        assert reported.json()["root_cause"] == "EXCEPTION_SUPPRESSION"

        admin = Actor(client, people["admin"]["email"], people["admin"]["password"])
        admin.post("/api/v1/detection/rules/sync", json=None)
        gaps = admin.get("/api/v1/detection/gaps").json()
        assert gaps, "реестр пробелов должен быть загружен"
        assert all(gap["owner"] and gap["mitigation"] for gap in gaps)


class TestScenario3RuleRelease:
    """draft → review → publish (§44.3)."""

    def test_a_candidate_cannot_skip_the_benchmark_or_self_approval(self, client, people) -> None:  # type: ignore[no-untyped-def]
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        created = analyst.post(
            "/api/v1/detection/candidates",
            json={"name": "e2e-candidate", "source": "rules", "description": "тот же пакет"},
        )
        assert created.status_code == 200, created.text
        candidate_id = created.json()["candidate_id"]

        # Review before a corpus run is refused: otherwise a reviewer judges a rule by reading it.
        too_early = analyst.post(f"/api/v1/detection/candidates/{candidate_id}/submit")
        assert too_early.status_code == 400

        benchmark = analyst.post(f"/api/v1/detection/candidates/{candidate_id}/benchmark")
        assert benchmark.status_code == 200, benchmark.text
        assert benchmark.json()["gate_passed"] is True

        submitted = analyst.post(f"/api/v1/detection/candidates/{candidate_id}/submit")
        assert submitted.status_code == 200
        assert submitted.json()["state"] == "READY_FOR_REVIEW"

        # An analyst may not review or publish.
        assert (
            analyst.post(
                f"/api/v1/detection/candidates/{candidate_id}/review",
                json={"approve": True, "comment": "сам"},
            ).status_code
            == 403
        )
        assert analyst.post("/api/v1/detection/releases", json={}).status_code == 403

        admin = Actor(client, people["admin"]["email"], people["admin"]["password"])
        approved = admin.post(
            f"/api/v1/detection/candidates/{candidate_id}/review",
            json={"approve": True, "comment": "проверено"},
        )
        assert approved.status_code == 200, approved.text

        published = admin.post("/api/v1/detection/releases", json={"candidate_id": candidate_id})
        assert published.status_code == 200, published.text
        release = published.json()
        assert release["version"].startswith("v")
        # The manifest records everything a verdict depends on.
        assert release["parser_version"] and release["risk_engine_version"]
        assert release["dataset_checksum"]
        assert "Воспроизводимость" in release["changelog"]


class TestScenario4Replay:
    """old analysis → new revision → diff (§44.4)."""

    def test_a_replay_adds_a_revision_and_leaves_the_original(self, client, people, db) -> None:  # type: ignore[no-untyped-def]
        analysis_id = _report(client, people)
        from msp_api.db.models import AnalysisResult
        from sqlalchemy import select

        before = db.execute(select(AnalysisResult).where(AnalysisResult.job_id == analysis_id)).scalar_one()
        original = before.classification

        admin = Actor(client, people["admin"]["email"], people["admin"]["password"])
        replayed = admin.post(f"/api/v1/analysis/{analysis_id}/replay", json={"apply": False})
        assert replayed.status_code == 200, replayed.text
        assert replayed.json()["dry_run"] is True

        revisions = admin.get(f"/api/v1/analysis/{analysis_id}/revisions").json()
        assert revisions[0]["kind"] == "original"
        assert any(item["kind"] == "replay" for item in revisions)

        db.expire_all()
        after = db.execute(select(AnalysisResult).where(AnalysisResult.job_id == analysis_id)).scalar_one()
        assert after.classification == original


class TestScenario5CampaignCuration:
    """auto cluster → analyst split → audit (§44.5)."""

    def test_an_analyst_decision_is_recorded_and_audited(self, client, people, db) -> None:  # type: ignore[no-untyped-def]
        from msp_api.db.models import AuditEvent, Campaign, CampaignMessage, MailMessage
        from msp_contracts import utcnow
        from sqlalchemy import select

        analysis_id = _report(client, people)
        message = db.execute(select(MailMessage)).scalars().first()
        assert message is not None

        campaign = Campaign(
            organization_id=message.organization_id,
            fingerprint="e2e-campaign",
            name="Волна",
            first_seen=utcnow(),
            last_seen=utcnow(),
            message_count=1,
            recipient_count=1,
            reported_count=0,
            verdict_distribution={},
            indicators=[],
            subjects=[],
            senders=[],
        )
        db.add(campaign)
        db.flush()
        db.add(CampaignMessage(campaign_id=campaign.id, message_id=message.id))
        db.commit()

        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        attached = analyst.post(f"/api/v1/campaigns/{campaign.id}/messages/{message.id}/attach")
        assert attached.status_code == 200, attached.text

        rejected = analyst.post(f"/api/v1/campaigns/{campaign.id}/messages/{message.id}/reject")
        assert rejected.status_code == 200, rejected.text
        assert rejected.json()["rejected"] is True

        measured = analyst.get("/api/v1/detection/campaigns/match-quality")
        assert measured.status_code == 200, measured.text
        quality = measured.json()
        assert quality["rejected_by_analyst"] == 1

        # Both literal campaign endpoints live under /detection/ because the incidents router
        # owns /campaigns/{campaign_id}; the probe is here so the paths stay reachable.
        suggestions = analyst.get("/api/v1/detection/campaigns/merge-suggestions")
        assert suggestions.status_code == 200, suggestions.text

        actions = set(db.execute(select(AuditEvent.action)).scalars().all())
        assert "campaign.message_attached" in actions
        assert "campaign.message_rejected" in actions
        _ = analysis_id


class TestScenario6DryRunReevaluation:
    """7-day dry run → affected messages → no remediation (§44.6)."""

    def test_a_dry_run_changes_nothing_and_can_be_cancelled(self, client, people, db) -> None:  # type: ignore[no-untyped-def]
        analysis_id = _report(client, people)
        from msp_api.db.models import AnalysisResult, RemediationAction
        from sqlalchemy import select

        before = db.execute(select(AnalysisResult).where(AnalysisResult.job_id == analysis_id)).scalar_one()
        original = before.classification

        admin = Actor(client, people["admin"]["email"], people["admin"]["password"])
        created = admin.post(
            "/api/v1/reanalysis/jobs", json={"days": 7, "dry_run": True, "max_messages": 100}
        )
        assert created.status_code == 200, created.text
        job = created.json()
        assert job["dry_run"] is True
        assert job["state"] == "QUEUED"

        ran = admin.post(f"/api/v1/reanalysis/jobs/{job['job_id']}/run?slices=5")
        assert ran.status_code == 200, ran.text
        assert ran.json()["processed"] >= 1

        # An analyst may look at the job but not drive it. The logins share one cookie jar, so
        # the analyst signs out before the admin acts again — otherwise the next admin call
        # fails CSRF and the test would "prove" the wrong thing.
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        assert analyst.get("/api/v1/reanalysis/jobs").status_code == 200
        assert analyst.post(f"/api/v1/reanalysis/jobs/{job['job_id']}/cancel").status_code == 403
        analyst.logout()

        admin = Actor(client, people["admin"]["email"], people["admin"]["password"])

        # The stand holds one message, so the five slices finished the job. Cancelling a finished
        # job is refused rather than silently rewriting its terminal state — a cancelled job and
        # a completed one mean different things to whoever reads the history later.
        finished = admin.get(f"/api/v1/reanalysis/jobs/{job['job_id']}").json()
        assert finished["state"] == "COMPLETED"
        assert admin.post(f"/api/v1/reanalysis/jobs/{job['job_id']}/cancel").status_code == 400

        # A job that has not finished can be cancelled, and stays cancelled.
        second = admin.post("/api/v1/reanalysis/jobs", json={"days": 7, "dry_run": True}).json()
        cancelled = admin.post(f"/api/v1/reanalysis/jobs/{second['job_id']}/cancel")
        assert cancelled.status_code == 200, cancelled.text
        assert cancelled.json()["state"] == "CANCELLED"

        db.expire_all()
        after = db.execute(select(AnalysisResult).where(AnalysisResult.job_id == analysis_id)).scalar_one()
        assert after.classification == original, "пробный прогон не меняет вердиктов"
        assert db.execute(select(RemediationAction)).scalars().all() == [], (
            "массовая переоценка никогда не предлагает реагирование"
        )
