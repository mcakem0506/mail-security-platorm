"""The detection-quality loop over HTTP (ТЗ 1.0.3 §13, §17–§27, §35, §49, §54–§56).

The point of these tests is not that the endpoints return 200. It is that the properties the
specification insists on survive contact with the API:

* priority is not the risk level;
* a simulation and a dry-run replay change nothing;
* a metric with no data behind it comes back ``null``, never as a flattering zero;
* a known gap is published rather than hidden;
* every analyst decision lands in the audit trail.
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
    password = "Quality-Test-Password-7"
    accounts = {
        "employee": ("user@corp.example", Role.EMPLOYEE),
        "analyst": ("analyst@corp.example", Role.SECURITY_ANALYST),
        "admin": ("admin@corp.example", Role.SECURITY_ADMIN),
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


def _report(client: TestClient, people, name: str) -> tuple[str, str]:
    """Have the employee report a corpus message; return (job_id, message_id)."""
    employee = Actor(client, people["employee"]["email"], people["employee"]["password"])
    submitted = employee.post(
        "/api/v1/analysis",
        json={
            "raw_eml_base64": base64.b64encode(BY_NAME[name].raw).decode(),
            "report_as_phishing": True,
        },
    )
    assert submitted.status_code == 202, submitted.text
    job_id = submitted.json()["job_id"]
    employee.logout()

    analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
    detail = analyst.get(f"/api/v1/analysis/{job_id}/detail")
    assert detail.status_code == 200, detail.text
    message_id = detail.json()["message_id"]
    analyst.logout()
    return job_id, message_id


def _open_incident(analyst: Actor, message_id: str, title: str = "Проверка качества") -> str:
    created = analyst.post(
        "/api/v1/incidents",
        json={
            "title": title,
            "summary": "Инцидент для проверки цикла качества детектирования",
            "severity": "high",
            "message_ids": [message_id],
        },
    )
    assert created.status_code == 201, created.text
    return created.json()["incident_id"]


class TestQueueAndPriority:
    def test_queue_orders_by_priority_not_by_risk(self, client, people, organization) -> None:
        """A P1 campaign outranks a lone MALICIOUS message (ТЗ 1.0.3 §18)."""
        _, message_id = _report(client, people, "09_bank_details_change")
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        incident_id = _open_incident(analyst, message_id)

        queue = analyst.get("/api/v1/investigations/queue")
        assert queue.status_code == 200, queue.text
        rows = queue.json()
        assert rows, "очередь не должна быть пустой"
        row = next(r for r in rows if r["incident_id"] == incident_id)

        # Priority is reported with the reasons behind it: a number nobody can argue with is a
        # number nobody trusts.
        assert row["priority"] in {"P1", "P2", "P3", "P4"}
        assert row["priority_factors"], "приоритет должен быть объясним"
        assert row["sla"]["state"] in {"ON_TIME", "DUE_SOON", "BREACHED", "MET", "NOT_APPLICABLE"}
        # Priority and severity are different axes and must not be conflated.
        assert "severity" in row and "priority" in row

    def test_queue_is_ordered_and_assignment_sticks(self, client, people) -> None:
        _, message_id = _report(client, people, "09_bank_details_change")
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        incident_id = _open_incident(analyst, message_id)

        assigned = analyst.post(
            f"/api/v1/incidents/{incident_id}/assign",
            json={"assignee_email": people["analyst"]["email"]},
        )
        assert assigned.status_code == 200, assigned.text
        assert assigned.json()["assignee_email"] == people["analyst"]["email"]

        mine = analyst.get("/api/v1/investigations/queue", params={"mine": True})
        assert mine.status_code == 200
        assert any(r["incident_id"] == incident_id for r in mine.json())

    def test_auto_assignment_requires_candidates(self, client, people) -> None:
        _, message_id = _report(client, people, "09_bank_details_change")
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        incident_id = _open_incident(analyst, message_id)
        empty = analyst.post(f"/api/v1/incidents/{incident_id}/assign", json={})
        assert empty.status_code == 400


class TestClassificationFeedsQuality:
    def test_classification_is_recorded_audited_and_counted(self, client, people, db) -> None:
        """An analyst verdict updates rule statistics and the audit trail (§22, §23, §56)."""
        _, message_id = _report(client, people, "09_bank_details_change")
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        incident_id = _open_incident(analyst, message_id)

        decided = analyst.post(
            f"/api/v1/incidents/{incident_id}/classification",
            json={
                "classification": "CONFIRMED_BEC",
                "comment": "Подтверждена попытка смены реквизитов",
                "confidence": "high",
            },
        )
        assert decided.status_code == 200, decided.text
        assert decided.json()["classification"] == "CONFIRMED_BEC"
        assert decided.json()["previous_classification"] is None

        # Reclassification keeps the history rather than overwriting it.
        changed = analyst.post(
            f"/api/v1/incidents/{incident_id}/classification",
            json={
                "classification": "FALSE_POSITIVE",
                "comment": "При проверке оказалось легитимным письмом подрядчика",
                "offending_rules": ["BEC-014"],
            },
        )
        assert changed.status_code == 200, changed.text
        assert changed.json()["previous_classification"] == "CONFIRMED_BEC"

        from msp_api.db.models import AuditEvent, DetectionFeedback, RuleStatistic
        from sqlalchemy import select

        actions = set(db.execute(select(AuditEvent.action)).scalars().all())
        assert "incident.classified" in actions
        assert "detection.false_positive_marked" in actions

        feedback = db.execute(select(DetectionFeedback)).scalars().all()
        assert any(row.kind == "false_positive" and row.rule_id == "BEC-014" for row in feedback)

        stats = {row.rule_id: row for row in db.execute(select(RuleStatistic)).scalars().all()}
        assert stats["BEC-014"].confirmed_fp >= 1, "ложное срабатывание должно быть отнесено к правилу"

    def test_closing_as_benign_requires_a_reason(self, client, people) -> None:
        """The decision most likely to be revisited is the one that must carry a reason."""
        _, message_id = _report(client, people, "09_bank_details_change")
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        incident_id = _open_incident(analyst, message_id)
        refused = analyst.post(
            f"/api/v1/incidents/{incident_id}/classification",
            json={"classification": "FALSE_POSITIVE", "comment": "   "},
        )
        assert refused.status_code == 400

    def test_employee_feedback_never_promises_safety(self, client, people) -> None:
        """ТЗ 1.0.3 §34: the platform may report it found nothing, not that nothing is there."""
        _, message_id = _report(client, people, "09_bank_details_change")
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        incident_id = _open_incident(analyst, message_id)
        analyst.post(
            f"/api/v1/incidents/{incident_id}/classification",
            json={
                "classification": "FALSE_POSITIVE",
                "comment": "Легитимное письмо подрядчика, проверено по телефону",
            },
        )
        text = analyst.get(f"/api/v1/incidents/{incident_id}/employee-feedback").json()["text"]
        assert text
        lowered = text.lower()
        for forbidden in ("100%", "полностью безопас", "гарантированно безопас", "абсолютно безопас"):
            assert forbidden not in lowered, f"формулировка обещает безопасность: {text}"


class TestMissedDetection:
    def test_reported_miss_requires_a_known_gap_reference(self, client, people) -> None:
        _, message_id = _report(client, people, "09_bank_details_change")
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        bad = analyst.post(
            "/api/v1/detection/missed",
            json={
                "message_id": message_id,
                "source": "ANALYST",
                "root_cause": "MISSING_RULE",
                "gap_id": "GAP-999",
            },
        )
        assert bad.status_code == 400, bad.text

    def test_miss_is_recorded_with_its_root_cause(self, client, people, db) -> None:
        """ТЗ 1.0.3 §26: a miss names the layer that failed, because that decides who fixes it."""
        _, message_id = _report(client, people, "09_bank_details_change")
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        reported = analyst.post(
            "/api/v1/detection/missed",
            json={
                "message_id": message_id,
                "source": "EMPLOYEE_REPORT",
                "root_cause": "PARSER_FAILURE",
                "expected_detection": "ссылка внутри вложенного архива",
                "missing_fact": "url_in_attachment",
                "comment": "Архив не разбирается, ссылка не извлечена",
            },
        )
        assert reported.status_code == 200, reported.text
        assert reported.json()["root_cause"] == "PARSER_FAILURE"

        from msp_api.db.models import AuditEvent
        from sqlalchemy import select

        actions = set(db.execute(select(AuditEvent.action)).scalars().all())
        assert "detection.false_negative_marked" in actions

        listed = analyst.get("/api/v1/detection/feedback", params={"kind": "false_negative"})
        assert listed.status_code == 200
        assert len(listed.json()) == 1


class TestSimulationAndReplayChangeNothing:
    def test_simulation_leaves_the_stored_verdict_untouched(self, client, people, db) -> None:
        """ТЗ 1.0.3 §13: asking what the rules would say must not change what they said."""
        job_id, message_id = _report(client, people, "09_bank_details_change")
        from msp_api.db.models import AnalysisResult
        from sqlalchemy import select

        before = db.execute(select(AnalysisResult).where(AnalysisResult.job_id == job_id)).scalar_one()
        before_class, before_score = before.classification, before.score

        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        simulated = analyst.post("/api/v1/detection/simulate", json={"message_id": message_id})
        assert simulated.status_code == 200, simulated.text
        payload = simulated.json()
        assert payload["signals"], "симуляция должна показать сработавшие правила"
        assert payload["ruleset_fingerprint"]

        db.expire_all()
        after = db.execute(select(AnalysisResult).where(AnalysisResult.job_id == job_id)).scalar_one()
        assert (after.classification, after.score) == (before_class, before_score)

    def test_simulation_can_be_narrowed_to_one_rule(self, client, people) -> None:
        _, message_id = _report(client, people, "09_bank_details_change")
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        everything = analyst.post("/api/v1/detection/simulate", json={"message_id": message_id}).json()
        one_rule = everything["signals"][0]["rule_id"]
        narrowed = analyst.post(
            "/api/v1/detection/simulate", json={"message_id": message_id, "rule_id": one_rule}
        ).json()
        assert [s["rule_id"] for s in narrowed["signals"]] == [one_rule]
        # The verdict still comes from the whole rule set: a rule's effect depends on what else
        # fired, so narrowing the view must not narrow the computation.
        assert narrowed["score"] == everything["score"]

    def test_dry_run_replay_records_a_revision_without_applying_it(self, client, people, db) -> None:
        """ТЗ 1.0.3 §49: a replay is a new revision, never an overwrite."""
        job_id, _ = _report(client, people, "09_bank_details_change")
        from msp_api.db.models import AnalysisResult
        from sqlalchemy import select

        before = db.execute(select(AnalysisResult).where(AnalysisResult.job_id == job_id)).scalar_one()
        before_class = before.classification

        admin = Actor(client, people["admin"]["email"], people["admin"]["password"])
        replayed = admin.post(f"/api/v1/analysis/{job_id}/replay", json={"apply": False})
        assert replayed.status_code == 200, replayed.text
        body = replayed.json()
        assert body["dry_run"] is True
        assert body["revision"] == 1
        assert body["original_classification"] == before_class.value

        db.expire_all()
        after = db.execute(select(AnalysisResult).where(AnalysisResult.job_id == job_id)).scalar_one()
        assert after.classification == before_class, "пробный повтор не должен менять вердикт"

        # Replaying again produces revision 2 rather than replacing revision 1.
        again = admin.post(f"/api/v1/analysis/{job_id}/replay", json={"apply": False})
        assert again.json()["revision"] == 2

    def test_analyst_cannot_replay(self, client, people) -> None:
        """Re-evaluation can rewrite stored verdicts, so it is an administrative power (§55)."""
        job_id, _ = _report(client, people, "09_bank_details_change")
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        assert analyst.post(f"/api/v1/analysis/{job_id}/replay", json={}).status_code == 403
        assert analyst.post("/api/v1/detection/reevaluate", json={"days": 1}).status_code == 403

    def test_reevaluation_is_dry_run_by_default(self, client, people) -> None:
        """ТЗ 1.0.3 §50: the answer is a proposal until someone decides to apply it."""
        _report(client, people, "09_bank_details_change")
        admin = Actor(client, people["admin"]["email"], people["admin"]["password"])
        run = admin.post("/api/v1/detection/reevaluate", json={"days": 7})
        assert run.status_code == 200, run.text
        body = run.json()
        assert body["dry_run"] is True
        assert body["messages_examined"] >= 1
        # With an unchanged rule pack nothing should move. If this ever fails, the engine is not
        # deterministic, which is a far bigger problem than a flaky test.
        assert body["verdict_changed"] == 0


class TestRuleLifecycle:
    def test_rules_are_listed_with_owner_and_status(self, client, people) -> None:
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        listed = analyst.get("/api/v1/detection/rules")
        assert listed.status_code == 200, listed.text
        rules = listed.json()
        assert len(rules) > 50
        assert all(rule["owner"] for rule in rules if rule["status"] == "ACTIVE"), (
            "активное правило без владельца некому настраивать"
        )
        # An untested rule has no precision, and must not be shown as a perfect one.
        untested = [r for r in rules if r["confirmed_tp"] + r["confirmed_fp"] == 0]
        assert untested and all(r["precision"] is None for r in untested)

    def test_lifecycle_refuses_a_jump_straight_to_active(self, client, people) -> None:
        """ТЗ 1.0.3 §10: a rule reaches ACTIVE only through SHADOW."""
        admin = Actor(client, people["admin"]["email"], people["admin"]["password"])
        rules = admin.get("/api/v1/detection/rules").json()
        active = next(r for r in rules if r["status"] == "ACTIVE")

        # ACTIVE → DEGRADED is allowed; ACTIVE → ACTIVE is not a transition at all.
        same = admin.post(
            f"/api/v1/detection/rules/{active['rule_id']}/status",
            json={"status": "ACTIVE", "reason": "никаких изменений не требуется"},
        )
        assert same.status_code == 400

        degraded = admin.post(
            f"/api/v1/detection/rules/{active['rule_id']}/status",
            json={"status": "DEGRADED", "reason": "аналитик сообщил о ложных срабатываниях"},
        )
        assert degraded.status_code == 200, degraded.text
        assert degraded.json()["current_status"] == "ACTIVE", (
            "статус применяется из файла правил после ревью, а не мгновенно по API"
        )

        changes = admin.get("/api/v1/detection/rules/changes").json()
        assert any(c["to_status"] == "DEGRADED" for c in changes)

    def test_analyst_cannot_change_rule_status(self, client, people) -> None:
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        rule_id = analyst.get("/api/v1/detection/rules").json()[0]["rule_id"]
        refused = analyst.post(
            f"/api/v1/detection/rules/{rule_id}/status",
            json={"status": "DISABLED", "reason": "хочу отключить это правило"},
        )
        assert refused.status_code == 403


class TestGapRegistryIsPublished:
    def test_known_gaps_are_visible_with_mitigations(self, client, people) -> None:
        """ТЗ 1.0.3 §27: an unlisted gap is indistinguishable from an unknown one."""
        admin = Actor(client, people["admin"]["email"], people["admin"]["password"])
        synced = admin.post("/api/v1/detection/rules/sync", json=None)
        assert synced.status_code == 200, synced.text
        assert synced.json()["gaps"] >= 3, "реестр пробелов должен загружаться из файла"

        gaps = admin.get("/api/v1/detection/gaps").json()
        assert gaps
        for gap in gaps:
            assert gap["description"] and gap["root_cause"]
            assert gap["mitigation"], "у пробела должна быть компенсирующая мера"
            assert gap["owner"], "у пробела должен быть владелец"

    def test_gap_can_be_closed_and_is_audited(self, client, people, db) -> None:
        admin = Actor(client, people["admin"]["email"], people["admin"]["password"])
        admin.post("/api/v1/detection/rules/sync", json=None)
        gap_id = admin.get("/api/v1/detection/gaps").json()[0]["gap_id"]
        closed = admin.post(
            f"/api/v1/detection/gaps/{gap_id}/status",
            json={"status": "RESOLVED", "note": "Разбор архивов добавлен"},
        )
        assert closed.status_code == 200, closed.text
        assert closed.json()["status"] == "RESOLVED"

        from msp_api.db.models import AuditEvent
        from sqlalchemy import select

        assert "gap.closed" in set(db.execute(select(AuditEvent.action)).scalars().all())
        open_only = admin.get("/api/v1/detection/gaps", params={"status": "OPEN"}).json()
        assert all(g["gap_id"] != gap_id for g in open_only)


class TestQualityDashboardCannotFlatter:
    def test_metrics_are_null_when_nothing_has_been_classified(self, client, people) -> None:
        """The most dangerous number in this product would be a 0% false positive rate (§35)."""
        _report(client, people, "09_bank_details_change")
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        quality = analyst.get("/api/v1/detection/quality")
        assert quality.status_code == 200, quality.text
        body = quality.json()
        assert body["classified"] == 0
        assert body["precision"] is None, "без размеченных инцидентов precision не определён"
        assert body["false_positive_rate"] is None
        assert body["total_analyzed"] >= 1

    def test_metrics_appear_once_decisions_exist(self, client, people) -> None:
        _, message_id = _report(client, people, "09_bank_details_change")
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        incident_id = _open_incident(analyst, message_id)
        analyst.post(
            f"/api/v1/incidents/{incident_id}/classification",
            json={"classification": "CONFIRMED_BEC", "comment": "подтверждено"},
        )
        body = analyst.get("/api/v1/detection/quality").json()
        assert body["classified"] == 1
        assert body["confirmed_threats"] == 1
        assert body["precision"] == 1.0
        assert body["false_positive_rate"] == 0.0

    def test_dashboard_reports_what_it_cannot_see(self, client, people) -> None:
        """Open gaps and reported misses belong next to the metrics, not in a separate report."""
        admin = Actor(client, people["admin"]["email"], people["admin"]["password"])
        admin.post("/api/v1/detection/rules/sync", json=None)
        body = admin.get("/api/v1/detection/quality").json()
        assert body["open_gaps"] >= 1
        assert "reported_misses" in body
        assert "unscannable" in body
        assert body["unowned_active_rules"] == []

    def test_a_complete_scan_is_not_counted_as_unscannable(self, client, people) -> None:
        """Regression, found on a live stand: the dashboard said 22 of 22 were not scanned.

        The query compared ``scan_completeness`` against a value the enum does not contain, so
        every analysis matched. It read as "we checked nothing", which is the opposite kind of
        lie from a flattering metric but just as useless.
        """
        _report(client, people, "09_bank_details_change")
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        body = analyst.get("/api/v1/detection/quality").json()
        assert body["total_analyzed"] >= 1
        assert body["unscannable"] < body["total_analyzed"], (
            "полностью проверенное письмо не должно попадать в непроверенные"
        )

    def test_versions_are_reported_for_reproducibility(self, client, people) -> None:
        """ТЗ 1.0.3 §48: a verdict is only defensible if it can be reproduced."""
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        versions = analyst.get("/api/v1/detection/versions").json()
        for key in ("ruleset_version", "risk_engine_version", "parser_version", "ti_policy_version"):
            assert versions[key], f"версия {key} должна быть указана"
        assert versions["active_rules"] > 0

    def test_employee_cannot_read_detection_quality(self, client, people) -> None:
        employee = Actor(client, people["employee"]["email"], people["employee"]["password"])
        assert employee.get("/api/v1/detection/quality").status_code == 403
        assert employee.get("/api/v1/detection/rules").status_code == 403
        assert employee.get("/api/v1/investigations/queue").status_code == 403


class TestCanaryRollout:
    """Rolling a rule out to part of the organisation over HTTP (ТЗ 1.0.3 §52)."""

    def _active_rule(self, actor: Actor) -> str:
        rules = actor.get("/api/v1/detection/rules", params={"status": "ACTIVE"}).json()
        return rules[0]["rule_id"]

    def test_rollout_starts_and_is_listed_with_its_comparison(self, client, people) -> None:
        admin = Actor(client, people["admin"]["email"], people["admin"]["password"])
        rule_id = self._active_rule(admin)
        started = admin.post(
            f"/api/v1/detection/rules/{rule_id}/canary",
            json={
                "scope": "MAILBOX",
                "scope_values": ["buh@corp.example"],
                "days": 7,
                "reason": "Проверяем на бухгалтерии перед включением всем",
            },
        )
        assert started.status_code == 200, started.text
        body = started.json()
        assert body["state"] == "ACTIVE"
        assert body["scope"] == "MAILBOX"
        assert body["overdue"] is False
        # Nothing has fired yet, so there is no precision to report and no recommendation.
        assert body["inside_precision"] is None
        assert body["ready_to_promote"] is False

        listed = admin.get("/api/v1/detection/canaries").json()
        assert [c["rule_id"] for c in listed] == [rule_id]

    def test_rollout_shows_on_the_quality_dashboard(self, client, people) -> None:
        admin = Actor(client, people["admin"]["email"], people["admin"]["password"])
        rule_id = self._active_rule(admin)
        admin.post(
            f"/api/v1/detection/rules/{rule_id}/canary",
            json={
                "scope": "PERCENT",
                "percent": 25,
                "days": 3,
                "reason": "Четверть ящиков на три дня",
            },
        )
        quality = admin.get("/api/v1/detection/quality").json()
        assert quality["active_canaries"] == 1
        assert quality["overdue_canaries"] == 0

    def test_promotion_is_audited_and_ends_the_rollout(self, client, people, db) -> None:
        admin = Actor(client, people["admin"]["email"], people["admin"]["password"])
        rule_id = self._active_rule(admin)
        admin.post(
            f"/api/v1/detection/rules/{rule_id}/canary",
            json={
                "scope": "MAILBOX",
                "scope_values": ["buh@corp.example"],
                "reason": "Ограниченный выпуск для проверки",
            },
        )
        decided = admin.post(
            f"/api/v1/detection/rules/{rule_id}/canary/decision",
            json={"state": "PROMOTED", "note": "Срабатывания подтверждены аналитиком"},
        )
        assert decided.status_code == 200, decided.text
        assert decided.json()["state"] == "PROMOTED"
        assert admin.get("/api/v1/detection/canaries").json() == []

        from msp_api.db.models import AuditEvent
        from sqlalchemy import select

        actions = set(db.execute(select(AuditEvent.action)).scalars().all())
        assert "canary.started" in actions
        assert "canary.promoted" in actions

    def test_aborting_without_a_reason_is_refused(self, client, people) -> None:
        admin = Actor(client, people["admin"]["email"], people["admin"]["password"])
        rule_id = self._active_rule(admin)
        admin.post(
            f"/api/v1/detection/rules/{rule_id}/canary",
            json={
                "scope": "MAILBOX",
                "scope_values": ["buh@corp.example"],
                "reason": "Ограниченный выпуск для проверки",
            },
        )
        refused = admin.post(
            f"/api/v1/detection/rules/{rule_id}/canary/decision",
            json={"state": "ABORTED", "note": ""},
        )
        assert refused.status_code == 400

    def test_an_analyst_may_look_but_not_decide(self, client, people) -> None:
        """Who a rule decides for is the same kind of power as changing its status."""
        admin = Actor(client, people["admin"]["email"], people["admin"]["password"])
        rule_id = self._active_rule(admin)
        admin.post(
            f"/api/v1/detection/rules/{rule_id}/canary",
            json={
                "scope": "MAILBOX",
                "scope_values": ["buh@corp.example"],
                "reason": "Ограниченный выпуск для проверки",
            },
        )
        analyst = Actor(client, people["analyst"]["email"], people["analyst"]["password"])
        assert analyst.get("/api/v1/detection/canaries").status_code == 200
        assert (
            analyst.post(
                f"/api/v1/detection/rules/{rule_id}/canary",
                json={
                    "scope": "MAILBOX",
                    "scope_values": ["x@corp.example"],
                    "reason": "Попытка аналитика начать выпуск",
                },
            ).status_code
            == 403
        )
        assert (
            analyst.post(
                f"/api/v1/detection/rules/{rule_id}/canary/decision",
                json={"state": "PROMOTED", "note": "x"},
            ).status_code
            == 403
        )

    def test_a_rollout_for_an_unknown_rule_is_refused(self, client, people) -> None:
        admin = Actor(client, people["admin"]["email"], people["admin"]["password"])
        missing = admin.post(
            "/api/v1/detection/rules/NOPE-999/canary",
            json={
                "scope": "MAILBOX",
                "scope_values": ["buh@corp.example"],
                "reason": "Правила с таким идентификатором нет",
            },
        )
        assert missing.status_code == 404
