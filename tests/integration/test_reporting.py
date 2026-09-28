"""Reporting and export tests (ТЗ 37)."""

from __future__ import annotations

import pytest
from fixtures.corpus import BY_NAME
from msp_api.db.base import utcnow
from msp_api.db.models import AnalysisJob, DetectionException, Incident
from msp_api.services.analysis import run_local_analysis
from msp_api.services.reporting import REPORTS, csv_safe, phishing_summary, to_csv
from msp_api.services.storage import FilesystemObjectStorage
from msp_contracts import IncidentStatus, IntakeSource, Severity


@pytest.fixture
def storage(storage_dir):  # type: ignore[no-untyped-def]
    return FilesystemObjectStorage(storage_dir)


@pytest.fixture
def analysed(db, organization, settings, storage):  # type: ignore[no-untyped-def]
    """A small corpus of analysed messages so reports have data to work with."""
    for name in ("01_normal_internal", "09_bank_details_change", "12_double_extension"):
        job = AnalysisJob(
            organization_id=organization.id,
            source=IntakeSource.ADDIN_REPORT,
            requester_mailbox="buh@corp.example",
            is_report=True,
        )
        db.add(job)
        db.flush()
        run_local_analysis(db, settings, job=job, raw=BY_NAME[name].raw, storage=storage)
    db.commit()
    return organization


class TestCsvSafety:
    @pytest.mark.parametrize(
        "value",
        ["=1+1", "+cmd", "-2", "@SUM(A1)", '=HYPERLINK("http://evil.test")', "\tstart", "\rreturn"],
    )
    def test_formula_injection_is_neutralised(self, value: str) -> None:
        """A CSV opened in Excel must not execute a formula from mail content."""
        assert csv_safe(value).startswith("'")

    def test_ordinary_values_are_untouched(self) -> None:
        assert csv_safe("ceo@corp.example") == "ceo@corp.example"
        assert csv_safe("Срочная оплата") == "Срочная оплата"
        assert csv_safe(None) == ""
        assert csv_safe(42) == "42"

    def test_csv_has_header_and_rows(self) -> None:
        body = to_csv([{"a": 1, "b": "x"}, {"a": 2, "b": "y"}])
        lines = body.strip().split("\n")
        assert lines[0] == "a,b"
        assert len(lines) == 3


class TestReports:
    def test_all_reports_build_without_error(self, db, analysed) -> None:
        for name, builder in REPORTS.items():
            kwargs = {"confirmed_only": False} if name == "indicators" else {"days": 30}
            report = builder(db, analysed.id, **kwargs)  # type: ignore[arg-type]
            assert report.name == name
            assert report.period.start < report.period.end
            payload = report.as_json()
            assert "summary" in payload and "rows" in payload
            report.as_csv()  # must not raise even when empty

    def test_phishing_summary_counts_and_states_its_limits(self, db, analysed) -> None:
        report = phishing_summary(db, analysed.id, days=7)
        assert report.summary["analyses"] == 3
        assert report.summary["employee_reports"] == 3
        assert sum(report.summary["verdicts"].values()) == 3
        # The report must not let a reader read "no detections" as "no threats" (ТЗ 49.9).
        assert "не означает отсутствие угроз" in report.summary["note"]
        assert report.rows, "top rules should be populated"
        assert all("rule_id" in row for row in report.rows)

    def test_incidents_report_computes_mean_times(self, db, organization) -> None:
        created = utcnow()
        incident = Incident(
            organization_id=organization.id,
            number=1,
            title="Тестовый инцидент",
            status=IncidentStatus.REMEDIATED,
            severity=Severity.HIGH,
            created_at=created,
            triaged_at=created,
            remediated_at=created,
        )
        db.add(incident)
        db.commit()
        report = REPORTS["incidents"](db, organization.id, days=30)  # type: ignore[operator]
        assert report.summary["total"] == 1
        assert report.summary["mean_minutes_to_triage"] is not None
        assert report.summary["mean_minutes_to_remediate"] is not None

    def test_false_positive_report_highlights_exceptions_without_expiry(self, db, organization) -> None:
        db.add(
            DetectionException(
                organization_id=organization.id,
                exception_type="trusted_domain",
                value="partner.example",
                owner_email="admin@corp.example",
                reason="проверенный контрагент",
                expires_at=None,
            )
        )
        db.commit()
        report = REPORTS["false_positives"](db, organization.id, days=30)  # type: ignore[operator]
        assert report.summary["exceptions_total"] == 1
        # An exception with no expiry is a permanent hole in detection and is called out.
        assert report.summary["exceptions_without_expiry"] == 1
        assert report.rows[0]["expires_at"] == "бессрочно"

    def test_employee_reporting_measures_precision(self, db, analysed) -> None:
        report = REPORTS["employee_reporting"](db, analysed.id, days=30)  # type: ignore[operator]
        assert report.summary["total_reports"] == 3
        row = report.rows[0]
        assert row["reporter"] == "buh@corp.example"
        assert 0.0 <= row["precision"] <= 1.0

    def test_indicators_export_respects_confirmed_filter(self, db, analysed) -> None:
        confirmed = REPORTS["indicators"](db, analysed.id, confirmed_only=True)  # type: ignore[operator]
        everything = REPORTS["indicators"](db, analysed.id, confirmed_only=False)  # type: ignore[operator]
        assert len(everything.rows) >= len(confirmed.rows)
        assert everything.summary["confirmed_only"] is False

    def test_reports_are_scoped_to_the_organization(self, db, analysed) -> None:
        report = phishing_summary(db, "another-organization", days=30)
        assert report.summary["analyses"] == 0
        assert report.rows == []
