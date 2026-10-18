"""Тревоги анти-спама (ТЗ 1.2 §30, §36): вычисляются из состояния и не требуют «закрытия» вручную."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest


def node_with(db, organization, rspamd: dict | None):  # type: ignore[no-untyped-def]
    from msp_api.db.models_transport import TransportNode

    node = TransportNode(organization_id=organization.id, node_id="b" * 32, name="gw-1", details={"rspamd": rspamd} if rspamd else {})
    node.last_heartbeat_at = datetime.now(UTC)
    db.add(node)
    db.commit()
    return node


def codes(db, organization, settings) -> dict[str, str]:  # type: ignore[no-untyped-def]
    from msp_api.services import antispam_alerts

    return {a.code: a.severity for a in antispam_alerts.compute(db, organization.id, settings)}


def fresh(**state: object) -> dict:
    return {"up": True, "redis_up": True, "drift": "IN_SYNC", "reported_at": datetime.now(UTC).isoformat(), **state}


def test_a_node_without_a_scanner_gets_no_scanner_alerts(db, organization, settings) -> None:  # type: ignore[no-untyped-def]
    node_with(db, organization, None)
    assert codes(db, organization, settings) == {}


def test_a_healthy_scanner_raises_nothing(db, organization, settings) -> None:  # type: ignore[no-untyped-def]
    node_with(db, organization, fresh())
    assert codes(db, organization, settings) == {}


def test_a_silent_scanner_is_down_but_mail_is_still_flowing_so_it_is_a_warning(db, organization, settings) -> None:  # type: ignore[no-untyped-def]
    old = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    node_with(db, organization, fresh(reported_at=old))
    assert codes(db, organization, settings) == {"RSPAMD_DOWN": "WARNING"}


def test_a_scanner_reporting_down_is_down(db, organization, settings) -> None:  # type: ignore[no-untyped-def]
    node_with(db, organization, fresh(up=False))
    assert "RSPAMD_DOWN" in codes(db, organization, settings)


def test_redis_loss_is_its_own_alert(db, organization, settings) -> None:  # type: ignore[no-untyped-def]
    node_with(db, organization, fresh(redis_up=False))
    assert codes(db, organization, settings) == {"RSPAMD_REDIS_DOWN": "WARNING"}


def test_drift_is_critical_and_unknown_is_only_a_note(db, organization, settings) -> None:  # type: ignore[no-untyped-def]
    node_with(db, organization, fresh(drift="DRIFTED"))
    assert codes(db, organization, settings)["RSPAMD_CONFIG_DRIFT"] == "CRITICAL"


def test_unknown_drift_state_is_named(db, organization, settings) -> None:  # type: ignore[no-untyped-def]
    node_with(db, organization, fresh(drift="UNKNOWN"))
    assert codes(db, organization, settings) == {"RSPAMD_CONFIG_STATE_UNKNOWN": "INFO"}


def test_scan_error_spike(db, organization, settings) -> None:  # type: ignore[no-untyped-def]
    node_with(db, organization, fresh(scans_received=100, scan_errors=20))
    assert "RSPAMD_SCAN_ERRORS" in codes(db, organization, settings)


def test_missing_signing_key_and_failed_apply(db, organization, settings) -> None:  # type: ignore[no-untyped-def]
    node_with(db, organization, fresh(dkim_missing_keys=["corp.example:s1"], last_apply={"outcome": "REJECTED", "detail": "x"}))
    found = codes(db, organization, settings)
    assert "DKIM_KEY_MISSING_ON_NODE" in found and "RSPAMD_CONFIG_NOT_APPLIED" in found


def test_a_dns_error_wave_is_named_as_missing_evidence_not_as_failures(db, organization, settings) -> None:  # type: ignore[no-untyped-def]
    from msp_api.db.models_antispam import SpamScan

    for i in range(30):
        db.add(
            SpamScan(
                organization_id=organization.id, node_id="b" * 32, queue_id=f"Q{i}", internet_message_id=f"m{i}@x.example",
                auth={"incomplete_reasons": ["SPF_TEMPERROR"], "dmarc": {"result": "TEMPERROR"}},
            )
        )
    db.commit()
    found = codes(db, organization, settings)
    assert {"DNS_ERRORS", "DMARC_TEMPERROR_SPIKE"} <= set(found)


def test_a_stuck_key_and_a_failed_key_are_lifecycle_alerts(db, organization, settings) -> None:  # type: ignore[no-untyped-def]
    from msp_api.db.models_antispam import DkimKeyRecord, DkimKeyStatus

    old = DkimKeyRecord(organization_id=organization.id, domain="corp.example", selector="s1", status=DkimKeyStatus.DNS_PENDING)
    db.add(old)
    db.flush()
    old.created_at = datetime.now(UTC) - timedelta(days=2)
    db.commit()
    assert "DKIM_LIFECYCLE" in codes(db, organization, settings)


def test_auth_conflict_and_reject_fp_spikes(db, organization, settings) -> None:  # type: ignore[no-untyped-def]
    from msp_api.db.models_antispam import AuthConflictRecord, SpamReview, SpamScan

    scan = SpamScan(organization_id=organization.id, node_id="b" * 32, queue_id="Q", internet_message_id="m@x.example")
    db.add(scan)
    db.flush()
    for _ in range(25):
        db.add(AuthConflictRecord(organization_id=organization.id, scan_id=scan.id, kind="SPF_MISMATCH"))
    for i in range(12):
        s = SpamScan(
            organization_id=organization.id, node_id="b" * 32, queue_id=f"R{i}", internet_message_id=f"r{i}@x.example",
            suggested_action="REJECT", spam_class="HIGH_CONFIDENCE_SPAM",
        )
        db.add(s)
        db.flush()
        db.add(
            SpamReview(
                organization_id=organization.id, scan_id=s.id, verdict="HAM" if i < 4 else "SPAM", selection="SUGGESTED_REJECT"
            )
        )
    db.commit()
    found = codes(db, organization, settings)
    assert {"AUTH_CONFLICT_SPIKE", "SUGGESTED_REJECT_FP_SPIKE"} <= set(found)


@pytest.mark.parametrize("reported", [None, "garbage"])
def test_an_unreadable_report_time_counts_as_silence(db, organization, settings, reported) -> None:  # type: ignore[no-untyped-def]
    node_with(db, organization, {"up": True, "reported_at": reported, "drift": "IN_SYNC"})
    assert "RSPAMD_DOWN" in codes(db, organization, settings)
