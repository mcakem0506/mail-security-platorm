"""Ядро принуждения MSP 1.3: готовность, пробелы, канарейка, исключения, политика, решения."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from msp_enforcement.canary import CanaryScope, all_recipients_in_scope, bucket, recipient_in_scope
from msp_enforcement.engine import (
    EnforcementInput,
    MalwareEvidence,
    Runtime,
    Switches,
    decide,
)
from msp_enforcement.exceptions import EnforcementException, matching
from msp_enforcement.model import (
    AppliedAction,
    ControlState,
    ControlType,
    Decision,
    ExceptionScope,
    FailMode,
    Readiness,
)
from msp_enforcement.policy import (
    ControlPolicy,
    EnforcementPolicy,
    PolicyBundle,
    PolicyCache,
    PolicyError,
    PolicyStatus,
    sign_policy,
    verify_bundle,
)
from msp_enforcement.readiness import (
    ReadinessInput,
    assess,
    blocking_gaps,
    build_reject_safety,
    restricted_reasons,
)

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
KEY = b"k" * 40


def good_inputs(**over: object) -> ReadinessInput:
    base: dict[str, object] = {
        "gaps": {"GAP-005": "VALIDATION", "GAP-006": "VALIDATION"},
        "reject_safety": build_reject_safety(reviewed=120, confirmed_correct=120, confirmed_fp=0),
        "thresholds_versioned": True,
        "control_tests_green": True,
        "rspamd_failopen_tested": True,
        "effective_actions_clean": True,
        "real_evidence": True,
    }
    base.update(over)
    return ReadinessInput(**base)  # type: ignore[arg-type]


# --- готовность и пробелы ---------------------------------------------------------------------
class TestReadiness:
    def test_dmarc_reject_is_blocked_by_an_open_gap_whatever_else_is_true(self) -> None:
        report = assess(ControlType.DMARC_REJECT, good_inputs())
        assert report.status is Readiness.BLOCKED_BY_GAP
        assert not report.can_canary and not report.can_pilot
        assert "GAP_OPEN:GAP-006" in report.reasons

    def test_a_missing_gap_record_counts_as_open(self) -> None:
        assert blocking_gaps(ControlType.DMARC_REJECT, {}) == ("GAP-006",)

    def test_dmarc_reject_unblocks_only_when_the_gap_is_resolved(self) -> None:
        report = assess(ControlType.DMARC_REJECT, good_inputs(gaps={"GAP-006": "RESOLVED"}))
        assert report.status is not Readiness.BLOCKED_BY_GAP

    def test_a_small_sample_is_not_ready(self) -> None:
        rs = build_reject_safety(reviewed=40, confirmed_correct=40, confirmed_fp=0)
        report = assess(ControlType.SPAM_REJECT, good_inputs(reject_safety=rs))
        assert report.status is Readiness.NOT_READY
        assert any(r.startswith("INSUFFICIENT_SAMPLE") for r in report.reasons)

    def test_a_critical_false_positive_blocks(self) -> None:
        rs = build_reject_safety(reviewed=500, confirmed_correct=499, confirmed_fp=1, critical_fp=1)
        report = assess(ControlType.SPAM_REJECT, good_inputs(reject_safety=rs))
        assert report.status is Readiness.NOT_READY and "CRITICAL_FP: 1" in report.reasons

    def test_unknown_rspamd_action_source_blocks_activation(self) -> None:
        report = assess(ControlType.SPAM_REJECT, good_inputs(effective_actions_clean=False))
        assert report.status is Readiness.NOT_READY

    def test_lab_evidence_allows_only_a_lab_canary(self) -> None:
        lab = assess(ControlType.SPAM_REJECT, good_inputs(real_evidence=False, lab_mode=True))
        assert lab.status is Readiness.READY_WITH_WARNINGS and lab.can_canary and not lab.can_pilot
        prod = assess(ControlType.SPAM_REJECT, good_inputs(real_evidence=False, lab_mode=False))
        assert not prod.can_canary and not prod.can_pilot

    def test_real_evidence_with_an_open_spf_gap_is_ready_with_warnings(self) -> None:
        report = assess(ControlType.SPAM_REJECT, good_inputs())
        assert report.status is Readiness.READY_WITH_WARNINGS and report.can_pilot
        assert any("GAP-005" in w for w in report.warnings)

    def test_rbl_needs_license_health_and_leakage_test(self) -> None:
        report = assess(ControlType.RBL_REJECT, good_inputs())
        assert {"LICENSE_NOT_APPROVED", "PROVIDER_NOT_HEALTHY", "SECRET_LEAKAGE_NOT_TESTED"} <= set(
            report.reasons
        )

    def test_phishing_reject_needs_an_approved_sync_path(self) -> None:
        assert "SYNC_PATH_NOT_APPROVED" in assess(ControlType.PHISHING_REJECT, good_inputs()).reasons

    def test_reject_safety_without_a_denominator_is_null_not_zero(self) -> None:
        rs = build_reject_safety(reviewed=0, confirmed_correct=0, confirmed_fp=0)
        assert rs.fp_rate is None and rs.fp_upper_bound is None
        assert not rs.ready_for_canary and "NO_DENOMINATOR" in rs.reasons

    def test_spf_reasons_are_restricted_until_gap_005_is_resolved(self) -> None:
        assert "AUTH_SPF_FAIL" in restricted_reasons({})
        assert restricted_reasons({"GAP-005": "RESOLVED"}) == frozenset()


# --- канарейка --------------------------------------------------------------------------------
class TestCanary:
    def args(self, **kw: object) -> dict[str, object]:
        base = {"recipient": "a@corp.example", "sender": "x@evil.example", "source_ip": "198.51.100.7"}
        base.update(kw)
        return base

    def test_an_empty_scope_selects_nobody(self) -> None:
        assert not recipient_in_scope(CanaryScope(), ControlType.SPAM_REJECT, **self.args())  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "scope",
        [
            CanaryScope(recipients=("A@corp.example",)),
            CanaryScope(pilot_domains=("corp.example",)),
            CanaryScope(sender_domains=("evil.example",)),
            CanaryScope(source_cidrs=("198.51.100.0/24",)),
            CanaryScope(groups=("pilot",)),
        ],
    )
    def test_each_selector_matches(self, scope: CanaryScope) -> None:
        assert recipient_in_scope(
            scope,
            ControlType.SPAM_REJECT,
            groups={"pilot": ["a@corp.example"]},
            **self.args(),  # type: ignore[arg-type]
        )

    def test_the_percentage_is_deterministic_and_roughly_proportional(self) -> None:
        scope = CanaryScope(percentage=20, salt="s1")
        picks = [
            recipient_in_scope(
                scope, ControlType.SPAM_REJECT, recipient=f"u{i}@corp.example", sender="", source_ip=""
            )
            for i in range(2000)
        ]
        again = [
            recipient_in_scope(
                scope, ControlType.SPAM_REJECT, recipient=f"u{i}@corp.example", sender="", source_ip=""
            )
            for i in range(2000)
        ]
        assert picks == again
        assert 0.15 < sum(picks) / 2000 < 0.25

    def test_bucket_is_stable_and_salted(self) -> None:
        assert bucket("s", ControlType.SPAM_REJECT, "A@x") == bucket("s", ControlType.SPAM_REJECT, "a@x")
        assert bucket("s", ControlType.SPAM_REJECT, "a@x") != bucket("t", ControlType.SPAM_REJECT, "a@x")

    def test_a_destructive_action_needs_every_recipient_in_scope(self) -> None:
        scope = CanaryScope(recipients=("a@corp.example",))
        assert all_recipients_in_scope(
            scope, ControlType.SPAM_REJECT, recipients=["a@corp.example"], sender="", source_ip=""
        )
        assert not all_recipients_in_scope(
            scope,
            ControlType.SPAM_REJECT,
            recipients=["a@corp.example", "b@corp.example"],
            sender="",
            source_ip="",
        )
        assert not all_recipients_in_scope(
            scope, ControlType.SPAM_REJECT, recipients=[], sender="", source_ip=""
        )


# --- исключения -------------------------------------------------------------------------------
def exc(**over: object) -> EnforcementException:
    base: dict[str, object] = {
        "id": "e1",
        "scope": ExceptionScope.SENDER,
        "control": ControlType.SPAM_REJECT,
        "value": "boss@partner.example",
        "reason": "известный партнёр",
        "owner": "alice",
        "created_at": NOW,
        "expires_at": NOW + timedelta(days=7),
    }
    base.update(over)
    return EnforcementException(**base)  # type: ignore[arg-type]


class TestExceptions:
    def test_an_open_ended_exception_cannot_be_created(self) -> None:
        with pytest.raises(ValueError):
            exc(expires_at=NOW + timedelta(days=400))

    def test_an_exception_expires(self) -> None:
        item = exc()
        assert item.is_active(NOW + timedelta(days=6))
        assert not item.is_active(NOW + timedelta(days=8))

    def test_max_uses_is_honoured(self) -> None:
        assert not exc(max_uses=2).is_active(NOW, uses=2)

    def test_sensitive_controls_need_a_second_person(self) -> None:
        item = exc(control=ControlType.MALWARE_REJECT)
        assert item.needs_four_eyes() and not item.is_approved()
        assert not exc(control=ControlType.MALWARE_REJECT, approved_by="alice").is_approved()
        assert exc(control=ControlType.MALWARE_REJECT, approved_by="bob").is_approved()

    def test_a_whole_control_exception_always_needs_four_eyes(self) -> None:
        item = exc(scope=ExceptionScope.CONTROL, value="*")
        assert item.needs_four_eyes() and not item.is_active(NOW)

    def test_matching_requires_every_recipient_for_recipient_scopes(self) -> None:
        item = exc(scope=ExceptionScope.RECIPIENT, value="a@corp.example")
        kw = {"now": NOW, "sender": "", "source_ip": ""}
        assert matching([item], ControlType.SPAM_REJECT, recipients=["a@corp.example"], **kw)  # type: ignore[arg-type]
        assert not matching(
            [item],
            ControlType.SPAM_REJECT,
            recipients=["a@corp.example", "b@corp.example"],
            **kw,  # type: ignore[arg-type]
        )


# --- политика и распространение ---------------------------------------------------------------
def make_policy(
    version: str = "v1", *, state: ControlState = ControlState.CANARY, **over: object
) -> EnforcementPolicy:
    controls = (
        ControlPolicy(
            control_type=ControlType.SPAM_REJECT,
            state=state,
            thresholds={"reject_score": 15.0},
            canary_scope=CanaryScope(recipients=("pilot@corp.example",)),
        ),
        ControlPolicy(
            control_type=ControlType.DMARC_REJECT,
            state=ControlState.CANARY,
            canary_scope=CanaryScope(pilot_domains=("corp.example",)),
        ),
        ControlPolicy(
            control_type=ControlType.QUARANTINE,
            state=ControlState.CANARY,
            canary_scope=CanaryScope(pilot_domains=("corp.example",)),
        ),
    )
    base: dict[str, object] = {
        "version": version,
        "controls": controls,
        "gaps": {"GAP-005": "VALIDATION", "GAP-006": "VALIDATION"},
        "valid_from": NOW - timedelta(hours=1),
        "valid_until": NOW + timedelta(days=1),
        "owner": "alice",
        "reviewer": "bob",
    }
    base.update(over)
    return EnforcementPolicy(**base)  # type: ignore[arg-type]


class TestPolicy:
    def test_a_published_policy_is_immutable(self) -> None:
        policy = make_policy()
        with pytest.raises(ValueError):
            policy.version = "v2"  # type: ignore[misc]

    def test_a_fail_mode_that_rejects_permanently_does_not_exist(self) -> None:
        assert {m.value for m in FailMode} == {"FAIL_OPEN", "FAIL_TEMPFAIL"}

    def test_reply_codes_are_checked(self) -> None:
        with pytest.raises(ValueError):
            ControlPolicy(control_type=ControlType.SPAM_REJECT, reject_reply="250 ok")

    def test_the_bundle_roundtrips_and_checks_checksum_and_signature(self) -> None:
        policy = make_policy()
        bundle = sign_policy(policy, KEY, issued_at=NOW)
        assert verify_bundle(bundle, KEY).checksum() == policy.checksum()
        tampered = PolicyBundle(**{**bundle.model_dump(), "policy": bundle.policy.replace('"v1"', '"v9"')})
        with pytest.raises(PolicyError):
            verify_bundle(tampered, KEY)
        with pytest.raises(PolicyError):
            verify_bundle(bundle, b"x" * 40)

    def test_a_short_signing_key_is_refused(self) -> None:
        with pytest.raises(PolicyError):
            sign_policy(make_policy(), b"short")

    def test_the_cache_serves_fresh_stale_and_safe_mode(self, tmp_path: Path) -> None:
        cache = PolicyCache(tmp_path, KEY, soft_ttl=timedelta(minutes=10), hard_ttl=timedelta(hours=1))
        assert cache.load(NOW)[1] is PolicyStatus.SAFE_MODE
        cache.install(sign_policy(make_policy(), KEY, issued_at=NOW), now=NOW)
        assert cache.load(NOW + timedelta(minutes=1))[1] is PolicyStatus.FRESH
        assert cache.load(NOW + timedelta(minutes=30))[1] is PolicyStatus.STALE
        policy, status = cache.load(NOW + timedelta(hours=2))
        assert policy is not None and status is PolicyStatus.SAFE_MODE

    def test_an_expired_policy_enters_safe_mode_even_if_recently_fetched(self, tmp_path: Path) -> None:
        cache = PolicyCache(tmp_path, KEY)
        cache.install(
            sign_policy(make_policy(valid_until=NOW + timedelta(minutes=5)), KEY, issued_at=NOW), now=NOW
        )
        assert cache.load(NOW + timedelta(minutes=6))[1] is PolicyStatus.SAFE_MODE

    def test_a_bad_bundle_does_not_replace_the_working_one(self, tmp_path: Path) -> None:
        cache = PolicyCache(tmp_path, KEY)
        cache.install(sign_policy(make_policy("v1"), KEY, issued_at=NOW), now=NOW)
        forged = sign_policy(make_policy("v2"), b"z" * 40, issued_at=NOW)
        with pytest.raises(PolicyError):
            cache.install(forged, now=NOW)
        policy, status = cache.load(NOW)
        assert policy is not None and policy.version == "v1" and status is PolicyStatus.FRESH

    def test_a_corrupt_active_file_falls_back_to_the_last_known_good(self, tmp_path: Path) -> None:
        cache = PolicyCache(tmp_path, KEY)
        cache.install(sign_policy(make_policy("v1"), KEY, issued_at=NOW), now=NOW)
        cache.install(sign_policy(make_policy("v2"), KEY, issued_at=NOW), now=NOW)
        (tmp_path / "active.json").write_text("{broken", encoding="utf-8")
        policy, _ = cache.load(NOW)
        assert policy is not None and policy.version == "v1"


# --- решения ----------------------------------------------------------------------------------
def spam_input(**over: object) -> EnforcementInput:
    base: dict[str, object] = {
        "transport_message_id": "Q1",
        "message_id": "m1@x",
        "sender": "spammer@evil.example",
        "recipients": ("pilot@corp.example",),
        "source_ip": "203.0.113.9",
        "trusted_evidence": True,
        "spam_score": 18.0,
        "spam_class": "HIGH_CONFIDENCE_SPAM",
        "reason_codes": ("SPAM_HIGH_SCORE", "BAYES_SPAM"),
        "evidence_ids": ("scan-1",),
    }
    base.update(over)
    return EnforcementInput(**base)  # type: ignore[arg-type]


def runtime(policy: EnforcementPolicy | None = None, **over: object) -> Runtime:
    base: dict[str, object] = {
        "policy": policy or make_policy(),
        "status": PolicyStatus.FRESH,
        "now": NOW,
        "engine_versions": {"rspamd": "3.12.1"},
    }
    base.update(over)
    return Runtime(**base)  # type: ignore[arg-type]


def spam_decision(out):  # type: ignore[no-untyped-def]
    return next(d for d in out.decisions if d.control_type is ControlType.SPAM_REJECT)


class TestDecisions:
    def test_a_canary_recipient_gets_a_generic_reject_with_evidence_and_version(self) -> None:
        out = decide(spam_input(), runtime())
        assert out.final is not None and out.final.decision is Decision.REJECT
        assert out.final.applied_action is AppliedAction.SMTP_REJECT
        assert out.final.policy_version == "v1" and out.final.evidence_ids == ("scan-1",)
        assert out.smtp_reply.startswith("550 ")
        for secret in ("18", "BAYES", "SPAM_HIGH_SCORE", "rspamd", "RBL"):
            assert secret not in out.smtp_reply

    def test_a_non_canary_recipient_gets_only_the_suggestion(self) -> None:
        out = decide(spam_input(recipients=("someone@corp.example",)), runtime())
        d = spam_decision(out)
        assert d.applied_action is AppliedAction.OBSERVE_ONLY and d.suggested_action == "REJECT"
        assert out.final is None

    def test_shadow_state_never_applies(self) -> None:
        out = decide(spam_input(), runtime(make_policy(state=ControlState.SHADOW)))
        assert out.final is None and spam_decision(out).suggested_action == "REJECT"

    @pytest.mark.parametrize("state", [ControlState.DISABLED, ControlState.PAUSED, ControlState.ROLLED_BACK])
    def test_inactive_states_never_apply(self, state: ControlState) -> None:
        assert decide(spam_input(), runtime(make_policy(state=state))).final is None

    def test_a_multi_recipient_message_is_not_rejected_for_a_partial_canary(self) -> None:
        out = decide(spam_input(recipients=("pilot@corp.example", "other@corp.example")), runtime())
        assert out.final is None

    def test_a_retry_decides_the_same_way(self) -> None:
        first = decide(spam_input(), runtime())
        second = decide(spam_input(previous_attempt="Q1"), runtime())
        assert first.final and second.final and first.final.decision == second.final.decision
        assert second.final.previous_attempt == "Q1"

    def test_untrusted_evidence_cannot_enforce(self) -> None:
        out = decide(spam_input(trusted_evidence=False), runtime())
        assert out.final is None and "UNTRUSTED_EVIDENCE" in spam_decision(out).reason_codes

    def test_a_reject_without_evidence_ids_is_not_executed(self) -> None:
        out = decide(spam_input(evidence_ids=()), runtime())
        assert out.final is None and "MISSING_EVIDENCE_FOR_REJECT" in spam_decision(out).reason_codes

    def test_spf_alone_is_never_a_reject_reason_while_gap_005_is_open(self) -> None:
        out = decide(spam_input(reason_codes=("AUTH_SPF_FAIL",)), runtime())
        assert out.final is None and "SPF_ONLY_FORBIDDEN_BY_GAP-005" in spam_decision(out).reason_codes

    def test_spf_may_accompany_other_reasons(self) -> None:
        out = decide(spam_input(reason_codes=("AUTH_SPF_FAIL", "BAYES_SPAM")), runtime())
        assert out.final is not None

    def test_a_dmarc_reject_is_blocked_by_the_open_gap_even_in_canary(self) -> None:
        inp = spam_input(spam_score=1.0, spam_class="NOT_SPAM", dmarc_result="FAIL", dmarc_policy="REJECT")
        out = decide(inp, runtime())
        dmarc = next(d for d in out.decisions if d.control_type is ControlType.DMARC_REJECT)
        assert out.final is None and "BLOCKED_BY_GAP" in dmarc.reason_codes

    def test_dmarc_reject_works_only_after_the_gap_is_resolved_and_not_for_temperror_or_forwarding(
        self,
    ) -> None:
        policy = make_policy(gaps={"GAP-006": "RESOLVED", "GAP-005": "VALIDATION"})
        base = {
            "spam_score": 1.0,
            "spam_class": "NOT_SPAM",
            "dmarc_policy": "REJECT",
            "recipients": ("a@corp.example",),
        }
        assert decide(spam_input(dmarc_result="FAIL", **base), runtime(policy)).final is not None
        assert decide(spam_input(dmarc_result="TEMPERROR", **base), runtime(policy)).final is None
        assert (
            decide(spam_input(dmarc_result="FAIL", forwarding_or_list=True, **base), runtime(policy)).final
            is None
        )
        assert decide(spam_input(dmarc_result="FAIL", arc_pass=True, **base), runtime(policy)).final is None

    def test_a_dmarc_quarantine_policy_is_not_a_reject(self) -> None:
        policy = make_policy(gaps={"GAP-006": "RESOLVED"})
        inp = spam_input(
            spam_score=1.0,
            spam_class="NOT_SPAM",
            dmarc_result="FAIL",
            dmarc_policy="QUARANTINE",
            recipients=("a@corp.example",),
        )
        assert decide(inp, runtime(policy)).final is None

    def test_kill_switch_and_local_bypass_stop_enforcement_without_changing_the_policy(self) -> None:
        for switches, applied in (
            (Switches(kill_switch=True), AppliedAction.BYPASS_KILL_SWITCH),
            (Switches(local_bypass=True), AppliedAction.BYPASS_LOCAL),
        ):
            out = decide(spam_input(), runtime(switches=switches))
            assert out.final is None
            d = spam_decision(out)
            assert d.applied_action is applied and d.suggested_action == "REJECT"
            assert d.policy_version == "v1"

    def test_a_stale_policy_enters_safe_mode(self) -> None:
        out = decide(spam_input(), runtime(status=PolicyStatus.SAFE_MODE))
        assert out.final is None and spam_decision(out).applied_action is AppliedAction.SAFE_MODE

    def test_an_exception_changes_only_the_applied_action(self) -> None:
        item = exc(approved_by="bob")
        policy = make_policy(exceptions=(item,))
        out = decide(spam_input(sender="boss@partner.example"), runtime(policy))
        d = spam_decision(out)
        assert out.final is None
        assert d.applied_action is AppliedAction.BYPASS_BY_EXCEPTION
        assert d.suggested_action == "REJECT" and d.evidence_ids == ("scan-1",)
        assert out.consumed_exceptions == ("e1",)

    def test_an_expired_exception_does_not_bypass(self) -> None:
        item = exc(expires_at=NOW + timedelta(hours=1))
        policy = make_policy(exceptions=(item,))
        later = Runtime(policy=policy, status=PolicyStatus.FRESH, now=NOW + timedelta(hours=2))
        assert decide(spam_input(sender="boss@partner.example"), later).final is not None

    def test_a_decision_timeout_fails_open_for_spam(self) -> None:
        out = decide(spam_input(elapsed_ms=99999), runtime())
        d = spam_decision(out)
        assert (
            out.final is None
            and d.fail_mode_applied is FailMode.FAIL_OPEN
            and "DECISION_TIMEOUT" in d.reason_codes
        )

    def test_a_timeout_never_becomes_a_permanent_reject(self) -> None:
        for kind in ControlType:
            for fail in (None, FailMode.FAIL_OPEN, FailMode.FAIL_TEMPFAIL):
                policy = make_policy(
                    controls=(
                        ControlPolicy(
                            control_type=kind,
                            state=ControlState.CANARY,
                            fail_mode=fail,
                            canary_scope=CanaryScope(pilot_domains=("corp.example",)),
                        ),
                    )
                )
                out = decide(spam_input(elapsed_ms=99999, recipients=("a@corp.example",)), runtime(policy))
                assert all(d.decision is not Decision.REJECT for d in out.decisions)

    def test_abuse_control_may_tempfail_on_timeout(self) -> None:
        policy = make_policy(
            controls=(
                ControlPolicy(
                    control_type=ControlType.TEMPFAIL_ABUSE,
                    state=ControlState.CANARY,
                    canary_scope=CanaryScope(pilot_domains=("corp.example",)),
                ),
            )
        )
        out = decide(spam_input(elapsed_ms=99999, recipients=("a@corp.example",)), runtime(policy))
        assert out.final is not None and out.final.decision is Decision.TEMPFAIL
        assert out.smtp_reply.startswith("451 ")

    def test_encrypted_or_unsupported_is_not_malware_reject(self) -> None:
        policy = make_policy(
            controls=(
                ControlPolicy(
                    control_type=ControlType.MALWARE_REJECT,
                    state=ControlState.CANARY,
                    canary_scope=CanaryScope(pilot_domains=("corp.example",)),
                ),
            )
        )
        for m in (
            MalwareEvidence(encrypted_unscannable=True, verdict="MALICIOUS", confidence=1.0),
            MalwareEvidence(unsupported=True),
        ):
            out = decide(spam_input(malware=m, recipients=("a@corp.example",)), runtime(policy))
            assert out.final is None

    def test_malware_reject_needs_high_confidence_and_scanner_timeout_fails_open(self) -> None:
        policy = make_policy(
            controls=(
                ControlPolicy(
                    control_type=ControlType.MALWARE_REJECT,
                    state=ControlState.CANARY,
                    thresholds={"min_confidence": 0.95},
                    canary_scope=CanaryScope(pilot_domains=("corp.example",)),
                ),
            )
        )
        kw = {"recipients": ("a@corp.example",)}
        assert (
            decide(
                spam_input(malware=MalwareEvidence(verdict="MALICIOUS", confidence=0.99), **kw),
                runtime(policy),
            ).final
            is not None
        )
        assert (
            decide(
                spam_input(malware=MalwareEvidence(verdict="MALICIOUS", confidence=0.6), **kw),
                runtime(policy),
            ).final
            is None
        )
        out = decide(
            spam_input(malware=MalwareEvidence(verdict="MALICIOUS", confidence=0.99, timed_out=True), **kw),
            runtime(policy),
        )
        assert out.final is None

    def test_rbl_provider_errors_are_no_decision(self) -> None:
        policy = make_policy(
            controls=(
                ControlPolicy(
                    control_type=ControlType.RBL_REJECT,
                    state=ControlState.CANARY,
                    canary_scope=CanaryScope(pilot_domains=("corp.example",)),
                ),
            )
        )
        inp = spam_input(rbl_provider_errors=True, recipients=("a@corp.example",))
        assert decide(inp, runtime(policy)).final is None
        listed = spam_input(rbl_listed=("labzone",), recipients=("a@corp.example",))
        assert decide(listed, runtime(policy)).final is not None

    def test_after_queue_quarantine_never_produces_a_5xx(self) -> None:
        inp = spam_input(
            spam_score=1.0, spam_class="NOT_SPAM", risk_verdict="HIGH_RISK", recipients=("a@corp.example",)
        )
        out = decide(inp, runtime())
        assert out.final is not None and out.final.decision is Decision.QUARANTINE
        assert out.smtp_reply == "" and out.final.applied_action is AppliedAction.QUARANTINED

    def test_encrypted_archive_is_a_quarantine_candidate_not_a_reject(self) -> None:
        inp = spam_input(
            spam_score=1.0,
            spam_class="NOT_SPAM",
            recipients=("a@corp.example",),
            malware=MalwareEvidence(encrypted_unscannable=True),
        )
        out = decide(inp, runtime())
        assert out.final is not None and out.final.decision is Decision.QUARANTINE

    def test_outbound_block_holds_malware_and_defers_a_compromised_account(self) -> None:
        policy = make_policy(
            controls=(
                ControlPolicy(
                    control_type=ControlType.OUTBOUND_BLOCK,
                    state=ControlState.PILOT,
                    canary_scope=CanaryScope(source_cidrs=("10.0.0.0/8",)),
                ),
            )
        )
        base = {"direction": "OUTBOUND", "source_ip": "10.1.1.1", "recipients": ("ext@partner.example",)}
        held = decide(
            spam_input(malware=MalwareEvidence(verdict="MALICIOUS", confidence=1.0), **base), runtime(policy)
        )
        assert held.final is not None and held.final.decision is Decision.HOLD
        deferred = decide(spam_input(compromised_account=True, **base), runtime(policy))
        assert deferred.final is not None and deferred.final.decision is Decision.TEMPFAIL
        assert decide(spam_input(**base), runtime(policy)).final is None

    def test_no_policy_means_no_decision(self) -> None:
        assert decide(spam_input(), Runtime()).final is None
