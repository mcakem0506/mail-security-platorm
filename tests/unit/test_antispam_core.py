"""Ядро анти-спама MSP 1.2: разбор результата, классы, отображение символов, политика, репутация."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from msp_antispam import bayes, conflicts, dkim_keys, rates, reputation
from msp_antispam.analysis import analyze
from msp_antispam.auth import authentication
from msp_antispam.authres import (
    build_authentication_results,
    inspect_headers,
    parse_authentication_results,
)
from msp_antispam.classification import BulkSignals, bulk_signals, classify
from msp_antispam.helo import helo_evidence, top_received
from msp_antispam.mapping import MappingError, apply_mapping, default_mapping, parse_mapping
from msp_antispam.model import (
    ActionMode,
    AppliedAction,
    Direction,
    HeloSignal,
    PtrState,
    SpamClass,
    SuggestedAction,
)
from msp_antispam.policy import (
    CandidateState,
    PolicyError,
    RspamdActionPolicy,
    SimulationInput,
    SpamPolicy,
    SpamThresholds,
    simulate,
)
from msp_antispam.rspamd_result import forged_scanner_headers, parse_scan
from pydantic import ValidationError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "rspamd"


def load(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


NOW = datetime(2026, 10, 18, tzinfo=UTC)


# ---------------------------------------------------------------------------------------------
class TestScanParsing:
    def test_a_real_record_is_normalised(self) -> None:
        evidence = parse_scan(load("all_pass"))
        assert evidence.message_id == "fx-allpass@sender.example"
        assert evidence.direction is Direction.INBOUND
        assert evidence.suggested_action in (SuggestedAction.GREYLIST, SuggestedAction.NO_ACTION)
        assert evidence.has("R_SPF_ALLOW") and evidence.client_ip == "10.77.0.150"
        assert "policies" in evidence.groups

    def test_the_direction_comes_from_the_listener_symbol_not_from_from(self) -> None:
        record = load("all_pass")
        record["symbols"] = [{"name": "MSP_DIRECTION_OUTBOUND", "score": 0}]
        record["from"] = "someone@external.example"
        assert parse_scan(record).direction is Direction.OUTBOUND

    def test_without_the_symbol_the_direction_is_not_guessed_from_the_sender(self) -> None:
        record = load("all_pass")
        record["symbols"] = []
        assert (
            parse_scan(record).direction is Direction.INBOUND
        )  # значение по умолчанию, признак «неизвестно» в direction_of

    @pytest.mark.parametrize(
        ("action", "expected"),
        [
            ("no action", SuggestedAction.NO_ACTION),
            ("greylist", SuggestedAction.GREYLIST),
            ("add header", SuggestedAction.ADD_HEADER),
            ("rewrite subject", SuggestedAction.REWRITE_SUBJECT),
            ("soft reject", SuggestedAction.SOFT_REJECT),
            ("reject", SuggestedAction.REJECT),
            ("something new", SuggestedAction.UNKNOWN),
            (None, SuggestedAction.UNKNOWN),
        ],
    )
    def test_native_actions_become_suggestions(self, action: object, expected: SuggestedAction) -> None:
        record = load("all_pass")
        record["action"] = action
        assert parse_scan(record).suggested_action is expected

    def test_a_suggested_reject_is_never_an_applied_action(self) -> None:
        policy = RspamdActionPolicy()
        for action in SuggestedAction:
            assert policy.applied(action) is AppliedAction.OBSERVE_ONLY

    def test_the_http_dictionary_shape_is_accepted_too(self) -> None:
        record = {
            "score": 3.0,
            "action": "no action",
            "symbols": {"R_SPF_ALLOW": {"name": "R_SPF_ALLOW", "score": -0.2}},
        }
        assert parse_scan(record).has("R_SPF_ALLOW")

    def test_secret_provider_options_are_dropped(self) -> None:
        record = {
            "symbols": [
                {"name": "MSP_RBL_PRIV_CLIENT_IP", "score": 0, "options": ["4.3.2.1.secret-zone.example"]}
            ]
        }
        evidence = parse_scan(record, secret_provider_ids=["priv"])
        assert evidence.symbols[0].options == []
        assert "secret-zone" not in evidence.model_dump_json()

    def test_forged_scanner_headers_are_reported_not_trusted(self) -> None:
        found = forged_scanner_headers(["From", "X-Spamd-Result", "X-Spam-Status", "Subject"])
        assert found == ["x-spam-status", "x-spamd-result"]

    def test_the_forged_header_fixture_changes_nothing_in_the_evidence(self) -> None:
        # В письме заявлено «X-Spamd-Result: -9.00», реальная оценка — из записи сканера.
        evidence = parse_scan(load("forged_scanner_headers"))
        assert evidence.score > 0

    @settings(max_examples=200, deadline=None)
    @given(
        st.recursive(
            st.none() | st.booleans() | st.integers() | st.floats(allow_nan=True) | st.text(max_size=40),
            lambda children: (
                st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children, max_size=4)
            ),
            max_leaves=20,
        )
    )
    def test_hostile_input_never_raises(self, junk: object) -> None:
        record = {
            "symbols": junk,
            "score": junk,
            "action": junk,
            "message_id": junk,
            "ip": junk,
            "from": junk,
            "_msp": junk,
        }
        parse_scan(record)

    def test_oversized_input_is_bounded(self) -> None:
        record = {
            "symbols": [{"name": f"S_{i}", "score": 1, "options": ["x" * 5000] * 100} for i in range(2000)]
        }
        evidence = parse_scan(record)
        assert len(evidence.symbols) <= 512
        assert all(len(s.options) <= 32 and all(len(o) <= 256 for o in s.options) for s in evidence.symbols)

    def test_invalid_symbol_names_are_skipped(self) -> None:
        record = {"symbols": [{"name": "OK_NAME"}, {"name": "bad name"}, {"name": "x\x00y"}, {"name": 5}]}
        assert [s.name for s in parse_scan(record).symbols] == ["OK_NAME"]


# ---------------------------------------------------------------------------------------------
class TestAuthenticationResults:
    def test_a_trusted_header_is_built_from_the_scan_record(self) -> None:
        analysis = analyze(load("all_pass"), SpamPolicy())
        text = build_authentication_results(
            "gw.lab.example", analysis.auth, smtp_mailfrom="a@example.test", header_from="example.test"
        )
        parsed = parse_authentication_results(text)
        assert parsed is not None and parsed.authserv_id == "gw.lab.example"
        assert parsed.result_of("spf") == "pass" and parsed.result_of("dmarc") == "pass"

    def test_a_forged_header_without_a_scan_record_is_flagged(self) -> None:
        forged = ["gw.lab.example; spf=pass; dkim=pass; dmarc=pass"]
        finding = inspect_headers(forged, "gw.lab.example", None)
        assert finding.tampered and "OUR_AUTHSERV_ID_WITHOUT_SCAN_RECORD" in finding.anomalies

    def test_a_header_that_disagrees_with_the_scan_is_flagged(self) -> None:
        analysis = analyze(load("dmarc_reject_fail"), SpamPolicy())
        finding = inspect_headers(["gw.lab.example; spf=pass; dmarc=pass"], "gw.lab.example", analysis.auth)
        assert {"SPF_MISMATCH_WITH_SCAN_RECORD", "DMARC_MISMATCH_WITH_SCAN_RECORD"} <= set(finding.anomalies)

    def test_two_headers_with_our_id_mean_an_injected_copy(self) -> None:
        analysis = analyze(load("all_pass"), SpamPolicy())
        header = build_authentication_results("gw.lab.example", analysis.auth)
        finding = inspect_headers([header, header], "gw.lab.example", analysis.auth)
        assert "DUPLICATE_OUR_AUTHSERV_ID" in finding.anomalies

    def test_foreign_authserv_ids_are_not_ours_and_are_kept(self) -> None:
        finding = inspect_headers(["ksmg.corp.example; spf=pass"], "gw.lab.example", None)
        assert finding.others and not finding.ours and not finding.tampered

    @pytest.mark.parametrize("value", ["", ";", "   ", "bad id;spf=pass", "x" * 400 + ";spf=pass"])
    def test_garbage_does_not_parse(self, value: str) -> None:
        assert parse_authentication_results(value) is None


# ---------------------------------------------------------------------------------------------
class TestSpamClasses:
    def test_scores_map_to_classes(self) -> None:
        policy = SpamPolicy()
        cases = {"all_pass": SpamClass.SUSPECTED_SPAM, "dmarc_reject_fail": SpamClass.HIGH_CONFIDENCE_SPAM}
        for name, expected in cases.items():
            assert classify(parse_scan(load(name)), policy).spam_class is expected

    def test_without_a_scan_the_class_is_unknown_not_clean(self) -> None:
        assert classify(None, SpamPolicy()).spam_class is SpamClass.UNKNOWN

    def test_a_newsletter_with_unsubscribe_is_bulk_not_spam(self) -> None:
        record = load("all_pass")
        record["score"] = 3.0
        bulk = bulk_signals({"List-Unsubscribe": "<mailto:u@example.test>"}, [])
        assert classify(parse_scan(record), SpamPolicy(), bulk).spam_class is SpamClass.BULK

    def test_a_mailing_list_is_not_spam_automatically(self) -> None:
        record = load("all_pass")
        record["score"] = 7.0  # SPAM по порогам
        bulk = bulk_signals({"List-Id": "<dev.lists.example>"}, [])
        assert classify(parse_scan(record), SpamPolicy(), bulk).spam_class is SpamClass.BULK

    def test_unsubscribe_alone_does_not_excuse_a_high_score(self) -> None:
        record = load("all_pass")
        record["score"] = 7.0
        bulk = bulk_signals({"List-Unsubscribe": "<x>"}, [])
        assert classify(parse_scan(record), SpamPolicy(), bulk).spam_class is SpamClass.SPAM

    def test_nothing_excuses_high_confidence(self) -> None:
        record = load("all_pass")
        record["score"] = 14.0
        bulk = bulk_signals({"List-Id": "<x>", "List-Unsubscribe": "<y>"}, [])
        assert classify(parse_scan(record), SpamPolicy(), bulk).spam_class is SpamClass.HIGH_CONFIDENCE_SPAM

    def test_spam_with_a_low_security_risk_and_clean_mail_with_a_high_one_are_both_valid(self) -> None:
        # Класс спама и вердикт безопасности — независимые оси: их нельзя сворачивать в одно число.
        analysis = analyze(load("dmarc_reject_fail"), SpamPolicy())
        sample = SimulationInput(
            score=analysis.evidence.score, msp_spam_class=analysis.spam_class, msp_security_verdict="LOW_RISK"
        )
        assert simulate(SpamPolicy(), sample).msp_security_verdict == "LOW_RISK"
        clean = SimulationInput(score=0.5, msp_security_verdict="HIGH_RISK")
        result = simulate(SpamPolicy(), clean)
        assert (
            result.candidate_spam_class is SpamClass.NOT_SPAM and result.msp_security_verdict == "HIGH_RISK"
        )

    def test_forwarding_context_is_noted_when_dkim_breaks_behind_arc(self) -> None:
        record = load("dkim_body_tampered")
        record["symbols"].append({"name": "ARC_ALLOW", "score": -1, "options": ["lists.example:arc"]})
        analysis = analyze(record, SpamPolicy())
        assert analysis.classification.forwarding_or_list_context is True

    def test_bulk_signals_from_headers(self) -> None:
        signals = bulk_signals(
            {"Precedence": "bulk"},
            ["PRECEDENCE_BULK"],
            recipient_count=80,
            sender_domain="m.bulkmail.example",
            known_bulk_domains=["bulkmail.example"],
            template_similarity=True,
        )
        assert signals.is_bulk and signals.precedence_bulk and signals.high_recipient_volume
        assert signals.known_bulk_infrastructure
        assert not BulkSignals().is_bulk


# ---------------------------------------------------------------------------------------------
class TestSymbolMapping:
    def test_mapped_symbols_become_named_signals(self) -> None:
        analysis = analyze(load("dmarc_reject_fail"), SpamPolicy())
        codes = analysis.signals.codes(risk_only=True)
        assert "AUTH_SPF_FAIL" in codes and "AUTH_DMARC_POLICY_REJECT" in codes

    def test_unknown_symbols_are_kept_as_evidence_and_do_not_affect_risk(self) -> None:
        record = load("all_pass")
        record["symbols"].append({"name": "BRAND_NEW_SYMBOL_9000", "score": 50.0})
        evidence = parse_scan(record)
        mapped = apply_mapping(evidence, SpamPolicy())
        assert "BRAND_NEW_SYMBOL_9000" in mapped.unmapped
        assert all(s.symbol != "BRAND_NEW_SYMBOL_9000" for s in mapped.signals)
        assert evidence.has("BRAND_NEW_SYMBOL_9000")

    def test_a_high_score_alone_is_a_signal_not_a_verdict(self) -> None:
        record = {"score": 20.0, "action": "reject", "symbols": []}
        mapped = apply_mapping(parse_scan(record), SpamPolicy())
        assert mapped.codes() == ["SPAM_HIGH_SCORE"]

    def test_the_mapping_is_versioned(self) -> None:
        assert default_mapping().version == "1"
        assert analyze(load("all_pass"), SpamPolicy()).symbol_mapping_version == "1"

    def test_prefix_entries_cover_provider_symbols(self) -> None:
        record = {"symbols": [{"name": "MSP_RBL_LABZONE_CLIENT_IP", "score": 0}]}
        assert apply_mapping(parse_scan(record), SpamPolicy()).codes(risk_only=True) == ["REPUTATION_LISTED"]

    def test_bad_mappings_are_refused(self) -> None:
        with pytest.raises(MappingError):
            parse_mapping({"entries": []})
        with pytest.raises(MappingError):
            parse_mapping(
                {
                    "version": "2",
                    "entries": [{"symbol": "A", "signal": "B", "kind": "AUTH", "risk_effect": "BLOCK"}],
                }
            )
        with pytest.raises(MappingError):
            parse_mapping(
                {
                    "version": "2",
                    "entries": [
                        {"symbol": "A", "signal": "B", "kind": "AUTH", "risk_effect": "NONE"},
                        {"symbol": "A", "signal": "C", "kind": "AUTH", "risk_effect": "NONE"},
                    ],
                }
            )


# ---------------------------------------------------------------------------------------------
class TestPolicy:
    def test_enforcement_cannot_be_enabled(self) -> None:
        with pytest.raises((PolicyError, ValidationError)):
            SpamPolicy(enforcement_enabled=True)

    def test_thresholds_must_ascend(self) -> None:
        with pytest.raises((PolicyError, ValidationError)):
            SpamThresholds(suspected=8, spam=6)

    def test_there_is_no_enforcing_state(self) -> None:
        assert "ACTIVE_ENFORCING" not in {s.value for s in CandidateState}

    def test_candidate_walks_the_ladder_with_four_eyes(self) -> None:
        policy = SpamPolicy(edited_by="alice")
        policy = policy.transition(CandidateState.SHADOW, actor="alice").transition(
            CandidateState.VALIDATION, actor="alice"
        )
        with pytest.raises(PolicyError):
            policy.transition(CandidateState.APPROVED, actor="alice")
        approved = policy.transition(CandidateState.APPROVED, actor="bob")
        assert approved.approved_by == "bob"
        assert (
            approved.transition(CandidateState.ACTIVE_SHADOW, actor="bob").state
            is CandidateState.ACTIVE_SHADOW
        )

    def test_steps_cannot_be_skipped_or_reversed(self) -> None:
        policy = SpamPolicy(edited_by="alice")
        with pytest.raises(PolicyError):
            policy.transition(CandidateState.APPROVED, actor="bob")
        shadow = policy.transition(CandidateState.SHADOW, actor="alice")
        with pytest.raises(PolicyError):
            shadow.transition(CandidateState.DRAFT, actor="alice")

    def test_every_mode_only_observes(self) -> None:
        for mode in ActionMode:
            assert RspamdActionPolicy(mode).applied(SuggestedAction.REJECT) is AppliedAction.OBSERVE_ONLY

    def test_simulator_shows_a_hypothetical_action_without_applying_it(self) -> None:
        candidate = SpamPolicy(
            thresholds=SpamThresholds(suspected=2, spam=3, high_confidence=5, suggest_reject=8)
        )
        result = simulate(
            candidate, SimulationInput(score=9.0, current_suggested_action=SuggestedAction.ADD_HEADER)
        )
        assert result.hypothetical_action is SuggestedAction.REJECT
        assert result.applied_action is AppliedAction.OBSERVE_ONLY
        assert result.changed_vs_current is True

    def test_unknown_modules_are_refused(self) -> None:
        with pytest.raises((PolicyError, ValidationError)):
            SpamPolicy(enabled_modules=("spf", "magic"))


# ---------------------------------------------------------------------------------------------
class TestHelo:
    def test_missing_ip_literal_and_bad_syntax(self) -> None:
        assert HeloSignal.MISSING in helo_evidence("").signals
        assert HeloSignal.IP_LITERAL in helo_evidence("[203.0.113.5]").signals
        assert HeloSignal.IP_LITERAL in helo_evidence("203.0.113.5").signals
        assert HeloSignal.INVALID_SYNTAX in helo_evidence("bad host!").signals

    def test_mismatch_with_the_reverse_name(self) -> None:
        assert HeloSignal.MISMATCH in helo_evidence("mail.example.test", rdns="mx.other.test").signals
        assert HeloSignal.MISMATCH not in helo_evidence("mail.example.test", rdns="mx.example.test").signals

    def test_protected_domain_impersonation_from_outside(self) -> None:
        signals = helo_evidence(
            "mail.corp.example", rdns="x.evil.test", protected_domains=["corp.example"]
        ).signals
        assert HeloSignal.PROTECTED_DOMAIN in signals
        trusted = helo_evidence(
            "mail.corp.example",
            rdns="x.evil.test",
            protected_domains=["corp.example"],
            client_is_trusted=True,
        )
        assert HeloSignal.PROTECTED_DOMAIN not in trusted.signals

    def test_internal_only_hostname_from_an_external_source(self) -> None:
        assert HeloSignal.INTERNAL_ONLY_FROM_EXTERNAL in helo_evidence("exchange01.corp.local").signals
        assert HeloSignal.INTERNAL_ONLY_FROM_EXTERNAL in helo_evidence("exchange01").signals

    def test_ptr_states(self) -> None:
        assert helo_evidence("a.example.test", rdns="unknown").ptr_state is PtrState.NONE
        assert helo_evidence("a.example.test", rdns="a.example.test").ptr_state is PtrState.FCRDNS_PASS
        scan = parse_scan({"symbols": [{"name": "RDNS_DNSFAIL"}]})
        assert helo_evidence("a.example.test", rdns="unknown", scan=scan).ptr_state is PtrState.TEMPERROR
        scan = parse_scan({"symbols": [{"name": "HFILTER_HOSTNAME_UNKNOWN"}]})
        assert (
            helo_evidence("a.example.test", rdns="a.example.test", scan=scan).ptr_state
            is PtrState.FCRDNS_FAIL
        )

    def test_only_the_gateways_own_received_header_is_used(self) -> None:
        top = top_received(
            ["from helo.example (rdns.example [203.0.113.7]) by gw with ESMTP", "from forged (x [1.1.1.1])"]
        )
        assert top == ("helo.example", "rdns.example", "203.0.113.7")
        assert top_received(["by gw with SMTP"]) is None


# ---------------------------------------------------------------------------------------------
class TestLocalReputation:
    def test_counters_decay(self) -> None:
        rep = reputation.observe_ip(
            None, "203.0.113.5", reputation.Outcome.SPAM, new_sender=True, new_domain=True, now=NOW
        )
        later = rep.decayed(NOW + timedelta(days=30))
        assert later.spam_count == pytest.approx(0.5)

    def test_old_history_falls_out_of_the_window(self) -> None:
        rep = reputation.observe_ip(
            None, "203.0.113.5", reputation.Outcome.THREAT, new_sender=True, new_domain=True, now=NOW
        )
        view = reputation.view_ip(rep, NOW + timedelta(days=400))
        assert view.tier is reputation.Tier.UNKNOWN and not view.in_window

    def test_positive_history_never_suppresses_hard_signals(self) -> None:
        rep = None
        for i in range(30):
            rep = reputation.observe_domain(
                rep,
                "good.example",
                reputation.Outcome.LEGITIMATE,
                authenticated=True,
                now=NOW - timedelta(days=60 - i),
            )
        view = reputation.view_domain(rep, NOW)
        assert view.tier is reputation.Tier.ESTABLISHED
        assert view.suppresses_hard_signals is False

    def test_a_bad_source_is_poor_and_explained(self) -> None:
        rep = None
        for _ in range(10):
            rep = reputation.observe_ip(
                rep, "203.0.113.5", reputation.Outcome.SPAM, new_sender=False, new_domain=False, now=NOW
            )
        rep = reputation.observe_ip(
            rep, "203.0.113.5", reputation.Outcome.THREAT, new_sender=False, new_domain=False, now=NOW
        )
        view = reputation.view_ip(rep, NOW)
        assert view.tier in (reputation.Tier.POOR, reputation.Tier.HOSTILE)
        assert view.explanations, "оценка без объяснения не показывается"

    def test_analyst_confirmation_decides(self) -> None:
        rep = reputation.SourceIpReputation(
            "203.0.113.5", NOW, NOW, analyst_confirmed=reputation.Analyst.MALICIOUS
        )
        assert reputation.view_ip(rep, NOW).tier is reputation.Tier.HOSTILE

    def test_few_observations_make_no_judgement(self) -> None:
        rep = reputation.observe_ip(
            None, "203.0.113.5", reputation.Outcome.SPAM, new_sender=True, new_domain=True, now=NOW
        )
        assert reputation.view_ip(rep, NOW).tier is reputation.Tier.NEW

    def test_every_view_has_an_explanation(self) -> None:
        assert reputation.view_ip(None, NOW).explanations and reputation.view_domain(None, NOW).explanations

    def test_sender_not_observed_is_informative_only_for_a_mature_history(self) -> None:
        young = reputation.OrganizationObservationMaturity(NOW - timedelta(days=3), 40, 10)
        growing = reputation.OrganizationObservationMaturity(NOW - timedelta(days=10), 300, 80)
        mature = reputation.OrganizationObservationMaturity(NOW - timedelta(days=90), 4000, 600)
        assert young.level(
            NOW
        ) is reputation.Maturity.IMMATURE and not young.sender_not_observed_is_informative(NOW)
        assert growing.level(NOW) is reputation.Maturity.DEVELOPING
        assert mature.sender_not_observed_is_informative(NOW)


class TestRateAnomalies:
    def test_a_spike_over_history_is_an_anomaly_that_only_observes(self) -> None:
        found = rates.anomaly(rates.AnomalyKind.RECIPIENTS_PER_SENDER, 500, [10, 12, 9, 11, 10, 13], floor=50)
        assert found is not None and found.action == "OBSERVE_ONLY"

    def test_normal_volume_is_not_flagged(self) -> None:
        assert (
            rates.anomaly(rates.AnomalyKind.RECIPIENTS_PER_SENDER, 60, [50, 55, 60, 58, 62, 57], floor=50)
            is None
        )

    def test_short_history_uses_only_the_absolute_floor(self) -> None:
        assert rates.anomaly(rates.AnomalyKind.SENDERS_PER_IP, 40, [1, 2], floor=50) is None
        assert rates.anomaly(rates.AnomalyKind.SENDERS_PER_IP, 400, [1, 2], floor=50) is not None

    def test_a_high_outbound_anomaly_is_still_only_an_observation(self) -> None:
        found = rates.outbound_account_anomaly(5000, [20, 25, 22, 19, 21, 24], spam_hits=5)
        assert found is not None and found.severity is rates.Severity.HIGH and found.action == "OBSERVE_ONLY"


class TestBayes:
    def test_not_trained_until_enough_reviewed_samples(self) -> None:
        assert bayes.state(10, 500) is bayes.BayesState.NOT_TRAINED
        assert bayes.state(200, 200) is bayes.BayesState.READY_TO_ENABLE
        assert bayes.state(200, 200, trained=True) is bayes.BayesState.TRAINED

    def test_autolearn_is_refused(self) -> None:
        ok, reason = bayes.can_enable(500, 500, autolearn=True)
        assert not ok and "автообуч" in reason

    @pytest.mark.parametrize(
        "source",
        [
            bayes.Source.UNREVIEWED,
            bayes.Source.UPSTREAM_VERDICT,
            bayes.Source.USER_REPORT,
            bayes.Source.OWN_SCORE,
            bayes.Source.SYNTHETIC_TEST,
        ],
    )
    def test_forbidden_sources_do_not_train(self, source: bayes.Source) -> None:
        with pytest.raises(bayes.LearnRefused):
            bayes.check_learn(bayes.LearnSample("m", bayes.Label.SPAM, source, confirmed_by="analyst"))

    def test_analyst_confirmed_samples_train(self) -> None:
        bayes.check_learn(
            bayes.LearnSample(
                "m", bayes.Label.SPAM, bayes.Source.ANALYST_CONFIRMED_SPAM, confirmed_by="analyst"
            )
        )
        bayes.check_learn(bayes.LearnSample("m", bayes.Label.HAM, bayes.Source.APPROVED_HISTORICAL_CORPUS))

    def test_confirmation_is_required_and_the_label_must_match(self) -> None:
        with pytest.raises(bayes.LearnRefused):
            bayes.check_learn(bayes.LearnSample("m", bayes.Label.SPAM, bayes.Source.ANALYST_CONFIRMED_SPAM))
        with pytest.raises(bayes.LearnRefused):
            bayes.check_learn(
                bayes.LearnSample("m", bayes.Label.HAM, bayes.Source.ANALYST_CONFIRMED_SPAM, confirmed_by="a")
            )

    def test_synthetic_samples_are_not_mixed_into_the_production_corpus(self) -> None:
        with pytest.raises(bayes.LearnRefused):
            bayes.check_learn(
                bayes.LearnSample(
                    "m",
                    bayes.Label.SPAM,
                    bayes.Source.ANALYST_CONFIRMED_SPAM,
                    confirmed_by="a",
                    synthetic=True,
                )
            )


class TestAuthenticationConflicts:
    def test_disagreement_is_recorded_not_hidden(self) -> None:
        analysis = analyze(load("spf_fail_dkim_pass"), SpamPolicy())
        upstream = parse_authentication_results("ksmg.corp.example; spf=pass; dkim=pass; dmarc=pass")
        report = conflicts.compare(
            upstream,
            analysis.auth,
            upstream_client_ip="198.51.100.9",
            msp_client_ip="10.77.0.151",
            expected_upstream_ids=("ksmg.corp.example",),
        )
        kinds = {c.kind for c in report.conflicts}
        assert conflicts.ConflictKind.SPF in kinds and conflicts.ConflictKind.CLIENT_IP in kinds
        spf = next(c for c in report.conflicts if c.kind is conflicts.ConflictKind.SPF)
        assert "адрес" in spf.note

    def test_an_unexpected_authserv_id_is_a_conflict(self) -> None:
        analysis = analyze(load("all_pass"), SpamPolicy())
        upstream = parse_authentication_results("evil.example; spf=pass")
        report = conflicts.compare(upstream, analysis.auth, expected_upstream_ids=("ksmg.corp.example",))
        assert any(c.kind is conflicts.ConflictKind.AUTHSERV_ID for c in report.conflicts)

    def test_no_upstream_means_no_conflict(self) -> None:
        assert not conflicts.compare(None, analyze(load("all_pass"), SpamPolicy()).auth).any

    def test_agreement_is_clean(self) -> None:
        analysis = analyze(load("all_pass"), SpamPolicy())
        upstream = parse_authentication_results("ksmg.corp.example; spf=pass; dkim=pass; dmarc=pass")
        assert not conflicts.compare(upstream, analysis.auth).any

    def test_a_clean_upstream_verdict_never_lowers_msp_risk(self) -> None:
        analysis = analyze(load("dmarc_reject_fail"), SpamPolicy())
        upstream = parse_authentication_results("ksmg.corp.example; spf=pass; dkim=pass; dmarc=pass")
        report = conflicts.compare(upstream, analysis.auth)
        assert report.any
        assert "AUTH_DMARC_POLICY_REJECT" in analysis.signals.codes(risk_only=True)


class TestDkimKeyLifecycle:
    TRUSTED = {"lab.example"}

    def make(self, generator: str = "alice"):  # type: ignore[no-untyped-def]
        return dkim_keys.generate("lab.example", "s2026", generated_by=generator)

    def test_the_private_key_is_returned_once_and_not_stored(self) -> None:
        key, pem = self.make()
        assert pem.startswith(b"-----BEGIN")
        assert "PRIVATE" not in repr(key) and pem.decode()[:30] not in repr(key)
        assert key.private_key_ref.endswith("lab.example.s2026.key")
        assert dkim_keys.MIN_BITS >= 2048

    def test_activation_is_forbidden_until_dns_is_verified(self) -> None:
        key, _ = self.make()
        with pytest.raises(dkim_keys.KeyError_):
            dkim_keys.activate(key, approver="bob", trusted_domains=self.TRUSTED)
        pending = dkim_keys.mark_dns_pending(key)
        with pytest.raises(dkim_keys.KeyError_):
            dkim_keys.activate(pending, approver="bob", trusted_domains=self.TRUSTED)

    def test_dns_checks(self) -> None:
        key, _ = self.make()
        pending = dkim_keys.mark_dns_pending(key)
        assert dkim_keys.check_dns(pending, None).problems == ("TXT_MISSING",)
        assert dkim_keys.check_dns(pending, ["v=spf1 -all"]).problems == ("TXT_NOT_DKIM",)
        assert "KEY_MISMATCH" in dkim_keys.check_dns(pending, ["v=DKIM1; k=rsa; p=AAAA"]).problems
        assert "KEY_REVOKED_OR_EMPTY" in dkim_keys.check_dns(pending, ["v=DKIM1; k=rsa; p="]).problems
        assert dkim_keys.check_dns(pending, [], dns_error=True).problems == ("DNS_NOT_VISIBLE",)
        assert dkim_keys.check_dns(pending, [key.public_record]).ok
        split = key.public_record.replace("p=", "p= ")
        assert dkim_keys.check_dns(pending, [split]).ok

    def test_failed_verification_leaves_the_key_unusable(self) -> None:
        key, _ = self.make()
        pending = dkim_keys.mark_dns_pending(key)
        failed = dkim_keys.verify_dns(pending, ["v=DKIM1; k=rsa; p=AAAA"])
        assert failed.status is dkim_keys.KeyStatus.DNS_PENDING and failed.failure
        with pytest.raises(dkim_keys.KeyError_):
            dkim_keys.activate(failed, approver="bob", trusted_domains=self.TRUSTED)

    def test_four_eyes_and_trusted_domains(self) -> None:
        key, _ = self.make()
        ready = dkim_keys.verify_dns(dkim_keys.mark_dns_pending(key), [key.public_record])
        assert ready.status is dkim_keys.KeyStatus.READY
        with pytest.raises(dkim_keys.KeyError_):
            dkim_keys.activate(ready, approver="alice", trusted_domains=self.TRUSTED)
        with pytest.raises(dkim_keys.KeyError_):
            dkim_keys.activate(ready, approver="bob", trusted_domains={"other.example"})
        assert (
            dkim_keys.activate(ready, approver="bob", trusted_domains=self.TRUSTED).status
            is dkim_keys.KeyStatus.ACTIVE
        )

    def test_rotation_overlap_then_retire(self) -> None:
        old, _ = self.make()
        old = dkim_keys.activate(
            dkim_keys.verify_dns(dkim_keys.mark_dns_pending(old), [old.public_record]),
            approver="bob",
            trusted_domains=self.TRUSTED,
        )
        new, _ = dkim_keys.generate("lab.example", "s2027", generated_by="alice")
        new = dkim_keys.activate(
            dkim_keys.verify_dns(dkim_keys.mark_dns_pending(new), [new.public_record]),
            approver="bob",
            trusted_domains=self.TRUSTED,
        )
        retiring = dkim_keys.begin_retirement(old, now=NOW)
        assert dkim_keys.signing_selectors([retiring, new])["lab.example"].selector == "s2027"
        with pytest.raises(dkim_keys.KeyError_):
            dkim_keys.retire(retiring, now=NOW + timedelta(days=1))
        assert dkim_keys.retire(retiring, now=NOW + timedelta(days=8)).status is dkim_keys.KeyStatus.RETIRED

    def test_bad_names_are_refused(self) -> None:
        with pytest.raises(dkim_keys.KeyError_):
            dkim_keys.generate("not a domain", "s1", generated_by="a")
        with pytest.raises(dkim_keys.KeyError_):
            dkim_keys.generate("lab.example", "bad selector;", generated_by="a")


def test_authentication_summary_roundtrip_is_json_serialisable() -> None:
    analysis = analyze(load("all_pass"), SpamPolicy())
    json.dumps(analysis.auth.model_dump(mode="json"))
    json.dumps(analysis.evidence.model_dump(mode="json"))
    assert authentication(analysis.evidence, from_header="a@example.test").spf.identity == "example.test"
