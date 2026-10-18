"""Нормализация SPF/DKIM/DMARC/ARC по записям настоящего Rspamd 3.12.1 (ТЗ 1.2 §8–§12, §38).

Записи в ``tests/fixtures/rspamd`` сняты со стенда: это ответ самого сканера, а не наша
реконструкция. Если Rspamd сменит имена символов, тесты упадут здесь, а не молча в эксплуатации.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from msp_antispam.analysis import analyze
from msp_antispam.auth import aligned, authentication, domain_of, from_domain_of
from msp_antispam.model import (
    ArcResult,
    DkimResult,
    DmarcPolicy,
    DmarcResult,
    SpfResult,
    SuggestedDisposition,
)
from msp_antispam.policy import SpamPolicy
from msp_antispam.rspamd_result import parse_scan

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "rspamd"
RECEIVED = ["from mail.example.test (unknown [10.77.0.150]) by gw.lab.example with ESMTP id X"]


def load(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def auth_of(name: str):  # type: ignore[no-untyped-def]
    record = load(name)
    evidence = parse_scan(record)
    return authentication(evidence, from_header=record.get("header_from"), helo="mail.example.test")


class TestSpf:
    def test_pass(self) -> None:
        assert auth_of("all_pass").spf.result is SpfResult.PASS

    def test_fail_does_not_by_itself_reject_anything(self) -> None:
        analysis = analyze(load("spf_fail_dkim_pass"), SpamPolicy(), received_headers=RECEIVED)
        assert analysis.auth.spf.result is SpfResult.FAIL
        assert analysis.applied_action.value == "OBSERVE_ONLY"

    def test_softfail(self) -> None:
        assert auth_of("spf_softfail_quarantine").spf.result is SpfResult.SOFTFAIL

    def test_none_when_no_record(self) -> None:
        assert auth_of("no_records_at_all").spf.result is SpfResult.NONE

    def test_the_identity_is_the_envelope_domain(self) -> None:
        spf = auth_of("all_pass").spf
        assert (spf.identity, spf.identity_kind) == ("example.test", "MAIL_FROM")

    def test_a_null_sender_is_evaluated_by_helo(self) -> None:
        record = load("null_sender_helo_spf")
        record["from"] = "unknown"
        evidence = parse_scan(record)
        spf = authentication(evidence, from_header=record["header_from"], helo="mail.example.test").spf
        assert (spf.identity, spf.identity_kind) == ("mail.example.test", "HELO")

    def test_a_dns_failure_is_an_error_not_a_fail(self) -> None:
        record = load("all_pass")
        record["symbols"] = [s for s in record["symbols"] if s["name"] != "R_SPF_ALLOW"]
        record["symbols"].append({"name": "R_SPF_DNSFAIL", "score": 0.0, "options": ["dns query timed out"]})
        auth = authentication(parse_scan(record), from_header="a@example.test")
        assert auth.spf.result is SpfResult.TEMPERROR
        assert auth.spf.error_class == "DNS_TEMPORARY"
        assert "SPF_TEMPERROR" in auth.incomplete_reasons

    def test_permerror(self) -> None:
        record = load("all_pass")
        record["symbols"] = [{"name": "R_SPF_PERMFAIL", "score": 0.0, "options": ["too many DNS lookups"]}]
        auth = authentication(parse_scan(record), from_header="a@example.test")
        assert auth.spf.result is SpfResult.PERMERROR
        assert auth.spf.error_class == "RECORD_INVALID_OR_LIMIT"


class TestDkim:
    def test_pass_and_alignment(self) -> None:
        dkim = auth_of("all_pass").dkim
        assert dkim.result is DkimResult.PASS
        assert [(s.domain, s.selector, s.aligned) for s in dkim.signatures] == [("example.test", "s1", True)]

    def test_a_tampered_body_fails(self) -> None:
        dkim = auth_of("dkim_body_tampered").dkim
        assert dkim.result is DkimResult.FAIL
        assert dkim.signatures[0].key_state == "SIGNATURE_MISMATCH"

    def test_absent_signature_is_none(self) -> None:
        assert auth_of("dmarc_reject_fail").dkim.result is DkimResult.NONE

    def test_two_signatures_one_valid_aligned_the_valid_one_wins(self) -> None:
        dkim = auth_of("dkim_two_signatures_one_bad").dkim
        assert dkim.result is DkimResult.PASS
        assert {(s.domain, s.aligned) for s in dkim.signatures} == {
            ("example.test", True),
            ("other.test", False),
        }

    def test_a_failed_signature_does_not_cancel_a_valid_aligned_one(self) -> None:
        record = load("all_pass")
        record["symbols"] = [
            {"name": "R_DKIM_ALLOW", "score": -0.2, "options": ["example.test:s=s1"]},
            {"name": "R_DKIM_REJECT", "score": 0.0, "options": ["evil.test:s=x"]},
            {"name": "DKIM_TRACE", "score": 0.0, "options": ["example.test:+", "evil.test:-"]},
        ]
        dkim = authentication(parse_scan(record), from_header="a@example.test").dkim
        assert dkim.result is DkimResult.PASS
        by_domain = {s.domain: s for s in dkim.signatures}
        assert by_domain["example.test"].result is DkimResult.PASS
        assert by_domain["evil.test"].result is DkimResult.FAIL

    def test_weak_or_unsupported_is_evidence_not_pass(self) -> None:
        record = load("all_pass")
        record["symbols"] = [
            {"name": "R_DKIM_PERMFAIL", "score": 0.0, "options": ["example.test:s=s1 unsupported algorithm"]}
        ]
        dkim = authentication(parse_scan(record), from_header="a@example.test").dkim
        assert dkim.result is DkimResult.PERMERROR
        assert dkim.signatures[0].unsupported_or_weak is True
        assert dkim.signatures[0].result is not DkimResult.PASS

    def test_a_dns_failure_is_temperror(self) -> None:
        record = load("all_pass")
        record["symbols"] = [{"name": "R_DKIM_TEMPFAIL", "score": 0.0, "options": ["example.test:s=s1"]}]
        auth = authentication(parse_scan(record), from_header="a@example.test")
        assert auth.dkim.result is DkimResult.TEMPERROR
        assert "DKIM_TEMPERROR" in auth.incomplete_reasons

    def test_a_valid_signature_of_a_foreign_domain_is_not_aligned(self) -> None:
        dkim = auth_of("dkim_two_signatures_one_bad").dkim
        foreign = next(s for s in dkim.signatures if s.domain == "other.test")
        assert foreign.result is DkimResult.PASS and foreign.aligned is False


class TestDmarc:
    def test_pass_with_policy(self) -> None:
        dmarc = auth_of("all_pass").dmarc
        assert dmarc.result is DmarcResult.PASS
        assert dmarc.policy is DmarcPolicy.REJECT
        assert dmarc.suggested_disposition is SuggestedDisposition.NONE

    def test_reject_policy_failure_only_suggests_reject(self) -> None:
        analysis = analyze(load("dmarc_reject_fail"), SpamPolicy(), received_headers=RECEIVED)
        dmarc = analysis.auth.dmarc
        assert dmarc.result is DmarcResult.FAIL
        assert dmarc.suggested_disposition is SuggestedDisposition.REJECT
        assert analysis.applied_action.value == "OBSERVE_ONLY"

    def test_quarantine_policy(self) -> None:
        dmarc = auth_of("spf_softfail_quarantine").dmarc
        assert dmarc.result is DmarcResult.FAIL
        assert dmarc.suggested_disposition is SuggestedDisposition.QUARANTINE

    def test_p_none_failure_suggests_nothing(self) -> None:
        dmarc = auth_of("dmarc_none_policy_fail").dmarc
        assert dmarc.result is DmarcResult.FAIL
        assert dmarc.policy is DmarcPolicy.NONE
        assert dmarc.suggested_disposition is SuggestedDisposition.NONE

    def test_no_record(self) -> None:
        assert auth_of("no_dmarc_record").dmarc.result is DmarcResult.NONE

    def test_dns_failure_is_temperror(self) -> None:
        auth = auth_of("dns_servfail")
        assert auth.dmarc.result is DmarcResult.TEMPERROR
        assert "DMARC_TEMPERROR" in auth.incomplete_reasons

    def test_the_policy_domain_does_not_swallow_the_reason(self) -> None:
        dmarc = auth_of("dmarc_reject_fail").dmarc
        assert dmarc.policy_domain == "example.test"
        assert "SPF" in dmarc.policy_meta.get("reason", "")

    def test_spf_pass_with_dkim_fail_is_a_dmarc_pass_through_spf_alignment(self) -> None:
        auth = auth_of("dkim_body_tampered")
        assert auth.dmarc.result is DmarcResult.PASS
        assert auth.dmarc.spf_aligned is True
        assert auth.dmarc.dkim_aligned is False


class TestArc:
    def test_absent(self) -> None:
        assert auth_of("all_pass").arc.result is ArcResult.NONE

    @pytest.mark.parametrize(
        ("symbol", "expected"),
        [
            ("ARC_ALLOW", ArcResult.PASS),
            ("ARC_REJECT", ArcResult.FAIL),
            ("ARC_INVALID", ArcResult.FAIL),
            ("ARC_DNSFAIL", ArcResult.UNKNOWN),
            ("ARC_NA", ArcResult.NONE),
        ],
    )
    def test_results(self, symbol: str, expected: ArcResult) -> None:
        record = load("all_pass")
        record["symbols"] = [{"name": symbol, "score": 0.0, "options": ["lists.example:arc"]}]
        assert authentication(parse_scan(record), from_header="a@example.test").arc.result is expected

    def test_arc_does_not_override_dmarc(self) -> None:
        record = load("dmarc_reject_fail")
        record["symbols"].append({"name": "ARC_ALLOW", "score": -1.0, "options": ["lists.example:arc"]})
        auth = authentication(parse_scan(record), from_header="a@example.test")
        assert auth.arc.result is ArcResult.PASS
        assert auth.dmarc.result is DmarcResult.FAIL


class TestHelpers:
    def test_alignment_relaxed_and_strict(self) -> None:
        assert aligned("mail.example.test", "example.test")
        assert not aligned("mail.example.test", "example.test", strict=True)
        assert not aligned("example.test", "other.test")
        assert not aligned("", "example.test")

    def test_domain_extraction(self) -> None:
        assert domain_of("Иван <Ivan@Example.Test>") == "example.test"
        assert domain_of("") == ""

    def test_an_ambiguous_from_has_no_domain(self) -> None:
        assert from_domain_of(["a@one.test", "b@two.test"]) == ""
        assert from_domain_of(["a@one.test", "b@one.test"]) == "one.test"

    def test_missing_checks_are_incomplete_not_failures(self) -> None:
        record = load("all_pass")
        record["symbols"] = [{"name": "MIME_GOOD", "score": 0.0}]
        auth = authentication(parse_scan(record), from_header="a@example.test")
        assert auth.incomplete and "AUTH_CHECKS_NOT_RUN" in auth.incomplete_reasons
        assert auth.spf.result is SpfResult.NONE and auth.dmarc.result is DmarcResult.NONE
