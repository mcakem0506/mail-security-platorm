"""Detection validation across the whole corpus (ТЗ 1.0.1 §9, §10, §11).

This is not a collection of per-fixture assertions — ``tests/unit/test_detection.py`` covers
those. It runs the entire corpus in one pass and asserts properties *of the corpus as a whole*,
which is what a pilot actually needs to know:

* nothing legitimate is flagged, and nothing malicious is missed;
* a message that could not be fully examined never comes out as LOW_RISK;
* the same gateway headers are evidence or a forgery depending only on the delivery chain;
* every rule that fires is attributable, and the noise is measurable.

The summary it prints is the same shape as the pilot report (ТЗ 1.0.1 §12), so a failing run
says which category regressed rather than only which assertion broke.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace

import pytest
from fixtures.corpus import CORPUS, by_category
from msp_contracts import (
    RISK_ORDER,
    GatewayState,
    RiskLevel,
    ScanCompleteness,
    Severity,
    TrustedMailHop,
)
from msp_detection import GatewayFindings, analyze
from msp_mail_gateway import (
    GatewayProviderConfig,
    GatewayRegistry,
    KsmgGatewayProvider,
    detect_conflicts,
)
from msp_mail_parser import parse_message
from msp_risk import RiskThresholds, employee_reasons, evaluate

#: Categories whose messages must not reach SUSPICIOUS or above on local analysis alone.
_BENIGN_CATEGORIES = {"legitimate"}
#: Categories where a verdict below SUSPICIOUS would be a miss.
_MALICIOUS_CATEGORIES = {"phishing", "bec", "impersonation"}


@dataclass
class Outcome:
    name: str
    category: str
    classification: RiskLevel
    score: int
    rules: list[str]
    facts: dict[str, object]
    missing_evidence: list[str]
    completeness: str
    employee_reason_count: int


def _ksmg_registry() -> GatewayRegistry:
    """The organisation's mail path, described the way a real deployment describes it.

    Two hops, not one. The gateway is what stamps the X-KSMG-* headers; the Exchange relay is
    what writes Authentication-Results. Declaring only the gateway would leave the relay's own
    authentication verdicts unverifiable on every message — which is exactly the false positive
    ТЗ 1.0.1 §4.3 warns about, in the opposite direction.
    """
    gateway_hop = TrustedMailHop(
        id="hop-ksmg",
        provider_id="ksmg",
        hostname="ksmg-01.corp.example",
        ip_networks=["10.20.0.0/24"],
        authserv_ids=["ksmg-01.corp.example"],
    )
    relay_hop = TrustedMailHop(
        id="hop-exchange",
        type="exchange_mailbox",
        hostname="mx.corp.example",
        authserv_ids=["mx.corp.example"],
    )
    return GatewayRegistry(
        [
            KsmgGatewayProvider(
                GatewayProviderConfig(
                    provider_id="ksmg",
                    provider_type="ksmg",
                    display_name="KSMG",
                    trusted_hops=[gateway_hop],
                )
            )
        ],
        extra_hops=[relay_hop],
    )


def _findings(registry: GatewayRegistry, parsed) -> GatewayFindings:  # type: ignore[no-untyped-def]
    analysis = registry.analyze_message(
        parsed.headers,
        received=parsed.received,
        authentication_results=parsed.authentication_results,
        internet_message_id=parsed.message_id,
    )
    verification = analysis.verification
    return GatewayFindings(
        evidence=list(analysis.evidence),
        state=analysis.state or GatewayState.NOT_PRESENT,
        trusted_auth_results=list(analysis.trusted_auth_results),
        untrusted_auth_results=list(analysis.untrusted_auth_results),
        auth_tampering_suspected=analysis.auth_tampering_suspected,
        unverified_gateways=list(analysis.untrusted_gateways),
        position_mismatches=list(verification.position_mismatches) if verification else [],
        chain_verified=bool(verification and verification.matches),
        conflicts=detect_conflicts(analysis.evidence, None),
    )


@pytest.fixture(scope="module")
def validation_context():  # type: ignore[no-untyped-def]
    """A context built without the database.

    The corpus is validated against detection logic, not against stored state, so building the
    context directly keeps this run independent of fixtures with a narrower scope.
    """
    from msp_contracts import ProtectedCategory
    from msp_detection import AnalysisContext, DirectoryUser, ProtectedIdentity

    return AnalysisContext(
        organization_id="validation",
        organization_name="Corp",
        corporate_domains=("corp.example",),
        trusted_infrastructure_domains=("mailer.trusted-service.example",),
        protected_identities=(
            ProtectedIdentity(
                "pi-ceo",
                "Иван Петров",
                "ceo@corp.example",
                (ProtectedCategory.EXECUTIVE,),
                risk_class="critical",
                vip=True,
            ),
            ProtectedIdentity(
                "pi-cfo",
                "Мария Кузнецова",
                "cfo@corp.example",
                (ProtectedCategory.FINANCE,),
                risk_class="high",
            ),
            ProtectedIdentity(
                "pi-hr",
                "Отдел кадров",
                "hr@corp.example",
                (ProtectedCategory.HR,),
                risk_class="high",
            ),
        ),
        directory_users=(
            DirectoryUser("ivanov@corp.example", "Сергей Иванов", department="ИТ"),
            DirectoryUser("buh@corp.example", "Бухгалтерия", department="Финансовый отдел"),
        ),
        recipient_department="Финансовый отдел",
    )


@pytest.fixture(scope="module")
def outcomes(validation_context, ruleset) -> list[Outcome]:  # type: ignore[no-untyped-def]
    """Every corpus message, analysed once with the gateway layer active."""
    registry = _ksmg_registry()
    thresholds = RiskThresholds()
    results: list[Outcome] = []
    for fixture in CORPUS:
        parsed = parse_message(fixture.raw)
        ctx = replace(validation_context, gateway_findings=_findings(registry, parsed))
        detection = analyze(parsed, ctx, ruleset=ruleset)
        verdict = evaluate(
            detection.signals,
            missing_evidence=detection.facts.missing_evidence,
            thresholds=thresholds,
            # Local analysis only: enrichment has not run, which is the state the add-in sees
            # first and the one where a premature "clean" would do the most harm.
            analysis_complete=False,
            content_encrypted=parsed.encrypted,
            unparseable=not parsed.parse_ok,
        )
        results.append(
            Outcome(
                name=fixture.name,
                category=fixture.category,
                classification=verdict.classification,
                score=verdict.score,
                rules=[s.rule_id for s in detection.signals if s.rule_id and not s.suppressed],
                facts=dict(detection.facts.truthy()),
                missing_evidence=list(verdict.missing_evidence),
                completeness=str(detection.facts.get("scan_completeness") or "COMPLETE"),
                employee_reason_count=len(employee_reasons(verdict)),
            )
        )
    return results


def _by_name(outcomes: list[Outcome]) -> dict[str, Outcome]:
    return {o.name: o for o in outcomes}


class TestCorpusShape:
    def test_every_category_is_populated(self) -> None:
        """A category with no fixtures validates nothing, so an empty one is a gap."""
        grouped = by_category()
        empty = [category for category, items in grouped.items() if not items]
        assert not empty, f"categories without fixtures: {empty}"

    def test_corpus_is_inert(self) -> None:
        """No fixture may reference a resolvable domain or carry real malware."""
        for fixture in CORPUS:
            lowered = fixture.raw.lower()
            for forbidden in (b"http://bit.ly", b".com/", b".ru/"):
                assert forbidden not in lowered, (
                    f"{fixture.name} references a live-looking domain: fixtures must stay inert"
                )


class TestNoFalsePositives:
    def test_legitimate_mail_is_not_flagged(self, outcomes: list[Outcome]) -> None:
        flagged = [
            (o.name, o.classification.value, o.rules)
            for o in outcomes
            if o.category in _BENIGN_CATEGORIES
            and RISK_ORDER[o.classification] >= RISK_ORDER[RiskLevel.SUSPICIOUS]
        ]
        assert not flagged, f"legitimate mail flagged: {flagged}"

    def test_spam_is_not_treated_as_an_attack(self, outcomes: list[Outcome]) -> None:
        """Unwanted bulk mail is not phishing; treating it as such trains people to ignore us."""
        over = [
            (o.name, o.classification.value)
            for o in outcomes
            if o.category == "spam" and RISK_ORDER[o.classification] >= RISK_ORDER[RiskLevel.HIGH_RISK]
        ]
        assert not over, f"spam escalated to an attack verdict: {over}"


class TestNoFalseNegatives:
    def test_attacks_are_detected(self, outcomes: list[Outcome]) -> None:
        missed = [
            (o.name, o.classification.value, o.score)
            for o in outcomes
            if o.category in _MALICIOUS_CATEGORIES
            and RISK_ORDER[o.classification] < RISK_ORDER[RiskLevel.SUSPICIOUS]
        ]
        assert not missed, f"attacks not detected: {missed}"

    def test_every_fixture_meets_its_declared_minimum(self, outcomes: list[Outcome]) -> None:
        by_name = _by_name(outcomes)
        shortfalls = []
        for fixture in CORPUS:
            outcome = by_name[fixture.name]
            expected = RiskLevel(fixture.expect_min_level)
            if fixture.requires_enrichment:
                # Without enrichment the honest answer is UNKNOWN, not the enriched verdict.
                continue
            if RISK_ORDER[outcome.classification] < RISK_ORDER[expected]:
                shortfalls.append((fixture.name, outcome.classification.value, expected.value))
        assert not shortfalls, f"verdict below the declared minimum: {shortfalls}"

    def test_declared_rules_fire(self, outcomes: list[Outcome]) -> None:
        by_name = _by_name(outcomes)
        missing = [
            (fixture.name, rule)
            for fixture in CORPUS
            for rule in fixture.expect_rules
            if rule not in by_name[fixture.name].rules
        ]
        assert not missing, f"expected rules did not fire: {missing}"

    def test_declared_facts_are_produced(self, outcomes: list[Outcome]) -> None:
        by_name = _by_name(outcomes)
        missing = [
            (fixture.name, fact)
            for fixture in CORPUS
            for fact in fixture.expect_facts
            if fact not in by_name[fixture.name].facts
        ]
        assert not missing, f"expected facts absent: {missing}"


class TestIncompleteAnalysisIsNeverClean:
    """ТЗ 1.0.1 §4.2 / ТЗ 49.9: absence of detection is not safety."""

    def test_an_unexamined_message_is_never_low_risk(self, outcomes: list[Outcome]) -> None:
        wrong = [
            (o.name, o.completeness)
            for o in outcomes
            if o.completeness != ScanCompleteness.COMPLETE.value and o.classification is RiskLevel.LOW_RISK
        ]
        assert not wrong, f"incompletely examined messages reported as LOW_RISK: {wrong}"

    def test_limits_are_recorded_as_missing_evidence(self, outcomes: list[Outcome]) -> None:
        for outcome in outcomes:
            if outcome.completeness != ScanCompleteness.COMPLETE.value:
                assert outcome.missing_evidence, (
                    f"{outcome.name}: a limit was hit but nothing was recorded as missing"
                )

    def test_local_analysis_alone_does_not_return_low_risk(self, outcomes: list[Outcome]) -> None:
        """Enrichment has not run for any of these, so LOW_RISK would overstate what is known."""
        premature = [o.name for o in outcomes if o.classification is RiskLevel.LOW_RISK]
        assert not premature, (
            "local analysis reported LOW_RISK before enrichment ran: "
            f"{premature}. UNKNOWN is the honest answer at this stage."
        )


class TestGatewayTrustAcrossTheCorpus:
    def test_forged_gateway_headers_do_not_lower_the_verdict(self, outcomes: list[Outcome]) -> None:
        forged = _by_name(outcomes)["23_spoofed_ksmg_header"]
        assert forged.facts.get("unverified_gateway_header") is True
        assert "upstream_malware_detection" not in forged.facts
        assert RISK_ORDER[forged.classification] >= RISK_ORDER[RiskLevel.HIGH_RISK], (
            "a forged clean gateway header must not rescue a BEC message"
        )

    def test_verified_detection_is_a_hard_signal(self, outcomes: list[Outcome]) -> None:
        detected = _by_name(outcomes)["22_gateway_malware_verified"]
        assert detected.facts.get("upstream_malware_detection") is True
        assert detected.classification is RiskLevel.MALICIOUS

    def test_verified_clean_verdict_changes_nothing(self, outcomes: list[Outcome]) -> None:
        clean = _by_name(outcomes)["21_gateway_clean_verified"]
        assert clean.facts.get("upstream_gateway_clean_observed") is True
        # A gateway that found nothing has not made the message safe, so the verdict stays
        # UNKNOWN until enrichment runs — not LOW_RISK.
        assert clean.classification is not RiskLevel.LOW_RISK

    def test_forged_authentication_results_are_not_read(self, outcomes: list[Outcome]) -> None:
        spoofed = _by_name(outcomes)["24_spoofed_authentication_results"]
        assert spoofed.facts.get("authentication_results_forged") is True
        assert "spf_pass" not in spoofed.facts
        assert "dmarc_pass" not in spoofed.facts


class TestExplainability:
    def test_every_flagged_message_has_an_employee_facing_reason(self, outcomes: list[Outcome]) -> None:
        """A verdict an employee cannot be given a reason for is not actionable (ТЗ 49.12)."""
        silent = [
            o.name
            for o in outcomes
            if RISK_ORDER[o.classification] >= RISK_ORDER[RiskLevel.SUSPICIOUS]
            and o.employee_reason_count == 0
        ]
        assert not silent, f"flagged with no employee-visible reason: {silent}"

    def test_every_signal_is_attributable_to_a_rule(self, outcomes: list[Outcome]) -> None:
        for outcome in outcomes:
            assert all(outcome.rules), f"{outcome.name}: a signal fired with no rule id"


def test_quality_summary(outcomes: list[Outcome], ruleset, capsys) -> None:  # type: ignore[no-untyped-def]
    """Print the metrics of ТЗ 1.0.1 §11 and assert the noise floor.

    The assertion is on rule *concentration*: if one rule fires on nearly every message it is
    either miscalibrated or meaningless, and in a pilot that is the failure that matters most,
    because it is the one that makes analysts stop reading.
    """
    counts = Counter(rule for outcome in outcomes for rule in set(outcome.rules))
    verdicts = Counter(o.classification.value for o in outcomes)
    categories = Counter(o.category for o in outcomes)

    lines = [
        "",
        f"Корпус: {len(outcomes)} писем в {len(categories)} категориях",
        f"Вердикты: {dict(verdicts)}",
        f"Неполный анализ: {sum(1 for o in outcomes if o.completeness != 'COMPLETE')}",
        f"Уникальных сработавших правил: {len(counts)}",
        "Топ правил: " + ", ".join(f"{rule}={count}" for rule, count in counts.most_common(10)),
    ]
    with capsys.disabled():
        print("\n".join(lines))

    # Info-severity rules are context, not detections: "sender not seen before" firing on every
    # message of a history-less corpus is correct, and weighting it as noise would be wrong.
    # The check is on rules that actually contribute to a verdict.
    contributing = {
        rule.id for rule in ruleset.rules if rule.severity is not Severity.INFO and rule.effective_weight > 0
    }
    total = len(outcomes)
    too_broad = [
        (rule, count) for rule, count in counts.items() if rule in contributing and count > total * 0.8
    ]
    assert not too_broad, (
        f"weighted rules firing on more than 80% of the corpus: {too_broad}. "
        "A rule that always fires carries no information."
    )
