"""Priority is not the risk level (ТЗ 1.0.3 §18).

The tests below are the specification's own examples plus the properties that keep the bands
usable. The last group exists because of a defect found on a live stand: 16 of 19 incidents came
back as P1, which is a queue with no priority at all.
"""

from __future__ import annotations

from msp_api.services.triage import (
    THRESHOLDS,
    WEIGHTS,
    IncidentContext,
    Priority,
    score_priority,
)
from msp_contracts import RiskLevel


def _context(**kwargs) -> IncidentContext:  # type: ignore[no-untyped-def]
    return IncidentContext(**kwargs)


class TestPriorityIsNotRisk:
    def test_malicious_to_one_recipient_ranks_below_a_campaign(self) -> None:
        lone = score_priority(_context(classification=RiskLevel.MALICIOUS, recipient_count=1))
        campaign = score_priority(
            _context(
                classification=RiskLevel.HIGH_RISK,
                recipient_count=8,
                protected_recipient=True,
                finance_recipient=True,
                signal_categories={"invoice_payment_fraud"},
                campaign_size=14,
                employee_reported=True,
            )
        )
        assert lone.priority is Priority.P3
        assert campaign.priority is Priority.P1
        assert campaign.score > lone.score

    def test_suspicious_to_a_vip_outranks_suspicious_to_anyone(self) -> None:
        vip = score_priority(
            _context(
                classification=RiskLevel.SUSPICIOUS,
                recipient_count=1,
                vip_recipient=True,
                signal_categories={"phishing_url"},
            )
        )
        ordinary = score_priority(_context(classification=RiskLevel.SUSPICIOUS, recipient_count=1))
        assert vip.priority is Priority.P2
        assert ordinary.priority is Priority.P4

    def test_every_factor_is_explained(self) -> None:
        """A priority nobody can argue with is a priority nobody trusts."""
        result = score_priority(
            _context(
                classification=RiskLevel.MALICIOUS,
                recipient_count=4,
                protected_recipient=True,
                signal_categories={"malicious_attachment"},
                campaign_size=6,
            )
        )
        assert result.factors
        assert all(":" in factor for factor in result.factors)
        # The points in the factors add up to the score, so the number is checkable by hand.
        total = sum(
            int(factor.split(":")[1].split()[0])
            for factor in result.factors
            if factor.split(":")[1].split()[0].isdigit()
        )
        assert total == result.score


class TestNoDoubleCounting:
    def test_one_recipient_is_scored_once(self) -> None:
        """A protected mailbox in finance is one property, not two.

        Scoring `protected_recipient` and `finance_recipient` together counted the same person
        twice and put practically every finance incident into P1.
        """
        both = score_priority(
            _context(
                classification=RiskLevel.SUSPICIOUS,
                recipient_count=1,
                protected_recipient=True,
                finance_recipient=True,
            )
        )
        recipient_factors = [
            factor for factor in both.factors if factor.startswith(("vip", "protected", "finance"))
        ]
        assert len(recipient_factors) == 1, recipient_factors
        assert both.score == WEIGHTS["verdict_suspicious"] + WEIGHTS["protected_finance_recipient"]

    def test_the_strongest_recipient_description_wins(self) -> None:
        vip_finance = score_priority(_context(recipient_count=1, vip_recipient=True, finance_recipient=True))
        protected_finance = score_priority(
            _context(recipient_count=1, protected_recipient=True, finance_recipient=True)
        )
        plain_protected = score_priority(_context(recipient_count=1, protected_recipient=True))
        assert vip_finance.score > protected_finance.score > plain_protected.score

    def test_reporting_cannot_carry_a_band_on_its_own(self) -> None:
        """Reporting says who noticed, not how bad it is, and is nearly always present."""
        reported = score_priority(_context(recipient_count=1, employee_reported=True))
        assert reported.priority is Priority.P4
        assert WEIGHTS["employee_report"] < THRESHOLDS[-1][0]


class TestP1NeedsTwoAxes:
    """§18 derives priority from consequence **and** spread."""

    def test_single_recipient_reversible_case_is_downgraded_with_a_reason(self) -> None:
        result = score_priority(
            _context(
                classification=RiskLevel.MALICIOUS,
                recipient_count=1,
                protected_recipient=True,
                finance_recipient=True,
                signal_categories={"invoice_payment_fraud"},
                employee_reported=True,
            )
        )
        assert result.score >= 70, "по сумме баллов это P1"
        assert result.priority is Priority.P2, "но охвата нет, а последствие обратимо"
        assert any("single_recipient_reversible" in factor for factor in result.factors), (
            "понижение обязано быть объяснено в факторах"
        )

    def test_malware_to_one_recipient_stays_p1(self) -> None:
        """An attachment cannot be un-run once it is opened, so spread is not required."""
        result = score_priority(
            _context(
                classification=RiskLevel.MALICIOUS,
                recipient_count=1,
                protected_recipient=True,
                finance_recipient=True,
                signal_categories={"malicious_attachment"},
                employee_reported=True,
            )
        )
        assert result.priority is Priority.P1

    def test_a_targeted_attack_on_a_vip_stays_p1(self) -> None:
        result = score_priority(
            _context(
                classification=RiskLevel.MALICIOUS,
                recipient_count=1,
                vip_recipient=True,
                finance_recipient=True,
                signal_categories={"invoice_payment_fraud"},
            )
        )
        assert result.priority is Priority.P1

    def test_spread_alone_also_reaches_p1(self) -> None:
        result = score_priority(
            _context(
                classification=RiskLevel.MALICIOUS,
                recipient_count=12,
                protected_recipient=True,
                finance_recipient=True,
                campaign_size=20,
            )
        )
        assert result.priority is Priority.P1

    def test_the_bands_separate_on_a_realistic_mix(self) -> None:
        """A queue where everything is P1 has no priority — that is the defect this prevents.

        The mix below is what a security mailbox actually delivers: mostly reported messages
        aimed at the people attackers aim at.
        """
        mix = [
            _context(
                classification=RiskLevel.MALICIOUS,
                recipient_count=1,
                protected_recipient=True,
                finance_recipient=True,
                signal_categories={"invoice_payment_fraud"},
                employee_reported=True,
            ),
            _context(
                classification=RiskLevel.MALICIOUS,
                recipient_count=1,
                protected_recipient=True,
                finance_recipient=True,
                signal_categories={"phishing_url"},
                employee_reported=True,
            ),
            _context(
                classification=RiskLevel.HIGH_RISK,
                recipient_count=1,
                protected_recipient=True,
                finance_recipient=True,
                employee_reported=True,
            ),
            _context(
                classification=RiskLevel.MALICIOUS,
                recipient_count=6,
                protected_recipient=True,
                finance_recipient=True,
                signal_categories={"invoice_payment_fraud"},
                campaign_size=11,
                employee_reported=True,
            ),
            _context(
                classification=RiskLevel.SUSPICIOUS,
                recipient_count=1,
                employee_reported=True,
            ),
        ]
        bands = [score_priority(context).priority for context in mix]
        assert bands.count(Priority.P1) == 1, bands
        assert len(set(bands)) >= 3, f"полосы должны различаться: {bands}"
