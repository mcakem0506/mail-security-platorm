"""Статистика пилота (MSP 1.3P, ТЗ §13): нулевой знаменатель, граница Вильсона, размер выборки."""

from __future__ import annotations

import pytest
from msp_enforcement import pilot_stats as ps


class TestNoDenominator:
    def test_rates_without_a_denominator_are_none_not_zero(self) -> None:
        assert ps.rate(0, 0) is None
        assert ps.per_1000(0, 0) is None
        assert ps.wilson_upper(0, 0) is None

    def test_zero_of_zero_reviewed_is_no_data_and_not_a_pass(self) -> None:
        result = ps.evaluate_reject_statistics(0, 0)
        assert result["status"] == ps.STAT_NO_DATA
        assert result["observed_fp_rate"] is None
        assert result["wilson_upper_95"] is None

    def test_an_empty_series_has_no_percentile(self) -> None:
        assert ps.percentile([], 0.95) is None


class TestWilson:
    def test_zero_failures_in_100_does_not_prove_a_rate_below_one_percent(self) -> None:
        upper = ps.wilson_upper(0, 100)
        assert upper is not None
        assert 0.036 < upper < 0.038

    def test_the_sample_needed_for_one_percent_with_no_failures_is_381(self) -> None:
        assert ps.required_sample_for_zero_failures(0.01) == 381

    def test_the_boundary_of_the_sample_is_exact(self) -> None:
        assert (ps.wilson_upper(0, 380) or 1) > 0.01
        assert (ps.wilson_upper(0, 381) or 1) <= 0.01

    @pytest.mark.parametrize("bad", [0.0, 1.0, -0.1, 2.0])
    def test_a_threshold_outside_zero_and_one_is_refused(self, bad: float) -> None:
        with pytest.raises(ValueError):
            ps.required_sample_for_zero_failures(bad)


class TestRejectStatistics:
    def test_a_small_clean_sample_is_below_the_minimum(self) -> None:
        assert ps.evaluate_reject_statistics(0, 99)["status"] == ps.STAT_FAIL

    def test_a_clean_minimum_sample_needs_a_written_risk_acceptance(self) -> None:
        result = ps.evaluate_reject_statistics(0, 100)
        assert result["status"] == ps.STAT_RISK_ACCEPT_REQUIRED
        assert result["observed_fp_rate"] == 0.0
        assert result["sample_for_zero_failures"] == 381

    def test_a_large_clean_sample_passes(self) -> None:
        assert ps.evaluate_reject_statistics(0, 400)["status"] == ps.STAT_PASS

    def test_an_observed_rate_above_the_threshold_fails_whatever_the_size(self) -> None:
        assert ps.evaluate_reject_statistics(5, 400)["status"] == ps.STAT_FAIL

    def test_the_observed_rate_and_the_upper_bound_are_reported_separately(self) -> None:
        result = ps.evaluate_reject_statistics(1, 500)
        assert result["observed_fp_rate"] == 0.002
        assert result["wilson_upper_95"] > result["observed_fp_rate"]
        assert result["sample_size"] == 500


def test_per_1000_and_percentile() -> None:
    assert ps.per_1000(3, 1500) == 2.0
    assert ps.percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 0.95) == 10.0
    assert ps.percentile([5.0], 0.5) == 5.0
