"""Состояние узла: слив, шлюз получателей, давление, свежесть справочника (ТЗ 1.1 §16, §25, §26)."""

from __future__ import annotations

import pytest
from msp_gateway.state import (
    DRAIN_RULE,
    STALE_RULE,
    PressureState,
    RecipientFreshness,
    classify_freshness,
    classify_pressure,
    is_draining,
    set_drain,
    set_recipient_gate,
)

GB = 1024**3
THRESHOLDS = {
    "disk_pressure_free_bytes": 5 * GB,
    "disk_critical_free_bytes": 1 * GB,
    "queue_pressure_messages": 1000,
    "queue_critical_messages": 5000,
}


def pressure(free: int = 50 * GB, queue: int = 0, draining: bool = False) -> PressureState:
    return classify_pressure(free_bytes=free, queue_messages=queue, draining=draining, **THRESHOLDS)


class TestPressure:
    def test_healthy_node_is_normal(self) -> None:
        assert pressure() is PressureState.NORMAL

    @pytest.mark.parametrize(
        ("free", "queue", "expected"),
        [
            (5 * GB, 0, PressureState.PRESSURE),  # граница включается в худшее состояние
            (5 * GB + 1, 0, PressureState.NORMAL),
            (50 * GB, 1000, PressureState.PRESSURE),
            (50 * GB, 999, PressureState.NORMAL),
            (1 * GB, 0, PressureState.CRITICAL),
            (1 * GB + 1, 0, PressureState.PRESSURE),
            (50 * GB, 5000, PressureState.CRITICAL),
            (50 * GB, 4999, PressureState.PRESSURE),
        ],
    )
    def test_thresholds(self, free: int, queue: int, expected: PressureState) -> None:
        assert pressure(free, queue) is expected

    def test_the_worse_of_disk_and_queue_wins(self) -> None:
        assert pressure(free=4 * GB, queue=6000) is PressureState.CRITICAL
        assert pressure(free=500 * 1024**2, queue=1500) is PressureState.CRITICAL

    def test_drain_is_reported_as_drain_not_as_pressure(self) -> None:
        assert pressure(draining=True) is PressureState.DRAINING
        assert pressure(free=0, queue=10**6, draining=True) is PressureState.DRAINING


class TestFreshness:
    def classify(self, age: float | None) -> RecipientFreshness:
        return classify_freshness(age_seconds=age, fresh_seconds=3600, grace_seconds=7200)

    @pytest.mark.parametrize(
        ("age", "expected"),
        [
            (0, RecipientFreshness.FRESH),
            (3600, RecipientFreshness.FRESH),
            (3601, RecipientFreshness.STALE_GRACE),
            (10800, RecipientFreshness.STALE_GRACE),
            (10801, RecipientFreshness.STALE_HARD),
        ],
    )
    def test_boundaries(self, age: float, expected: RecipientFreshness) -> None:
        assert self.classify(age) is expected

    def test_a_directory_that_was_never_loaded_is_the_worst_state(self) -> None:
        assert self.classify(None) is RecipientFreshness.STALE_HARD


class TestDrainFile:
    def test_drain_writes_a_temporary_refusal_not_a_permanent_one(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        set_drain(True, state_dir=tmp_path, reload=False)
        text = (tmp_path / "drain.pcre").read_text(encoding="utf-8")
        assert text == DRAIN_RULE
        assert " 450 4." in text  # 4xx: отправитель повторит, письмо не теряется
        assert " 5" not in text.split("/./")[1][:5]

    def test_drain_roundtrip(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        assert is_draining(tmp_path) is False
        set_drain(True, state_dir=tmp_path, reload=False)
        assert is_draining(tmp_path) is True
        set_drain(False, state_dir=tmp_path, reload=False)
        assert is_draining(tmp_path) is False

    def test_no_temporary_file_is_left_behind(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        set_drain(True, state_dir=tmp_path, reload=False)
        assert [p.name for p in tmp_path.iterdir()] == ["drain.pcre"]

    def test_drain_creates_the_state_directory(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        target = tmp_path / "nested" / "state"
        set_drain(True, state_dir=target, reload=False)
        assert is_draining(target) is True


class TestRecipientGate:
    @pytest.mark.parametrize("freshness", [RecipientFreshness.FRESH, RecipientFreshness.STALE_GRACE])
    def test_usable_directory_does_not_close_the_gate(self, tmp_path, freshness) -> None:  # type: ignore[no-untyped-def]
        set_recipient_gate(freshness, state_dir=tmp_path, reload=False)
        assert (tmp_path / "recipient_gate.pcre").read_text(encoding="utf-8") == ""

    def test_hard_stale_directory_gives_a_temporary_refusal(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        set_recipient_gate(RecipientFreshness.STALE_HARD, state_dir=tmp_path, reload=False)
        text = (tmp_path / "recipient_gate.pcre").read_text(encoding="utf-8")
        assert text == STALE_RULE
        assert " 451 4." in text

    def test_gate_reopens_when_the_directory_becomes_fresh_again(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        set_recipient_gate(RecipientFreshness.STALE_HARD, state_dir=tmp_path, reload=False)
        set_recipient_gate(RecipientFreshness.FRESH, state_dir=tmp_path, reload=False)
        assert (tmp_path / "recipient_gate.pcre").read_text(encoding="utf-8") == ""

    def test_drain_and_gate_are_independent(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        set_drain(True, state_dir=tmp_path, reload=False)
        set_recipient_gate(RecipientFreshness.FRESH, state_dir=tmp_path, reload=False)
        assert is_draining(tmp_path) is True
