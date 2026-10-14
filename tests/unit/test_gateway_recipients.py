"""Справочник получателей (ТЗ 1.1 §16, §51): загрузка, защита от пустого и сокращённого, конфликты."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from msp_gateway.recipients import (
    MAX_ALIASES,
    LoadResult,
    RecipientEntry,
    RecipientKind,
    RecipientSourceError,
    Snapshot,
    UpdateRefused,
    accepted_addresses,
    load_csv,
    load_json,
    map_text,
    merge,
    validate_update,
)

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)


def snap(n: int, *, at: datetime = NOW) -> Snapshot:
    return Snapshot(tuple(RecipientEntry(f"u{i}@corp.example") for i in range(n)), generated_at=at)


class TestCsv:
    def test_basic_with_header_kinds_and_aliases(self) -> None:
        result = load_csv(
            "address,kind,aliases\n"
            "Ivan@Corp.Example,user,ivan.p@corp.example;i.petrov@corp.example\n"
            "sales@corp.example,shared_mailbox,\n"
        )
        assert result.rejected_count == 0
        first, second = result.entries
        assert first.address == "ivan@corp.example"
        assert first.aliases == ("i.petrov@corp.example", "ivan.p@corp.example")
        assert second.kind is RecipientKind.SHARED_MAILBOX

    def test_header_is_optional(self) -> None:
        assert load_csv("a@corp.example\n").entries[0].address == "a@corp.example"

    def test_blank_lines_are_skipped(self) -> None:
        assert len(load_csv("\n\na@corp.example\n,,\n").entries) == 1

    def test_bad_rows_are_rejected_individually_and_do_not_echo_the_value(self) -> None:
        result = load_csv(
            "good@corp.example\nnot-an-address\nev il@corp.example\nok@corp.example,WRONGKIND\n"
        )
        assert [e.address for e in result.entries] == ["good@corp.example"]
        assert result.rejected_count == 3
        assert all("evil" not in r and "not-an-address" not in r for r in result.rejected)

    @pytest.mark.parametrize(
        "hostile",
        [
            'a@corp.example"; rm -rf',
            "a@corp.example\x00",
            "a@b@corp.example",
            "a b@corp.example",
            "$(id)@corp.example",
        ],
    )
    def test_injection_attempts_never_reach_the_map(self, hostile: str) -> None:
        result = load_csv(f"{hostile}\n")
        assert result.entries == ()
        assert result.rejected_count == 1


class TestJson:
    def test_list_of_objects_and_strings(self) -> None:
        result = load_json(json.dumps([{"address": "a@corp.example", "kind": "GROUP"}, "b@corp.example"]))
        assert [e.address for e in result.entries] == ["a@corp.example", "b@corp.example"]
        assert result.entries[0].kind is RecipientKind.GROUP

    def test_wrapped_in_object(self) -> None:
        assert len(load_json(json.dumps({"recipients": ["a@corp.example"]})).entries) == 1

    @pytest.mark.parametrize("text", ["", "{bad", "42", '"x"', json.dumps({"other": []}), "null"])
    def test_source_that_is_not_a_list_is_refused_whole(self, text: str) -> None:
        with pytest.raises(RecipientSourceError):
            load_json(text)

    def test_wrong_types_inside_are_rejected_per_item(self) -> None:
        result = load_json(
            json.dumps(
                [
                    {"address": 5},
                    {"address": "a@corp.example", "aliases": "not-a-list"},
                    {"address": "b@corp.example", "aliases": [1]},
                    ["x"],
                    "ok@corp.example",
                ]
            )
        )
        assert [e.address for e in result.entries] == ["ok@corp.example"]
        assert result.rejected_count == 4

    def test_too_many_aliases(self) -> None:
        aliases = [f"a{i}@corp.example" for i in range(MAX_ALIASES + 1)]
        result = load_json(json.dumps([{"address": "m@corp.example", "aliases": aliases}]))
        assert result.entries == ()
        assert result.rejected_count == 1


class TestMerge:
    def test_duplicates_are_combined(self) -> None:
        merged, conflicts = merge(
            [
                RecipientEntry("a@corp.example", aliases=("x@corp.example",)),
                RecipientEntry("a@corp.example", aliases=("y@corp.example",)),
            ]
        )
        assert len(merged) == 1
        assert merged[0].aliases == ("x@corp.example", "y@corp.example")
        assert conflicts == ()

    def test_alias_equal_to_another_primary_is_a_conflict_and_is_dropped(self) -> None:
        merged, conflicts = merge(
            [RecipientEntry("a@corp.example", aliases=("b@corp.example",)), RecipientEntry("b@corp.example")]
        )
        assert len(conflicts) == 1
        assert all("b@corp.example" not in e.aliases for e in merged)

    def test_alias_claimed_by_two_owners_goes_to_the_first_only(self) -> None:
        merged, conflicts = merge(
            [
                RecipientEntry("a@corp.example", aliases=("shared@corp.example",)),
                RecipientEntry("b@corp.example", aliases=("shared@corp.example",)),
            ]
        )
        assert len(conflicts) == 1
        owners = [e.address for e in merged if "shared@corp.example" in e.aliases]
        assert owners == ["a@corp.example"]

    def test_result_is_ordered_regardless_of_input_order(self) -> None:
        a = [RecipientEntry("b@corp.example"), RecipientEntry("a@corp.example")]
        assert merge(a)[0] == merge(list(reversed(a)))[0]


class TestMap:
    def test_map_contains_addresses_and_aliases(self) -> None:
        entries = [RecipientEntry("a@corp.example", aliases=("z@corp.example",))]
        assert map_text(entries) == "a@corp.example OK\nz@corp.example OK\n"

    def test_map_is_deterministic(self) -> None:
        a = [RecipientEntry("b@corp.example"), RecipientEntry("a@corp.example")]
        assert map_text(a) == map_text(list(reversed(a)))
        assert accepted_addresses(a) == ["a@corp.example", "b@corp.example"]

    def test_render_uses_the_same_text(self) -> None:
        from msp_gateway.render import Recipient, render_relay_recipients

        entries = [RecipientEntry("a@corp.example", aliases=("z@corp.example",))]
        assert render_relay_recipients([Recipient("a@corp.example", ("z@corp.example",))]) == map_text(
            entries
        )


class TestUpdateGuard:
    def test_empty_update_is_refused_even_without_a_previous_directory(self) -> None:
        with pytest.raises(UpdateRefused, match="пуст"):
            validate_update(snap(0), None)

    def test_empty_update_never_replaces_a_working_directory(self) -> None:
        with pytest.raises(UpdateRefused):
            validate_update(snap(0), snap(100))

    def test_sharp_shrink_needs_confirmation(self) -> None:
        with pytest.raises(UpdateRefused, match="сократился"):
            validate_update(snap(40), snap(100))
        validate_update(snap(40), snap(100), confirm_shrink=True)

    def test_moderate_shrink_is_fine(self) -> None:
        validate_update(snap(60), snap(100))

    def test_growth_is_fine(self) -> None:
        validate_update(snap(500), snap(100))

    def test_first_directory_is_accepted(self) -> None:
        validate_update(snap(3), None)

    def test_older_directory_cannot_replace_a_newer_one(self) -> None:
        with pytest.raises(UpdateRefused, match="старше"):
            validate_update(snap(100, at=NOW - timedelta(hours=1)), snap(100))


class TestSnapshotMeta:
    def test_checksum_depends_on_content_not_on_time(self) -> None:
        assert snap(5).checksum == snap(5, at=NOW + timedelta(days=1)).checksum
        assert snap(5).checksum != snap(6).checksum

    def test_meta_has_the_freshness_fields(self) -> None:
        meta = snap(3).meta()
        assert meta["recipient_count"] == 3
        assert meta["generated_at"] == NOW.isoformat()
        assert set(meta) >= {"generated_at", "source_snapshot_at", "recipient_count", "checksum", "source"}


def test_load_result_counts_rejections() -> None:
    assert LoadResult((), ("a", "b")).rejected_count == 2
