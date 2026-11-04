"""Порты стенда шлюза не повторяются (регрессия: «port is already allocated» в CI)."""

from __future__ import annotations

from tests.gateway.harness import _free_ports


def test_the_ports_of_one_stand_are_always_distinct() -> None:
    for _ in range(300):
        ports = _free_ports(6)
        assert len(set(ports)) == 6, ports


def test_every_port_is_a_valid_unprivileged_number() -> None:
    assert all(1024 <= port <= 65535 for port in _free_ports(6))
