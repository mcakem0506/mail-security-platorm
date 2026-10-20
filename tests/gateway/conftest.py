"""Фикстуры стенда шлюза. Стенд поднимается один раз на модуль: запуск Postfix и сборка образа
занимают минуты, а сценарии друг от друга изолируются сбросом двойников и очередью."""

from __future__ import annotations

import pytest

from .harness import LAB_RECIPIENTS, Stack, docker_available, lab_spec


def pytest_collection_modifyitems(config, items):  # type: ignore[no-untyped-def]
    if docker_available():
        return
    # Без Docker эти тесты не могут сказать ничего. Падение здесь честнее пропуска: пропуск
    # в зелёном отчёте выглядит как проверенное.
    for item in items:
        item.add_marker(pytest.mark.xfail(reason="Docker недоступен", run=False, strict=True))


@pytest.fixture(scope="module")
def lab(tmp_path_factory):  # type: ignore[no-untyped-def]
    stack = Stack(tmp_path_factory.mktemp("gwlab"))
    try:
        stack.up(lab_spec(), LAB_RECIPIENTS)
        yield stack
    finally:
        stack.down()


@pytest.fixture
def clean(lab):  # type: ignore[no-untyped-def]
    """Чистое состояние перед сценарием: двойники в режиме приёма, их журналы пусты."""
    for control in (lab.exchange1, lab.exchange2, lab.sink):
        control.reset()
    return lab
