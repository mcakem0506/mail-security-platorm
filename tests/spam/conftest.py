"""Фикстуры стенда MSP 1.2. Стенд поднимается один раз на модуль; сценарии изолируются сбросом
DNS, двойников и журнала результатов."""

from __future__ import annotations

import pytest

from tests.gateway.harness import LAB_RECIPIENTS, docker_available

from .harness import SpamStack, milter_spec


def pytest_collection_modifyitems(config, items):  # type: ignore[no-untyped-def]
    if docker_available():
        return
    for item in items:
        item.add_marker(pytest.mark.xfail(reason="Docker недоступен", run=False, strict=True))


@pytest.fixture(scope="module")
def spam(tmp_path_factory):  # type: ignore[no-untyped-def]
    stack = SpamStack(tmp_path_factory.mktemp("spamlab"))
    try:
        stack.up(milter_spec(), LAB_RECIPIENTS)
        yield stack
    finally:
        stack.down()


@pytest.fixture
def clean_spam(spam):  # type: ignore[no-untyped-def]
    for control in (spam.exchange1, spam.exchange2, spam.sink):
        control.reset()
    spam.dns.reset()
    return spam
