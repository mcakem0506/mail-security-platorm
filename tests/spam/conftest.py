"""Фикстуры стенда MSP 1.2.

Стенд поднимается один раз на весь прогон: запуск Postfix, Rspamd и DNS занимает минуты. Тесты
изолируются сбросом DNS и двойников; тесты, меняющие конфигурацию сканера или узла, возвращают
её обратно сами.

Для разработки: ``MSP_SPAM_REUSE=<каталог со state.json>`` подключает тесты к уже работающему
стенду и не гасит его по окончании.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from tests.gateway.harness import LAB_RECIPIENTS, docker_available

from .harness import SpamStack, milter_spec, node_config


def pytest_collection_modifyitems(config, items):  # type: ignore[no-untyped-def]
    if docker_available():
        return
    for item in items:
        item.add_marker(pytest.mark.xfail(reason="Docker недоступен", run=False, strict=True))


def _attach(directory: Path) -> SpamStack:
    state = json.loads((directory / "state.json").read_text(encoding="utf-8"))
    stack = SpamStack.__new__(SpamStack)
    stack.project = state["project"]
    stack.ports = state["ports"]
    stack.workdir = directory
    stack.panel_port = None
    stack.panel_token = ""
    stack.node_cfg = node_config()
    stack._bundle_counter = int(time.time())  # версии пакетов растут: узел не принимает старые
    return stack


@pytest.fixture(scope="session")
def spam(tmp_path_factory):  # type: ignore[no-untyped-def]
    reuse = os.environ.get("MSP_SPAM_REUSE")
    if reuse:
        yield _attach(Path(reuse))
        return
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
    spam.clear_scans()
    return spam
