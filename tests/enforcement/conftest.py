"""Фикстуры стенда принуждения MSP 1.3.

Стенд поднимается один раз на весь прогон: Postfix, Rspamd, служба принуждения, послеочередной шлюз и панель.
Панель — настоящее приложение с ключом подписи политики и ключом шифрования карантина; узлы забирают у неё
подписанную политику. Тесты изолируются сбросом DNS и двойников и возвращают общее состояние сами:
контроль после теста снова в наблюдении, выключатель снят.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest import mock

import pytest

from tests.gateway.harness import LAB_RECIPIENTS
from tests.gateway.panel import Panel
from tests.spam.harness import milter_spec

from .harness import (
    POLICY_TOKEN,
    QUARANTINE_KEY,
    SIGNING_KEY,
    EnforcementStack,
    Person,
    after_queue_spec,
)


@pytest.fixture(scope="session")
def enf(tmp_path_factory):  # type: ignore[no-untyped-def]
    from msp_api.config import get_settings

    panel = Panel(tmp_path_factory.mktemp("enfpanel"))
    panel.start()
    settings = get_settings()
    patches = [
        mock.patch.object(settings, "enforcement_policy_signing_key", SIGNING_KEY),
        mock.patch.object(settings, "quarantine_encryption_key", QUARANTINE_KEY),
        mock.patch.object(settings, "enforcement_policy_token", POLICY_TOKEN),
        mock.patch.object(settings, "enforcement_lab_mode", True),
    ]
    for patch in patches:
        patch.start()
    stack = EnforcementStack(
        tmp_path_factory.mktemp("enflab"), panel_port=panel.port, panel_token=panel.token
    )
    stack.panel = panel  # type: ignore[attr-defined]
    try:
        stack.write_enforcement_secrets()
        stack.up(milter_spec(afterqueue=after_queue_spec()), LAB_RECIPIENTS)
        yield stack
    finally:
        stack.down()
        for patch in patches:
            patch.stop()
        panel.close()


@pytest.fixture(scope="session")
def admin(enf):  # type: ignore[no-untyped-def]
    return Person(enf.panel, "admin@corp.example")


@pytest.fixture(scope="session")
def admin2(enf):  # type: ignore[no-untyped-def]
    return Person(enf.panel, "admin2@corp.example")


@pytest.fixture(scope="session")
def analyst(enf):  # type: ignore[no-untyped-def]
    return Person(enf.panel, "analyst@corp.example", role="SECURITY_ANALYST")


@pytest.fixture
def lab(enf):  # type: ignore[no-untyped-def]
    for control in (enf.exchange1, enf.exchange2, enf.sink):
        control.reset()
    enf.dns.reset()
    enf.clear_scans()
    return enf


def utcnow() -> datetime:
    return datetime.now(UTC)
