"""Сценарии Exchange не меняют Exchange (ТЗ 1.1 §20, §21).

«Никаких автоматических production-изменений без оператора» — требование, которое нельзя
проверить, запустив сценарий: настоящего Exchange в тестах нет. Зато можно проверить то, из чего
оно следует: в исполняемой части сценария нет ни одного командлета, который меняет состояние.
Команды изменения допустимы только внутри here-строк, то есть как текст плана, который печатается
оператору.

Проверка читает исходник, а не выполняет его, поэтому она не зависит от наличия PowerShell.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DIRECTORY = Path(__file__).resolve().parents[2] / "deployment" / "exchange"
SCRIPTS = sorted(DIRECTORY.glob("*.ps1"))

#: Глаголы PowerShell, меняющие состояние. ``Set-StrictMode`` — настройка самого сценария.
MUTATING = re.compile(
    r"\b(New|Set|Remove|Add|Enable|Disable|Install|Uninstall|Start|Stop|Restart|Clear|Import|Move|"
    r"Rename|Grant|Revoke|Update|Register|Unregister|Reset|Resume|Suspend|Mount|Dismount|Invoke|"
    r"Send|Publish|Sync|Write-ADPermission)-[A-Za-z]+\b"
)
ALLOWED = {"Set-StrictMode"}
DANGEROUS = re.compile(
    r"(?i)\b(Invoke-Expression|iex|Invoke-Command|Start-Process|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b"
)

HERE_STRING = re.compile(r"@(['\"])\s*\n.*?\n\1@", re.DOTALL)
BLOCK_COMMENT = re.compile(r"<#.*?#>", re.DOTALL)
LINE_COMMENT = re.compile(r"(?m)^\s*#.*$")


def executable_part(text: str) -> str:
    text = BLOCK_COMMENT.sub("", text)
    text = HERE_STRING.sub("", text)
    return LINE_COMMENT.sub("", text)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def test_the_pack_is_complete() -> None:
    names = {p.name for p in DIRECTORY.iterdir()}
    assert {
        "inspect.ps1",
        "plan-receive-connector.ps1",
        "plan-send-connector.ps1",
        "verify-connectors.ps1",
        "rollback-plan.md",
    } <= names


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
class TestEveryScript:
    def test_no_state_changing_cmdlet_outside_plan_text(self, script: Path) -> None:
        code = executable_part(read(script))
        found = {m.group(0) for m in MUTATING.finditer(code)} - ALLOWED
        assert not found, f"{script.name}: изменяющие командлеты в исполняемом коде: {sorted(found)}"

    def test_no_dynamic_or_remote_execution(self, script: Path) -> None:
        assert not DANGEROUS.search(executable_part(read(script)))

    def test_carries_the_production_warning(self, script: Path) -> None:
        assert "MSP 1.1 IS NOT APPROVED FOR PRODUCTION MX CUTOVER" in read(script)

    def test_has_no_apply_switch(self, script: Path) -> None:
        """Применять сценарий не умеет по построению: ключа, который это включает, нет."""
        assert not re.search(r"(?i)\[switch\]\s*\$(Apply|Execute|Force|Commit|Run)\b", read(script))

    def test_has_a_bom_so_powershell_5_reads_utf8(self, script: Path) -> None:
        assert script.read_bytes().startswith(b"\xef\xbb\xbf")

    def test_stops_on_errors(self, script: Path) -> None:
        assert '$ErrorActionPreference = "Stop"' in read(script)


def test_only_the_inventory_writes_a_file() -> None:
    writers = [p.name for p in SCRIPTS if re.search(r"\bOut-File\b", executable_part(read(p)))]
    assert writers == ["inspect.ps1"]


def test_the_checker_itself_catches_a_violation() -> None:
    """Проверка, которая не умеет падать, ничего не доказывает."""
    bad = 'param()\nNew-ReceiveConnector -Name x\n$plan = @"\nRemove-ReceiveConnector\n"@\n'
    code = executable_part(bad)
    assert {m.group(0) for m in MUTATING.finditer(code)} == {"New-ReceiveConnector"}
    assert not MUTATING.search(executable_part('param()\n$plan = @"\nNew-ReceiveConnector\n"@\n'))


class TestPlanScriptsValidateInput:
    def test_the_wide_range_guard_is_present(self) -> None:
        text = read(DIRECTORY / "plan-receive-connector.ps1")
        assert "-AllowWideRange" in text
        assert "matches every address" in text

    def test_wildcard_address_space_is_refused_by_default(self) -> None:
        text = read(DIRECTORY / "plan-send-connector.ps1")
        assert "AllowWildcardAddressSpace" in text
        assert "disabled by default in MSP 1.1" in text

    def test_the_receive_plan_never_grants_relay(self) -> None:
        text = read(DIRECTORY / "plan-receive-connector.ps1")
        assert "Accept-Any-Recipient" in text  # упомянуто как запрещённое
        assert not re.search(r"(?i)Add-ADPermission", executable_part(text))

    def test_the_rollback_plan_says_dns_is_untouched(self) -> None:
        text = (DIRECTORY / "rollback-plan.md").read_text(encoding="utf-8")
        assert "не меняет DNS" in text
        assert "MSP 1.1 IS NOT APPROVED FOR PRODUCTION MX CUTOVER" in text
