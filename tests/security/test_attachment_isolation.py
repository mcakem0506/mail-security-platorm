"""Изоляция песочницы вложений (ТЗ 1.1 §55; ADR_ISOLATED_ATTACHMENT_ANALYSIS).

Те же проверки, что для декодера QR (``test_qr_isolation.py``), повторённые для архивов и PDF, а не
придуманные заново: модуль разбора не импортирует сетевое, не открывает файлов и не порождает
процессов, а пределы ставятся раньше, чем в процесс попадает первый байт чужого файла.

Проверка читает исходник и не зависит от платформы: на Windows пределы процесса не работают, но
свойство «лимиты выставляются первым действием» проверяется по тексту и там.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[2] / "packages" / "attachment-sandbox" / "msp_attachment_sandbox"
WORKERS = ("archive_worker", "pdf_worker", "limits")

FORBIDDEN_IMPORTS = frozenset(
    {
        "socket",
        "ssl",
        "http",
        "urllib",
        "requests",
        "httpx",
        "aiohttp",
        "ftplib",
        "smtplib",
        "telnetlib",
        "imaplib",
        "poplib",
        "xmlrpc",
        "subprocess",
        "multiprocessing",
        "ctypes",
        "pty",
        "shutil",
        "tempfile",
        "pathlib",
        "glob",
        "importlib",
    }
)
FORBIDDEN_CALLS = frozenset(
    {"open", "eval", "exec", "compile", "__import__", "system", "popen", "fork", "forkpty", "spawnv", "execv"}
)


def tree(name: str) -> ast.Module:
    return ast.parse((PACKAGE / f"{name}.py").read_text(encoding="utf-8"))


def imported(module: ast.Module) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module.split(".")[0])
    return found


def calls(module: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(module):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
    return names


def violations(module: ast.Module) -> tuple[set[str], set[str]]:
    return imported(module) & FORBIDDEN_IMPORTS, calls(module) & FORBIDDEN_CALLS


@pytest.mark.parametrize("name", WORKERS)
class TestWorkerModules:
    def test_no_network_or_process_or_filesystem_imports(self, name: str) -> None:
        bad_imports, _ = violations(tree(name))
        assert not bad_imports, f"{name}: запрещённые импорты {sorted(bad_imports)}"

    def test_no_file_access_or_dynamic_execution_calls(self, name: str) -> None:
        _, bad_calls = violations(tree(name))
        assert not bad_calls, f"{name}: запрещённые вызовы {sorted(bad_calls)}"


@pytest.mark.parametrize("name", ["archive_worker", "pdf_worker"])
class TestLimitsComeFirst:
    def main_body(self, name: str) -> list[ast.stmt]:
        for node in tree(name).body:
            if isinstance(node, ast.FunctionDef) and node.name == "main":
                return node.body
        raise AssertionError(f"{name}: нет функции main")

    def test_limits_are_applied_before_stdin_is_read(self, name: str) -> None:
        body = self.main_body(name)

        def position(predicate) -> int:  # type: ignore[no-untyped-def]
            for index, statement in enumerate(body):
                if any(predicate(node) for node in ast.walk(statement)):
                    return index
            return -1

        limits_at = position(
            lambda n: isinstance(n, ast.Call) and getattr(n.func, "id", "") == "apply_limits"
        )
        read_at = position(
            lambda n: isinstance(n, ast.Attribute) and n.attr == "stdin" and isinstance(n.value, ast.Name)
        )
        assert limits_at != -1, f"{name}: apply_limits() не вызывается"
        assert read_at != -1, f"{name}: stdin не читается"
        assert limits_at < read_at, f"{name}: чужие байты читаются раньше, чем ставятся пределы"

    def test_limits_are_applied_by_the_process_itself_not_the_parent(self, name: str) -> None:
        runner = (PACKAGE / "runner.py").read_text(encoding="utf-8")
        assert "preexec_fn" not in runner

    def test_input_size_is_capped_before_parsing(self, name: str) -> None:
        source = (PACKAGE / f"{name}.py").read_text(encoding="utf-8")
        assert "MAX_STDIN_BYTES" in source
        assert "MAX_INPUT_BYTES" in source


class TestServiceModule:
    def test_the_service_has_no_network_imports(self) -> None:
        bad_imports, _ = violations(tree("service"))
        assert not (
            bad_imports & {"socket", "ssl", "http", "urllib", "requests", "httpx", "ftplib", "smtplib"}
        )

    def test_the_service_runs_only_known_workers(self) -> None:
        source = (PACKAGE / "service.py").read_text(encoding="utf-8")
        assert "ALLOWED_WORKERS" in source
        assert "module not in ALLOWED_WORKERS" in source

    def test_job_ids_are_validated_before_use_in_paths(self) -> None:
        source = (PACKAGE / "service.py").read_text(encoding="utf-8")
        assert "_ID.match(job_id)" in source


class TestTheRunner:
    def test_it_never_uses_a_shell(self) -> None:
        source = (PACKAGE / "runner.py").read_text(encoding="utf-8")
        assert "shell=True" not in source

    def test_it_scrubs_the_environment(self) -> None:
        source = (PACKAGE / "runner.py").read_text(encoding="utf-8")
        assert "env=_environment()" in source


class TestTheCheckerCanFail:
    """Проверка, которая не умеет падать, ничего не доказывает."""

    @pytest.mark.parametrize(
        ("code", "expected_import", "expected_call"),
        [
            ("import socket\n", {"socket"}, set()),
            ("import subprocess\nsubprocess.run(['x'])\n", {"subprocess"}, set()),
            ("from urllib.request import urlopen\n", {"urllib"}, set()),
            ("data = open('/etc/passwd').read()\n", set(), {"open"}),
            ("import os\nos.system('x')\n", set(), {"system"}),
            ("exec('1')\n", set(), {"exec"}),
        ],
    )
    def test_hostile_code_is_caught(
        self, code: str, expected_import: set[str], expected_call: set[str]
    ) -> None:
        bad_imports, bad_calls = violations(ast.parse(code))
        assert bad_imports == expected_import
        assert bad_calls == expected_call

    def test_clean_code_passes(self) -> None:
        assert violations(ast.parse("import json\nimport sys\nprint(json.dumps({}))\n")) == (set(), set())
