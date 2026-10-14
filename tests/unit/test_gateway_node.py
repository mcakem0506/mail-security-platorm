"""Узловая часть шлюза: граница зависимостей, писатель журнала, пробы (ТЗ 1.1 §34, §47, §62).

Код узла работает в образе транспорта, где нет зависимостей продукта. Первая версия нарушила это
сразу: применение конфигурации через генератор тянуло pydantic, и узел падал при старте с
``ModuleNotFoundError``. Граница теперь проверяется тестом, а не соглашением.
"""

from __future__ import annotations

import ast
import base64
import io
import json
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from msp_gateway import journal_writer, probes

PACKAGE = Path(__file__).resolve().parents[2] / "packages" / "gateway" / "msp_gateway"

#: Модули, которые работают на узле и поэтому не вправе иметь зависимостей кроме стандартной
#: библиотеки. render и spec — на стороне центра управления, им pydantic можно.
NODE_MODULES = (
    "apply",
    "node",
    "probes",
    "journal_writer",
    "validation",
    "bundle",
    "state",
    "logparser",
    "metrics",
    "agent",
    "collector",
    "recipients",
)


def third_party_imports(module: str) -> set[str]:
    tree = ast.parse((PACKAGE / f"{module}.py").read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names - set(sys.stdlib_module_names)


class TestTheNodeNeedsOnlyTheStandardLibrary:
    @pytest.mark.parametrize("module", NODE_MODULES)
    def test_the_module_imports_nothing_outside_the_standard_library(self, module: str) -> None:
        assert third_party_imports(module) == set()

    @pytest.mark.parametrize("module", NODE_MODULES)
    def test_the_module_does_not_reach_into_the_generator(self, module: str) -> None:
        """Именно так граница и была нарушена: apply импортировал render, а тот — модель на pydantic."""
        tree = ast.parse((PACKAGE / f"{module}.py").read_text(encoding="utf-8"))
        local = {
            (node.module or "")
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.level == 1
        }
        assert not (local & {"render", "spec"}), f"{module} зависит от {local & {'render', 'spec'}}"

    def test_the_node_imports_work_with_the_heavy_dependencies_made_unavailable(self) -> None:
        """Не разбор исходника, а настоящий импорт в процессе, где pydantic недоступен."""
        code = (
            "import sys; sys.modules['pydantic'] = None; sys.modules['yaml'] = None; "
            "import msp_gateway.node, msp_gateway.journal_writer, msp_gateway.probes, "
            "msp_gateway.apply, msp_gateway.validation, msp_gateway.bundle, msp_gateway.state, "
            "msp_gateway.logparser, msp_gateway.metrics, msp_gateway.agent, "
            "msp_gateway.collector; print('ok')"
        )
        completed = subprocess.run(  # nosec B603 - фиксированная команда
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=False,
            env={"PYTHONPATH": str(PACKAGE.parent), "PATH": ""},
        )
        assert completed.returncode == 0, completed.stderr
        assert "ok" in completed.stdout

    def test_the_guard_would_notice_a_violation(self) -> None:
        """Проверка самой проверки: на модуле с pydantic она обязана вернуть непустое множество."""
        assert "pydantic" in third_party_imports("spec")


# ---------------------------------------------------------------------------------------------
# Писатель журнала
# ---------------------------------------------------------------------------------------------
class TestJournalWriter:
    def write(
        self, directory: Path, payload: bytes = b"Subject: x\r\n\r\nbody\r\n", **overrides: str
    ) -> str | None:
        arguments = {
            "queue_id": "A1B2C3D4E5",
            "recipient": "journal-in@journal.msp.invalid",
            "sender": "sender@partner.example",
            "client_address": "203.0.113.9",
            "client_helo": "mail.partner.example",
            "size": str(len(payload)),
        }
        arguments.update(overrides)
        return journal_writer.write_copy(io.BytesIO(payload), directory=str(directory), **arguments)

    def read(self, directory: Path, name: str) -> tuple[dict[str, object], bytes]:
        raw = (directory / "new" / name).read_bytes()
        first, _, rest = raw.partition(b"\n")
        assert first.startswith(journal_writer.MAGIC)
        return json.loads(base64.b64decode(first[len(journal_writer.MAGIC) :])), rest

    def test_a_copy_is_written_with_metadata_and_the_message_intact(self, tmp_path: Path) -> None:
        payload = b"Subject: x\r\n\r\nbody\r\n"
        name = self.write(tmp_path, payload)
        assert name
        meta, body = self.read(tmp_path, name)
        assert body == payload, "письмо в журнале побайтно равно принятому"
        assert meta["queue_id"] == "A1B2C3D4E5"
        assert meta["envelope_from"] == "sender@partner.example"
        assert meta["client_address"] == "203.0.113.9"

    def test_direction_comes_from_the_listener_not_from_the_sender(self, tmp_path: Path) -> None:
        """ТЗ §30: направление определяется слушателем. Домен отправителя им не управляет."""
        inbound = self.write(tmp_path, recipient="journal-in@journal.msp.invalid", sender="boss@corp.example")
        outbound = self.write(
            tmp_path, recipient="journal-out@journal.msp.invalid", sender="x@partner.example"
        )
        assert self.read(tmp_path, inbound)[0]["direction"] == "INBOUND"  # type: ignore[arg-type]
        assert self.read(tmp_path, outbound)[0]["direction"] == "OUTBOUND"  # type: ignore[arg-type]

    @pytest.mark.parametrize("recipient", ["", "someone@else.example", "journal-sideways@x"])
    def test_an_unrecognised_recipient_gives_unknown_direction(self, tmp_path: Path, recipient: str) -> None:
        name = self.write(tmp_path, recipient=recipient)
        assert self.read(tmp_path, name)[0]["direction"] == "UNKNOWN"  # type: ignore[arg-type]

    def test_the_first_line_belongs_to_us_whatever_the_message_contains(self, tmp_path: Path) -> None:
        """Метаданные не лежат в заголовке письма: отправитель может написать любой заголовок."""
        forged = b'X-MSP-Journal: {"direction": "OUTBOUND"}\r\nMSPJ1 forged\r\n\r\nbody'
        name = self.write(tmp_path, forged, recipient="journal-in@journal.msp.invalid")
        meta, body = self.read(tmp_path, name)  # type: ignore[arg-type]
        assert meta["direction"] == "INBOUND"
        assert body == forged

    def test_a_hostile_queue_id_is_dropped_not_trusted(self, tmp_path: Path) -> None:
        name = self.write(tmp_path, queue_id="../../etc/passwd")
        assert self.read(tmp_path, name)[0]["queue_id"] == ""  # type: ignore[arg-type]
        assert "passwd" not in name  # type: ignore[operator]

    def test_oversized_metadata_is_truncated(self, tmp_path: Path) -> None:
        name = self.write(tmp_path, sender="a" * 5000, client_helo="h" * 5000)
        meta, _ = self.read(tmp_path, name)  # type: ignore[arg-type]
        assert len(str(meta["envelope_from"])) <= 320
        assert len(str(meta["client_helo"])) <= 255

    def test_a_copy_is_never_visible_half_written(self, tmp_path: Path) -> None:
        """Запись во временный каталог и переименование: коллектор видит готовую копию или ничего."""

        class Boom(io.BytesIO):
            def read(self, size: int = -1) -> bytes:
                raise OSError("disk went away")

        assert (
            journal_writer.write_copy(
                Boom(),
                directory=str(tmp_path),
                queue_id="A1B2C3D4E5",
                recipient="journal-in@x",
                sender="",
                client_address="",
                client_helo="",
                size="",
            )
            is None
        )
        assert list((tmp_path / "new").iterdir()) == []

    def test_a_failure_to_write_is_counted_not_raised(self, tmp_path: Path) -> None:
        """Ненулевой код Postfix истолковал бы как отказ доставки копии и в конце срока вернул бы
        ОТПРАВИТЕЛЮ уведомление о недоставке — сбой тени стал бы виден людям снаружи."""
        blocker = tmp_path / "not-a-directory"
        blocker.write_text("x")
        assert self.write(blocker / "journal") is None
        assert (blocker.parent / "not-a-directory").is_file()

    def test_a_drop_is_counted_in_the_journal_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(journal_writer.shutil, "disk_usage", lambda _p: type("U", (), {"free": 1})())
        assert self.write(tmp_path) is None
        assert self.write(tmp_path) is None
        assert (tmp_path / ".dropped").stat().st_size == 2, "по байту на каждую потерю: счёт — размер файла"

    def test_low_free_space_stops_the_journal_before_it_eats_the_queue_volume(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            journal_writer.shutil,
            "disk_usage",
            lambda _p: type("U", (), {"free": journal_writer.MIN_FREE_BYTES - 1})(),
        )
        assert self.write(tmp_path) is None

    def test_the_entry_point_always_exits_successfully(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("MSP_JOURNAL_DIR", str(tmp_path / "missing" / "deeper"))
        monkeypatch.setattr(sys, "stdin", type("S", (), {"buffer": io.BytesIO(b"x")})())
        assert journal_writer.main(["only-one-argument"]) == 0

    def test_file_names_sort_in_arrival_order(self, tmp_path: Path) -> None:
        names = [self.write(tmp_path, queue_id=f"Q{i:09d}") for i in range(3)]
        assert names == sorted(names)  # type: ignore[type-var]


# ---------------------------------------------------------------------------------------------
# Пробы
# ---------------------------------------------------------------------------------------------
class TestProbes:
    @pytest.mark.parametrize(
        ("code", "state"),
        [
            (250, probes.ProbeState.ACCEPTED),
            (451, probes.ProbeState.DEFERRED),
            (550, probes.ProbeState.REJECTED),
            (554, probes.ProbeState.REJECTED),
        ],
    )
    def test_a_reply_code_maps_to_one_state(self, code: int, state: probes.ProbeState) -> None:
        assert probes._classify(code) is state

    def test_an_unreachable_listener_is_not_safe(self) -> None:
        """«Не дошли» — это «не проверено», а не «шлюз отказал». Записать его как прохождение нельзя."""
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        result = probes.open_relay_probe("127.0.0.1", port, timeout=1.0)
        assert result.state is probes.ProbeState.UNREACHABLE
        assert result.is_safe_for_relay_test is False

    def test_rejection_and_deferral_are_both_safe_for_the_relay_test(self) -> None:
        assert probes.ProbeResult(probes.ProbeState.REJECTED, "rcpt", 554).is_safe_for_relay_test
        assert probes.ProbeResult(probes.ProbeState.DEFERRED, "rcpt", 451).is_safe_for_relay_test

    def test_acceptance_is_never_safe(self) -> None:
        assert not probes.ProbeResult(probes.ProbeState.ACCEPTED, "rcpt", 250).is_safe_for_relay_test

    def test_the_probe_address_is_in_a_zone_that_never_resolves(self) -> None:
        assert probes.EXTERNAL_PROBE_ADDRESS.endswith(".invalid")

    def _serve(self, replies: dict[str, bytes]) -> int:
        """Крошечный SMTP-сервер: проверяем, что проба действительно останавливается до DATA."""
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        seen: list[str] = replies.setdefault("_seen", [])  # type: ignore[assignment]

        def run() -> None:
            connection, _ = server.accept()
            with connection:
                connection.sendall(b"220 test ESMTP\r\n")
                buffer = b""
                while True:
                    chunk = connection.recv(1024)
                    if not chunk:
                        return
                    buffer += chunk
                    while b"\r\n" in buffer:
                        line, buffer = buffer.split(b"\r\n", 1)
                        command = line.decode().split(" ")[0].upper()
                        seen.append(command)
                        if command == "EHLO":
                            connection.sendall(b"250 test\r\n")
                        elif command == "MAIL":
                            connection.sendall(b"250 ok\r\n")
                        elif command == "RCPT":
                            connection.sendall(replies["rcpt"])
                        elif command == "QUIT":
                            connection.sendall(b"221 bye\r\n")
                            return
                        else:
                            connection.sendall(b"250 ok\r\n")

        threading.Thread(target=run, daemon=True).start()
        return int(server.getsockname()[1])

    def test_a_probe_reaches_rcpt_and_never_sends_data(self) -> None:
        """Проверки релея безопасны на узле с живым трафиком: ни одно письмо не попадёт в очередь."""
        replies: dict[str, object] = {"rcpt": b"554 5.7.1 Relay access denied\r\n"}
        port = self._serve(replies)  # type: ignore[arg-type]
        result = probes.open_relay_probe("127.0.0.1", port, timeout=3.0)
        assert result.state is probes.ProbeState.REJECTED
        assert result.stage == "rcpt"
        assert result.code == 554
        assert "DATA" not in replies["_seen"]  # type: ignore[operator]

    def test_an_accepting_listener_is_reported_as_accepted(self) -> None:
        replies: dict[str, object] = {"rcpt": b"250 2.1.5 Ok\r\n"}
        port = self._serve(replies)  # type: ignore[arg-type]
        result = probes.open_relay_probe("127.0.0.1", port, timeout=3.0)
        assert result.state is probes.ProbeState.ACCEPTED
        assert not result.is_safe_for_relay_test

    def test_the_error_text_does_not_repeat_the_probe_address(self) -> None:
        """Сообщение исключения может содержать адрес из запроса; достаточно класса."""
        result = probes.smtp_probe(
            "127.0.0.1", 1, mail_from="a@x.invalid", rcpt_to="secret@x.invalid", timeout=0.5
        )
        assert "secret" not in result.message


class TestCommandLine:
    """Парсер аргументов собирается на каждом запуске контейнера; ошибка в нём роняет узел."""

    @pytest.mark.parametrize("command", ["apply x", "status", "agent", "drain on", "collector"])
    def test_every_command_parses(self, command: str) -> None:
        from msp_gateway import node

        parser_calls = []
        original = node.argparse.ArgumentParser.parse_args

        def spy(self, args=None, namespace=None):  # type: ignore[no-untyped-def]
            parsed = original(self, args, namespace)
            parser_calls.append(parsed)
            return parsed

        node.argparse.ArgumentParser.parse_args = spy  # type: ignore[method-assign]
        try:
            with pytest.raises(SystemExit) as info:
                node.main([*command.split(), "--help"])
        finally:
            node.argparse.ArgumentParser.parse_args = original  # type: ignore[method-assign]
        assert info.value.code == 0
