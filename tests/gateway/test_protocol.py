"""Поведение SMTP на настоящем Postfix (ТЗ 1.1 §29, §49, §63, §68.6).

Шлюз — граница, на которую приходит всё, что умеет отправить интернет. Проверяется, что он
не ломает корректные письма (точки в начале строк, пустой отправитель, 8-битный текст) и
не пропускает некорректные там, где это опасно: «контрабанда SMTP» через одиночный LF,
обрыв посреди передачи, чрезмерные размеры и числа, зацикленные письма.
"""

from __future__ import annotations

import contextlib
import hashlib
import smtplib
import socket
import uuid

import pytest
from msp_gateway.spec import Limits

from .harness import LAB_RECIPIENTS, lab_spec, make_message


def new_id() -> str:
    return f"prt-{uuid.uuid4().hex[:10]}"


def full_id(mid: str) -> str:
    return f"<{mid}@lab.example>"


class RawSmtp:
    """Клиент, который говорит байтами и ничего не исправляет за собеседника."""

    def __init__(self, port: int) -> None:
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=20)
        self.buffer = b""
        self.greeting = self.reply()

    def reply(self) -> str:
        lines: list[str] = []
        while True:
            while b"\n" not in self.buffer:
                chunk = self.sock.recv(4096)
                if not chunk:
                    return "\n".join(lines) or "EOF"
                self.buffer += chunk
            line, _, self.buffer = self.buffer.partition(b"\n")
            text = line.decode("utf-8", "replace").rstrip("\r")
            lines.append(text)
            if len(text) < 4 or text[3] != "-":
                return "\n".join(lines)

    def say(self, data: bytes | str) -> str:
        self.sock.sendall(data.encode() if isinstance(data, str) else data)
        return self.reply()

    def hello(self) -> None:
        assert self.say("EHLO external.example\r\n").startswith("250")

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.close()


@pytest.fixture
def raw(clean):  # type: ignore[no-untyped-def]
    clients: list[RawSmtp] = []

    def connect() -> RawSmtp:
        client = RawSmtp(clean.ports["GW_PORT_IN"])
        clients.append(client)
        return client

    yield connect
    for client in clients:
        client.close()


def deliver_raw(client: RawSmtp, mail_from: str, rcpt: str, data: bytes) -> str:
    client.hello()
    assert client.say(f"MAIL FROM:<{mail_from}>\r\n").startswith("250")
    assert client.say(f"RCPT TO:<{rcpt}>\r\n").startswith("250")
    assert client.say("DATA\r\n").startswith("354")
    return client.say(data + b"\r\n.\r\n")


def mime(mid: str, body: bytes) -> bytes:
    head = (
        f"From: a@partner.example\r\nTo: ivan@corp.example\r\nSubject: t\r\nMessage-ID: {full_id(mid)}\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: 8bit\r\n\r\n"
    )
    return head.encode() + body


class TestCorrectMailPassesIntact:
    def test_null_sender_is_accepted(self, raw, clean) -> None:  # type: ignore[no-untyped-def]
        """Уведомления о недоставке приходят с пустым отправителем; отвергать их нельзя."""
        mid = new_id()
        assert deliver_raw(raw(), "", "ivan@corp.example", mime(mid, b"bounce\r\n")).startswith("250")
        assert clean.exchange1.wait_for(full_id(mid), timeout=60) is not None

    @pytest.mark.parametrize(
        "body",
        [
            b".leading dot line\r\n..two dots\r\nend\r\n",
            b"first\r\n.\r\n".replace(b"\r\n.\r\n", b"\r\n..\r\n") + b"after\r\n",
            "Привет, мир — 日本語 ✓\r\n".encode(),
            (b"x" * 900 + b"\r\n") * 20,
            b"\r\n\r\n\r\ntrailing blank lines\r\n\r\n",
        ],
        ids=["leading-dots", "stuffed-dot-line", "utf8", "long-lines", "blank-lines"],
    )
    def test_the_body_reaches_exchange_unchanged(self, raw, clean, body: bytes) -> None:  # type: ignore[no-untyped-def]
        mid = new_id()
        # передаётся ровно то, что «получится» после снятия точечной вставки: клиент вставляет точки сам
        stuffed = b"\r\n".join(
            (b"." + line if line.startswith(b".") else line) for line in body.split(b"\r\n")
        )
        assert deliver_raw(raw(), "a@partner.example", "ivan@corp.example", mime(mid, stuffed)).startswith(
            "250"
        )
        received = clean.exchange1.wait_for(full_id(mid), timeout=60)
        assert received is not None
        expected = body + bytes([13, 10])
        assert received["body_sha256"] == hashlib.sha256(expected).hexdigest()


class TestSmuggling:
    @pytest.mark.parametrize(
        "terminator",
        [b"\n.\n", b"\n.\r\n", b"\r\n.\n"],
        ids=["lf-dot-lf", "lf-dot-crlf", "crlf-dot-lf"],
    )
    def test_bare_lf_cannot_end_the_message_early(self, raw, clean, terminator: bytes) -> None:  # type: ignore[no-untyped-def]
        """Классическая «контрабанда SMTP»: конец данных, видимый шлюзу иначе, чем Exchange."""
        mid, evil = new_id(), new_id()
        client = raw()
        client.hello()
        client.say("MAIL FROM:<a@partner.example>\r\n")
        client.say("RCPT TO:<ivan@corp.example>\r\n")
        client.say("DATA\r\n")
        smuggled = (
            b"Subject: s\r\nMessage-ID: "
            + full_id(mid).encode()
            + b"\r\n\r\nhi"
            + terminator
            + b"MAIL FROM:<boss@corp.example>\r\nRCPT TO:<ivan@corp.example>\r\nDATA\r\n"
            + b"Message-ID: "
            + full_id(evil).encode()
            + b"\r\n\r\nsmuggled\r\n.\r\n"
        )
        answer = client.say(smuggled + b"\r\n.\r\n")
        assert not answer.startswith("250") or clean.exchange1.message_ids().count(full_id(evil)) == 0
        clean.wait_until(lambda: clean.queue_size() == 0, timeout=60, what="очередь пуста")
        assert clean.exchange1.message_ids().count(full_id(evil)) == 0, "второе письмо появиться не должно"
        assert clean.exchange2.message_ids().count(full_id(evil)) == 0


class TestBrokenSessions:
    def test_disconnect_in_the_middle_of_data_leaves_nothing(self, raw, clean) -> None:  # type: ignore[no-untyped-def]
        mid = new_id()
        before = clean.queue_size()
        client = raw()
        client.hello()
        client.say("MAIL FROM:<a@partner.example>\r\n")
        client.say("RCPT TO:<ivan@corp.example>\r\n")
        client.say("DATA\r\n")
        client.sock.sendall(
            b"Subject: half\r\nMessage-ID: " + full_id(mid).encode() + b"\r\n\r\nbody without end"
        )
        client.close()
        clean.wait_until(lambda: clean.queue_size() == before, what="недопринятое письмо не попало в очередь")
        assert clean.exchange1.message_ids().count(full_id(mid)) == 0

    def test_unknown_commands_get_errors_and_do_not_crash_the_server(self, raw, clean) -> None:  # type: ignore[no-untyped-def]
        client = raw()
        assert client.say("XYZZY\r\n").startswith("5")
        assert client.say("\x00\x01\x02\r\n").startswith("5")
        assert client.say("NOOP\r\n").startswith("250")

    def test_repeated_errors_end_the_session(self, raw, clean) -> None:  # type: ignore[no-untyped-def]
        client = raw()
        answers = [client.say("BOGUS\r\n") for _ in range(30)]
        assert answers[-1] in ("EOF",) or answers[-1].startswith("421") or "too many" in answers[-1].lower()

    def test_a_giant_command_line_is_refused(self, raw, clean) -> None:  # type: ignore[no-untyped-def]
        client = raw()
        answer = client.say("NOOP " + "A" * 70000 + "\r\n")
        assert answer.startswith("5") or answer == "EOF" or answer.startswith("421")

    def test_the_server_still_works_after_all_of_that(self, clean) -> None:  # type: ignore[no-untyped-def]
        mid = new_id()
        sender, rcpt = "a@partner.example", "ivan@corp.example"
        assert clean.send_external(sender, [rcpt], make_message(mid, sender, rcpt)) == {}
        assert clean.exchange1.wait_for(full_id(mid), timeout=60) is not None


class TestLimits:
    @pytest.fixture(autouse=True)
    def restore(self, lab):  # type: ignore[no-untyped-def]
        yield
        lab.apply(lab_spec(), LAB_RECIPIENTS)

    def test_oversized_message_is_refused_with_552_and_not_queued(self, clean) -> None:  # type: ignore[no-untyped-def]
        spec = lab_spec(limits=Limits(max_message_size=1024 * 1024))
        assert clean.apply(spec, LAB_RECIPIENTS)["outcome"] == "ACTIVE"
        sender, rcpt = "a@partner.example", "ivan@corp.example"
        before = clean.queue_size()
        with pytest.raises(smtplib.SMTPException) as info:
            clean.send_external(sender, [rcpt], make_message(new_id(), sender, rcpt, size=2 * 1024 * 1024))
        assert "552" in str(info.value) or "size" in str(info.value).lower()
        assert clean.queue_size() == before

    def test_message_just_under_the_limit_passes(self, clean) -> None:  # type: ignore[no-untyped-def]
        spec = lab_spec(limits=Limits(max_message_size=1024 * 1024))
        clean.apply(spec, LAB_RECIPIENTS)
        mid = new_id()
        sender, rcpt = "a@partner.example", "ivan@corp.example"
        assert clean.send_external(sender, [rcpt], make_message(mid, sender, rcpt, size=900 * 1024)) == {}
        assert clean.exchange1.wait_for(full_id(mid), timeout=60) is not None

    def test_recipient_count_is_limited(self, clean) -> None:  # type: ignore[no-untyped-def]
        clean.apply(lab_spec(limits=Limits(max_recipients=2)), LAB_RECIPIENTS)
        sender = "a@partner.example"
        rcpts = ["ivan@corp.example", "shared@corp.example", "all-staff@corp.example"]
        refused = clean.send_external(sender, rcpts, make_message(new_id(), sender, rcpts[0]))
        assert list(refused) == ["all-staff@corp.example"]
        assert refused["all-staff@corp.example"][0] == 452


class TestLoops:
    def test_a_message_that_has_travelled_too_far_is_refused(self, raw, clean) -> None:  # type: ignore[no-untyped-def]
        """Предел переходов (hopcount) останавливает письмо, бегающее между серверами по кругу."""
        mid = new_id()
        received = b"".join(
            b"Received: from hop%d.example by relay.example; Mon, 01 Jan 2024 00:00:00 +0000\r\n" % i
            for i in range(40)
        )
        answer = deliver_raw(
            raw(), "a@partner.example", "ivan@corp.example", received + mime(mid, b"loop\r\n")
        )
        assert answer.startswith("5") or answer.startswith("4"), answer
        clean.wait_until(lambda: clean.queue_size() == 0, what="зациклившееся письмо не осталось в очереди")
        assert clean.exchange1.message_ids().count(full_id(mid)) == 0
