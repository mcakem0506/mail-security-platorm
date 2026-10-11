"""Управляемый SMTP-приёмник для проверки шлюза (ТЗ 1.1 §67).

Он играет роль Exchange (и приёмника исходящей почты) и умеет то, что нужно для проверки
транспорта и чего не умеет настоящий сервер по команде:

    accept       принять письмо
    tempfail     ответить 451 после DATA (временный отказ — шлюз должен держать письмо в очереди)
    permfail     ответить 554 после DATA (постоянный — шлюз должен вернуть уведомление)
    delay        принять, но с задержкой в секундах (медленный получатель)
    disconnect   оборвать соединение посреди DATA (письмо принято НЕ было)
    reject_rcpt  отказать на RCPT TO для перечисленных адресов (неизвестный получатель)

Режим переключается во время работы по HTTP, без перезапуска: сценарий «Exchange недоступен,
затем вернулся» должен идти на одном и том же процессе. Принятые письма записываются с
``Message-ID`` и контрольной суммой — по ним тест отвечает на вопрос «дошло ли ровно одно
такое письмо».

Приёмник нарочно ничего не делает с телом письма кроме подсчёта суммы: это тестовый инструмент,
а не продукт.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import ssl
import threading
import time
from email import message_from_bytes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as SmtpProtocol

STATE_LOCK = threading.Lock()
STATE: dict[str, object] = {
    "mode": "accept",
    "delay": 0.0,
    "rejected_recipients": [],
    "received": [],
    "starttls_sessions": 0,
    "plain_sessions": 0,
}


def _record(envelope, session) -> dict[str, object]:  # type: ignore[no-untyped-def]
    raw = envelope.original_content or envelope.content or b""
    message = message_from_bytes(raw)
    return {
        "message_id": str(message.get("Message-ID", "")).strip(),
        "mail_from": envelope.mail_from,
        "rcpt_tos": list(envelope.rcpt_tos),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "received_at": time.time(),
        "tls": bool(session.ssl),
        "peer": session.peer[0] if session.peer else "",
        "has_received_header": bool(message.get_all("Received")),
    }


class Handler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):  # type: ignore[no-untyped-def]
        with STATE_LOCK:
            rejected = list(STATE["rejected_recipients"])  # type: ignore[call-overload]
            mode = STATE["mode"]
        if mode == "reject_rcpt" and address.lower() in {item.lower() for item in rejected}:
            return "550 5.1.1 User unknown"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):  # type: ignore[no-untyped-def]
        with STATE_LOCK:
            mode = str(STATE["mode"])
            delay = float(STATE["delay"])  # type: ignore[arg-type]
        if mode == "tempfail":
            return "451 4.3.0 Temporary failure, try again later"
        if mode == "permfail":
            return "554 5.7.1 Message rejected"
        if mode == "disconnect":
            server.transport.close()
            return "250 OK"  # недостижимо: соединение уже закрыто
        if mode == "delay" and delay > 0:
            await asyncio.sleep(delay)
        entry = _record(envelope, session)
        with STATE_LOCK:
            STATE["received"].append(entry)  # type: ignore[union-attr]
            key = "starttls_sessions" if entry["tls"] else "plain_sessions"
            STATE[key] = int(STATE[key]) + 1  # type: ignore[call-overload]
        return "250 2.0.0 Message accepted for delivery"


class ControlHandler(BaseHTTPRequestHandler):
    def _send(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:  # тишина: тестам нужен только результат
        return

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send({"ok": True})
        elif self.path == "/state":
            with STATE_LOCK:
                summary = {k: v for k, v in STATE.items() if k != "received"}
                summary["count"] = len(STATE["received"])  # type: ignore[arg-type]
                self._send(summary)
        elif self.path == "/received":
            with STATE_LOCK:
                self._send(list(STATE["received"]))  # type: ignore[call-overload]
        else:
            self._send({"error": "unknown"}, 404)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        payload = json.loads(self.rfile.read(length) or b"{}")
        with STATE_LOCK:
            if self.path == "/mode":
                STATE["mode"] = str(payload.get("mode", "accept"))
                STATE["delay"] = float(payload.get("delay", 0))
                STATE["rejected_recipients"] = list(payload.get("rejected_recipients", []))
            elif self.path == "/reset":
                STATE["received"] = []
                STATE["mode"] = "accept"
                STATE["starttls_sessions"] = 0
                STATE["plain_sessions"] = 0
            else:
                self._send({"error": "unknown"}, 404)
                return
        self._send({"ok": True})


def make_tls_context() -> ssl.SSLContext | None:
    cert, key = os.environ.get("TLS_CERT"), os.environ.get("TLS_KEY")
    if not cert or not key:
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return context


class Server(Controller):
    def factory(self) -> SmtpProtocol:
        return SmtpProtocol(self.handler, **self.SMTP_kwargs)


def main() -> None:
    port = int(os.environ.get("SMTP_PORT", "2526"))
    control = int(os.environ.get("CONTROL_PORT", "8025"))
    context = make_tls_context()
    controller = Server(
        Handler(),
        hostname="0.0.0.0",  # noqa: S104 - тестовый приёмник внутри изолированной сети
        port=port,
        tls_context=context,
        require_starttls=os.environ.get("REQUIRE_STARTTLS", "0") == "1" and context is not None,
        data_size_limit=int(os.environ.get("MAX_SIZE", str(100 * 1024 * 1024))),
        decode_data=False,
    )
    controller.start()
    ThreadingHTTPServer(("0.0.0.0", control), ControlHandler).serve_forever()  # noqa: S104


if __name__ == "__main__":
    main()
