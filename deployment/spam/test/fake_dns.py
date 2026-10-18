"""Управляемый DNS для проверок MSP 1.2 (ТЗ 1.2 §37).

CI не зависит от настоящих DNSBL и чужих зон: все записи SPF, DKIM, DMARC, PTR и «чёрных списков»
лабораторной зоны отдаёт этот сервер, а тест меняет их по HTTP. Умеет отвечать: записью, NXDOMAIN
(по умолчанию), SERVFAIL (временная ошибка по имени или суффиксу) и молчанием (таймаут). Это
не продукт: стандартная библиотека, UDP и TCP, только нужные типы записей.

Управление (HTTP, порт ``--control``):

    PUT  /records   тело — JSON ``{"имя": {"TXT": [...], "A": [...], "MX": [[10, "хост"]], ...}}``
    PUT  /faults    тело — JSON ``{"servfail": ["суффикс", ...], "timeout": [...], "delay": секунды}``
    GET  /queries   журнал запросов (имя, тип) — для проверки, что секрет не ушёл в запрос
    POST /reset     очистить всё
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
CODES = {value: key for key, value in TYPES.items()}

LOCK = threading.Lock()
STATE: dict[str, object] = {"records": {}, "faults": {"servfail": [], "timeout": [], "delay": 0.0}, "log": []}


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\0"


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = offset
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            continue
        labels.append(data[offset + 1 : offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    return ".".join(labels).lower(), (end if jumped else offset)


def txt_rdata(text: str) -> bytes:
    raw = text.encode("utf-8")
    chunks = [raw[i : i + 255] for i in range(0, len(raw), 255)] or [b""]
    return b"".join(bytes([len(c)]) + c for c in chunks)


def rdata(kind: str, value: object) -> bytes:
    if kind == "A":
        return socket.inet_aton(str(value))
    if kind == "AAAA":
        return socket.inet_pton(socket.AF_INET6, str(value))
    if kind == "TXT":
        return txt_rdata(str(value))
    if kind in ("PTR", "NS", "CNAME"):
        return encode_name(str(value))
    if kind == "MX":
        preference, host = value  # type: ignore[misc]
        return struct.pack("!H", int(preference)) + encode_name(str(host))
    raise ValueError(kind)


def matches(name: str, suffixes: list[str]) -> bool:
    return any(name == s or name.endswith("." + s) for s in suffixes)


def answer(data: bytes) -> bytes | None:
    if len(data) < 12:
        return None
    ident = data[:2]
    name, offset = read_name(data, 12)
    qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
    question = data[12 : offset + 4]
    kind = CODES.get(qtype, str(qtype))
    with LOCK:
        STATE["log"].append({"name": name, "type": kind, "at": time.time()})  # type: ignore[union-attr]
        faults = dict(STATE["faults"])  # type: ignore[arg-type]
        records = dict(STATE["records"])  # type: ignore[arg-type]
    if matches(name, list(faults.get("timeout", []))):
        return None
    delay = float(faults.get("delay", 0) or 0)
    if delay:
        time.sleep(delay)
    header = ident
    if matches(name, list(faults.get("servfail", []))):
        return header + struct.pack("!HHHHH", 0x8182, 1, 0, 0, 0) + question
    entry = records.get(name)
    if entry is None:
        return header + struct.pack("!HHHHH", 0x8183, 1, 0, 0, 0) + question  # NXDOMAIN
    values = entry.get(kind, [])
    body = b""
    for value in values:
        payload = rdata(kind, value)
        body += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 30, len(payload)) + payload
    return header + struct.pack("!HHHHH", 0x8180, 1, len(values), 0, 0) + question + body


def serve_udp(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    while True:
        data, peer = sock.recvfrom(4096)

        def handle(data: bytes = data, peer: tuple[str, int] = peer) -> None:
            reply = answer(data)
            if reply is not None:
                sock.sendto(reply, peer)

        threading.Thread(target=handle, daemon=True).start()


def serve_tcp(port: int) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(16)
    while True:
        conn, _ = server.accept()

        def handle(conn: socket.socket = conn) -> None:
            try:
                conn.settimeout(5)
                length = struct.unpack("!H", conn.recv(2))[0]
                data = b""
                while len(data) < length:
                    data += conn.recv(length - len(data))
                reply = answer(data)
                if reply is not None:
                    conn.sendall(struct.pack("!H", len(reply)) + reply)
            except (OSError, struct.error):
                pass
            finally:
                conn.close()

        threading.Thread(target=handle, daemon=True).start()


class Control(BaseHTTPRequestHandler):
    def _body(self) -> object:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length) or b"{}")

    def _send(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self) -> None:  # noqa: N802
        payload = self._body()
        with LOCK:
            if self.path == "/records":
                STATE["records"] = {k.lower().rstrip("."): v for k, v in dict(payload).items()}  # type: ignore[call-overload]
            elif self.path == "/faults":
                STATE["faults"] = {"servfail": [], "timeout": [], "delay": 0.0, **dict(payload)}  # type: ignore[call-overload]
            else:
                self._send({"error": "unknown"}, 404)
                return
        self._send({"ok": True})

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/reset":
            with LOCK:
                STATE["records"] = {}
                STATE["faults"] = {"servfail": [], "timeout": [], "delay": 0.0}
                STATE["log"] = []
            self._send({"ok": True})
        else:
            self._send({"error": "unknown"}, 404)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/queries":
            with LOCK:
                self._send(list(STATE["log"]))  # type: ignore[call-overload]
        else:
            self._send({"ok": True})

    def log_message(self, *args: object) -> None:
        pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--control", type=int, default=8053)
    args = parser.parse_args()
    threading.Thread(target=serve_udp, args=(args.port,), daemon=True).start()
    threading.Thread(target=serve_tcp, args=(args.port,), daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", args.control), Control).serve_forever()


if __name__ == "__main__":
    main()
