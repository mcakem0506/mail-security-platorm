"""Послеочередной шлюз узла: карантин и удержание после ``250`` (ТЗ 1.3 §11, §12, §32–§36, §54, §58).

Postfix принял письмо (оно в его очереди — источник истины для транспорта, §12) и передаёт его этой службе как
``content_filter``. Служба получает полный анализ MSP (с ограниченным временем), решает по подписанной политике и
делает одно из трёх:

* **доставляет** — возвращает письмо в Postfix на отдельный слушатель без фильтра и без сканера
  (повторной проверки и петли нет, §35); письмо уходит байт в байт, подписанное содержимое не меняется (§56, §58);
* **кладёт в карантин** — отправляет исходное письмо панели (шифрование и хранение там) и отвечает ``250``: письмо
  больше не в очереди Postfix, но и не потеряно — оно в карантине;
* **удерживает** (``HOLD``) — отвечает ``451``: письмо остаётся в очереди Postfix на ограниченное время; затем
  оно переходит в управляемый карантин.

Служба **никогда не отвечает ``5xx``**: письмо уже принято, отказ породил бы недоставленное уведомление отправителю
(backscatter, §54), и постоянный отказ из-за внутренней ошибки запрещён (§15). Любая ошибка анализа,
панели или карантина — открытый сбой: письмо доставляется, событие учитывается. Недоступная точка повторной подачи
даёт ``451``: Postfix повторит доставку из своей очереди.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import re
import smtplib
import threading
import time
import urllib.error
from datetime import UTC, datetime
from email import policy
from email.parser import BytesHeaderParser
from typing import Any

from .engine import EnforcementInput, MalwareEvidence, Outcome
from .model import Decision
from .node import EnforcementNode

MAX_ANALYSIS_BYTES = 25 * 1024 * 1024
#: Служебные получатели транспорта (копия для теневого анализа, always_bcc): не получатели письма и в область
#: канарейки, решения и карантин не входят.
INTERNAL_RECIPIENT_DOMAINS = frozenset({"journal.msp.invalid"})
_RECEIVED_ID = re.compile(r"\bid ([0-9A-Za-z]{6,20})\b")
_RECEIVED_IP = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,39})\]")
_ADDR = re.compile(r"<([^<>]*)>")


_BARE_LF = re.compile(rb"(?<!\r)\n")


def wire_form(raw: bytes) -> bytes:
    """Письмо в том виде, в каком его передаёт SMTP: строки оканчиваются CRLF.

    Postfix отвергает одиночный LF (``smtpd_forbid_bare_newline``). Письмо, которое он сам передал фильтру, уже в
    таком виде и не меняется; ослабляется только хранимая копия, записанная с LF (например, пересобранная вручную).
    Подписанное DKIM содержимое от этого не меняется: каноникализация DKIM работает с CRLF.
    """
    return _BARE_LF.sub(b"\r\n", raw)


def _now() -> datetime:
    return datetime.now(UTC)


class AfterQueue:
    def __init__(
        self,
        node: EnforcementNode,
        *,
        reinject_host: str,
        reinject_port: int,
        gate_timeout: float = 20.0,
        hold_ttl: float = 1800.0,
        direction: str = "INBOUND",
    ) -> None:
        self.node = node
        self.reinject_host = reinject_host
        self.reinject_port = reinject_port
        self.gate_timeout = gate_timeout
        self.hold_ttl = hold_ttl
        self.direction = direction
        self.hold_dir = node.cfg.state_dir / "hold"
        self.hold_dir.mkdir(parents=True, exist_ok=True)

    # --- разбор -----------------------------------------------------------------------------
    @staticmethod
    def parse(raw: bytes) -> dict[str, str]:
        headers = BytesHeaderParser(policy=policy.default).parsebytes(raw[:200000])
        received = headers.get_all("Received") or []
        top = str(received[0]) if received else ""
        queue_id = (_RECEIVED_ID.search(top) or [None, ""])[1] if top else ""
        ip = ""
        for match in _RECEIVED_IP.finditer(top):
            ip = match.group(1)
            break
        return {
            "message_id": str(headers.get("Message-ID", "")).strip("<> \r\n"),
            "subject": str(headers.get("Subject", ""))[:300],
            "queue_id": queue_id or "",
            "client_ip": ip,
        }

    # --- обращение к панели -----------------------------------------------------------------
    def gate(self, raw: bytes, meta: dict[str, str]) -> dict[str, Any] | None:
        if len(raw) > MAX_ANALYSIS_BYTES or not self.node.cfg.panel_url:
            return None
        try:
            return self.node._request(
                "/gateway-agent/enforcement/gate",
                body={
                    "node_id": self.node.cfg.node_id,
                    "queue_id": meta["queue_id"],
                    "message_id": meta["message_id"],
                    "direction": self.direction,
                    "client_address": meta["client_ip"],
                    "raw_b64": base64.b64encode(raw).decode(),
                },
                timeout=self.gate_timeout,
            )
        except (OSError, urllib.error.URLError, ValueError):
            self.node.counters["gate_errors"] += 1
            return None

    def quarantine(
        self, raw: bytes, meta: dict[str, str], sender: str, rcpts: list[str], outcome: Outcome
    ) -> bool:
        final = outcome.final
        assert final is not None
        try:
            answer = self.node._request(
                "/gateway-agent/quarantine",
                body={
                    "node_id": self.node.cfg.node_id,
                    "transport_message_id": meta["queue_id"] or f"AQ{hashlib.sha256(raw).hexdigest()[:14]}",
                    "internet_message_id": meta["message_id"],
                    "decision_ref": f"{final.policy_version}:{final.control_type.value}",
                    "sender": sender,
                    "recipients": rcpts,
                    "subject": meta["subject"],
                    "reason_codes": list(final.reason_codes),
                    "policy_version": final.policy_version,
                    "original_route": "",
                    "raw_b64": base64.b64encode(raw).decode(),
                },
                timeout=30.0,
            )
        except (OSError, urllib.error.URLError, ValueError):
            self.node.counters["quarantine_errors"] += 1
            return False
        # Уже выпущенное письмо второй раз в карантин не попадает: его доставляют (ТЗ §35).
        return not answer.get("already_released")

    # --- повторная подача -------------------------------------------------------------------
    def reinject(self, raw: bytes, sender: str, rcpts: list[str]) -> bool:
        raw = wire_form(raw)
        try:
            with smtplib.SMTP(
                self.reinject_host, self.reinject_port, timeout=60, local_hostname="gateway-afterqueue"
            ) as c:
                c.sendmail(sender, rcpts, raw)
            return True
        except (OSError, smtplib.SMTPException):
            self.node.counters["reinject_errors"] += 1
            return False

    # --- решение по письму ------------------------------------------------------------------
    def process(self, raw: bytes, sender: str, rcpts: list[str]) -> tuple[int, str]:
        """Вернуть ответ SMTP фильтра. Никогда не 5xx."""
        meta = self.parse(raw)
        deliver_to = list(rcpts)
        rcpts = [r for r in rcpts if r.rsplit("@", 1)[-1].lower() not in INTERNAL_RECIPIENT_DOMAINS] or list(
            rcpts
        )
        started = time.monotonic()
        verdict = self.gate(raw, meta)
        elapsed = (time.monotonic() - started) * 1000.0
        malware = MalwareEvidence()
        risk = "UNKNOWN"
        late = False
        if verdict is None:
            # Анализ недоступен: тайм-аут режима сбоя, письмо идёт дальше (открытый сбой, ТЗ §14, §15).
            late = True
        else:
            risk = str(verdict.get("risk_verdict") or "UNKNOWN")
            malware = MalwareEvidence(
                verdict="MALICIOUS" if verdict.get("malware_detected") else "UNKNOWN",
                confidence=1.0 if verdict.get("malware_detected") else 0.0,
                encrypted_unscannable=bool(verdict.get("encrypted_unscannable")),
            )
        inp = EnforcementInput(
            transport_message_id=meta["queue_id"] or f"AQ{hashlib.sha256(raw).hexdigest()[:14]}",
            message_id=meta["message_id"],
            sender=sender,
            recipients=tuple(rcpts),
            source_ip=meta["client_ip"],
            direction=self.direction,
            trusted_evidence=verdict is not None,
            risk_verdict=risk,
            malware=malware,
            evidence_ids=(f"analysis:{verdict.get('job_id')}",) if verdict and verdict.get("job_id") else (),
            elapsed_ms=10**9 if late else elapsed,
        )
        outcome = self.node.decide_inp(inp)
        final = outcome.final
        if final is not None and final.decision is Decision.TEMPFAIL:
            return 451, "4.7.1 Temporary local policy deferral, try again later"
        if final is not None and final.decision is Decision.HOLD:
            return self._hold(raw, meta, sender, rcpts, outcome)
        if final is not None and final.decision is Decision.QUARANTINE:
            if self.quarantine(raw, meta, sender, rcpts, outcome):
                return 250, "2.0.0 Ok: queued"
            self.node.counters["quarantine_failopen"] += 1  # хранилище недоступно: письмо доставляется
        if self.reinject(raw, sender, deliver_to):
            return 250, "2.0.0 Ok: queued"
        return 451, "4.3.0 Reinjection failed, try again later"

    def _hold(
        self, raw: bytes, meta: dict[str, str], sender: str, rcpts: list[str], outcome: Outcome
    ) -> tuple[int, str]:
        key = hashlib.sha256(raw).hexdigest()
        path = self.hold_dir / f"{key}.json"
        try:
            first = float(json.loads(path.read_text(encoding="utf-8"))["first_seen"])
        except (OSError, ValueError, KeyError):
            first = time.time()
            path.write_text(json.dumps({"first_seen": first}), encoding="utf-8")
        if time.time() - first < self.hold_ttl:
            self.node.counters["held"] += 1
            return 451, "4.7.1 Message held for review, try again later"
        # Срок удержания вышел: письмо становится управляемым карантином, а не уходит само (HOLD ≠ QUARANTINE, §36).
        path.unlink(missing_ok=True)
        if self.quarantine(raw, meta, sender, rcpts, outcome):
            return 250, "2.0.0 Ok: queued"
        return 451, "4.7.1 Message held for review, try again later"

    # --- выпуск из карантина ----------------------------------------------------------------
    def release_once(self) -> int:
        if not self.node.cfg.panel_url:
            return 0
        try:
            pending = self.node._request(
                f"/gateway-agent/quarantine/releases?node_id={self.node.cfg.node_id}", timeout=5.0
            ).get("items", [])
        except (OSError, urllib.error.URLError, ValueError):
            return 0
        done = 0
        for item in pending:
            ok, error = False, ""
            try:
                content = self.node._request(
                    f"/gateway-agent/quarantine/{item['id']}/content?token={item['token']}", timeout=30.0
                )
                raw = base64.b64decode(content["raw_b64"])
                if hashlib.sha256(raw).hexdigest() != item["sha256"]:
                    error = "контрольная сумма не совпала"
                else:
                    ok = self.reinject(raw, item.get("sender", ""), list(item["recipients"]))
                    error = "" if ok else "повторная подача не удалась"
            except (OSError, urllib.error.URLError, ValueError, KeyError) as exc:
                error = type(exc).__name__
            with contextlib.suppress(OSError, urllib.error.URLError, ValueError):
                self.node._request(
                    f"/gateway-agent/quarantine/{item['id']}/confirm",
                    body={"token": item["token"], "delivered": ok, "error": error},
                )
            done += 1 if ok else 0
        return done


# ---------------------------------------------------------------------------------------------
# Минимальный SMTP-приёмник для Postfix
# ---------------------------------------------------------------------------------------------
async def _line(reader: asyncio.StreamReader, timeout: float = 120.0) -> bytes:
    return await asyncio.wait_for(reader.readline(), timeout=timeout)


def _address(argument: str) -> str:
    match = _ADDR.search(argument)
    return match.group(1) if match else ""


async def handle(aq: AfterQueue, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    loop = asyncio.get_running_loop()

    async def reply(code: int, text: str) -> None:
        writer.write(f"{code} {text}\r\n".encode())
        await writer.drain()

    sender = ""
    rcpts: list[str] = []
    try:
        await reply(220, "gateway-afterqueue ESMTP")
        while True:
            raw_line = await _line(reader)
            if not raw_line:
                break
            line = raw_line.decode("utf-8", "replace").rstrip("\r\n")
            verb = line.split(" ", 1)[0].upper()
            if verb in ("EHLO", "HELO"):
                writer.write(b"250-gateway-afterqueue\r\n250 8BITMIME\r\n")
                await writer.drain()
            elif verb == "MAIL":
                sender, rcpts = _address(line), []
                await reply(250, "2.1.0 Ok")
            elif verb == "RCPT":
                rcpts.append(_address(line))
                await reply(250, "2.1.5 Ok")
            elif verb == "DATA":
                if not rcpts:
                    await reply(503, "5.5.1 Need RCPT first")
                    continue
                await reply(354, "End data with <CR><LF>.<CR><LF>")
                chunks: list[bytes] = []
                while True:
                    part = await _line(reader, timeout=300.0)
                    if part in (b".\r\n", b".\n", b""):
                        break
                    chunks.append(part[1:] if part.startswith(b"..") else part)
                data = b"".join(chunks)
                code, text = await loop.run_in_executor(None, aq.process, data, sender, list(rcpts))
                await reply(code, text)
                sender, rcpts = "", []
            elif verb == "RSET":
                sender, rcpts = "", []
                await reply(250, "2.0.0 Ok")
            elif verb == "NOOP":
                await reply(250, "2.0.0 Ok")
            elif verb == "QUIT":
                await reply(221, "2.0.0 Bye")
                break
            else:
                await reply(502, "5.5.2 Command not implemented")
    except (TimeoutError, ConnectionError, OSError):
        pass
    finally:
        with contextlib.suppress(Exception):
            writer.close()


def run(aq: AfterQueue, host: str, port: int) -> None:
    def releases() -> None:
        while True:
            aq.release_once()
            time.sleep(3)

    threading.Thread(target=releases, daemon=True).start()

    async def main() -> None:
        server = await asyncio.start_server(lambda r, w: handle(aq, r, w), host, port)
        async with server:
            await server.serve_forever()

    asyncio.run(main())


def cli(argv: list[str] | None = None) -> int:
    import argparse

    from .node import NodeConfig, background_loop

    parser = argparse.ArgumentParser(prog="msp_enforcement.afterqueue")
    parser.add_argument("--host", default="0.0.0.0")  # noqa: S104 - слушатель в изолированной сети узла
    parser.add_argument("--port", type=int, default=10025)
    parser.add_argument("--reinject-host", required=True)
    parser.add_argument("--reinject-port", type=int, default=10026)
    parser.add_argument("--direction", choices=("INBOUND", "OUTBOUND"), default="INBOUND")
    parser.add_argument("--gate-timeout", type=float, default=20.0)
    parser.add_argument("--hold-ttl", type=float, default=1800.0)
    args = parser.parse_args(argv)
    node = EnforcementNode(NodeConfig())
    node.sync_policy()
    threading.Thread(target=background_loop, args=(node,), daemon=True).start()
    # Метрики и проверка живости; решения для Rspamd здесь не принимаются (разрешённых клиентов нет).
    from .node import serve

    metrics = serve(node, "0.0.0.0", 11390)  # noqa: S104 - в изолированной сети узла
    threading.Thread(target=metrics.serve_forever, daemon=True).start()
    run(
        AfterQueue(
            node,
            reinject_host=args.reinject_host,
            reinject_port=args.reinject_port,
            gate_timeout=args.gate_timeout,
            hold_ttl=args.hold_ttl,
            direction=args.direction,
        ),
        args.host,
        args.port,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
