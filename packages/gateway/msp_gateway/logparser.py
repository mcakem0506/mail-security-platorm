"""Разбор журнала Postfix в события транспорта (ТЗ 1.1 §31, §33, §62).

Журнал — не источник долговечности почты (§33): письма живут в очереди Postfix. Журнал нужен
для наблюдаемости — сколько принято, отвергнуто, отложено, доставлено и почему. Поэтому разбор
устроен так, чтобы ошибка в нём никогда не могла повлиять на почту: он ничего не пишет в очередь
и не падает на незнакомой строке, а считает её в ``unparsed``.

Часть текста журнала задаёт клиент: HELO, адреса отправителя и получателя, текст ответа
сервера. Это канал для внедрения в журнал (§62), и разбор обращается с такими значениями как с
враждебными: управляющие символы вырезаются, длина ограничивается, значение никогда не
интерпретируется (ни как команда, ни как формат).

Тела писем в журнале Postfix нет, и этот модуль их не восстанавливает и не принимает (§31).

Только стандартная библиотека: модуль работает на узле.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

MAX_FIELD = 320
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

# «Oct 11 12:28:51 gw postfix-in/smtpd[354]: <сообщение>» — формат maillog_file.
_LINE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<program>[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)?)\[(?P<pid>\d+)\]:\s+(?P<message>.*)$"
)
# В идентификаторе очереди Postfix всегда есть цифра; без этого слово «statistics» (ровно десять
# букв) принималось за идентификатор.
_QUEUE_ID = re.compile(r"^(?P<qid>(?=[A-Za-z]*\d)[0-9A-Za-z]{10,16}|[0-9A-Fa-f]{8,}): (?P<rest>.*)$")
_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1
    )
}


class EventType(StrEnum):
    CONNECT = "CONNECT"
    DISCONNECT = "DISCONNECT"
    ACCEPTED = "ACCEPTED"
    QUEUED = "QUEUED"
    REJECTED = "REJECTED"
    DELIVERY = "DELIVERY"
    #: Получатель отказал, и Postfix продолжает (запасная цель или повтор). Итоговая строка
    #: доставки относится уже к другому серверу, поэтому без этого события отказ не виден.
    REMOTE_REPLY = "REMOTE_REPLY"
    SHADOW = "SHADOW"
    BOUNCE_NOTICE = "BOUNCE_NOTICE"
    REMOVED = "REMOVED"
    TLS = "TLS"
    WARNING = "WARNING"


class Direction(StrEnum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    INTERNAL_TEST = "INTERNAL_TEST"
    UNKNOWN = "UNKNOWN"


@dataclass
class LogEvent:
    """Событие транспорта. Тела письма в нём нет и быть не может."""

    event_type: EventType
    occurred_at: datetime
    program: str
    queue_id: str = ""
    direction: Direction = Direction.UNKNOWN
    envelope_from: str = ""
    recipients_count: int | None = None
    relay: str = ""
    status: str = ""
    smtp_code: int | None = None
    delay: float | None = None
    dsn: str = ""
    client_address: str = ""
    message_id: str = ""
    detail: str = ""
    extras: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "event_type": self.event_type.value,
            "occurred_at": self.occurred_at.isoformat(),
            "program": self.program,
            "queue_id": self.queue_id,
            "direction": self.direction.value,
            "envelope_from": self.envelope_from,
            "recipients_count": self.recipients_count,
            "relay": self.relay,
            "status": self.status,
            "smtp_code": self.smtp_code,
            "delay": self.delay,
            "dsn": self.dsn,
            "client_address": self.client_address,
            "message_id": self.message_id,
            "detail": self.detail,
            "extras": dict(self.extras),
        }


def clean(value: str, limit: int = MAX_FIELD) -> str:
    """Значение из журнала: без управляющих символов и ограниченной длины."""
    return _CONTROL.sub("?", value)[:limit]


def _timestamp(month: str, day: str, clock: str, year: int) -> datetime | None:
    number = _MONTHS.get(month)
    if number is None:
        return None
    try:
        return datetime.strptime(f"{year} {number} {int(day)} {clock}", "%Y %m %d %H:%M:%S")
    except ValueError:
        return None


def direction_of_program(program: str) -> Direction:
    """Направление определяется слушателем, принявшим письмо (ТЗ §30), а не доменом отправителя."""
    if program.startswith("postfix-in/"):
        return Direction.INBOUND
    if program.startswith("postfix-out/"):
        return Direction.OUTBOUND
    return Direction.UNKNOWN


_CLIENT = re.compile(r"client=(?P<host>[^\[\s]*)\[(?P<ip>[^\]]*)\]")
_CONNECT = re.compile(r"^(?P<what>connect|disconnect) from (?P<host>[^\[\s]*)\[(?P<ip>[^\]]*)\]")
_REJECT = re.compile(
    r"^NOQUEUE: reject: (?P<stage>\w+) from (?P<host>[^\[\s]*)\[(?P<ip>[^\]]*)\]: "
    r"(?P<code>[2-5]\d\d) (?P<dsn>\d\.\d+\.\d+)?\s*(?P<text>.*)$"
)
_FROM = re.compile(r"^from=<(?P<sender>[^>]*)>(?:, size=(?P<size>\d+))?(?:, nrcpt=(?P<nrcpt>\d+))?")
_MESSAGE_ID = re.compile(r"^message-id=<?(?P<id>[^>\s]*)>?")
_DELIVERY = re.compile(
    r"^to=<(?P<to>[^>]*)>(?:, orig_to=<[^>]*>)?, relay=(?P<relay>[^,]*), "
    r"(?:conn_use=\d+, )?delay=(?P<delay>[\d.]+), delays=[\d./]+, dsn=(?P<dsn>\d\.\d+\.\d+), "
    r"status=(?P<status>\w+)(?: \((?P<text>.*)\))?$"
)
_SMTP_CODE = re.compile(r"\b(?P<code>[2-5]\d\d)\b")
_TLS = re.compile(
    r"^(?P<kind>Verified TLS|Untrusted TLS|Anonymous TLS|Trusted TLS) connection established (?:to|from) "
    r"(?P<peer>\S+): (?P<proto>\S+) with cipher (?P<cipher>\S+)"
)
_TLS_FAIL = re.compile(
    r"^(?P<peer>\S+): (?:certificate verification failed|TLS cipher|Server certificate not trusted)"
)
_REMOTE_SAID = re.compile(
    r"^host (?P<peer>\S+) said: (?P<code>[2-5]\d\d) (?P<dsn>\d\.\d+\.\d+)?\s*(?P<text>.*?)"
    r"(?: \(in reply to (?P<stage>[^)]*)\))?$"
)
_BOUNCE = re.compile(r"^(?P<what>sender non-delivery notification|postmaster notification): (?P<new>\S+)")


@dataclass
class ParseStats:
    parsed: int = 0
    unparsed: int = 0
    ignored: int = 0


class LogParser:
    """Разбор по строкам с памятью о соответствии «очередной идентификатор → слушатель».

    Память нужна потому, что слушатель известен только из строки smtpd, а доставка, отказ и
    удаление приходят от других процессов с тем же идентификатором. Запись о письме удаляется
    вместе с ним (строка ``removed``), а общий размер ограничен: узел с миллионами писем в
    очереди не должен съедать память разбора.
    """

    MAX_TRACKED = 50_000

    def __init__(self, *, year: int | None = None) -> None:
        self.year = year or datetime.now().year
        self.stats = ParseStats()
        self._direction: dict[str, Direction] = {}
        self._sender: dict[str, str] = {}
        self._message_id: dict[str, str] = {}

    def parse_line(self, line: str) -> LogEvent | None:
        """Разобрать строку. ``None`` — строка не порождает события; учёт ведётся в ``stats``."""
        try:
            return self._parse(line.rstrip("\r\n"))
        except Exception:  # noqa: BLE001 - разбор не вправе падать ни на какой строке
            self.stats.unparsed += 1
            return None

    def parse_lines(self, lines: Iterable[str]) -> list[LogEvent]:
        return [event for line in lines if (event := self.parse_line(line)) is not None]

    # ------------------------------------------------------------------------------
    def _parse(self, line: str) -> LogEvent | None:
        match = _LINE.match(line)
        if match is None:
            self.stats.unparsed += 1
            return None
        when = _timestamp(match["month"], match["day"], match["time"], self.year)
        if when is None:
            self.stats.unparsed += 1
            return None
        program = clean(match["program"], 64)
        message = match["message"]

        qmatch = _QUEUE_ID.match(message)
        if qmatch and not message.startswith("NOQUEUE"):
            return self._queued(when, program, qmatch["qid"], qmatch["rest"])
        return self._unqueued(when, program, message)

    def _unqueued(self, when: datetime, program: str, message: str) -> LogEvent | None:
        connection = _CONNECT.match(message)
        if connection:
            kind = EventType.CONNECT if connection["what"] == "connect" else EventType.DISCONNECT
            self.stats.parsed += 1
            return LogEvent(
                kind,
                when,
                program,
                direction=direction_of_program(program),
                client_address=clean(connection["ip"], 64),
            )

        reject = _REJECT.match(message)
        if reject:
            self.stats.parsed += 1
            return LogEvent(
                EventType.REJECTED,
                when,
                program,
                direction=direction_of_program(program),
                client_address=clean(reject["ip"], 64),
                status="rejected",
                smtp_code=int(reject["code"]),
                dsn=reject["dsn"] or "",
                detail=clean(reject["text"], 200),
                extras={"stage": reject["stage"]},
            )

        tls = _TLS.match(message)
        if tls:
            self.stats.parsed += 1
            return LogEvent(
                EventType.TLS,
                when,
                program,
                direction=direction_of_program(program),
                relay=clean(tls["peer"], 128),
                status=tls["kind"].split()[0].lower(),
                detail=clean(f"{tls['proto']} {tls['cipher']}", 100),
            )
        if _TLS_FAIL.match(message):
            self.stats.parsed += 1
            return LogEvent(
                EventType.TLS,
                when,
                program,
                status="failed",
                detail=clean(message, 200),
                direction=direction_of_program(program),
            )

        if "warning:" in message or "error:" in message or "fatal:" in message or "panic:" in message:
            self.stats.parsed += 1
            return LogEvent(EventType.WARNING, when, program, detail=clean(message, 300))

        # Периодические сообщения самого Postfix (статистика anvil, «system is running»,
        # перезагрузка) — известная шумовая часть, а не нераспознанное.
        if program.startswith(
            ("postfix/anvil", "postfix/postfix-script", "postfix/master", "postfix/postlog")
        ) or message.startswith(
            ("statistics:", "reload --", "daemon started", "starting the Postfix", "NOQUEUE: lost connection")
        ):
            self.stats.ignored += 1
            return None

        self.stats.unparsed += 1
        return None

    def _remember(
        self,
        qid: str,
        *,
        direction: Direction | None = None,
        sender: str | None = None,
        message_id: str | None = None,
    ) -> None:
        if len(self._direction) > self.MAX_TRACKED:
            # Переполнение означает, что строки «removed» не приходят (журнал обрезан или очередь
            # огромна). Лучше забыть самые старые, чем расти без предела.
            for old in list(self._direction)[: self.MAX_TRACKED // 10]:
                self._forget(old)
        if direction is not None:
            self._direction[qid] = direction
        if sender is not None:
            self._sender[qid] = sender
        if message_id is not None:
            self._message_id[qid] = message_id

    def _forget(self, qid: str) -> None:
        self._direction.pop(qid, None)
        self._sender.pop(qid, None)
        self._message_id.pop(qid, None)

    def _queued(self, when: datetime, program: str, qid: str, rest: str) -> LogEvent | None:
        direction = self._direction.get(qid, Direction.UNKNOWN)

        client = _CLIENT.match(rest)
        if client:
            self._remember(qid, direction=direction_of_program(program))
            self.stats.parsed += 1
            return LogEvent(
                EventType.ACCEPTED,
                when,
                program,
                queue_id=qid,
                direction=direction_of_program(program),
                client_address=clean(client["ip"], 64),
            )

        mid = _MESSAGE_ID.match(rest)
        if mid:
            self._remember(qid, message_id=clean(mid["id"], 255))
            self.stats.parsed += 1
            return LogEvent(
                EventType.QUEUED,
                when,
                program,
                queue_id=qid,
                direction=direction,
                message_id=clean(mid["id"], 255),
                detail="message-id",
            )

        sender = _FROM.match(rest)
        if sender:
            self._remember(qid, sender=clean(sender["sender"]))
            self.stats.parsed += 1
            return LogEvent(
                EventType.QUEUED,
                when,
                program,
                queue_id=qid,
                direction=direction,
                envelope_from=clean(sender["sender"]),
                recipients_count=int(sender["nrcpt"]) if sender["nrcpt"] else None,
                message_id=self._message_id.get(qid, ""),
                extras={"size": sender["size"] or ""},
                status="queued",
            )

        delivery = _DELIVERY.match(rest)
        if delivery:
            return self._delivery(when, program, qid, direction, delivery)

        remote = _REMOTE_SAID.match(rest)
        if remote:
            self.stats.parsed += 1
            return LogEvent(
                EventType.REMOTE_REPLY,
                when,
                program,
                queue_id=qid,
                direction=direction,
                relay=clean(remote["peer"], 128),
                smtp_code=int(remote["code"]),
                dsn=remote["dsn"] or "",
                status="refused" if remote["code"][0] == "5" else "deferred",
                detail=clean(remote["text"], 200),
                extras={"stage": clean(remote["stage"] or "", 64)},
            )

        bounce = _BOUNCE.match(rest)
        if bounce:
            self.stats.parsed += 1
            return LogEvent(
                EventType.BOUNCE_NOTICE,
                when,
                program,
                queue_id=qid,
                direction=direction,
                detail=bounce["what"],
                extras={"notice_queue_id": clean(bounce["new"], 32)},
            )

        if rest.strip() == "removed":
            self.stats.parsed += 1
            event = LogEvent(
                EventType.REMOVED,
                when,
                program,
                queue_id=qid,
                direction=direction,
                envelope_from=self._sender.get(qid, ""),
                message_id=self._message_id.get(qid, ""),
                status="removed",
            )
            self._forget(qid)
            return event

        if "warning:" in rest or "error:" in rest:
            self.stats.parsed += 1
            return LogEvent(
                EventType.WARNING, when, program, queue_id=qid, direction=direction, detail=clean(rest, 300)
            )

        self.stats.unparsed += 1
        return None

    def _delivery(
        self, when: datetime, program: str, qid: str, direction: Direction, delivery: re.Match[str]
    ) -> LogEvent:
        self.stats.parsed += 1
        relay = clean(delivery["relay"], 128)
        text = delivery["text"] or ""
        code = _SMTP_CODE.search(text)
        shadow = delivery["to"].startswith(("journal-in@", "journal-out@")) or relay == "msp-journal"
        return LogEvent(
            EventType.SHADOW if shadow else EventType.DELIVERY,
            when,
            program,
            queue_id=qid,
            direction=direction,
            envelope_from=self._sender.get(qid, ""),
            relay=relay,
            status=delivery["status"],
            smtp_code=int(code["code"]) if code else None,
            delay=float(delivery["delay"]),
            dsn=delivery["dsn"],
            message_id=self._message_id.get(qid, ""),
            detail=clean(text, 200),
            # Получатель не сохраняется адресом: событие должно считаться по числу, а не по людям.
            recipients_count=1,
        )
