"""Агент узла: журнал → метрики, состояние очереди и диска, события наружу (ТЗ 1.1 §38, §45).

Принцип: агент наблюдает, но не стоит на пути письма. Он читает журнал Postfix, спрашивает
очередь у самого Postfix (``postqueue -j``, каталог очереди напрямую не читается — ТЗ §34) и
отдаёт метрики. Если агент остановится, Postfix продолжит принимать и доставлять почту;
пропадёт только наблюдаемость, и об этом скажет метрика ``msp_gateway_node_up`` и тишина в
панели управления.

Связь с панелью управления односторонняя и терпит её отсутствие: события складываются в файл
(``outbox.jsonl``) ограниченного размера и отправляются, когда панель снова доступна. Недоступная
панель не останавливает ни приём, ни доставку и не растит память агента.

Только стандартная библиотека: модуль работает на узле.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import sys
import threading
import time
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .apply import Runner, subprocess_runner
from .logparser import LogParser
from .metrics import Metrics, age_seconds, parse_postqueue_json
from .state import (
    PressureState,
    RecipientFreshness,
    classify_freshness,
    classify_pressure,
    is_draining,
    read_disk,
    set_recipient_gate,
)

_NODE_ID = re.compile(r"^[0-9a-f]{32}$")

#: За один проход читается не больше, чем это: журнал за время простоя агента может быть огромным,
#: а память агента не должна зависеть от того, сколько писем пришло, пока он не работал.
MAX_READ_BYTES = 4 * 1024 * 1024
MAX_LINE_BYTES = 8192

#: Снимок очереди старше этого считается устаревшим (секунды).
SNAPSHOT_MAX_AGE = 60.0


def node_identity(state_dir: Path) -> str:
    """Постоянный идентификатор узла: переживает перезапуск, не зависит от имени хоста.

    Имя хоста в контейнере меняется при каждом пересоздании, а по идентификатору панель связывает
    историю узла; поэтому он хранится в томе состояния и не строится из внешних данных.
    """
    path = state_dir / "node_id"
    try:
        value = path.read_text(encoding="ascii").strip()
        if _NODE_ID.match(value):
            return value
    except OSError:
        pass
    value = uuid.uuid4().hex
    state_dir.mkdir(parents=True, exist_ok=True)
    temp = path.with_name("node_id.tmp")
    temp.write_text(value, encoding="ascii")
    os.replace(temp, path)
    return value


class LogTailer:
    """Чтение новых строк файла с учётом ротации и усечения.

    Неполная последняя строка не отдаётся, пока не допишется: Postfix пишет построчно, но чтение
    может попасть посреди записи, и половина строки разобралась бы как другое событие.
    """

    def __init__(self, path: Path, *, from_start: bool = False) -> None:
        self.path = path
        self._from_start = from_start
        self._position: int | None = None
        self._inode: int | None = None
        self._partial = b""
        self.overflow_bytes = 0

    def read_new(self) -> list[str]:
        try:
            stat = self.path.stat()
        except OSError:
            return []
        rotated = self._inode is not None and stat.st_ino != self._inode
        if self._position is None:
            self._position = 0 if self._from_start else stat.st_size
        elif rotated or stat.st_size < self._position:
            self._position = 0
            self._partial = b""
        self._inode = stat.st_ino
        if stat.st_size <= self._position:
            return []
        want = stat.st_size - self._position
        if want > MAX_READ_BYTES:
            # Слишком много накопилось: берём хвост, а пропущенное честно считаем.
            self.overflow_bytes += want - MAX_READ_BYTES
            self._position = stat.st_size - MAX_READ_BYTES
            self._partial = b""
            want = MAX_READ_BYTES
        try:
            with self.path.open("rb") as handle:
                handle.seek(self._position)
                chunk = handle.read(want)
        except OSError:
            return []
        self._position += len(chunk)
        data = self._partial + chunk
        *complete, self._partial = data.split(b"\n")
        if len(self._partial) > MAX_LINE_BYTES:
            self._partial = b""  # строка без конца и без разумной длины — не копим
        return [line[:MAX_LINE_BYTES].decode("utf-8", "replace") for line in complete if line]


class Outbox:
    """Файловая очередь событий для панели: ограничена по размеру, переживает перезапуск."""

    def __init__(self, path: Path, *, max_events: int = 5000) -> None:
        self.path = path
        self.max_events = max_events
        self.dropped = 0

    def _load(self) -> list[str]:
        try:
            return [x for x in self.path.read_text(encoding="utf-8").splitlines() if x]
        except OSError:
            return []

    def _store(self, lines: list[str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_name(self.path.name + ".tmp")
        temp.write_text("".join(x + "\n" for x in lines), encoding="utf-8")
        os.replace(temp, self.path)

    def append(self, event: dict[str, object]) -> None:
        lines = self._load()
        lines.append(json.dumps(event, ensure_ascii=False, sort_keys=True))
        if len(lines) > self.max_events:
            excess = len(lines) - self.max_events
            self.dropped += excess
            lines = lines[excess:]  # теряем самые старые: свежие события важнее для оператора
        self._store(lines)

    def pending(self) -> list[dict[str, object]]:
        events: list[dict[str, object]] = []
        for line in self._load():
            with contextlib.suppress(ValueError):
                value = json.loads(line)
                if isinstance(value, dict):
                    events.append(value)
        return events

    def flush(self, sender: Callable[[list[dict[str, object]]], None], *, batch: int = 100) -> int:
        """Отправить накопленное; при любой ошибке оставить всё на месте. Вернуть число отправленных."""
        sent = 0
        while True:
            lines = self._load()
            if not lines:
                return sent
            part = lines[:batch]
            decoded: list[dict[str, object]] = []
            for line in part:
                with contextlib.suppress(ValueError):
                    value = json.loads(line)
                    if isinstance(value, dict):
                        decoded.append(value)
            try:
                if decoded:
                    sender(decoded)
            except Exception:  # noqa: BLE001 - панель недоступна: оставляем события до следующего раза
                return sent
            self._store(lines[len(part) :])
            sent += len(decoded)


def http_sender(
    url: str, token: str, node_id: str, *, timeout: float = 5.0
) -> Callable[[list[dict[str, object]]], None]:
    """Отправка пакета событий в панель. Токен нигде не записывается и не попадает в ошибки."""
    if not url.startswith(("https://", "http://")):
        raise ValueError("адрес панели должен быть http(s)")

    def send(events: list[dict[str, object]]) -> None:
        body = json.dumps({"node_id": node_id, "events": events}).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - схема проверена выше
            url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310  # nosec B310
            if response.status >= 300:
                raise OSError(f"панель ответила {response.status}")

    return send


@dataclass(frozen=True)
class Thresholds:
    disk_pressure_free_bytes: int = 5 * 1024**3
    disk_critical_free_bytes: int = 1 * 1024**3
    queue_pressure_messages: int = 1000
    queue_critical_messages: int = 5000
    recipients_fresh_seconds: float = 3600.0
    recipients_grace_seconds: float = 7200.0


def read_recipient_generated_at(state_dir: Path) -> datetime | None:
    """Время формирования справочника из ``recipients.meta.json``; ``None`` — справочника нет."""
    try:
        data = json.loads((state_dir / "recipients.meta.json").read_text(encoding="utf-8"))
        value = datetime.fromisoformat(str(data["generated_at"]))
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class Agent:
    def __init__(
        self,
        *,
        state_dir: Path,
        log_path: Path,
        role: str,
        data_dir: Path | None = None,
        queue_snapshot: Path | None = None,
        runner: Runner = subprocess_runner,
        thresholds: Thresholds | None = None,
        disk_reader: Callable[[], int] | None = None,
        config_reader: Callable[[], tuple[str, str]] | None = None,
        manage_gate: bool = False,
    ) -> None:
        self.state_dir = state_dir
        self.runner = runner
        self.queue_snapshot = queue_snapshot
        self.thresholds = thresholds or Thresholds()
        self.metrics = Metrics()
        self.metrics.node_role = role
        self.parser = LogParser(year=datetime.now(UTC).year)
        self.tailer = LogTailer(log_path)
        # Собственные данные агента (идентификатор, очередь событий) лежат отдельно от состояния
        # Postfix: агент не вправе писать в каталог, который читает Postfix.
        self.data_dir = data_dir or state_dir
        self.outbox = Outbox(self.data_dir / "outbox.jsonl")
        self.node_id = node_identity(self.data_dir)
        self._disk_reader = disk_reader or (lambda: read_disk().free_bytes)
        self._config_reader = config_reader or (lambda: ("", ""))
        self._manage_gate = manage_gate
        self._freshness: RecipientFreshness | None = None
        self._pressure: PressureState | None = None
        self.last_collect: float = 0.0

    def event(self, kind: str, **data: object) -> None:
        self.outbox.append(
            {"type": kind, "at": datetime.now(UTC).isoformat(), "node_id": self.node_id, **data}
        )

    def collect_once(self, now: datetime | None = None) -> None:
        now = now or datetime.now(UTC)
        self.metrics.observe_all(self.parser.parse_lines(self.tailer.read_new()))

        # Postfix не ответил или снимок устарел — остаётся прошлый снимок очереди
        with contextlib.suppress(Exception):
            lines = self._queue_lines()
            if lines is not None:
                self.metrics.queue = parse_postqueue_json(lines, now=now.timestamp())

        try:
            self.metrics.disk_free_bytes = self._disk_reader()
        except OSError:
            self.metrics.disk_free_bytes = None

        t = self.thresholds
        free = self.metrics.disk_free_bytes
        self._update_pressure(free, self.metrics.queue.messages)

        age = age_seconds(read_recipient_generated_at(self.state_dir), now)
        self.metrics.recipient_map_age = age
        freshness = classify_freshness(
            age_seconds=age,
            fresh_seconds=t.recipients_fresh_seconds,
            grace_seconds=t.recipients_grace_seconds,
        )
        if freshness is not self._freshness:
            if self._manage_gate:
                set_recipient_gate(freshness, state_dir=self.state_dir)
            if self._freshness is not None or freshness is not RecipientFreshness.FRESH:
                self.event("recipient_freshness", state=freshness.value, age_seconds=age)
            self._freshness = freshness

        self.metrics.config_version, self.metrics.config_checksum = self._config_reader()
        self.last_collect = time.monotonic()

    def _queue_lines(self) -> list[str] | None:
        """Очередь: из снимка, который кладёт root-цикл контейнера, либо напрямую у Postfix.

        В контейнере действует ``no-new-privileges``, и setgid-бинарник ``postqueue`` у обычного
        пользователя не получает нужной группы. Давать агенту группу ``postdrop`` (право писать в
        каталог входящей почты) ради чтения числа писем не стоит, поэтому снимок снимает root, а
        агент его только читает. Устаревший снимок (цикл остановился) не используется: старое число
        писем выглядело бы как свежее.
        """
        if self.queue_snapshot is not None:
            try:
                age = time.time() - self.queue_snapshot.stat().st_mtime
                if age > SNAPSHOT_MAX_AGE:
                    return None
                return self.queue_snapshot.read_text(encoding="utf-8").splitlines()
            except OSError:
                return None
        result = self.runner(["postqueue", "-j"], timeout=30.0)
        return result.stdout.splitlines() if result.returncode == 0 else None

    def _update_pressure(self, free: int | None, queue_messages: int) -> None:
        t = self.thresholds
        state = classify_pressure(
            free_bytes=free if free is not None else 0,
            queue_messages=queue_messages,
            draining=is_draining(self.state_dir),
            disk_pressure_free_bytes=t.disk_pressure_free_bytes,
            disk_critical_free_bytes=t.disk_critical_free_bytes,
            queue_pressure_messages=t.queue_pressure_messages,
            queue_critical_messages=t.queue_critical_messages,
        )
        if free is None and state is PressureState.NORMAL:
            # Диск не измерили: «норма» была бы выдумкой, поэтому состояние не меняем.
            return
        self.metrics.pressure = state
        if state is not self._pressure:
            if self._pressure is not None:
                self.event("pressure", state=state.value, previous=self._pressure.value)
            self._pressure = state

    def heartbeat(self) -> None:
        self.event(
            "heartbeat",
            config_version=self.metrics.config_version,
            queue_messages=self.metrics.queue.messages,
            pressure=self.metrics.pressure.value,
            unparsed_log_lines=self.parser.stats.unparsed,
            log_overflow_bytes=self.tailer.overflow_bytes,
        )


def make_handler(agent: Agent, *, stale_after: float = 120.0) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/metrics":
                body, status = agent.metrics.render().encode("utf-8"), 200
                ctype = "text/plain; version=0.0.4; charset=utf-8"
            elif self.path == "/healthz":
                fresh = agent.last_collect > 0 and (time.monotonic() - agent.last_collect) < stale_after
                body, status, ctype = (
                    (b"ok\n" if fresh else b"stale\n"),
                    (200 if fresh else 503),
                    "text/plain",
                )
            else:
                body, status, ctype = b"not found\n", 404, "text/plain"
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return  # адреса клиентов метрик в журнал агента не пишутся

    return Handler


def serve_metrics(agent: Agent, host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(agent))
    threading.Thread(target=server.serve_forever, name="metrics", daemon=True).start()
    return server


def run_forever(
    agent: Agent,
    *,
    interval: float = 10.0,
    sender: Callable[[list[dict[str, object]]], None] | None = None,
    heartbeat_every: float = 60.0,
) -> None:  # pragma: no cover - цикл, проверяется на стенде
    last_beat = 0.0
    while True:
        try:
            agent.collect_once()
            if time.monotonic() - last_beat >= heartbeat_every:
                agent.heartbeat()
                last_beat = time.monotonic()
            if sender is not None:
                agent.outbox.flush(sender)
        except Exception as error:  # noqa: BLE001 - один плохой проход не останавливает агента
            print(f"agent: проход не удался: {type(error).__name__}", file=sys.stderr, flush=True)
        time.sleep(interval)
