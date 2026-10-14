"""Сборщик теневых копий: журнал узла → анализ (ТЗ 1.1 §34, §35, §58, §68.16).

Сборщик — отдельный процесс, не звено доставки. Письмо к этому моменту уже передано Exchange
(или лежит в очереди Postfix независимо от нас); сборщик лишь забирает *копию*, которую
записал ``journal_writer``. Поэтому любой его сбой — недоступная панель, битый файл, нехватка
места, остановка процесса — не может ни задержать, ни отклонить, ни потерять почту
(политика ``DETECTION_FAILS_OPEN_FOR_DELIVERY``). Цена сбоя — потеря *наблюдения*, и она
считается отдельно (файл состояния, метрика ``msp_gateway_shadow_failures_total``), а не
скрывается.

Гарантии самого сборщика:

* **Доставка «не меньше одного раза».** Файл переносится из ``new`` в ``done`` только после того,
  как приёмник подтвердил приём. Упал сборщик посреди — файл остаётся и будет отправлен снова.
* **Идемпотентность.** Повтор не создаёт второго анализа: у копии стабильный ключ (направление,
  Message-ID, SHA-256 содержимого, отпечаток конверта), и приёмник обязан принимать его повторно.
  Локально файл в ``done`` называется по ключу, поэтому дубль перезаписывает сам себя.
* **Битое не блокирует хорошее.** Файл, который не удаётся разобрать, уходит в ``bad`` и не
  мешает остальным; он остаётся там для разбора человеком до конца срока хранения.
* **Недоверие к содержимому.** Письмо разбирается только в части заголовков и в пределах
  размера; метаданные файла проверяются по типам и длинам. Содержимое письма не исполняется,
  не открывается и не интерпретируется.

Только стандартная библиотека: модуль работает на узле.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import json
import os
import re
import time
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .journal_writer import MAGIC

#: Строка заголовка файла длиннее этого — не наша запись.
MAX_HEADER_LINE = 16 * 1024
#: Предел копии, которую сборщик согласен читать. Совпадает с пределом писателя.
MAX_COPY_BYTES = 1024 * 1024 * 1024
#: Сколько байт письма смотрим при разборе заголовков.
HEADER_SCAN_BYTES = 256 * 1024

_DIRECTIONS = frozenset({"INBOUND", "OUTBOUND", "UNKNOWN"})
_QUEUE_ID = re.compile(r"^[0-9A-Za-z]{0,40}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MESSAGE_ID = re.compile(rb"^message-id:[ \t]*(.*?)\r?$", re.IGNORECASE | re.MULTILINE)
_HEADER_END = re.compile(rb"\r?\n\r?\n")


class CopyError(Exception):
    """Файл копии не разобрать; он уходит в карантин."""


@dataclass(frozen=True)
class CopyRecord:
    """Всё, что известно о копии, кроме самого письма."""

    key: str
    direction: str
    message_id: str
    sha256: str
    size: int
    envelope_fingerprint: str
    queue_id: str
    client_address: str
    client_helo: str
    journaled_at: float
    declared_size: int | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "idempotency_key": self.key,
            "direction": self.direction,
            "message_id": self.message_id,
            "sha256": self.sha256,
            "size": self.size,
            "envelope_fingerprint": self.envelope_fingerprint,
            "queue_id": self.queue_id,
            "client_address": self.client_address,
            "client_helo": self.client_helo,
            "journaled_at": self.journaled_at,
            "declared_size": self.declared_size,
        }


def _text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return _CONTROL.sub("?", value)[:limit]


def _number(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return float(value) if 0 <= value < 1e12 else 0.0


def parse_meta(line: bytes) -> dict[str, object]:
    """Разобрать первую строку файла. Любое отклонение от формата — ``CopyError``."""
    if not line.startswith(MAGIC):
        raise CopyError("нет сигнатуры MSPJ1")
    try:
        meta = json.loads(base64.b64decode(line[len(MAGIC) :].strip(), validate=True))
    except (binascii.Error, ValueError) as error:
        raise CopyError("заголовок не разбирается") from error
    if not isinstance(meta, dict):
        raise CopyError("заголовок не объект")
    direction = meta.get("direction")
    if direction not in _DIRECTIONS:
        raise CopyError("неизвестное направление")
    queue_id = meta.get("queue_id", "")
    if not isinstance(queue_id, str) or not _QUEUE_ID.match(queue_id):
        raise CopyError("недопустимый идентификатор очереди")
    declared = meta.get("declared_size")
    return {
        "direction": direction,
        "queue_id": queue_id,
        "envelope_from": _text(meta.get("envelope_from"), 320),
        "client_address": _text(meta.get("client_address"), 64),
        "client_helo": _text(meta.get("client_helo"), 255),
        "journaled_at": _number(meta.get("journaled_at")),
        "declared_size": declared if isinstance(declared, int) and not isinstance(declared, bool) else None,
    }


def extract_message_id(head: bytes) -> str:
    """Message-ID из заголовков; пусто, если его нет. Тело письма не просматривается."""
    end = _HEADER_END.search(head)
    headers = head[: end.start()] if end else head
    # Складчатые заголовки: продолжение строки начинается с пробела или табуляции.
    unfolded = re.sub(rb"\r?\n[ \t]+", b" ", headers)
    match = _MESSAGE_ID.search(unfolded)
    if match is None:
        return ""
    return _text(match.group(1).decode("utf-8", "replace").strip(), 998)


def make_key(direction: str, message_id: str, sha256: str, envelope_fingerprint: str) -> str:
    """Стабильный ключ копии. Поля разделены символом, которого нет ни в одном из них."""
    joined = "\x1f".join((direction, message_id, sha256, envelope_fingerprint))
    return hashlib.sha256(joined.encode("utf-8", "replace")).hexdigest()


def read_copy(path: Path) -> CopyRecord:
    """Прочитать файл копии и вычислить запись. Содержимое письма не загружается целиком."""
    try:
        with path.open("rb") as handle:
            line = handle.readline(MAX_HEADER_LINE + 1)
            if len(line) > MAX_HEADER_LINE or not line.endswith(b"\n"):
                raise CopyError("заголовок слишком длинный или не закончен")
            meta = parse_meta(line)
            digest = hashlib.sha256()
            head = b""
            size = 0
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_COPY_BYTES:
                    raise CopyError("копия больше предела")
                if len(head) < HEADER_SCAN_BYTES:
                    head += chunk[: HEADER_SCAN_BYTES - len(head)]
                digest.update(chunk)
    except OSError as error:
        raise CopyError(f"файл не читается: {type(error).__name__}") from error
    if size == 0:
        raise CopyError("в копии нет письма")
    sha256 = digest.hexdigest()
    message_id = extract_message_id(head)
    fingerprint = hashlib.sha256(str(meta["envelope_from"]).encode("utf-8", "replace")).hexdigest()
    direction = str(meta["direction"])
    return CopyRecord(
        key=make_key(direction, message_id, sha256, fingerprint),
        direction=direction,
        message_id=message_id,
        sha256=sha256,
        size=size,
        envelope_fingerprint=fingerprint,
        queue_id=str(meta["queue_id"]),
        client_address=str(meta["client_address"]),
        client_helo=str(meta["client_helo"]),
        journaled_at=float(meta["journaled_at"]),  # type: ignore[arg-type]
        declared_size=meta["declared_size"],  # type: ignore[arg-type]
    )


def message_bytes(path: Path) -> bytes:
    """Само письмо (без служебной строки). Читается только при отправке приёмнику."""
    with path.open("rb") as handle:
        handle.readline(MAX_HEADER_LINE + 1)
        return handle.read()


class Sink(Protocol):
    """Приёмник копий. ``deliver`` должен быть идемпотентным по ключу и бросать исключение при отказе."""

    def deliver(self, record: CopyRecord, raw: bytes) -> None: ...


class DirectorySink:
    """Складывает копии в каталог (лаборатория, отладка). Имя файла — ключ, поэтому повтор безвреден."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def deliver(self, record: CopyRecord, raw: bytes) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        meta = self.directory / f"{record.key}.json"
        mime = self.directory / f"{record.key}.eml"
        temp = mime.with_name(mime.name + ".tmp")
        temp.write_bytes(raw)
        os.replace(temp, mime)
        meta.write_text(json.dumps(record.as_dict(), sort_keys=True), encoding="utf-8")


def _header_safe(value: str, limit: int) -> str:
    """Значение для HTTP-заголовка: только печатный ASCII, без переводов строк и управляющих символов."""
    return "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in value)[:limit]


class HttpSink:
    """Передача панели управления. Тело — письмо как есть, метаданные — в заголовках.

    Токен хранится только в памяти процесса и не попадает ни в адрес, ни в сообщения об ошибках.
    """

    def __init__(self, url: str, token: str, *, node_id: str = "", timeout: float = 30.0) -> None:
        if not url.startswith(("https://", "http://")):
            raise ValueError("адрес приёмника должен быть http(s)")
        self.url = url
        self._token = token
        self.node_id = node_id
        self.timeout = timeout

    def headers(self, record: CopyRecord) -> dict[str, str]:
        """Заголовки запроса; вынесены, чтобы контракт с панелью проверялся тестом, а не глазами."""
        return {
            "Content-Type": "message/rfc822",
            "Authorization": f"Bearer {self._token}",
            "X-MSP-Idempotency-Key": record.key,
            "X-MSP-Node-Id": self.node_id,
            "X-MSP-Direction": record.direction,
            "X-MSP-Message-Id": _header_safe(record.message_id, 998),
            "X-MSP-Queue-Id": _header_safe(record.queue_id, 40),
            "X-MSP-Envelope-Fingerprint": record.envelope_fingerprint,
            "X-MSP-Client-Address": _header_safe(record.client_address, 64),
        }

    def deliver(self, record: CopyRecord, raw: bytes) -> None:
        request = urllib.request.Request(  # noqa: S310 - схема проверена в конструкторе
            self.url,
            data=raw,
            method="POST",
            headers=self.headers(record),
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310  # nosec B310
            if response.status >= 300:
                raise OSError(f"приёмник ответил {response.status}")


@dataclass
class CollectorStats:
    collected: int = 0
    duplicates: int = 0
    failed: int = 0
    quarantined: int = 0
    pruned: int = 0
    last_success: float = 0.0
    last_failure_reason: str = ""
    oldest_pending_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)


class Collector:
    def __init__(
        self,
        journal: Path,
        sink: Sink,
        *,
        retention_days: float = 7.0,
        batch: int = 200,
        clock: Callable[[], float] = time.time,
        status_file: Path | None = None,
    ) -> None:
        self.new = journal / "new"
        self.done = journal / "done"
        self.bad = journal / "bad"
        #: Отчёт лежит вне журнала: каталог журнала закрыт для всех, кроме сборщика, а агент
        #: наблюдения обязан видеть состояние сборщика, не видя самих писем.
        self.status_file = status_file or journal / "collector.status.json"
        self.sink = sink
        self.retention = retention_days * 86400
        self.batch = batch
        self.clock = clock
        self.stats = CollectorStats()

    def _pending(self) -> Iterator[Path]:
        try:
            names = sorted(p for p in self.new.iterdir() if p.suffix == ".msj" and p.is_file())
        except OSError:
            return
        yield from names[: self.batch]

    def run_once(self) -> CollectorStats:
        for directory in (self.done, self.bad):
            directory.mkdir(parents=True, exist_ok=True)
        now = self.clock()
        for path in self._pending():
            try:
                record = read_copy(path)
            except CopyError as error:
                self._quarantine(path, str(error))
                continue
            try:
                self.sink.deliver(record, message_bytes(path))
            except Exception as error:  # noqa: BLE001 - приёмник недоступен: файл остаётся до следующего прохода
                self.stats.failed += 1
                self.stats.last_failure_reason = type(error).__name__
                continue
            target = self.done / f"{record.key}.msj"
            if target.exists():
                self.stats.duplicates += 1
            os.replace(path, target)
            self.stats.collected += 1
            self.stats.last_success = now
        self.stats.oldest_pending_seconds = self._oldest_pending(now)
        self._prune(now)
        self._write_status()
        return self.stats

    def _oldest_pending(self, now: float) -> float:
        """Возраст самой старой копии, которая всё ещё ждёт отправки (после прохода, а не до него)."""
        oldest = 0.0
        try:
            names = [p for p in self.new.iterdir() if p.suffix == ".msj"]
        except OSError:
            return 0.0
        for path in names:
            with contextlib.suppress(OSError):
                oldest = max(oldest, now - path.stat().st_mtime)
        return oldest

    def _quarantine(self, path: Path, reason: str) -> None:
        self.stats.quarantined += 1
        self.stats.last_failure_reason = reason[:200]
        with contextlib.suppress(OSError):
            os.replace(path, self.bad / path.name)

    def _prune(self, now: float) -> None:
        for directory in (self.done, self.bad):
            try:
                entries = list(directory.iterdir())
            except OSError:
                continue
            for entry in entries:
                try:
                    if now - entry.stat().st_mtime > self.retention:
                        entry.unlink()
                        self.stats.pruned += 1
                except OSError:
                    continue

    def _write_status(self) -> None:
        """Состояние для агента: он превращает его в метрики и тревоги (ТЗ §46)."""
        data = {
            "collected": self.stats.collected,
            "duplicates": self.stats.duplicates,
            "failed": self.stats.failed,
            "quarantined": self.stats.quarantined,
            "last_success": self.stats.last_success,
            "last_failure_reason": self.stats.last_failure_reason,
            "oldest_pending_seconds": self.stats.oldest_pending_seconds,
            "updated_at": self.clock(),
        }
        temp = self.status_file.with_name(self.status_file.name + ".tmp")
        with contextlib.suppress(OSError):
            temp.write_text(json.dumps(data), encoding="utf-8")
            os.replace(temp, self.status_file)


def run_forever(collector: Collector, interval: float = 5.0) -> None:  # pragma: no cover - цикл
    while True:
        with contextlib.suppress(Exception):
            collector.run_once()
        time.sleep(interval)
