"""Запись копии письма в локальный журнал (ТЗ 1.1 §34).

Этот модуль запускает сам Postfix как транспорт ``pipe``: каждое письмо, получившее копию
через ``always_bcc``, подаётся ему на стандартный ввод. Он написан так, чтобы **никогда не
мешать основной доставке**, и все его решения следуют из этого.

* Завершается с кодом 0 всегда, даже при сбое записи. Ненулевой код Postfix истолковал бы как
  отказ доставки копии, отложил бы её и в конце срока вернул **отправителю** уведомление о
  недоставке, адресованное получателю, о существовании которого отправитель не знал. То есть
  сбой тени стал бы виден людям снаружи. Потерянная копия для анализа — потеря наблюдения,
  а не почты, и считается отдельной метрикой, по которой есть тревога.
* Пишет во временный файл и переименовывает: коллектор видит либо готовую копию, либо ничего.
* Не доверяет ничему, что пришло в аргументах: они приходят от Postfix, но содержат значения,
  заданные клиентом (HELO, адрес отправителя).
* Использует только стандартную библиотеку: образ Postfix не должен нести зависимости продукта.

Формат записи: первая строка ``MSPJ1 <base64 от JSON>``, затем письмо как есть. Заголовок
письма не используется для метаданных намеренно: отправитель может написать любой заголовок,
а первая строка файла принадлежит только нам.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import sys
import time
import uuid

#: Минимум свободного места в томе журнала. Ниже — копии не пишутся: журнал не должен съесть
#: том, на котором живёт очередь.
MIN_FREE_BYTES = 256 * 1024 * 1024

#: Предел размера одной копии. Выше предела письмо Postfix не принял бы в любом случае, но
#: защита от неверно настроенного лимита дешёвая.
MAX_COPY_BYTES = 1024 * 1024 * 1024

_QUEUE_ID = re.compile(r"^[0-9A-Za-z]{5,40}$")
_DIRECTION = re.compile(r"^journal-(in|out)@")

MAGIC = b"MSPJ1 "


def _directory() -> str:
    return os.environ.get("MSP_JOURNAL_DIR", "/var/lib/msp/journal")


def parse_direction(recipient: str) -> str:
    """Направление определяется слушателем, принявшим письмо (ТЗ §30), а не доменом отправителя."""
    match = _DIRECTION.match(recipient or "")
    if match is None:
        return "UNKNOWN"
    return "INBOUND" if match.group(1) == "in" else "OUTBOUND"


def _count_drop(directory: str) -> None:
    """Учесть потерянную копию. Один байт на потерю: счёт — размер файла."""
    try:
        fd = os.open(os.path.join(directory, ".dropped"), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, b".")
        finally:
            os.close(fd)
    except OSError:
        # Нечем даже посчитать. Это и есть крайний случай, и тихо уйти здесь честнее, чем
        # падать: ненулевой код хуже потерянной копии (см. описание модуля).
        pass


def write_copy(
    stream,  # type: ignore[no-untyped-def]
    *,
    queue_id: str,
    recipient: str,
    sender: str,
    client_address: str,
    client_helo: str,
    size: str,
    directory: str | None = None,
) -> str | None:
    """Записать копию. Возвращает имя файла или ``None``, если копия потеряна."""
    root = directory or _directory()
    try:
        for sub in ("tmp", "new"):
            os.makedirs(os.path.join(root, sub), mode=0o700, exist_ok=True)
        if shutil.disk_usage(root).free < MIN_FREE_BYTES:
            _count_drop(root)
            return None

        meta = {
            "queue_id": queue_id if _QUEUE_ID.match(queue_id or "") else "",
            "direction": parse_direction(recipient),
            "envelope_from": (sender or "")[:320],
            "client_address": (client_address or "")[:64],
            "client_helo": (client_helo or "")[:255],
            "declared_size": int(size) if (size or "").isdigit() else None,
            "journaled_at": time.time(),
        }
        header = MAGIC + base64.b64encode(json.dumps(meta, sort_keys=True).encode()) + b"\n"

        name = f"{int(time.time() * 1000):013d}-{meta['queue_id'] or 'noid'}-{uuid.uuid4().hex[:8]}.msj"
        temp = os.path.join(root, "tmp", name)
        written = 0
        with open(temp, "wb") as out:
            out.write(header)
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_COPY_BYTES:
                    raise OSError("copy exceeds the cap")
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, os.path.join(root, "new", name))
        return name
    except Exception:  # noqa: BLE001 - любая причина сводится к одному: копии нет
        _count_drop(root)
        return None


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    args += [""] * (6 - len(args))
    queue_id, recipient, sender, client_address, client_helo, size = args[:6]
    write_copy(
        sys.stdin.buffer,
        queue_id=queue_id,
        recipient=recipient,
        sender=sender,
        client_address=client_address,
        client_helo=client_helo,
        size=size,
    )
    # Всегда успех: см. описание модуля.
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
