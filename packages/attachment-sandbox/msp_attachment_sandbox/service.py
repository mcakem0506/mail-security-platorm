"""Сервис песочницы: задания через каталог-очередь, без сети (ТЗ 1.1 §55).

Запуск: ``python -m msp_attachment_sandbox.service``. Контейнер с этим сервисом работает без сетевых
интерфейсов (``network_mode: none``), от непривилегированного пользователя, с файловой системой
только для чтения и временным рабочим каталогом в памяти. Единственное, чем он связан с миром, —
каталог очереди:

    <spool>/in/<id>.job    задание: JSON {"module": "...", "job": {...}}
    <spool>/out/<id>.res   результат: JSON, тот же, что вернул бы воркер
    <spool>/work/          рабочий каталог сервиса (то, что в нём лежит, — только он сам)

Почему каталог, а не сокет: у контейнера нет сети, а сокет в общем томе — это тоже канал, который
надо защищать правами. Каталог проще проверить: имена файлов — случайные идентификаторы, размеры
ограничены, а читать и писать там может только родитель и этот сервис.

Свойства:

* **Сервис не доверяет заданиям.** Имя воркера выбирается из закрытого списка, размер ограничен,
  идентификатор — строго 32 шестнадцатеричных символа (ни путей, ни обхода каталогов).
* **Каждое задание — отдельный процесс-воркер** со своими пределами (``limits.py``); сбой одного не
  касается следующих. Остановка сервиса не теряет задания: они остаются в ``in`` и будут взяты
  после запуска.
* **Очистка.** Обработанное задание удаляется; результат, который никто не забрал за
  ``RESULT_TTL`` секунд, удаляется сервисом. Зависших файлов не копится.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from . import runner

#: Допустимые воркеры: имя модуля → таймаут. Всё остальное сервис не запускает.
ALLOWED_WORKERS: dict[str, float] = {
    runner.ARCHIVE_WORKER: runner.ARCHIVE_TIMEOUT_SECONDS,
    runner.PDF_WORKER: runner.PDF_TIMEOUT_SECONDS,
}
MAX_JOB_BYTES = 40 * 1024 * 1024
RESULT_TTL = 300.0
POLL_INTERVAL = 0.2
_ID = re.compile(r"^[0-9a-f]{32}$")


def spool_dirs(spool: Path) -> tuple[Path, Path, Path]:
    return spool / "in", spool / "out", spool / "work"


def _write_atomic(path: Path, payload: dict[str, Any]) -> None:
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(temp, path)


def _failure(status: str, detail: str) -> dict[str, Any]:
    return {"status": status, "flags": [], "detail": detail, "pages": []}


def process_job(path: Path, out_dir: Path) -> bool:
    """Обработать один файл задания. Возвращает ``True``, если файл был заданием."""
    job_id = path.name.removesuffix(".job")
    if not path.name.endswith(".job") or not _ID.match(job_id):
        return False
    result_path = out_dir / f"{job_id}.res"
    try:
        size = path.stat().st_size
        if size > MAX_JOB_BYTES:
            _write_atomic(result_path, _failure("LIMIT_EXCEEDED", "задание больше допустимого"))
        else:
            try:
                request = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                request = None
            module = request.get("module") if isinstance(request, dict) else None
            job = request.get("job") if isinstance(request, dict) else None
            if module not in ALLOWED_WORKERS or not isinstance(job, dict):
                _write_atomic(result_path, _failure("PROTOCOL_ERROR", "неизвестный воркер или задание"))
            else:
                outcome = runner.run_local(module, job, timeout=ALLOWED_WORKERS[module])
                payload = dict(outcome.payload) if outcome.payload else {}
                payload["status"] = outcome.status
                if outcome.detail:
                    payload["detail"] = outcome.detail
                _write_atomic(result_path, payload)
    except OSError:
        return True  # файл остался: будет взят снова
    finally:
        with contextlib.suppress(OSError):
            path.unlink()
    return True


def sweep_results(out_dir: Path, now: float | None = None) -> int:
    """Удалить результаты, которые никто не забрал."""
    now = time.time() if now is None else now
    removed = 0
    for entry in out_dir.iterdir():
        try:
            if now - entry.stat().st_mtime > RESULT_TTL:
                entry.unlink()
                removed += 1
        except OSError:
            continue
    return removed


def run_once(spool: Path) -> int:
    """Один проход по очереди. Возвращает число обработанных заданий."""
    in_dir, out_dir, _work = spool_dirs(spool)
    handled = 0
    try:
        entries = sorted(in_dir.iterdir(), key=lambda p: p.stat().st_mtime)
    except OSError:
        return 0
    for entry in entries:
        if process_job(entry, out_dir):
            handled += 1
    sweep_results(out_dir)
    sweep_results(in_dir)  # чужие и брошенные файлы тоже не копятся
    return handled


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - цикл
    spool = Path((argv or sys.argv[1:] or [os.environ.get("MSP_SANDBOX_SPOOL", "/spool")])[0])
    for directory in spool_dirs(spool):
        directory.mkdir(parents=True, exist_ok=True)
    alive = spool / "work" / "alive"
    last_beat = 0.0
    while True:
        if time.monotonic() - last_beat > 5.0:
            # Отметка живости для проверки здоровья контейнера.
            with contextlib.suppress(OSError):
                alive.write_text(str(time.time()), encoding="utf-8")
            last_beat = time.monotonic()
        if run_once(spool) == 0:
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
