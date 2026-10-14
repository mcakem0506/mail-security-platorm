"""Запуск воркеров песочницы из родительского процесса (ТЗ 1.1 §55).

Родитель ничего не разбирает сам. Он запускает воркер отдельным процессом, отдаёт ему байты и
ждёт — не дольше таймаута, который ставит **снаружи** того, что ограничивает: зависший воркер
убивается родителем, а не собственным терпением. Любой исход, кроме нормального ответа,
превращается в *названный* статус (``TIMEOUT``, ``CRASHED``, ``OUTPUT_TOO_LARGE``,
``PROTOCOL_ERROR``), а не в исключение и не в пустой результат: пустой результат в вердикте читался
бы как «ничего не найдено», тогда как правда — «разобрать не удалось».

Среда воркера очищена: он не наследует переменных окружения родителя (там могут быть секреты и
адреса сервисов). Вывод ограничен по размеру.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import subprocess  # nosec B404 - запускает собственные воркеры, фиксированный argv
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ARCHIVE_WORKER = "msp_attachment_sandbox.archive_worker"
PDF_WORKER = "msp_attachment_sandbox.pdf_worker"

ARCHIVE_TIMEOUT_SECONDS = 20.0
PDF_TIMEOUT_SECONDS = 30.0
MAX_OUTPUT_BYTES = 80 * 1024 * 1024

#: Названные исходы запуска, кроме ответов самого воркера.
LAUNCH_STATUSES = frozenset({"TIMEOUT", "CRASHED", "OUTPUT_TOO_LARGE", "PROTOCOL_ERROR", "UNAVAILABLE"})


@dataclass
class SandboxResult:
    status: str
    payload: dict[str, Any] = field(default_factory=dict)
    detail: str = ""
    seconds: float = 0.0

    @property
    def flags(self) -> list[str]:
        return list(self.payload.get("flags") or [])

    @property
    def ok(self) -> bool:
        return self.status in {"OK"}


def _environment() -> dict[str, str]:
    """Минимум, без которого интерпретатор не запустится. Секретов родителя здесь нет."""
    keep = ("PATH", "SYSTEMROOT", "PYTHONPATH", "LD_LIBRARY_PATH", "TEMP", "TMP")
    env = {key: os.environ[key] for key in keep if key in os.environ}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # Воркер без права порождать потоки: числовым библиотекам нужен один поток (см. pdf_worker).
    for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
        env[name] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    return env


def run_worker(module: str, job: dict[str, Any], *, timeout: float) -> SandboxResult:
    """Выполнить задание: в сервисе-песочнице, если задан ``MSP_SANDBOX_SPOOL``, иначе здесь.

    Сервис — это отдельный контейнер без сети (ТЗ 1.1 §55). Если очередь настроена, но сервис не
    отвечает, возвращается ``TIMEOUT``: молчаливого перехода на локальный запуск нет, потому что
    он снял бы именно ту изоляцию, ради которой сервис запущен.
    """
    spool = os.environ.get("MSP_SANDBOX_SPOOL", "")
    if spool:
        return run_remote(Path(spool), module, job, timeout=timeout)
    return run_local(module, job, timeout=timeout)


def run_remote(spool: Path, module: str, job: dict[str, Any], *, timeout: float) -> SandboxResult:
    """Передать задание сервису через каталог-очередь и дождаться результата."""
    started = time.monotonic()
    job_id = uuid.uuid4().hex
    in_dir, out_dir = spool / "in", spool / "out"
    request = in_dir / f"{job_id}.job"
    result_file = out_dir / f"{job_id}.res"
    try:
        temp = in_dir / f"{job_id}.tmp"
        temp.write_text(json.dumps({"module": module, "job": job}), encoding="utf-8")
        os.replace(temp, request)
    except OSError as error:
        return SandboxResult("UNAVAILABLE", detail=f"очередь песочницы недоступна: {type(error).__name__}")
    deadline = started + timeout + 5.0  # запас на передачу через каталог
    unreadable = 0
    try:
        while time.monotonic() < deadline:
            if result_file.exists():
                try:
                    payload = json.loads(result_file.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    # Файл могли подменять в этот момент (на Windows чтение и замена не атомарны
                    # друг относительно друга). Несколько попыток, и только потом отказ.
                    unreadable += 1
                    if unreadable >= 5:
                        with contextlib.suppress(OSError):
                            result_file.unlink()
                        return SandboxResult("PROTOCOL_ERROR", detail="результат песочницы не читается")
                    time.sleep(0.1)
                    continue
                with contextlib.suppress(OSError):
                    result_file.unlink()
                if not isinstance(payload, dict) or not isinstance(payload.get("status"), str):
                    return SandboxResult("PROTOCOL_ERROR", detail="неожиданная структура результата")
                return SandboxResult(
                    str(payload["status"]),
                    payload,
                    detail=str(payload.get("detail", "")),
                    seconds=time.monotonic() - started,
                )
            time.sleep(0.1)
    finally:
        with contextlib.suppress(OSError):
            request.unlink()  # не взято сервисом: убираем, чтобы не копились
    return SandboxResult(
        "TIMEOUT", detail="песочница не ответила вовремя", seconds=time.monotonic() - started
    )


def run_local(module: str, job: dict[str, Any], *, timeout: float) -> SandboxResult:
    """Запустить воркер отдельным процессом; вернуть ответ или названный отказ. Не бросает."""
    started = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603 - фиксированный argv, без оболочки
            [sys.executable, "-m", module],
            input=json.dumps(job).encode(),
            capture_output=True,
            timeout=timeout,
            check=False,
            env=_environment(),
        )
    except subprocess.TimeoutExpired:
        return SandboxResult(
            "TIMEOUT", detail=f"воркер не уложился в {timeout:.0f} с", seconds=time.monotonic() - started
        )
    except OSError as error:
        return SandboxResult("UNAVAILABLE", detail=f"воркер не запустился: {type(error).__name__}")
    elapsed = time.monotonic() - started
    if len(completed.stdout) > MAX_OUTPUT_BYTES:
        return SandboxResult("OUTPUT_TOO_LARGE", detail="вывод воркера превысил предел", seconds=elapsed)
    if completed.returncode != 0:
        # Отрицательный код — убит сигналом (на Linux это и есть превышение лимита или сбой).
        # Хвост stderr нужен администратору, чтобы отличить нехватку библиотеки от сбоя разбора; в нём
        # нет содержимого письма: воркер не печатает того, что читает.
        tail = completed.stderr.decode("utf-8", "replace").strip()[-300:]
        return SandboxResult(
            "CRASHED",
            detail=f"воркер завершился с кодом {completed.returncode}" + (f": {tail}" if tail else ""),
            seconds=elapsed,
        )
    try:
        payload = json.loads(completed.stdout.decode("utf-8", "replace"))
    except ValueError:
        return SandboxResult("PROTOCOL_ERROR", detail="воркер вернул не JSON", seconds=elapsed)
    if not isinstance(payload, dict) or not isinstance(payload.get("status"), str):
        return SandboxResult("PROTOCOL_ERROR", detail="воркер вернул неожиданную структуру", seconds=elapsed)
    return SandboxResult(str(payload["status"]), payload, seconds=elapsed)


def list_archive(data: bytes, kind: str, *, timeout: float = ARCHIVE_TIMEOUT_SECONDS) -> SandboxResult:
    """Оглавление архива 7z или RAR."""
    return run_worker(
        ARCHIVE_WORKER, {"kind": kind, "data": base64.b64encode(data).decode("ascii")}, timeout=timeout
    )


def render_pdf(data: bytes, *, timeout: float = PDF_TIMEOUT_SECONDS) -> SandboxResult:
    """Страницы PDF как PNG (байты для декодера QR) в ``payload["pages"]``."""
    return run_worker(PDF_WORKER, {"data": base64.b64encode(data).decode("ascii")}, timeout=timeout)


def page_images(result: SandboxResult, name: str) -> list[tuple[str, bytes]]:
    """Страницы из ответа воркера как пары (имя, байты PNG) для декодера QR."""
    images: list[tuple[str, bytes]] = []
    for page in result.payload.get("pages") or []:
        try:
            images.append(
                (f"{name}#page{int(page['index']) + 1}", base64.b64decode(page["png"], validate=True))
            )
        except (KeyError, ValueError, TypeError):
            continue
    return images
