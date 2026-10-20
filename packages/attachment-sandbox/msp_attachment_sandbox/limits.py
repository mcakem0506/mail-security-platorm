"""Пределы процесса-воркера (ТЗ 1.1 §55; ADR_ISOLATED_ATTACHMENT_ANALYSIS).

Пределы ставит **сам воркер первым действием**, до чтения чего-либо из недоверенного входа, а не
родитель через ``preexec_fn``. Вызов произвольного кода между ``fork`` и ``exec`` в
многопоточной программе — известный источник зависаний, и сбой там нечем сообщить; процесс,
который ограничил себя сам и только потом взялся за данные, либо ограничен, либо не начал работу.

Что именно ограничивается и зачем:

* ``RLIMIT_CPU`` — потребление процессора. Таймаут родителя ограничивает ожидание, этот предел —
  расход: разборщик в патологическом цикле иначе греет ядро все секунды таймаута.
* ``RLIMIT_AS`` — адресное пространство: вместо убийства по памяти всей машины получается ошибка
  одного процесса.
* ``RLIMIT_FSIZE = 0`` — запрет создавать и дописывать файлы. «Очистка временных файлов» в самом
  надёжном виде: файл, который нельзя создать, не нужно удалять.
* ``RLIMIT_NPROC = 0`` — запрет порождать процессы. Воркер, взломанный через разбираемый формат,
  не запустит ни оболочку, ни распаковщик.
* ``RLIMIT_NOFILE`` — малое число дескрипторов: открывать нечего, кроме стандартных потоков.
* ``RLIMIT_CORE = 0`` — дампы памяти с содержимым чужого письма не пишутся.

На Windows модуля ``resource`` нет, и тогда возвращается описание того, что предел не поставлен:
пустой ответ означал бы «ограничено», а это было бы неправдой. Боевой путь — Linux-контейнер.
"""

from __future__ import annotations

import os
from typing import Any

MAX_CPU_SECONDS = 20
MAX_ADDRESS_SPACE_BYTES = 2 * 1024 * 1024 * 1024
MAX_OPEN_FILES = 32


def apply_limits(
    *,
    cpu_seconds: int = MAX_CPU_SECONDS,
    address_space: int = MAX_ADDRESS_SPACE_BYTES,
    forbid_processes: bool = True,
) -> dict[str, Any]:
    """Ограничить себя. Возвращает, что реально поставлено."""
    try:
        import resource
    except ImportError:  # pragma: no cover - Windows
        return {"applied": False, "reason": "resource module is unavailable on this platform"}

    applied: dict[str, Any] = {"applied": True}
    # RLIMIT_NPROC не действует на root: воркер обязан быть запущен непривилегированным
    # пользователем (USER в образе песочницы). Если это не так, пределы выставлены, но запрет
    # на порождение процессов — нет, и честный ответ об этом виден в результате.
    geteuid = getattr(os, "geteuid", None)
    applied["non_root"] = bool(geteuid and geteuid() != 0)
    requested = [
        ("RLIMIT_CPU", cpu_seconds),
        ("RLIMIT_AS", address_space),
        ("RLIMIT_FSIZE", 0),
        ("RLIMIT_CORE", 0),
        ("RLIMIT_NOFILE", MAX_OPEN_FILES),
    ]
    if forbid_processes:
        requested.append(("RLIMIT_NPROC", 0))
    for name, value in requested:
        constant = getattr(resource, name, None)
        if constant is None:
            applied[name] = "unsupported"
            continue
        try:
            resource.setrlimit(constant, (value, value))  # type: ignore[attr-defined]
            applied[name] = value
        except (ValueError, OSError) as error:
            applied[name] = f"failed: {type(error).__name__}"
            applied["applied"] = False
    return applied
