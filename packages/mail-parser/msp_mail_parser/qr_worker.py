"""Decode QR codes from images, in a process of its own (ТЗ 1.0.3B §31).

Run as ``python -m msp_mail_parser.qr_worker``. It reads a JSON job on stdin and writes a JSON
result on stdout, and it is started as a separate process on purpose: decoding the pixels of an
image an attacker sent is the one step here that hands attacker-controlled bytes to a large C++
library. In its own process a crash is an error message rather than a dead worker, and the
timeout that bounds it is enforced by something outside the thing being bounded.

The worker performs **no network access and no file access** beyond its own standard streams.
Everything it needs arrives on stdin.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
from typing import Any

#: Refuse images larger than this many pixels before decoding. A 20 000 × 20 000 PNG decodes to
#: 1.2 GB; the limit is what keeps a decode from becoming an out-of-memory kill.
MAX_PIXELS = 40_000_000
#: Refuse encoded images larger than this. Anything bigger is not a QR code in an email.
MAX_BYTES = 8 * 1024 * 1024
#: Payloads longer than this are truncated: a QR code can carry a few kilobytes, and nothing
#: useful to an analyst lives past the first two.
MAX_PAYLOAD = 2048
#: Процессорное время на весь пакет. Таймаут родителя ограничивает ожидание, этот предел —
#: потребление: декодер, попавший в патологический цикл, иначе греет ядро все десять секунд.
MAX_CPU_SECONDS = 15
#: Адресное пространство. Сорок миллионов пикселей в градациях серого — это 40 МБ, плюс запас на
#: внутренние буферы библиотеки. Предел существует, чтобы вместо убийства по памяти всей машины
#: получалась ошибка одного процесса.
MAX_ADDRESS_SPACE_BYTES = 1024 * 1024 * 1024


def apply_limits() -> dict[str, Any]:
    """Ограничить себя до того, как в процесс попадут байты злоумышленника.

    Ограничения ставит сам процесс, а не родитель через ``preexec_fn``: вызов произвольного кода
    между fork и exec в многопоточной программе — известный источник зависаний, а здесь он и не
    нужен. Декодируемые байты — это данные для библиотеки, они не исполняются и снять предел не
    могут.

    ``RLIMIT_FSIZE = 0`` запрещает запись файлов вообще. Это и есть «очистка временных файлов» в
    самом надёжном виде: файл, который невозможно создать, не нужно удалять.

    На Windows модуль ``resource`` отсутствует, и тогда возвращается описание того, что предел
    не поставлен. Пустой ответ означал бы «ограничено», а это было бы неправдой.
    """
    applied: dict[str, Any] = {}
    try:
        import resource
    except ImportError:  # pragma: no cover - Windows
        return {"applied": False, "reason": "resource module is unavailable on this platform"}

    for name, limit in (
        ("RLIMIT_CPU", MAX_CPU_SECONDS),
        ("RLIMIT_AS", MAX_ADDRESS_SPACE_BYTES),
        ("RLIMIT_FSIZE", 0),
    ):
        number = getattr(resource, name, None)
        if number is None:  # pragma: no cover - platform without this limit
            continue
        try:
            # Атрибуты помечены для проверки типов: модуль существует только на POSIX, и его
            # описание на Windows пустое. Отсутствие модуля уже обработано выше.
            _soft, hard = resource.getrlimit(number)  # type: ignore[attr-defined]
            infinity = resource.RLIM_INFINITY  # type: ignore[attr-defined]
            ceiling = limit if hard == infinity else min(limit, hard)
            resource.setrlimit(number, (ceiling, hard))  # type: ignore[attr-defined]
            applied[name] = ceiling
        except (ValueError, OSError) as exc:  # pragma: no cover - restricted environment
            applied[name] = f"not set: {type(exc).__name__}"
    applied["applied"] = True
    return applied


def decode(data: bytes) -> list[str]:
    """Decode every QR code in one image."""
    import cv2  # imported here so the module can be inspected without the optional extra
    import numpy

    if len(data) > MAX_BYTES:
        raise ValueError("image too large")

    array = numpy.frombuffer(data, dtype=numpy.uint8)
    image = cv2.imdecode(array, cv2.IMREAD_GRAYSCALE)
    if image is None:
        raise ValueError("undecodable image")
    height, width = image.shape[:2]
    if height * width > MAX_PIXELS:
        raise ValueError("image has too many pixels")

    detector = cv2.QRCodeDetector()
    found: list[str] = []
    ok, payloads, _points, _straight = detector.detectAndDecodeMulti(image)
    if ok:
        found = [str(payload) for payload in payloads]
    else:
        # Some images carry one code that the multi-detector misses; a single pass is cheap.
        single, _single_points, _single_straight = detector.detectAndDecode(image)
        if single:
            found = [str(single)]
    return [payload[:MAX_PAYLOAD] for payload in found if payload]


def main() -> int:
    # Момент старта процесса: родитель вычтет из него своё время до запуска и получит стоимость
    # самого запуска отдельно от стоимости декодирования. Без этого 0,5 секунды на письмо
    # выглядят как медленный декодер, хотя это запуск интерпретатора.
    started_at = time.time()
    limits = apply_limits()

    try:
        job: dict[str, Any] = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        print(json.dumps({"error": "bad_job", "started_at": started_at, "limits": limits}))
        return 1

    if job.get("probe"):
        # Проверка здоровья: подтвердить, что библиотека импортируется и декодер работает, не
        # трогая ни одного недоверенного байта.
        try:
            import cv2  # noqa: F401
            import numpy  # noqa: F401
        except ImportError as exc:
            # О пределах сообщается и здесь: администратору нужно знать, в каком режиме
            # работает процесс, независимо от того, установлен ли декодер.
            print(
                json.dumps(
                    {
                        "probe": "import_failed",
                        "detail": str(exc)[:200],
                        "started_at": started_at,
                        "limits": limits,
                    }
                )
            )
            return 1
        print(
            json.dumps(
                {
                    "probe": "ok",
                    "started_at": started_at,
                    "limits": limits,
                    "pid": os.getpid(),
                    "max_pixels": MAX_PIXELS,
                    "max_bytes": MAX_BYTES,
                    "max_payload": MAX_PAYLOAD,
                }
            )
        )
        return 0

    results: list[dict[str, Any]] = []
    for item in (job.get("images") or [])[: int(job.get("max_images", 20))]:
        name = str(item.get("name", ""))[:255]
        try:
            data = base64.b64decode(item.get("data", ""), validate=True)
        except (ValueError, TypeError):
            results.append({"name": name, "error": "bad_base64"})
            continue
        try:
            payloads = decode(data)
        except Exception as exc:  # noqa: BLE001 - a broken image is a result, not a crash
            results.append({"name": name, "error": type(exc).__name__})
            continue
        results.append({"name": name, "payloads": payloads})

    print(
        json.dumps(
            {
                "results": results,
                "started_at": started_at,
                "finished_at": time.time(),
                "limits": limits,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
