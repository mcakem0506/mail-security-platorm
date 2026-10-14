"""Отрисовка страниц PDF в изображения в отдельном процессе (ТЗ 1.1 §55, §57; GAP-004).

Запуск: ``python -m msp_attachment_sandbox.pdf_worker``. Вход — JSON на stdin (байты PDF в base64),
выход — JSON на stdout: страницы в виде PNG. **Ничего, кроме изображений, наружу не выходит**: ни
текста, ни ссылок, ни вложенных объектов. Изображения затем идут в уже существующий декодер QR —
во **второй** изолированный процесс: тот, что разбирает PDF, не должен ещё и декодировать
(ADR_ISOLATED_ATTACHMENT_ANALYSIS).

Отрисовка, а не извлечение встроенных картинок, выбрана потому, что QR-код в PDF нередко нарисован
векторно: извлечение изображений такой код пропустило бы, а вердикт «изображений нет» выглядел бы
как «кода нет». Страница, нарисованная целиком, содержит и тот и другой случай.

Скрипты и активное содержимое не исполняются. Библиотека PDFium в составе ``pypdfium2`` собрана
без JavaScript-движка; формы не инициализируются (``init_forms`` не вызывается), поэтому поля и
действия формы не отрисовываются и не срабатывают. Это проверяется тестом на документе с
``/OpenAction`` и JavaScript.

Пределы: размер PDF, число страниц, число пикселей на страницу и в сумме. Превышение — не молчаливая
обрезка: оно возвращается как признак (``PAGES_NOT_RENDERED``, ``PAGE_TOO_LARGE``), и вердикт
получает ``missing_evidence``. Зашифрованный или повреждённый PDF — ``ENCRYPTED_UNSCANNABLE`` или
``MALFORMED``, а не «QR нет».
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import sys
from typing import Any

from .limits import apply_limits

#: Воркеру запрещено порождать процессы и потоки (``RLIMIT_NPROC = 0``), а числовые библиотеки при
#: импорте создают пул потоков. Без этого numpy обрывает импорт, и воркер не запускается вовсе.
for _name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
    os.environ[_name] = "1"

MAX_INPUT_BYTES = 20 * 1024 * 1024
MAX_STDIN_BYTES = MAX_INPUT_BYTES * 4 // 3 + 4096
MAX_PAGES_RENDERED = 10
#: Целевое разрешение: при 150 dpi QR размером в два сантиметра занимает около 120 пикселей —
#: этого хватает декодеру. Больше — дороже по памяти без выигрыша.
TARGET_DPI = 150.0
MAX_PIXELS_PER_PAGE = 4_000_000
MAX_PIXELS_TOTAL = 24_000_000
MIN_SCALE = 0.35
MAX_PNG_BYTES_PER_PAGE = 6 * 1024 * 1024


def _result(status: str, **extra: Any) -> dict[str, Any]:
    return {"status": status, "pages": [], "flags": [], **extra}


def render(data: bytes) -> dict[str, Any]:
    import cv2
    import pypdfium2 as pdfium
    from pypdfium2 import PdfiumError

    try:
        document = pdfium.PdfDocument(data)
    except PdfiumError as error:
        message = str(error).lower()
        if "password" in message:
            return _result("ENCRYPTED_UNSCANNABLE", flags=["ENCRYPTED_PDF"])
        return _result("MALFORMED", flags=["CORRUPT_PDF"])

    flags: set[str] = set()
    pages: list[dict[str, Any]] = []
    try:
        total = len(document)
        if total == 0:
            return _result("MALFORMED", flags=["CORRUPT_PDF"], pages_total=0)
        spent = 0
        for index in range(min(total, MAX_PAGES_RENDERED)):
            page = document[index]
            try:
                width, height = page.get_size()
                if width <= 0 or height <= 0 or width != width or height != height:
                    flags.add("PAGE_TOO_LARGE")
                    continue
                scale = TARGET_DPI / 72.0
                pixels = width * height * scale * scale
                if pixels > MAX_PIXELS_PER_PAGE:
                    scale = (MAX_PIXELS_PER_PAGE / (width * height)) ** 0.5
                if scale < MIN_SCALE:
                    # Страница настолько велика, что при допустимом числе пикселей QR-код на ней
                    # не прочесть: честно сказать «не отрисована», а не отдать нечитаемое.
                    flags.add("PAGE_TOO_LARGE")
                    continue
                if spent + width * height * scale * scale > MAX_PIXELS_TOTAL:
                    flags.add("PIXEL_BUDGET_EXHAUSTED")
                    break
                bitmap = page.render(scale=scale, grayscale=True)
                array = bitmap.to_numpy()
                spent += int(array.shape[0]) * int(array.shape[1])
                ok, png = cv2.imencode(".png", array)
                if not ok or len(png) > MAX_PNG_BYTES_PER_PAGE:
                    flags.add("PAGE_TOO_LARGE")
                    continue
                pages.append(
                    {
                        "index": index,
                        "width": int(array.shape[1]),
                        "height": int(array.shape[0]),
                        "png": base64.b64encode(png.tobytes()).decode("ascii"),
                    }
                )
            except PdfiumError:
                flags.add("PAGE_UNREADABLE")
            finally:
                page.close()
        if total > MAX_PAGES_RENDERED:
            flags.add("PAGES_NOT_RENDERED")
    finally:
        document.close()

    complete = not flags and bool(pages)
    if complete:
        status = "OK"
    elif pages:
        status = "PARTIAL"
    elif flags & {"PAGE_TOO_LARGE", "PIXEL_BUDGET_EXHAUSTED"}:
        # Ни одной страницы не отрисовано из-за пределов, а не из-за повреждения файла.
        status = "LIMIT_EXCEEDED"
    else:
        status = "MALFORMED"
    return {
        "status": status,
        "pages": pages,
        "pages_total": total,
        "pages_rendered": len(pages),
        "flags": sorted(flags),
    }


def handle(job: Any) -> dict[str, Any]:
    if not isinstance(job, dict):
        return _result("MALFORMED", flags=["CORRUPT_PDF"])
    try:
        data = base64.b64decode(job.get("data", ""), validate=True)
    except (binascii.Error, ValueError, TypeError):
        return _result("MALFORMED", flags=["CORRUPT_PDF"])
    if not data.startswith(b"%PDF-") and b"%PDF-" not in data[:1024]:
        return _result("MALFORMED", flags=["NOT_A_PDF"])
    if len(data) > MAX_INPUT_BYTES:
        return _result("LIMIT_EXCEEDED", flags=["PDF_TOO_LARGE"])
    try:
        return render(data)
    except MemoryError:
        return _result("LIMIT_EXCEEDED", flags=["PDF_TOO_LARGE"])
    except ImportError:
        return _result("UNAVAILABLE", flags=["SANDBOX_UNAVAILABLE"])
    except Exception as error:  # noqa: BLE001 - любой отказ отрисовщика — «не отрисовано», не «кода нет»
        return _result("MALFORMED", flags=["CORRUPT_PDF"], error=type(error).__name__)


def main() -> int:
    limits = apply_limits()
    raw = sys.stdin.read(MAX_STDIN_BYTES + 1)
    if len(raw) > MAX_STDIN_BYTES:
        out = _result("LIMIT_EXCEEDED", flags=["PDF_TOO_LARGE"])
    else:
        try:
            out = handle(json.loads(raw))
        except ValueError:
            out = _result("MALFORMED", flags=["CORRUPT_PDF"])
    out["limits"] = limits
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
