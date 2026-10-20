"""Оглавление архивов 7z и RAR в отдельном процессе (ТЗ 1.1 §55, §56; GAP-003).

Запуск: ``python -m msp_attachment_sandbox.archive_worker``. Вход — JSON на stdin, выход — JSON на
stdout. Воркер **не распаковывает** содержимое: читает заголовки и сообщает имена, размеры,
признаки шифрования и ссылок. Это второй вариант из ADR («разбор без распаковки»): он не
исполняет чужой код над содержимым вложений и не может быть превращён в бомбу, потому что
разворачивать нечего.

Цена этого выбора названа вслух, а не спрятана: вложенные архивы внутри 7z/RAR по оглавлению
видны только по имени, а содержимое файлов остаётся непроверенным. Поэтому результат всегда несёт
признак ``LISTING_ONLY``, и вердикт не опускается до безопасного (``scan_completeness``).

Что воркер не делает никогда:

* не открывает файлов и не использует сеть (проверяется тестом по AST);
* не порождает процессов (``RLIMIT_NPROC = 0``);
* не считает пароль защитой от разбора: зашифрованный архив — ``ENCRYPTED_UNSCANNABLE``, а не
  «чистый» (ТЗ §56);
* не доверяет объявленным в заголовке размерам для расхода ресурсов — он ничего по ним не
  выделяет; размеры используются только как признаки (бомба, коэффициент сжатия).
"""

from __future__ import annotations

import base64
import binascii
import io
import json
import sys
from typing import Any

from .limits import apply_limits

#: Предел входа: больше — не письмо с вложением, а подозрительный объём.
MAX_INPUT_BYTES = 25 * 1024 * 1024
MAX_STDIN_BYTES = MAX_INPUT_BYTES * 4 // 3 + 4096
#: Больше записей в оглавлении не разбираем: число — уже признак.
MAX_ENTRIES_SCANNED = 20_000
MAX_ENTRIES_REPORTED = 500
MAX_NAME_LENGTH = 255
MAX_FILES = 500
MAX_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024
MAX_COMPRESSION_RATIO = 150.0
MAX_RATIO_MIN_SIZE = 1024 * 1024

#: Расширения вложенных архивов: оглавление показывает их только по имени.
NESTED_ARCHIVE_EXTENSIONS = frozenset({".zip", ".7z", ".rar", ".gz", ".tgz", ".cab", ".iso", ".img"})


def _result(status: str, fmt: str = "", **extra: Any) -> dict[str, Any]:
    return {"status": status, "format": fmt, "listing_only": True, **extra}


def _clean_name(raw: Any) -> str:
    text = raw if isinstance(raw, str) else str(raw)
    return "".join(ch if ch.isprintable() else "?" for ch in text)[: MAX_NAME_LENGTH + 1]


def _name_flags(name: str, flags: set[str]) -> None:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        flags.add("ABSOLUTE_PATH")
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    if ".." in parts:
        flags.add("PATH_TRAVERSAL")
    if len(name) > MAX_NAME_LENGTH:
        flags.add("FILENAME_TOO_LONG")
    lowered = normalized.lower()
    for extension in NESTED_ARCHIVE_EXTENSIONS:
        if lowered.endswith(extension):
            flags.add("NESTED_ARCHIVE")


def _finish(fmt: str, entries: list[dict[str, Any]], flags: set[str], encrypted_files: int) -> dict[str, Any]:
    if not entries:
        # Архив без единой записи неотличим от обрезанного или испорченного: библиотека читает
        # заголовки до первого непонятного места и молча останавливается. «Ничего не нашли» здесь
        # означало бы «чисто», а правда — «разобрать не удалось».
        return _result("MALFORMED", fmt, flags=sorted({*flags, "CORRUPT_ARCHIVE", "EMPTY_LISTING"}))
    files = [e for e in entries if not e["dir"]]
    total = sum(e["size"] for e in files)
    compressed = sum(e["compressed"] for e in files)
    if len(files) > MAX_FILES:
        flags.add("TOO_MANY_FILES")
    if total > MAX_TOTAL_UNCOMPRESSED:
        flags.add("EXTRACTION_LIMIT")
    if total > MAX_RATIO_MIN_SIZE and total / max(compressed, 1) > MAX_COMPRESSION_RATIO:
        flags.add("EXCESSIVE_COMPRESSION_RATIO")
    if encrypted_files:
        flags.add("ENCRYPTED_ARCHIVE")
    status = "ENCRYPTED_UNSCANNABLE" if "ENCRYPTED_ARCHIVE" in flags else "OK"
    return _result(
        status,
        fmt,
        entries=entries[:MAX_ENTRIES_REPORTED],
        entries_total=len(entries),
        entries_truncated=len(entries) > MAX_ENTRIES_REPORTED,
        file_count=len(files),
        total_uncompressed=total,
        flags=sorted(flags),
    )


def list_7z(data: bytes) -> dict[str, Any]:
    import py7zr
    from py7zr import exceptions as sz_exceptions

    try:
        archive = py7zr.SevenZipFile(io.BytesIO(data), mode="r")
    except sz_exceptions.PasswordRequired:
        # Шифруются сами заголовки: имён не видно вообще.
        return _result("ENCRYPTED_UNSCANNABLE", "7z", flags=["ENCRYPTED_ARCHIVE", "ENCRYPTED_HEADERS"])
    except (sz_exceptions.Bad7zFile, sz_exceptions.UnsupportedCompressionMethodError):
        return _result("MALFORMED", "7z", flags=["CORRUPT_ARCHIVE"])
    with archive:
        flags: set[str] = set()
        entries: list[dict[str, Any]] = []
        encrypted = 0
        needs_password = bool(archive.needs_password())
        for index, info in enumerate(archive.list()):
            if index >= MAX_ENTRIES_SCANNED:
                flags.add("TOO_MANY_FILES")
                break
            name = _clean_name(info.filename)
            _name_flags(name, flags)
            is_dir = bool(info.is_directory)
            entry_encrypted = needs_password and not is_dir and not getattr(info, "emptystream", False)
            encrypted += 1 if entry_encrypted else 0
            entries.append(
                {
                    "name": name[:MAX_NAME_LENGTH],
                    "size": max(int(info.uncompressed or 0), 0),
                    "compressed": max(int(getattr(info, "compressed", 0) or 0), 0),
                    "dir": is_dir,
                    "encrypted": entry_encrypted,
                    "symlink": bool(getattr(info, "is_symlink", False)),
                }
            )
            if entries[-1]["symlink"]:
                flags.add("SYMLINK")
    return _finish("7z", entries, flags, encrypted)


def list_rar(data: bytes) -> dict[str, Any]:
    import rarfile

    # Распаковщик не нужен и не будет вызван: читаются только заголовки.
    rarfile.UNRAR_TOOL = "/nonexistent/unrar"
    rarfile.UNAR_TOOL = "/nonexistent/unar"
    rarfile.BSDTAR_TOOL = "/nonexistent/bsdtar"
    rarfile.SEVENZIP_TOOL = "/nonexistent/7z"
    rarfile.SEVENZIP2_TOOL = "/nonexistent/7zz"
    try:
        archive = rarfile.RarFile(io.BytesIO(data))
    except rarfile.PasswordRequired:
        return _result("ENCRYPTED_UNSCANNABLE", "rar", flags=["ENCRYPTED_ARCHIVE", "ENCRYPTED_HEADERS"])
    except (rarfile.BadRarFile, rarfile.NotRarFile, rarfile.NeedFirstVolume, rarfile.RarCannotExec):
        return _result("MALFORMED", "rar", flags=["CORRUPT_ARCHIVE"])
    except rarfile.Error:
        return _result("MALFORMED", "rar", flags=["CORRUPT_ARCHIVE"])
    with archive:
        flags: set[str] = set()
        entries: list[dict[str, Any]] = []
        encrypted = 0
        for index, info in enumerate(archive.infolist()):
            if index >= MAX_ENTRIES_SCANNED:
                flags.add("TOO_MANY_FILES")
                break
            name = _clean_name(info.filename)
            _name_flags(name, flags)
            is_dir = bool(info.is_dir())
            entry_encrypted = bool(info.needs_password())
            encrypted += 1 if entry_encrypted else 0
            symlink = bool(getattr(info, "is_symlink", lambda: False)())
            entries.append(
                {
                    "name": name[:MAX_NAME_LENGTH],
                    "size": max(int(info.file_size or 0), 0),
                    "compressed": max(int(info.compress_size or 0), 0),
                    "dir": is_dir,
                    "encrypted": entry_encrypted,
                    "symlink": symlink,
                }
            )
            if symlink:
                flags.add("SYMLINK")
    return _finish("rar", entries, flags, encrypted)


def handle(job: Any) -> dict[str, Any]:
    if not isinstance(job, dict) or job.get("kind") not in {"7z", "rar"}:
        return _result("UNSUPPORTED", "", flags=["UNSUPPORTED_ARCHIVE_FORMAT"])
    kind = job["kind"]
    try:
        data = base64.b64decode(job.get("data", ""), validate=True)
    except (binascii.Error, ValueError, TypeError):
        return _result("MALFORMED", kind, flags=["CORRUPT_ARCHIVE"])
    if not data:
        return _result("MALFORMED", kind, flags=["CORRUPT_ARCHIVE"])
    if len(data) > MAX_INPUT_BYTES:
        return _result("LIMIT_EXCEEDED", kind, flags=["EXTRACTION_LIMIT"])
    try:
        return list_7z(data) if kind == "7z" else list_rar(data)
    except MemoryError:
        return _result("LIMIT_EXCEEDED", kind, flags=["EXTRACTION_LIMIT"])
    except ImportError:
        # Библиотека не установлена: это не «архив повреждён» и не «архив чист», а «разбирать нечем».
        return _result("UNAVAILABLE", kind, flags=["SANDBOX_UNAVAILABLE"])
    except Exception as error:  # noqa: BLE001 - любой отказ разборщика — «разобрать не удалось», не «чисто»
        return _result("MALFORMED", kind, flags=["CORRUPT_ARCHIVE"], error=type(error).__name__)


def main() -> int:
    limits = apply_limits()
    raw = sys.stdin.read(MAX_STDIN_BYTES + 1)
    if len(raw) > MAX_STDIN_BYTES:
        out = _result("LIMIT_EXCEEDED", "", flags=["EXTRACTION_LIMIT"])
    else:
        try:
            out = handle(json.loads(raw))
        except ValueError:
            out = _result("MALFORMED", "", flags=["CORRUPT_ARCHIVE"])
    out["limits"] = limits
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
