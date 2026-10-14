"""Образцы вложений: детерминированные генераторы для проверок и золотого корпуса (ТЗ 1.1 §55-§57).

Настоящих архивов RAR и защищённых PDF в репозиторий не кладут: бинарные образцы нельзя прочитать
глазами, а их происхождение приходится принимать на веру. Здесь они строятся из описания формата,
и каждая строка видна.

Результат всегда один и тот же для одних и тех же входных данных. Это важно для золотого корпуса:
его контрольная сумма считается по собранным письмам, и образец, зависящий от времени сборки (как
архив, записанный библиотекой py7zr), менял бы её при каждом запуске.

Построены только те варианты, которые нужны проверкам: хранение без сжатия, шифрование файлов и
заголовков, обрезка. Это не архиваторы общего назначения, и ничего из этого модуля не вызывается при
обработке настоящей почты.
"""

from __future__ import annotations

import os
import struct
import zlib

# ---------------------------------------------------------------------------------------------
# 7z (без сжатия, без шифрования)
# ---------------------------------------------------------------------------------------------


def _number(value: int) -> bytes:
    """Число в кодировке 7z: первые биты первого байта говорят, сколько байт следует."""
    if value < 0x80:
        return bytes([value])
    for extra in range(1, 9):
        if value < (1 << (7 * (extra + 1))) or extra == 8:
            mask = (0xFF << (8 - extra)) & 0xFF
            high = (value >> (8 * extra)) & ((1 << (7 - extra)) - 1) if extra < 8 else 0
            return bytes([mask | high]) + (value & ((1 << (8 * extra)) - 1)).to_bytes(extra, "little")
    raise ValueError("число не помещается")


def make_7z_stored(files: dict[str, bytes], *, declared_size: int | None = None) -> bytes:
    """Архив 7z, в котором файлы лежат как есть.

    ``declared_size`` позволяет заявить в заголовке распакованный размер больше настоящего: так
    выглядит «бомба», у которой маленький архив обещает огромный файл. Сам архив при этом честен
    по размеру упакованных данных.
    """
    names = list(files)
    contents = [files[name] for name in names]
    packed = b"".join(contents)
    unpack_total = declared_size if declared_size is not None else len(packed)

    streams = bytearray()
    streams += b"\x06" + _number(0) + _number(1) + b"\x09" + _number(len(packed)) + b"\x00"  # PackInfo
    streams += b"\x07" + b"\x0b" + _number(1) + b"\x00"  # UnpackInfo, один Folder
    streams += _number(1) + bytes([0x01, 0x00])  # один кодер, идентификатор 1 байт, метод Copy
    streams += b"\x0c" + _number(unpack_total) + b"\x00"  # размер распакованного
    streams += b"\x08" + b"\x0d" + _number(len(contents))  # SubStreamsInfo: число файлов
    if len(contents) > 1:
        streams += b"\x09" + b"".join(_number(len(c)) for c in contents[:-1])
    streams += b"\x0a" + b"\x01" + b"".join(struct.pack("<I", zlib.crc32(c) & 0xFFFFFFFF) for c in contents)
    streams += b"\x00" + b"\x00"  # конец SubStreams и StreamsInfo

    encoded_names = b"".join(name.encode("utf-16-le") + b"\x00\x00" for name in names)
    files_info = b"\x05" + _number(len(names))
    files_info += b"\x11" + _number(len(encoded_names) + 1) + b"\x00" + encoded_names + b"\x00"

    header = b"\x01" + b"\x04" + bytes(streams) + files_info + b"\x00"
    start_header = struct.pack("<QQI", len(packed), len(header), zlib.crc32(header) & 0xFFFFFFFF)
    signature = b"7z\xbc\xaf\x27\x1c" + bytes([0, 4])
    return (
        signature + struct.pack("<I", zlib.crc32(start_header) & 0xFFFFFFFF) + start_header + packed + header
    )


# ---------------------------------------------------------------------------------------------
# RAR 5
# ---------------------------------------------------------------------------------------------
RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"


def _vint(value: int) -> bytes:
    out = bytearray()
    while True:
        low = value & 0x7F
        value >>= 7
        if value:
            out.append(low | 0x80)
        else:
            out.append(low)
            return bytes(out)


def _rar5_block(header_body: bytes, data: bytes = b"") -> bytes:
    size = _vint(len(header_body))
    crc = zlib.crc32(size + header_body) & 0xFFFFFFFF
    return struct.pack("<I", crc) + size + header_body + data


def _rar5_extra_encryption() -> bytes:
    # Запись «шифрование файла»: версия 0, флаги 0, счётчик KDF, соль, вектор инициализации.
    body = _vint(0) + _vint(0) + bytes([15]) + b"\x01" * 16 + b"\x02" * 16
    record = _vint(1) + body  # тип записи 1
    return _vint(len(record)) + record


def make_rar5(
    files: dict[str, bytes], *, encrypt_headers: bool = False, encrypt_files: bool = False
) -> bytes:
    out = RAR5_SIGNATURE
    if encrypt_headers:
        # Блок шифрования архива: дальше все заголовки зашифрованы, имён не видно.
        body = _vint(4) + _vint(0) + _vint(0) + _vint(0) + bytes([15]) + b"\x03" * 16
        return out + _rar5_block(body)
    out += _rar5_block(_vint(1) + _vint(0) + _vint(0))  # главный заголовок
    for name, content in files.items():
        raw_name = name.encode("utf-8")
        extra = _rar5_extra_encryption() if encrypt_files else b""
        header_flags = 0x0002 | (0x0001 if extra else 0)  # есть область данных [+ дополнительная область]
        body = _vint(2) + _vint(header_flags)
        if extra:
            body += _vint(len(extra))
        body += _vint(len(content))  # размер области данных
        body += _vint(0x0004)  # флаги файла: есть CRC32
        body += _vint(len(content))  # размер без сжатия
        body += _vint(0o100644)  # атрибуты
        body += struct.pack("<I", zlib.crc32(content) & 0xFFFFFFFF)
        body += _vint(0)  # сжатие: хранение
        body += _vint(1)  # ОС-источник: Unix
        body += _vint(len(raw_name)) + raw_name
        body += extra
        out += _rar5_block(body, content)
    out += _rar5_block(_vint(5) + _vint(0) + _vint(0))  # конец архива
    return out


# ---------------------------------------------------------------------------------------------
# RAR 4
# ---------------------------------------------------------------------------------------------
RAR4_SIGNATURE = b"Rar!\x1a\x07\x00"


def _rar4_block(block_type: int, flags: int, payload: bytes, data: bytes = b"") -> bytes:
    head_size = 7 + len(payload)
    after_crc = struct.pack("<BHH", block_type, flags, head_size) + payload
    crc = zlib.crc32(after_crc) & 0xFFFF
    return struct.pack("<H", crc) + after_crc + data


def make_rar4(files: dict[str, bytes], *, encrypt_files: bool = False) -> bytes:
    out = RAR4_SIGNATURE
    out += _rar4_block(0x73, 0x0000, struct.pack("<HI", 0, 0))  # главный заголовок
    for name, content in files.items():
        raw_name = name.encode("utf-8")
        flags = 0x8000 | (0x0004 if encrypt_files else 0)  # есть данные [+ пароль]
        payload = struct.pack(
            "<IIBIIBBHI",
            len(content),  # размер упакованных данных
            len(content),  # размер распакованных
            3,  # ОС: Unix
            zlib.crc32(content) & 0xFFFFFFFF,
            0x5A210000,  # время (DOS)
            29,  # версия для распаковки
            0x30,  # метод: хранение
            len(raw_name),
            0o100644,
        )
        out += _rar4_block(0x74, flags, payload + raw_name, content)
    out += bytes.fromhex("c43d7b00400700")  # конец архива
    return out


# ---------------------------------------------------------------------------------------------
# QR и PDF
# ---------------------------------------------------------------------------------------------
def qr_matrix(text: str, scale: int = 1):  # type: ignore[no-untyped-def]
    import cv2

    matrix = cv2.QRCodeEncoder.create().encode(text)  # 0 — тёмный модуль, 255 — светлый
    if scale > 1:
        matrix = cv2.resize(matrix, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
    return matrix


def _pdf(objects: list[bytes], *, trailer_extra: bytes = b"") -> bytes:
    out = b"%PDF-1.4\n"
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R %s>>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        trailer_extra,
        xref,
    )
    return out


def _stream(dictionary: bytes, content: bytes) -> bytes:
    return b"<< %s /Length %d >>\nstream\n" % (dictionary, len(content)) + content + b"\nendstream"


def pdf_with_embedded_qr(text: str, *, page: tuple[int, int] = (595, 842)) -> bytes:
    """Страница с QR-кодом, вставленным растровой картинкой."""
    matrix = qr_matrix(text, 6)
    height, width = matrix.shape
    raw = zlib.compress(matrix.tobytes())
    content = b"q 220 0 0 220 100 500 cm /Im0 Do Q"
    return _pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Contents 4 0 R "
            b"/Resources << /XObject << /Im0 5 0 R >> >> >>" % page,
            _stream(b"", content),
            _stream(
                b"/Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceGray "
                b"/BitsPerComponent 8 /Filter /FlateDecode" % (width, height),
                raw,
            ),
        ]
    )


def pdf_with_vector_qr(text: str) -> bytes:
    """QR-код, нарисованный прямоугольниками: встроенных изображений в документе нет."""
    matrix = qr_matrix(text)
    side = 8
    quiet = 4
    size = (matrix.shape[0] + 2 * quiet) * side
    commands = [b"1 1 1 rg 0 0 %d %d re f" % (size + 200, size + 200), b"0 0 0 rg"]
    for y in range(matrix.shape[0]):
        for x in range(matrix.shape[1]):
            if matrix[y, x] == 0:
                px = 100 + (x + quiet) * side
                py = 500 + (matrix.shape[0] - 1 - y + quiet) * side
                commands.append(b"%d %d %d %d re f" % (px, py, side, side))
    return _pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R >>",
            _stream(b"", b"\n".join(commands)),
        ]
    )


def pdf_text_only() -> bytes:
    content = b"BT /F1 24 Tf 100 700 Td (Hello) Tj ET"
    return _pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>",
            _stream(b"", content),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        ]
    )


def pdf_with_active_content(text: str) -> bytes:
    """PDF с JavaScript в /OpenAction и ссылкой-запуском: движок исполнения скриптов не должен срабатывать."""
    matrix = qr_matrix(text, 6)
    height, width = matrix.shape
    raw = zlib.compress(matrix.tobytes())
    return _pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R "
            b"/Resources << /XObject << /Im0 5 0 R >> >> >>",
            _stream(b"", b"q 220 0 0 220 100 500 cm /Im0 Do Q"),
            _stream(
                b"/Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceGray "
                b"/BitsPerComponent 8 /Filter /FlateDecode" % (width, height),
                raw,
            ),
            b"<< /S /JavaScript /JS (app.alert\\(1\\); this.submitForm\\(1\\);) >>",
        ]
    )


def pdf_pages(count: int, *, size: tuple[int, int] = (200, 200)) -> bytes:
    kids = b" ".join(b"%d 0 R" % (3 + i) for i in range(count))
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [%s] /Count %d >>" % (kids, count),
    ]
    objects += [b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] >>" % size for _ in range(count)]
    return _pdf(objects)


def pdf_encrypted() -> bytes:
    """Стандартный обработчик безопасности с заведомо неподходящим паролем-владельцем и пользователя."""
    return _pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
            b"<< /Filter /Standard /V 1 /R 2 /Length 40 /P -4 /O <"
            + b"00" * 32
            + b"> /U <"
            + b"11" * 32
            + b"> >>",
        ],
        trailer_extra=b"/Encrypt 4 0 R /ID [<" + b"22" * 16 + b"> <" + b"22" * 16 + b">] ",
    )


def random_bytes(size: int) -> bytes:
    return os.urandom(size)
