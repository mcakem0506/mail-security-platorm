"""Генераторы вложений для проверки песочницы (ТЗ 1.1 §55–§57).

Настоящих архивов RAR и защищённых PDF в репозиторий не кладут: бинарные образцы нельзя прочитать
глазами, а их происхождение приходится принимать на веру. Здесь они строятся из описания формата,
и каждая строка видна. Для 7z используется библиотека записи py7zr, для QR — кодировщик OpenCV.

Построены только те варианты, которые нужны проверкам: хранение без сжатия, шифрование заголовков
и файлов, обрезка. Это не архиваторы общего назначения.
"""

from __future__ import annotations

import io

# ---------------------------------------------------------------------------------------------
# 7z
# ---------------------------------------------------------------------------------------------


def make_7z(
    files: dict[str, bytes],
    *,
    password: str | None = None,
    encrypt_headers: bool = False,
) -> bytes:
    from unittest import mock

    import py7zr

    buffer = io.BytesIO()
    # Библиотека записи сама отказывается класть в архив имена вроде «../../x»; архив злоумышленника
    # строил не она, поэтому проверку на время сборки образца снимаем.
    with (
        mock.patch("py7zr.py7zr.check_archive_path", lambda _name: True),
        py7zr.SevenZipFile(buffer, "w", password=password, header_encryption=encrypt_headers) as archive,
    ):
        for name, content in files.items():
            archive.writestr(content, name)
    return buffer.getvalue()


# Остальные генераторы живут в пакете: их использует и золотой корпус.
from msp_attachment_sandbox.samples import (  # noqa: E402, F401
    _pdf,
    _stream,
    make_7z_stored,
    make_rar4,
    make_rar5,
    pdf_encrypted,
    pdf_pages,
    pdf_text_only,
    pdf_with_active_content,
    pdf_with_embedded_qr,
    pdf_with_vector_qr,
    qr_matrix,
    random_bytes,
)
