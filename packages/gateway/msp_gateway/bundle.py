"""Пакет конфигурации: контрольная сумма и проверка целостности (ТЗ 1.1 §39–§40).

Модуль вынесен отдельно ради одного свойства: **только стандартная библиотека**. Его используют
и центр управления, который генерирует пакеты, и узел, который их применяет. Узел работает в
образе транспорта, где нет зависимостей продукта (pydantic и прочего), — и не должен их
получать: каждая лишняя зависимость в образе, принимающем почту из Интернета, — это ещё одна
поверхность для уязвимости, не имеющая отношения к доставке.

Первая версия держала функцию суммы в генераторе (``render``), а тот импортировал модель
топологии на pydantic. Узел падал при запуске с ``ModuleNotFoundError``. Граница теперь
проверяется тестом, а не соглашением.
"""

from __future__ import annotations

import hashlib


class BundleError(ValueError):
    """Пакет повреждён или не соответствует своему описанию."""


def bundle_checksum(files: dict[str, bytes]) -> str:
    """Сумма пакета. Одна функция на центр и узел: расхождение в способе счёта выглядело бы дрейфом."""
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(files[name])
        digest.update(b"\0")
    return digest.hexdigest()


def manifest_names(manifest: dict[str, object], key: str) -> list[str]:
    """Список имён из описания пакета. Другая форма — повреждённое описание, а не пустой список."""
    value = manifest.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise BundleError(f"описание пакета: поле {key} должно быть списком строк")
    return [str(item) for item in value]


def verify_bundle(files: dict[str, bytes], manifest: dict[str, object]) -> str:
    """Сверить пакет с описанием: контрольная сумма и состав файлов.

    Сумма считается заново на узле, а не берётся из описания на веру: пакет мог быть изменён
    по дороге (§62: подмена очереди и конфигурации), и описание, лежащее рядом с файлами,
    изменилось бы вместе с ними. Сверка полезна только тогда, когда ожидаемую сумму узел
    получает отдельным каналом; здесь она сверяется с описанием, а канал — забота вызывающего.
    """
    declared = manifest.get("checksum")
    actual = bundle_checksum(files)
    if declared != actual:
        raise BundleError("контрольная сумма пакета не совпадает с описанием")
    if sorted(files) != sorted(manifest_names(manifest, "files")):
        raise BundleError("состав файлов пакета не совпадает с описанием")
    for name in files:
        if "/" in name or "\\" in name or name.startswith("."):
            raise BundleError("имя файла пакета содержит путь")
    return actual


def version_id(manifest: dict[str, object]) -> str:
    version = manifest.get("version", 0)
    if isinstance(version, bool) or not isinstance(version, int):
        raise BundleError("описание пакета: version должен быть целым числом")
    return f"{version:06d}-{str(manifest['checksum'])[:12]}"
