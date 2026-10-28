"""Проверка резервной копии ключа карантина (MSP 1.3P, ТЗ 1.3P §9, §14, §21).

Потеря ключа делает хранимые письма нечитаемыми, поэтому резервная копия считается рабочей, только когда ею удалось
расшифровать письмо. Скрипт проверяет именно это и не печатает ни ключа, ни его частей: в отчёте только идентификатор
ключа (первые 12 символов SHA-256 производного ключа) и исход.

Режимы::

    # Рабочий ключ из окружения (MSP_QUARANTINE_ENCRYPTION_KEY или файл), копия из файла:
    python scripts/quarantine_key_check.py --backup-file /secure/escrow/quarantine.key

    # Дополнительно расшифровать настоящий зашифрованный объект карантина (идентификатор письма — дополнительные данные AAD):
    python scripts/quarantine_key_check.py --backup-file ... --blob object.bin --item-id <id> --sha256 <контрольная сумма>

Исходы: ``OK`` (копия расшифровала пробу и объект), ``MISMATCH`` (копия отличается от рабочего ключа), ``NO_ACTIVE_KEY``,
``NO_BACKUP``, ``BLOB_UNREADABLE``, ``BLOB_MISMATCH``. Код возврата 0 только для ``OK``.

Результат — подтверждение для ``quarantine_key_restore`` (``POST /api/v1/pilot/attestations/quarantine_key_restore``) со
ссылкой на этот отчёт. Сам скрипт ничего в платформе не записывает.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any

MIN_KEY_CHARS = 32


def derive(raw: str) -> bytes:
    """Тот же вывод ключа, что в ``services/quarantine._key_bytes``."""
    return hashlib.sha256(raw.encode()).digest()


def key_id(raw: str) -> str:
    return hashlib.sha256(derive(raw)).hexdigest()[:12]


def _active_key() -> str:
    direct = (os.environ.get("MSP_QUARANTINE_ENCRYPTION_KEY") or "").strip()
    if direct:
        return direct
    path = os.environ.get("MSP_QUARANTINE_ENCRYPTION_KEY_FILE")
    if path and Path(path).is_file():
        return Path(path).read_text(encoding="utf-8").strip()
    return ""


def check(
    active: str,
    backup: str,
    *,
    blob: bytes | None = None,
    item_id: str = "",
    expected_sha256: str = "",
) -> dict[str, Any]:
    """Сравнить рабочий ключ и копию расшифровкой. Ключи в результат не попадают."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    report: dict[str, Any] = {
        "status": "OK",
        "active_key_id": "",
        "backup_key_id": "",
        "probe": False,
        "blob": None,
    }
    if len(active) < MIN_KEY_CHARS:
        report["status"] = "NO_ACTIVE_KEY"
        return report
    if len(backup) < MIN_KEY_CHARS:
        report["status"] = "NO_BACKUP"
        report["active_key_id"] = key_id(active)
        return report
    report["active_key_id"], report["backup_key_id"] = key_id(active), key_id(backup)

    # Проба: зашифровать рабочим ключом и расшифровать копией. Совпадение идентификаторов этого не заменяет.
    probe = secrets.token_bytes(64)
    nonce = secrets.token_bytes(12)
    sealed = AESGCM(derive(active)).encrypt(nonce, probe, b"probe")
    try:
        report["probe"] = AESGCM(derive(backup)).decrypt(nonce, sealed, b"probe") == probe
    except InvalidTag:
        report["probe"] = False
    if not report["probe"]:
        report["status"] = "MISMATCH"
        return report

    if blob is not None:
        try:
            plain = AESGCM(derive(backup)).decrypt(blob[:12], blob[12:], item_id.encode())
        except (InvalidTag, ValueError):
            report["blob"] = False
            report["status"] = "BLOB_UNREADABLE"
            return report
        report["blob"] = True
        if expected_sha256 and hashlib.sha256(plain).hexdigest() != expected_sha256:
            report["status"] = "BLOB_MISMATCH"
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Проверка резервной копии ключа карантина")
    parser.add_argument("--backup-file", required=True, help="файл с резервной копией ключа")
    parser.add_argument("--blob", help="зашифрованный объект карантина из хранилища")
    parser.add_argument("--item-id", default="", help="идентификатор письма в карантине (AAD)")
    parser.add_argument("--sha256", default="", help="ожидаемая контрольная сумма расшифрованного письма")
    parser.add_argument("--json", dest="json_path", help="записать отчёт в файл")
    args = parser.parse_args(argv)

    backup_path = Path(args.backup_file)
    backup = backup_path.read_text(encoding="utf-8").strip() if backup_path.is_file() else ""
    blob = Path(args.blob).read_bytes() if args.blob and Path(args.blob).is_file() else None
    if args.blob and blob is None:
        report: dict[str, Any] = {"status": "BLOB_UNREADABLE", "blob": False}
    else:
        report = check(_active_key(), backup, blob=blob, item_id=args.item_id, expected_sha256=args.sha256)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.json_path:
        Path(args.json_path).write_text(text + "\n", encoding="utf-8")
    sys.stdout.write(text + "\n")
    return 0 if report["status"] == "OK" else 1


if __name__ == "__main__":
    raise SystemExit(main())
