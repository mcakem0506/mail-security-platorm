"""Проверка резервной копии ключа карантина (MSP 1.3P, ТЗ §9, §21)."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import secrets
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("quarantine_key_check", Path("scripts/quarantine_key_check.py"))
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)

ACTIVE = "a" * 48
OTHER = "b" * 48


def sealed(key: str, plain: bytes, item_id: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(tool.derive(key)).encrypt(nonce, plain, item_id.encode())


class TestProbe:
    def test_the_same_key_passes(self) -> None:
        report = tool.check(ACTIVE, ACTIVE)
        assert report["status"] == "OK" and report["probe"] is True
        assert report["active_key_id"] == report["backup_key_id"]

    def test_a_different_key_is_a_mismatch(self) -> None:
        report = tool.check(ACTIVE, OTHER)
        assert report["status"] == "MISMATCH" and report["probe"] is False

    def test_no_backup_and_no_active_key_are_distinct_outcomes(self) -> None:
        assert tool.check(ACTIVE, "")["status"] == "NO_BACKUP"
        assert tool.check("", ACTIVE)["status"] == "NO_ACTIVE_KEY"
        assert tool.check(ACTIVE, "short")["status"] == "NO_BACKUP"


class TestRealObject:
    def test_the_backup_decrypts_a_stored_object_and_the_checksum_matches(self) -> None:
        plain = b"From: a@corp.example\r\n\r\ntext"
        blob = sealed(ACTIVE, plain, "item-1")
        report = tool.check(
            ACTIVE, ACTIVE, blob=blob, item_id="item-1", expected_sha256=hashlib.sha256(plain).hexdigest()
        )
        assert report["status"] == "OK" and report["blob"] is True

    def test_a_wrong_item_id_does_not_decrypt(self) -> None:
        blob = sealed(ACTIVE, b"x", "item-1")
        assert tool.check(ACTIVE, ACTIVE, blob=blob, item_id="item-2")["status"] == "BLOB_UNREADABLE"

    def test_a_wrong_checksum_is_reported(self) -> None:
        blob = sealed(ACTIVE, b"x", "item-1")
        report = tool.check(ACTIVE, ACTIVE, blob=blob, item_id="item-1", expected_sha256="0" * 64)
        assert report["status"] == "BLOB_MISMATCH"

    def test_a_truncated_object_is_unreadable_and_does_not_raise(self) -> None:
        assert tool.check(ACTIVE, ACTIVE, blob=b"\x00" * 5, item_id="i")["status"] == "BLOB_UNREADABLE"


class TestSecrecy:
    def test_the_report_never_contains_a_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setenv("MSP_QUARANTINE_ENCRYPTION_KEY", ACTIVE)
        backup = tmp_path / "escrow.key"
        backup.write_text(ACTIVE, encoding="utf-8")
        out = tmp_path / "report.json"

        code = tool.main(["--backup-file", str(backup), "--json", str(out)])

        printed = capsys.readouterr().out + out.read_text(encoding="utf-8")
        assert code == 0
        assert ACTIVE not in printed
        assert json.loads(out.read_text(encoding="utf-8"))["status"] == "OK"

    def test_a_missing_backup_file_is_a_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("MSP_QUARANTINE_ENCRYPTION_KEY", ACTIVE)
        assert tool.main(["--backup-file", str(tmp_path / "none.key")]) == 1

    def test_the_active_key_can_come_from_a_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("MSP_QUARANTINE_ENCRYPTION_KEY", raising=False)
        key_file = tmp_path / "active.key"
        key_file.write_text(ACTIVE, encoding="utf-8")
        monkeypatch.setenv("MSP_QUARANTINE_ENCRYPTION_KEY_FILE", str(key_file))
        backup = tmp_path / "escrow.key"
        backup.write_text(ACTIVE, encoding="utf-8")
        assert tool.main(["--backup-file", str(backup)]) == 0

    def test_the_derivation_matches_the_one_the_platform_uses(self) -> None:
        from msp_api.config import Settings
        from msp_api.services.quarantine import _key_bytes

        assert tool.derive(ACTIVE) == _key_bytes(Settings(quarantine_encryption_key=ACTIVE))
