"""Генератор пары ключей подписи политики (MSP 1.3P, ТЗ §9)."""

from __future__ import annotations

import base64
import importlib.util
from pathlib import Path

import pytest
from msp_enforcement import policy as pol

SPEC = importlib.util.spec_from_file_location("policy_keygen", Path("scripts/policy_keygen.py"))
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def test_the_generated_files_form_a_working_pair(tmp_path: Path) -> None:
    result = tool.generate(tmp_path / "k" / "sign.key", tmp_path / "sign.pub")

    private = pol.decode_key((tmp_path / "k" / "sign.key").read_text(encoding="utf-8"))
    public = pol.decode_key((tmp_path / "sign.pub").read_text(encoding="utf-8"))
    assert pol.public_key_from_private(private) == public
    assert result["public_key"] == base64.b64encode(public).decode()


def test_the_private_key_is_never_printed(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    code = tool.main(["--private", str(tmp_path / "sign.key"), "--public", str(tmp_path / "sign.pub")])

    out = capsys.readouterr()
    private_text = (tmp_path / "sign.key").read_text(encoding="utf-8").strip()
    assert code == 0
    assert private_text not in out.out + out.err


def test_an_existing_key_is_not_overwritten(tmp_path: Path) -> None:
    (tmp_path / "sign.key").write_text("старый ключ", encoding="utf-8")
    with pytest.raises(FileExistsError):
        tool.generate(tmp_path / "sign.key", tmp_path / "sign.pub")
    assert (tmp_path / "sign.key").read_text(encoding="utf-8") == "старый ключ"
    assert not (tmp_path / "sign.pub").exists()


def test_the_command_fails_instead_of_overwriting(tmp_path: Path) -> None:
    (tmp_path / "sign.pub").write_text("x", encoding="utf-8")
    assert tool.main(["--private", str(tmp_path / "sign.key"), "--public", str(tmp_path / "sign.pub")]) == 1
    assert not (tmp_path / "sign.key").exists(), "закрытый ключ создан, хотя открытый файл занят"


def test_two_runs_give_different_keys(tmp_path: Path) -> None:
    a = tool.generate(tmp_path / "a.key", tmp_path / "a.pub")
    b = tool.generate(tmp_path / "b.key", tmp_path / "b.pub")
    assert a["public_key"] != b["public_key"] and a["fingerprint"] != b["fingerprint"]
