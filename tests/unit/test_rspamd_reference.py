"""Эталон отрисованной конфигурации Rspamd не расходится с генератором (ТЗ 1.2 §27)."""

from __future__ import annotations

import runpy
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = runpy.run_path(str(REPO_ROOT / "scripts" / "render_rspamd_reference.py"))


def test_reference_matches_the_generator() -> None:
    expected = SCRIPT["reference_files"]()
    reference_dir: Path = SCRIPT["REFERENCE_DIR"]
    on_disk = {
        path.relative_to(reference_dir).as_posix(): path.read_bytes()
        for path in reference_dir.rglob("*")
        if path.is_file()
    }
    assert set(on_disk) == set(expected), (
        "состав эталона изменился: python scripts/render_rspamd_reference.py"
    )
    changed = sorted(name for name in expected if on_disk[name] != expected[name])
    assert not changed, f"эталон устарел: {changed}; обновите python scripts/render_rspamd_reference.py"


def test_reference_contains_no_secrets_or_enforcement() -> None:
    reference_dir: Path = SCRIPT["REFERENCE_DIR"]
    text = "\n".join(p.read_text(encoding="utf-8") for p in reference_dir.rglob("*") if p.is_file())
    assert "BEGIN PRIVATE KEY" not in text
    assert "milter_default_action" not in text
