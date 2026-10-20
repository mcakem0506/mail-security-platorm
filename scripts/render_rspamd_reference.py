"""Эталон отрисованной конфигурации Rspamd (ТЗ 1.2 §27, CI «rspamd-config-test»).

Файлы в ``infrastructure/rspamd/reference`` — результат ``render`` для фиксированной конфигурации. Тест
сравнивает их с текущим кодом: правка генератора без обновления эталона видна в обзоре как изменение
файлов, а не проходит незамеченной.

    python scripts/render_rspamd_reference.py          # обновить эталон
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "packages" / "antispam"))

from msp_antispam.rspamd_config import (  # noqa: E402
    DkimSigning,
    RspamdNodeConfig,
    Thresholds,
    render,
)

REFERENCE_DIR = REPO_ROOT / "infrastructure" / "rspamd" / "reference"


def reference_files() -> dict[str, bytes]:
    cfg = RspamdNodeConfig(
        authserv_id="gw.example.test",
        nameservers=("192.0.2.53",),
        redis={"host": "192.0.2.52", "port": 6379},  # type: ignore[arg-type]
        thresholds=Thresholds(),
        local_networks=("192.0.2.0/26",),
        hyperscan=False,
        dkim_signing=DkimSigning(enabled=False, sign_networks=("192.0.2.0/26",)),
    )
    return render(cfg).files


def main() -> None:
    if REFERENCE_DIR.exists():
        shutil.rmtree(REFERENCE_DIR)
    for name, body in reference_files().items():
        target = REFERENCE_DIR / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    print(f"записано файлов: {len(reference_files())}")


if __name__ == "__main__":
    main()
