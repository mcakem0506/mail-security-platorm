"""Прогнать тесты в Linux-контейнере (ТЗ 1.1: узел шлюза работает только на Linux).

Часть тестов шлюза зависит от платформы: символические ссылки, права, ``resource``. На Windows
они пропускаются или ведут себя иначе, и «зелёное» там не доказывает ничего про Linux, где шлюз
и работает. Этот скрипт запускает указанные тесты в чистом контейнере ``python:3.12-slim`` — так
же, как это увидит CI.

    python scripts/linux_pytest.py tests/unit/test_gateway_apply.py
    python scripts/linux_pytest.py tests/unit -k gateway
    python scripts/linux_pytest.py --sandbox tests/unit/test_attachment_sandbox.py

Ключ ``--sandbox`` добавляет библиотеки изолированного разбора вложений (7z, RAR, PDF, QR): без
них эти тесты не запустятся. Пределы процесса (RLIMIT_*) проверяются только здесь — на Windows
модуля ``resource`` нет.

Репозиторий монтируется только для чтения, без ``.venv`` и ``node_modules``; пакеты ставятся
в контейнере, на хост ничего не пишется.
"""

from __future__ import annotations

import subprocess  # nosec B404 - вызывает docker с фиксированными аргументами
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: Зависимости, которых хватает для тестов без базы данных. Для тестов с БД используйте CI.
DEPENDENCIES = "pytest pydantic pyyaml cryptography prometheus-client hypothesis idna tldextract nh3"
SANDBOX_DEPENDENCIES = "py7zr rarfile pypdfium2 opencv-python-headless numpy idna nh3 tldextract"


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    dependencies = DEPENDENCIES
    pythonpath = "packages/gateway:packages/antispam:packages/shared-contracts:packages/mail-parser"
    if "--sandbox" in argv:
        argv = [item for item in argv if item != "--sandbox"]
        dependencies = f"{DEPENDENCIES} {SANDBOX_DEPENDENCIES}"
        pythonpath += ":packages/attachment-sandbox:packages/detection-engine:tests"
    pytest_args = " ".join(f"'{item}'" for item in argv)
    script = (
        "mkdir -p /w/repo && cd /src && "
        "tar --exclude=.venv --exclude=node_modules --exclude=.git --exclude=dist "
        "-cf - . | tar -xf - -C /w/repo && cd /w/repo && "
        f"pip install -q {dependencies} 2>&1 | tail -1; "
        f"PYTHONPATH={pythonpath} "
        f"python -m pytest --noconftest -p no:cacheprovider -rs -q {pytest_args}"
    )
    completed = subprocess.run(  # noqa: S603  # nosec B603 B607 - фиксированный docker
        [  # noqa: S607
            "docker",
            "run",
            "--rm",
            "-v",
            f"{REPO}:/src:ro",
            "-w",
            "/w",
            "python:3.12-slim",
            "sh",
            "-c",
            script,
        ],
        check=False,
    )
    return completed.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
