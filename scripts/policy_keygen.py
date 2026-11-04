"""Пара ключей Ed25519 для подписи политики принуждения (MSP 1.3P, ТЗ 1.3P §9).

Закрытый ключ нужен только панели (``MSP_ENFORCEMENT_POLICY_SIGNING_PRIVATE_KEY_FILE``), открытый — узлам
(``MSP_ENFORCEMENT_PUBLIC_KEY_FILE``). Узел с открытым ключом принимает только подпись Ed25519, поэтому захваченный узел подделать
политику не может.

Скрипт пишет закрытый ключ в файл (права 0600, существующий файл не перезаписывается) и **не печатает его**. На экран выходит
только открытый ключ и его отпечаток — для сверки на узлах::

    python scripts/policy_keygen.py --private /secure/policy-signing.key --public policy-signing.pub

Резервную копию закрытого ключа храните в изолированном хранилище, как ключ карантина. Смена ключа: выпустить новую пару, раздать новый
открытый ключ узлам, затем включить новый закрытый ключ на панели и опубликовать политику.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import sys
from pathlib import Path


def generate(private_path: Path, public_path: Path) -> dict[str, str]:
    from msp_enforcement.policy import generate_ed25519_keypair

    for path in (private_path, public_path):
        if path.exists():
            raise FileExistsError(f"{path} уже существует: ключ не перезаписывается")
    private, public = generate_ed25519_keypair()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(base64.b64encode(private).decode() + "\n")
    public_path.write_text(base64.b64encode(public).decode() + "\n", encoding="utf-8")
    return {
        "public_key": base64.b64encode(public).decode(),
        "fingerprint": hashlib.sha256(public).hexdigest()[:16],
        "private_key_file": str(private_path),
        "public_key_file": str(public_path),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Пара ключей Ed25519 для подписи политики")
    parser.add_argument("--private", required=True, help="куда записать закрытый ключ (для панели)")
    parser.add_argument("--public", required=True, help="куда записать открытый ключ (для узлов)")
    args = parser.parse_args(argv)
    try:
        result = generate(Path(args.private), Path(args.public))
    except FileExistsError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    for key, value in result.items():
        sys.stdout.write(f"{key}: {value}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
