"""Сведения о сертификатах узла (ТЗ 1.1 §41, §46).

Читается **только сертификат** (открытая часть). Закрытые ключи этим модулем не открываются и не
передаются: путь к ключу сюда не попадает по построению, а в панель уходят лишь назначение,
субъект, издатель, сроки и отпечаток. Алерт о скором истечении срока строится на этих сведениях
(``GatewayCertificate``), а не на файле ключа.

Разбор делает ``openssl x509``: разбирать X.509 вручную в стандартной библиотеке нечем, а
приватный интерфейс ``ssl`` не гарантирует стабильности. ``openssl`` вызывается с фиксированными
аргументами, без оболочки, и читает один файл.
"""

from __future__ import annotations

import re
import subprocess  # nosec B404 - фиксированная команда openssl без оболочки
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_FIELDS = re.compile(
    r"^(?P<key>subject|issuer|notBefore|notAfter|sha256 Fingerprint)\s*=\s*(?P<value>.+)$", re.I
)
_FINGERPRINT = re.compile(r"^[0-9A-F:]{95}$")


@dataclass(frozen=True)
class CertificateInfo:
    usage: str
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    fingerprint: str

    def seconds_left(self, now: datetime) -> float:
        return (self.not_after - now).total_seconds()

    def as_event(self) -> dict[str, object]:
        return {
            "usage": self.usage,
            "subject": self.subject[:300],
            "issuer": self.issuer[:300],
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "fingerprint": self.fingerprint,
        }


class CertificateError(Exception):
    """Сертификат не удалось прочитать. Сообщение не содержит содержимого файла."""


def _parse_date(text: str) -> datetime:
    # Формат openssl: "Oct 14 12:00:00 2026 GMT".
    return datetime.strptime(text.strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)


def parse_openssl_output(usage: str, output: str) -> CertificateInfo:
    values: dict[str, str] = {}
    for line in output.splitlines():
        match = _FIELDS.match(line.strip())
        if match:
            values[match["key"].lower()] = match["value"].strip()
    try:
        fingerprint = values["sha256 fingerprint"].upper()
        if not _FINGERPRINT.match(fingerprint):
            raise ValueError("отпечаток")
        return CertificateInfo(
            usage=usage,
            subject=values["subject"],
            issuer=values["issuer"],
            not_before=_parse_date(values["notbefore"]),
            not_after=_parse_date(values["notafter"]),
            fingerprint=fingerprint.replace(":", "").lower(),
        )
    except (KeyError, ValueError) as error:
        raise CertificateError("вывод openssl не разобран") from error


def read_certificate(
    usage: str, path: Path, *, openssl: str = "openssl", timeout: float = 10.0
) -> CertificateInfo:
    """Прочитать один файл сертификата."""
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603 - фиксированные аргументы, без оболочки
            [
                openssl,
                "x509",
                "-noout",
                "-subject",
                "-issuer",
                "-dates",
                "-fingerprint",
                "-sha256",
                "-in",
                str(path),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CertificateError(f"openssl недоступен: {type(error).__name__}") from error
    if completed.returncode != 0:
        raise CertificateError("файл не является сертификатом или не читается")
    return parse_openssl_output(usage, completed.stdout)
