"""Image inspection and QR codes (ТЗ 1.0.3 §38, gap GAP-002).

A QR code moves the link out of the text the platform can read and into a picture, and then out
of the corporate network entirely — the victim scans it with a personal phone. Treating such a
message as clean because it contains no URLs is exactly the failure ТЗ §3 prohibits: absence of
detection is not safety.

This module therefore separates two questions that are usually conflated:

* **Is there a QR code?** Answered without any third-party dependency, from the image header
  and a bounded structural check. No pixel decoding of untrusted image data happens in the
  worker, which keeps a decade of image-library CVEs out of the parsing path.
* **What does it contain?** Answered only when an optional decoder is installed. When it is
  not, the module says so, and the caller records missing evidence — the platform reports that
  it could not read the code rather than that the code was harmless.

The structural check reads only the dimensions from the file header. That is enough to recognise
the shape a QR code is delivered in — a small, square, lossless image — which together with
"scan this code" wording in the body is a usable quishing signal, and is honest about being a
heuristic rather than a decode.
"""

from __future__ import annotations

import base64
import json
import re
import struct
import subprocess  # nosec B404 - runs the decoder in its own process, fixed argv
import sys
import time
from dataclasses import dataclass, field

from msp_contracts import ExtractedUrl, QrHealth

from .urls import normalize_url

#: Only headers are read, never the pixel data.
_HEADER_BYTES = 64

#: A QR code is square. The lower bound is set by the format, not by taste: the smallest
#: possible symbol (version 1) is 21 modules across, so nothing below that can be a QR code at
#: all. The upper bound just excludes full-page graphics.
_MIN_SIDE_BY_SPEC = 21
#: Without any wording to go on, a square image is only treated as a candidate at a size that
#: is actually scannable from a screen. Below this, square images are overwhelmingly icons,
#: avatars and logos, and flagging them would make the signal useless.
_MIN_SIDE = 64
_MAX_SIDE = 2000
#: How far from square a candidate may be. QR codes are square by specification; a little
#: tolerance covers the white margin some generators add unevenly.
_MAX_ASPECT_DRIFT = 0.12

#: Body wording that asks the reader to use the camera. Russian and English, since a Russian
#: organisation receives both.
_SCAN_PROMPT_RE = re.compile(
    r"(?:"
    r"отскан|сканир|наведите\s+камеру|камерой\s+телефона|QR[-\s]?код|QR[-\s]?code"
    r"|scan\s+(?:the\s+)?(?:qr|code)|use\s+your\s+(?:phone|camera)"
    r")",
    re.IGNORECASE,
)


@dataclass
class ImageInfo:
    """What the header says about an image."""

    format: str = ""
    width: int = 0
    height: int = 0

    @property
    def square(self) -> bool:
        if not self.width or not self.height:
            return False
        longest, shortest = max(self.width, self.height), min(self.width, self.height)
        return (longest - shortest) / longest <= _MAX_ASPECT_DRIFT

    def qr_shaped(self, *, prompted: bool = False) -> bool:
        """The shape a QR code arrives in: square, lossless, and large enough to scan.

        ``prompted`` relaxes the size floor to what the QR specification allows, and is passed
        when the message itself asks the reader to scan something. A small square image is
        ordinarily a logo; a small square image in a message saying "scan this code" is not,
        and the wording is what tells them apart.
        """
        if not self.square:
            return False
        floor = _MIN_SIDE_BY_SPEC if prompted else _MIN_SIDE
        if not (floor <= self.width <= _MAX_SIDE):
            return False
        # A photograph is square only by accident, and JPEG is a poor container for the hard
        # edges of a QR code, so generators overwhelmingly emit PNG or GIF.
        return self.format in {"png", "gif", "bmp"}


def read_image_header(data: bytes) -> ImageInfo:
    """Read format and dimensions from the first bytes of an image.

    Hand-rolled on purpose: the alternative is handing attacker-controlled bytes to an image
    library in the main worker, and the only thing needed here is two integers from a fixed
    offset.
    """
    info = ImageInfo()
    if len(data) < 16:
        return info
    head = data[:_HEADER_BYTES]

    if head.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24 and data[12:16] == b"IHDR":
        info.format = "png"
        info.width, info.height = struct.unpack(">II", data[16:24])
        return info

    if head.startswith((b"GIF87a", b"GIF89a")) and len(data) >= 10:
        info.format = "gif"
        info.width, info.height = struct.unpack("<HH", data[6:10])
        return info

    if head.startswith(b"BM") and len(data) >= 26:
        info.format = "bmp"
        width, height = struct.unpack("<ii", data[18:26])
        info.width, info.height = abs(width), abs(height)
        return info

    if head.startswith(b"\xff\xd8\xff"):
        info.format = "jpeg"
        info.width, info.height = _jpeg_dimensions(data)
        return info

    return info


def _jpeg_dimensions(data: bytes, max_scan: int = 256 * 1024) -> tuple[int, int]:
    """Walk JPEG segment headers to the frame header.

    The walk is bounded by both the scan limit and the segment lengths themselves, so a file
    with a corrupt length field ends the loop instead of spinning in it.
    """
    index = 2
    limit = min(len(data), max_scan)
    while index + 9 < limit:
        if data[index] != 0xFF:
            index += 1
            continue
        marker = data[index + 1]
        if marker in {0xD8, 0x01} or 0xD0 <= marker <= 0xD7:
            index += 2
            continue
        length = int.from_bytes(data[index + 2 : index + 4], "big")
        if length < 2:
            return 0, 0
        # SOF0..SOF15, excluding the DHT/JPG/DAC markers interleaved in that range.
        if 0xC0 <= marker <= 0xCF and marker not in {0xC4, 0xC8, 0xCC}:
            height = int.from_bytes(data[index + 5 : index + 7], "big")
            width = int.from_bytes(data[index + 7 : index + 9], "big")
            return width, height
        index += 2 + length
    return 0, 0


@dataclass
class QrReport:
    """What is known about QR codes in a message, including what could not be read."""

    #: Images whose shape matches a QR code. A heuristic, and labelled as one.
    candidate_images: list[str] = field(default_factory=list)
    #: True when the body asks the reader to scan something.
    scan_prompt: bool = False
    #: URLs actually decoded from a code. Empty unless a decoder is installed.
    urls: list[ExtractedUrl] = field(default_factory=list)
    decoded_payloads: list[str] = field(default_factory=list)
    #: False when no decoder is available, which makes this missing evidence rather than a
    #: clean result (ТЗ 1.0.3 §3, gap GAP-002).
    decoder_available: bool = False
    decode_errors: list[str] = field(default_factory=list)
    #: Стоимость и исход декодирования. Пустая статистика означает, что декодер не вызывался.
    stats: DecodeStats = field(default_factory=lambda: DecodeStats())

    @property
    def likely_quishing(self) -> bool:
        """A QR-shaped image in a message that asks the reader to scan it.

        Stated as a likelihood, not a verdict: this is the strongest statement available
        without a decoder, and the rules weigh it as such.
        """
        return bool(self.candidate_images) and self.scan_prompt

    def as_dict(self) -> dict[str, object]:
        return {
            "candidate_images": self.candidate_images,
            "scan_prompt": self.scan_prompt,
            "decoded_urls": [url.normalized for url in self.urls],
            "decoder_available": self.decoder_available,
            "decode_errors": self.decode_errors,
            "likely_quishing": self.likely_quishing,
            "stats": self.stats.as_dict(),
        }


@dataclass
class DecodeStats:
    """Чем обошлось декодирование одного письма (ТЗ 1.0.4 §6).

    Считается здесь, а наблюдаемость заполняет вызывающая сторона: разборщик писем не знает про
    метрики и не должен — он работает и в рабочем процессе, и в оценке на корпусе, и в утилитах.
    """

    images_submitted: int = 0
    #: Изображения, не отданные декодеру: слишком большие или не вошедшие в лимит пакета.
    images_skipped: int = 0
    codes_found: int = 0
    #: Изображения, разобранные без ошибки, включая те, в которых кода не оказалось.
    successes: int = 0
    timeouts: int = 0
    failures: int = 0
    duration_seconds: float = 0.0
    #: Сколько из них ушло на запуск процесса. ``None``, если процесс не сообщил время старта:
    #: ноль означал бы «запуск бесплатный», а это неправда.
    spawn_seconds: float | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "images_submitted": self.images_submitted,
            "images_skipped": self.images_skipped,
            "codes_found": self.codes_found,
            "successes": self.successes,
            "timeouts": self.timeouts,
            "failures": self.failures,
            "duration_seconds": round(self.duration_seconds, 4),
            "spawn_seconds": (round(self.spawn_seconds, 4) if self.spawn_seconds is not None else None),
        }


#: How long the decoder may run for a whole batch, in seconds. The bound is enforced from
#: outside the process doing the work, which is the only place a bound on that work can be
#: trusted.
DECODE_TIMEOUT_SECONDS = 10.0
#: Images handed to the decoder in one batch.
MAX_DECODED_IMAGES = 20
#: Largest image the decoder is asked to look at.
MAX_DECODE_BYTES = 8 * 1024 * 1024


def decoder_available() -> bool:
    """Whether the optional decoding extra is installed."""
    try:  # pragma: no cover - depends on the deployment
        import cv2  # type: ignore[import-not-found]  # noqa: F401
        import numpy  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        return False
    return True


def decode_images(
    images: list[tuple[str, bytes]], *, timeout: float = DECODE_TIMEOUT_SECONDS
) -> tuple[dict[str, list[str]], list[str]]:
    """Декодировать QR-коды. Обёртка над :func:`decode_images_with_stats` для прежних вызовов."""
    decoded, errors, _stats = decode_images_with_stats(images, timeout=timeout)
    return decoded, errors


def decode_images_with_stats(
    images: list[tuple[str, bytes]], *, timeout: float = DECODE_TIMEOUT_SECONDS
) -> tuple[dict[str, list[str]], list[str], DecodeStats]:
    """Декодировать QR-коды в отдельном процессе (ТЗ 1.0.3B §31, ТЗ 1.0.4 §6).

    Возвращает ``(payloads_by_image, errors, stats)``. Процесс отдельный намеренно: разбор
    пикселей присланного изображения — единственный шаг, отдающий байты злоумышленника большой
    C++-библиотеке. В своём процессе падение становится сообщением об ошибке, а не мёртвым
    рабочим процессом, и таймаут задаётся снаружи того, что он ограничивает.

    Процесс не обращается к сети и не пишет файлов: всё нужное приходит на stdin, а запись
    запрещена пределом ``RLIMIT_FSIZE = 0``, который он ставит себе сам.
    """
    stats = DecodeStats()
    if not images:
        return {}, [], stats
    if not decoder_available():
        # Отсутствие декодера — не ошибка декодирования, и в счётчик отказов оно не идёт.
        return {}, [], stats

    selected = [
        (name, data) for name, data in images[:MAX_DECODED_IMAGES] if data and len(data) <= MAX_DECODE_BYTES
    ]
    stats.images_submitted = len(selected)
    stats.images_skipped = len(images) - len(selected)
    if not selected:
        return {}, [], stats

    job = {
        "max_images": MAX_DECODED_IMAGES,
        "images": [{"name": name, "data": base64.b64encode(data).decode("ascii")} for name, data in selected],
    }

    launched_at = time.time()
    try:
        completed = subprocess.run(  # nosec B603 - fixed argv, no shell
            [sys.executable, "-m", "msp_mail_parser.qr_worker"],
            input=json.dumps(job),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        # Декодирование, которое не заканчивается, — это декодирование, которого не было.
        # Сказать об этом и есть весь смысл: иначе письмо выглядит проверенным, потому что
        # никто не пожаловался.
        stats.duration_seconds = time.time() - launched_at
        stats.timeouts = 1
        return {}, ["DECODE_TIMEOUT"], stats
    except OSError as exc:  # pragma: no cover - проблема интерпретатора или сборки
        stats.duration_seconds = time.time() - launched_at
        stats.failures = 1
        return {}, [f"DECODER_UNAVAILABLE:{type(exc).__name__}"], stats

    stats.duration_seconds = time.time() - launched_at

    if completed.returncode != 0:
        stats.failures = 1
        return {}, [f"DECODER_FAILED:{completed.returncode}"], stats
    try:
        payload = json.loads(completed.stdout or "{}")
    except ValueError:
        stats.failures = 1
        return {}, ["DECODER_BAD_OUTPUT"], stats

    started_at = payload.get("started_at")
    if isinstance(started_at, int | float) and started_at >= launched_at:
        # Стоимость запуска интерпретатора отдельно от стоимости разбора пикселей: без этого
        # полсекунды на письмо читаются как медленный декодер, хотя это запуск процесса.
        stats.spawn_seconds = float(started_at) - launched_at

    decoded: dict[str, list[str]] = {}
    errors: list[str] = []
    for item in payload.get("results", []) or []:
        name = str(item.get("name", ""))
        if item.get("error"):
            errors.append(f"{name[:60]}:{item['error']}")
            stats.failures += 1
            continue
        stats.successes += 1
        payloads = [str(value) for value in (item.get("payloads") or [])]
        if payloads:
            decoded[name] = payloads
            stats.codes_found += len(payloads)
    return decoded, errors, stats


#: Сколько ждать пробу здоровья. Проба не декодирует недоверенных байтов и укладывается в запуск
#: интерпретатора, поэтому предел меньше рабочего.
PROBE_TIMEOUT_SECONDS = 20.0
#: Проба, уложившаяся дольше этого, означает работоспособный, но негодный для потока компонент.
PROBE_SLOW_SECONDS = 5.0


@dataclass
class QrComponentHealth:
    """Состояние профиля ``qr-analysis`` (ТЗ 1.0.4 §6)."""

    status: QrHealth
    detail: str
    probe_seconds: float | None = None
    limits: dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "detail": self.detail,
            "probe_seconds": (round(self.probe_seconds, 4) if self.probe_seconds is not None else None),
            "limits": self.limits,
        }


def component_health(*, timeout: float = PROBE_TIMEOUT_SECONDS) -> QrComponentHealth:
    """Проверить компонент, запустив процесс-декодер и ничего ему не декодируя.

    Проба отвечает на вопрос «работает ли то, что должно работать», и отвечает им **до** того,
    как придёт письмо с кодом. Четыре состояния различаются намеренно:

    ``DISABLED`` — компонента нет, и так задумано. ``FAILED`` — есть и не работает. Для
    администратора это разные задачи; для письма следствие одинаковое, и оно всё равно будет
    помечено как проверенное не полностью.

    ``DEGRADED`` — компонент работает, но одно из требований профиля не выполнено: либо проба
    идёт слишком долго, либо платформа не умеет ставить процессу ресурсные пределы. Второе — не
    придирка: без пределов остаются таймаут родителя и лимиты по пикселям, а запрет на запись
    файлов и ограничение памяти не действуют.
    """
    if not decoder_available():
        return QrComponentHealth(
            QrHealth.DISABLED,
            "необязательный компонент «qr» не установлен: содержимое кодов не читается, "
            "наличие кода определяется по-прежнему",
        )

    launched_at = time.time()
    try:
        completed = subprocess.run(  # nosec B603 - fixed argv, no shell
            [sys.executable, "-m", "msp_mail_parser.qr_worker"],
            input=json.dumps({"probe": True}),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return QrComponentHealth(
            QrHealth.FAILED,
            f"проба не ответила за {timeout:g} с",
            probe_seconds=time.time() - launched_at,
        )
    except OSError as exc:
        return QrComponentHealth(QrHealth.FAILED, f"процесс не запускается: {type(exc).__name__}")

    elapsed = time.time() - launched_at
    try:
        payload = json.loads(completed.stdout or "{}")
    except ValueError:
        return QrComponentHealth(QrHealth.FAILED, "проба вернула неразбираемый ответ", probe_seconds=elapsed)

    limits = payload.get("limits") or {}
    if completed.returncode != 0 or payload.get("probe") != "ok":
        detail = str(payload.get("detail") or payload.get("probe") or completed.returncode)
        return QrComponentHealth(
            QrHealth.FAILED, f"проба не прошла: {detail[:200]}", probe_seconds=elapsed, limits=limits
        )

    if not limits.get("applied"):
        return QrComponentHealth(
            QrHealth.DEGRADED,
            "декодер работает, но ресурсные пределы процессу не поставлены: "
            f"{limits.get('reason', 'причина не указана')}",
            probe_seconds=elapsed,
            limits=limits,
        )
    if elapsed > PROBE_SLOW_SECONDS:
        return QrComponentHealth(
            QrHealth.DEGRADED,
            f"проба заняла {elapsed:.1f} с: запуск процесса на каждое письмо обойдётся дорого",
            probe_seconds=elapsed,
            limits=limits,
        )
    return QrComponentHealth(
        QrHealth.AVAILABLE, "декодер работает, пределы поставлены", probe_seconds=elapsed, limits=limits
    )


def inspect_images(
    images: list[tuple[str, bytes]],
    *,
    body_text: str = "",
    decode: bool = True,
    max_images: int = 20,
    max_bytes: int = 4 * 1024 * 1024,
) -> QrReport:
    """Look for QR codes among a message's images (ТЗ 1.0.3 §38).

    ``images`` is a list of ``(name, data)`` pairs — attachments and inline parts alike, since a
    QR code is usually an inline image rather than an attachment.
    """
    report = QrReport()
    report.scan_prompt = bool(body_text) and _SCAN_PROMPT_RE.search(body_text) is not None

    report.decoder_available = decode and decoder_available()

    candidates: list[tuple[str, bytes]] = []
    for name, data in images[:max_images]:
        if not data or len(data) > max_bytes:
            continue
        info = read_image_header(data)
        if not info.qr_shaped(prompted=report.scan_prompt):
            continue
        report.candidate_images.append(name[:255])
        candidates.append((name[:255], data))

    if not candidates or not report.decoder_available:
        return report

    decoded, errors, report.stats = decode_images_with_stats(candidates)
    report.decode_errors.extend(errors)
    for name, payloads in decoded.items():
        for payload in payloads:
            report.decoded_payloads.append(payload[:2000])
            lowered = payload.strip().lower()
            if lowered.startswith(("http://", "https://", "www.")):
                url = normalize_url(payload.strip(), source="qr")
                if not url.parse_error and url.host:
                    report.urls.append(url)
        _ = name

    return report
