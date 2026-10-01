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

import re
import struct
from dataclasses import dataclass, field

from msp_contracts import ExtractedUrl

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
        }


def _load_decoder():  # type: ignore[no-untyped-def]
    """Return a callable decoding image bytes to payload strings, or ``None``.

    The decoder is an optional extra (``pip install mail-security-platform[qr]``). It is
    imported lazily and never required: a deployment that declines the dependency keeps a
    working platform and an honest "could not read this code" instead of a silent pass.
    """
    try:  # pragma: no cover - exercised only where the optional extra is installed
        import cv2  # type: ignore[import-not-found]
        import numpy  # type: ignore[import-not-found]
    except ImportError:
        return None

    def decode(data: bytes) -> list[str]:  # pragma: no cover - requires the optional extra
        array = numpy.frombuffer(data, dtype=numpy.uint8)
        image = cv2.imdecode(array, cv2.IMREAD_GRAYSCALE)
        if image is None:
            raise ValueError("undecodable image")
        detector = cv2.QRCodeDetector()
        ok, payloads, _, _ = detector.detectAndDecodeMulti(image)
        if not ok:
            return []
        return [p for p in payloads if p]

    return decode


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

    decoder = _load_decoder() if decode else None
    report.decoder_available = decoder is not None

    for name, data in images[:max_images]:
        if not data or len(data) > max_bytes:
            continue
        info = read_image_header(data)
        if not info.qr_shaped(prompted=report.scan_prompt):
            continue
        report.candidate_images.append(name[:255])
        if decoder is None:
            continue
        try:  # pragma: no cover - requires the optional extra
            payloads = decoder(data)
        except Exception as exc:  # noqa: BLE001 - a broken image is a fact, not a crash
            report.decode_errors.append(f"{name[:80]}:{type(exc).__name__}")
            continue
        for payload in payloads:  # pragma: no cover - requires the optional extra
            report.decoded_payloads.append(payload[:2000])
            lowered = payload.strip().lower()
            if lowered.startswith(("http://", "https://", "www.")):
                url = normalize_url(payload.strip(), source="qr")
                if not url.parse_error and url.host:
                    report.urls.append(url)

    return report
