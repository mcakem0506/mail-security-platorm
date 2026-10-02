"""Decode QR codes from images, in a process of its own (ТЗ 1.0.3B §31).

Run as ``python -m msp_mail_parser.qr_worker``. It reads a JSON job on stdin and writes a JSON
result on stdout, and it is started as a separate process on purpose: decoding the pixels of an
image an attacker sent is the one step here that hands attacker-controlled bytes to a large C++
library. In its own process a crash is an error message rather than a dead worker, and the
timeout that bounds it is enforced by something outside the thing being bounded.

The worker performs **no network access and no file access** beyond its own standard streams.
Everything it needs arrives on stdin.
"""

from __future__ import annotations

import base64
import json
import sys
from typing import Any

#: Refuse images larger than this many pixels before decoding. A 20 000 × 20 000 PNG decodes to
#: 1.2 GB; the limit is what keeps a decode from becoming an out-of-memory kill.
MAX_PIXELS = 40_000_000
#: Refuse encoded images larger than this. Anything bigger is not a QR code in an email.
MAX_BYTES = 8 * 1024 * 1024
#: Payloads longer than this are truncated: a QR code can carry a few kilobytes, and nothing
#: useful to an analyst lives past the first two.
MAX_PAYLOAD = 2048


def decode(data: bytes) -> list[str]:
    """Decode every QR code in one image."""
    import cv2  # imported here so the module can be inspected without the optional extra
    import numpy

    if len(data) > MAX_BYTES:
        raise ValueError("image too large")

    array = numpy.frombuffer(data, dtype=numpy.uint8)
    image = cv2.imdecode(array, cv2.IMREAD_GRAYSCALE)
    if image is None:
        raise ValueError("undecodable image")
    height, width = image.shape[:2]
    if height * width > MAX_PIXELS:
        raise ValueError("image has too many pixels")

    detector = cv2.QRCodeDetector()
    found: list[str] = []
    ok, payloads, _points, _straight = detector.detectAndDecodeMulti(image)
    if ok:
        found = [str(payload) for payload in payloads]
    else:
        # Some images carry one code that the multi-detector misses; a single pass is cheap.
        single, _single_points, _single_straight = detector.detectAndDecode(image)
        if single:
            found = [str(single)]
    return [payload[:MAX_PAYLOAD] for payload in found if payload]


def main() -> int:
    try:
        job: dict[str, Any] = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        print(json.dumps({"error": "bad_job"}))
        return 1

    results: list[dict[str, Any]] = []
    for item in (job.get("images") or [])[: int(job.get("max_images", 20))]:
        name = str(item.get("name", ""))[:255]
        try:
            data = base64.b64decode(item.get("data", ""), validate=True)
        except (ValueError, TypeError):
            results.append({"name": name, "error": "bad_base64"})
            continue
        try:
            payloads = decode(data)
        except Exception as exc:  # noqa: BLE001 - a broken image is a result, not a crash
            results.append({"name": name, "error": type(exc).__name__})
            continue
        results.append({"name": name, "payloads": payloads})

    print(json.dumps({"results": results}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
