"""QR decoding, and the limits that make it safe to do at all (ТЗ 1.0.3B §31).

Decoding the pixels of an image an attacker sent is the one step in the parser that hands
attacker-controlled bytes to a large C++ library. It therefore runs in a process of its own,
under a timeout the parent enforces, with caps on image size and pixel count — and the whole
thing is optional, because a platform that cannot be deployed without an imaging dependency is a
platform that will be deployed with an unpatched one.

What must hold either way: when the code cannot be read, the message is marked as not fully
scanned rather than passing as clean.
"""

from __future__ import annotations

import base64
import struct
import zlib

import pytest
from msp_mail_parser import inspect_images, parse_message
from msp_mail_parser.images import MAX_DECODE_BYTES, decode_images, decoder_available

requires_decoder = pytest.mark.skipif(
    not decoder_available(), reason="необязательный компонент «qr» не установлен"
)


def _qr_png(payload: str, scale: int = 6) -> bytes:
    """A real, scannable QR code."""
    import cv2
    import numpy

    matrix = cv2.QRCodeEncoder.create().encode(payload)
    # The encoder already returns 0/255. Scaling it again overflows uint8 into noise — which is
    # how the first version of this helper produced an image nothing could read.
    bordered = cv2.copyMakeBorder(matrix.astype(numpy.uint8), 4, 4, 4, 4, cv2.BORDER_CONSTANT, value=255)
    image = cv2.resize(bordered, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
    ok, buffer = cv2.imencode(".png", image)
    assert ok
    return bytes(buffer)


def _plain_png(side: int) -> bytes:
    def chunk(tag: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", zlib.crc32(tag + payload))

    header = struct.pack(">IIBBBBB", side, side, 8, 0, 0, 0, 0)
    pixels = b"".join(b"\x00" + b"\xff" * side for _ in range(side))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(pixels))
        + chunk(b"IEND", b"")
    )


class TestDecoding:
    @requires_decoder
    def test_a_real_code_is_read(self) -> None:
        url = "https://login.corp-portal.example/verify?id=7741"
        decoded, errors = decode_images([("code.png", _qr_png(url))])
        assert decoded == {"code.png": [url]}
        assert errors == []

    @requires_decoder
    def test_the_url_reaches_the_parsed_message(self) -> None:
        url = "https://pay-now.example/invoice/8821"
        raw = (
            "From: Billing <billing@partner.test>\r\n"
            "To: buh@corp.example\r\n"
            "Subject: Oplata\r\n"
            "MIME-Version: 1.0\r\n"
            'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
            "--b\r\n"
            'Content-Type: text/plain; charset="utf-8"\r\n'
            "Content-Transfer-Encoding: base64\r\n\r\n"
            + base64.b64encode("Отсканируйте QR-код для оплаты.".encode()).decode()
            + "\r\n--b\r\n"
            "Content-Type: image/png\r\n"
            'Content-Disposition: inline; filename="code.png"\r\n'
            "Content-Transfer-Encoding: base64\r\n\r\n"
            + base64.b64encode(_qr_png(url)).decode()
            + "\r\n--b--\r\n"
        ).encode()

        parsed = parse_message(raw)
        assert url in [u.normalized for u in parsed.urls if u.source == "qr"]
        # The code was read, so the scan is complete on that count.
        assert "QR_NOT_DECODED" not in parsed.limits_hit

    @requires_decoder
    def test_a_plain_square_yields_nothing_and_no_error(self) -> None:
        """A logo is not a QR code, and must not produce a spurious payload."""
        decoded, errors = decode_images([("logo.png", _plain_png(200))])
        assert decoded == {}
        assert errors == []

    def test_an_oversized_image_is_never_handed_to_the_decoder(self) -> None:
        oversized = b"\x89PNG\r\n\x1a\n" + b"\x00" * (MAX_DECODE_BYTES + 10)
        decoded, errors = decode_images([("huge.png", oversized)])
        assert decoded == {}
        assert errors == []

    def test_garbage_is_reported_as_an_error_not_a_crash(self) -> None:
        decoded, errors = decode_images([("broken.png", b"\x89PNG\r\n\x1a\nnot an image")])
        assert decoded == {}
        if decoder_available():
            assert errors, "нечитаемое изображение должно быть названо, а не промолчать"

    @requires_decoder
    def test_a_timeout_is_reported_rather_than_waited_out(self) -> None:
        """A decode that will not finish is a decode that did not happen.

        The bound is enforced by the parent process, which is the only place a bound on that
        work can be trusted.
        """
        decoded, errors = decode_images([("code.png", _qr_png("https://x.test"))], timeout=0.001)
        assert decoded == {}
        assert errors == ["DECODE_TIMEOUT"]


class TestWithoutTheDecoder:
    def test_an_unread_code_marks_the_scan_incomplete(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """ТЗ §3: the platform must say it could not read the code, not that it found nothing."""
        import msp_mail_parser.images as images

        monkeypatch.setattr(images, "decoder_available", lambda: False)
        raw = (
            "From: Billing <billing@partner.test>\r\n"
            "To: buh@corp.example\r\n"
            "Subject: Oplata\r\n"
            "MIME-Version: 1.0\r\n"
            'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
            "--b\r\n"
            'Content-Type: text/plain; charset="utf-8"\r\n'
            "Content-Transfer-Encoding: base64\r\n\r\n"
            + base64.b64encode("Отсканируйте QR-код для оплаты.".encode()).decode()
            + "\r\n--b\r\n"
            "Content-Type: image/png\r\n"
            'Content-Disposition: inline; filename="code.png"\r\n'
            "Content-Transfer-Encoding: base64\r\n\r\n"
            + base64.b64encode(_plain_png(200)).decode()
            + "\r\n--b--\r\n"
        ).encode()

        parsed = parse_message(raw)
        assert parsed.qr["decoder_available"] is False
        assert parsed.qr["likely_quishing"] is True
        assert "QR_NOT_DECODED" in parsed.limits_hit

    def test_the_signal_survives_without_the_decoder(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        import msp_mail_parser.images as images

        monkeypatch.setattr(images, "decoder_available", lambda: False)
        report = inspect_images([("code.png", _plain_png(200))], body_text="Отсканируйте QR-код для оплаты")
        assert report.candidate_images == ["code.png"]
        assert report.decoder_available is False
        assert report.urls == []
        assert report.likely_quishing
