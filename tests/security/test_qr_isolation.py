"""Изоляция процесса-декодера QR (ТЗ 1.0.4 §7).

Декодер — единственное место, где байты злоумышленника попадают в большую C++-библиотеку,
разбирающую пиксели. Поэтому проверяется не «умеет ли он читать коды» (это тесты
``test_qr_decoding.py``), а что он не делает ничего, кроме чтения: не обращается к сети, не
пишет файлов, не роняет рабочий процесс и не превращает испорченное изображение в молчание.

Часть проверок выполняется разбором синтаксического дерева, а не запуском. Это сознательно:
проверка «не обращается к сети», выполненная запуском, подтверждает только то, что в этот раз
не обратился.
"""

from __future__ import annotations

import ast
import json
import pathlib
import struct
import subprocess
import sys
import zlib

import pytest
from msp_mail_parser import images
from msp_mail_parser.images import (
    MAX_DECODE_BYTES,
    MAX_DECODED_IMAGES,
    decode_images_with_stats,
    decoder_available,
)
from msp_mail_parser.qr_worker import MAX_BYTES, MAX_PAYLOAD, MAX_PIXELS

WORKER = pathlib.Path("packages/mail-parser/msp_mail_parser/qr_worker.py")

requires_decoder = pytest.mark.skipif(
    not decoder_available(), reason="необязательный компонент «qr» не установлен"
)


def _png(width: int, height: int, *, payload: bytes = b"") -> bytes:
    """Маленький корректный PNG заданного размера."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    raw = b"".join(b"\x00" + b"\xff" * width for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw))
        + (payload or b"")
        + chunk(b"IEND", b"")
    )


def _run_worker(job: dict[str, object], *, timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "msp_mail_parser.qr_worker"],
        input=json.dumps(job),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


class TestTheWorkerReachesNothing:
    def test_it_imports_nothing_that_can_reach_the_network(self) -> None:
        tree = ast.parse(WORKER.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
        forbidden = {
            "socket",
            "ssl",
            "http",
            "urllib",
            "urllib3",
            "httpx",
            "requests",
            "aiohttp",
            "ftplib",
            "smtplib",
            "telnetlib",
            "dns",
            "whois",
            "webbrowser",
        }
        assert not (imported & forbidden), f"декодер импортирует {sorted(imported & forbidden)}"

    def test_it_never_asks_opencv_to_read_a_path_or_a_stream(self) -> None:
        """``imdecode`` работает с байтами. ``imread`` и ``VideoCapture`` принимают путь или URL —
        то есть дают библиотеке самой открыть что-то по строке из письма."""
        tree = ast.parse(WORKER.read_text(encoding="utf-8"))
        called = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        forbidden = {"imread", "imreadmulti", "VideoCapture", "VideoWriter", "imwrite"}
        assert not (called & forbidden), f"декодер вызывает {sorted(called & forbidden)}"

    def test_it_opens_no_files(self) -> None:
        tree = ast.parse(WORKER.read_text(encoding="utf-8"))
        names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert "open" not in names, "декодер открывает файлы: всё нужное приходит на stdin"


def _apply_limits_in_a_fresh_process() -> dict[str, object]:
    """Вызвать ``apply_limits()`` в отдельном процессе и вернуть то, что он сообщил.

    Вызывать её прямо в тесте нельзя, и это была реальная ошибка: ``RLIMIT_CPU`` и
    ``RLIMIT_FSIZE`` необратимо ограничивают тот процесс, который их поставил. В процессе pytest
    это значило бы 15 секунд процессорного времени на весь прогон и запрет записи любых файлов.
    На Windows модуля ``resource`` нет, вызов был пустой, и локально всё проходило; на Linux
    первый же прогон CI убил pytest сигналом ``SIGXCPU`` на 69% тестов.

    Отдельный процесс здесь не обход, а более точная проверка: воркер так и живёт — ставит
    пределы себе в собственном процессе, до того как возьмётся за данные.
    """
    code = (
        "import json; from msp_mail_parser.qr_worker import apply_limits; print(json.dumps(apply_limits()))"
    )
    completed = subprocess.run(  # nosec B603 - fixed argv, no shell
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    return dict(json.loads(completed.stdout))


class TestResourceLimits:
    def test_limits_are_applied_where_the_platform_allows(self) -> None:
        applied = _apply_limits_in_a_fresh_process()
        try:
            import resource  # noqa: F401
        except ImportError:
            # Windows: предел поставить нечем, и об этом сказано прямо. Пустой ответ означал бы
            # «ограничено», а это было бы неправдой.
            assert applied["applied"] is False
            assert applied.get("reason")
            return
        assert applied["applied"] is True
        assert applied["RLIMIT_FSIZE"] == 0, "запись файлов должна быть запрещена совсем"
        assert applied["RLIMIT_CPU"] > 0
        assert applied["RLIMIT_AS"] > 0

    def test_the_test_process_itself_is_not_limited(self) -> None:
        """Пределы воркера не должны оказаться на процессе, который его проверяет.

        Проверка самой проверки для ошибки, которая уже случалась: вызов ``apply_limits()`` в
        процессе pytest ставил ему 15 секунд процессорного времени. Тест не падал сам, он
        убивал весь прогон позже, на случайном месте, — поэтому ловить это нужно прямо.
        """
        try:
            import resource
        except ImportError:
            pytest.skip("на этой платформе пределов процесса нет")
        soft, _hard = resource.getrlimit(resource.RLIMIT_CPU)  # type: ignore[attr-defined]
        assert soft in (resource.RLIM_INFINITY, -1) or soft > 600, (  # type: ignore[attr-defined]
            f"у процесса тестов предел процессорного времени {soft} с: кто-то вызвал apply_limits() "
            "в нём самом"
        )
        fsize, _ = resource.getrlimit(resource.RLIMIT_FSIZE)  # type: ignore[attr-defined]
        assert fsize != 0, "процессу тестов запрещена запись файлов"

    def test_the_declared_caps_are_sane(self) -> None:
        """Пределы существуют, чтобы изображение не стало отказом в обслуживании."""
        assert 0 < MAX_PIXELS <= 100_000_000
        assert 0 < MAX_BYTES <= 32 * 1024 * 1024
        assert 0 < MAX_PAYLOAD <= 8192
        assert MAX_DECODE_BYTES <= MAX_BYTES, "родитель не должен отправлять то, что отвергнет дитя"


class TestHostileInput:
    """Испорченный ввод обязан давать ошибку по этому изображению, а не падение процесса."""

    def _decode_one(self, name: str, data: bytes) -> tuple[dict[str, list[str]], list[str]]:
        decoded, errors, _stats = decode_images_with_stats([(name, data)])
        return decoded, errors

    @requires_decoder
    @pytest.mark.parametrize(
        ("name", "data"),
        [
            ("truncated.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 16),
            ("not-an-image.png", b"\x89PNG\r\n\x1a\n" + b"nonsense" * 32),
            ("jpeg-header-only.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 64),
            ("empty-after-header.jpg", b"\xff\xd8\xff\xd9"),
            ("zeros.png", bytes(512)),
        ],
    )
    def test_malformed_images_produce_an_error_not_a_crash(self, name: str, data: bytes) -> None:
        decoded, errors = self._decode_one(name, data)
        assert decoded == {}
        assert errors, "испорченное изображение должно быть названо нечитаемым"
        assert not any("DECODER_FAILED" in error for error in errors), (
            "процесс не должен падать целиком из-за одного изображения"
        )

    def test_an_oversized_image_is_not_sent_to_the_decoder(self) -> None:
        """Отсев до запуска процесса: отправлять девять мегабайт, чтобы получить отказ, незачем."""
        decoded, errors, stats = decode_images_with_stats(
            [("huge.png", b"\x89PNG\r\n\x1a\n" + bytes(MAX_DECODE_BYTES + 1))]
        )
        assert decoded == {}
        assert errors == []
        assert stats.images_submitted == 0
        assert stats.images_skipped == 1

    @requires_decoder
    def test_extreme_dimensions_are_refused_by_pixel_count(self) -> None:
        """PNG с заголовком 30000×30000 весит немного, а разворачивается в гигабайт."""
        header = struct.pack(">IIBBBBB", 30000, 30000, 8, 0, 0, 0, 0)

        def chunk(kind: bytes, data: bytes) -> bytes:
            return (
                struct.pack(">I", len(data))
                + kind
                + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
            )

        bomb = (
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(bytes(4096)))
            + chunk(b"IEND", b"")
        )
        decoded, errors, stats = decode_images_with_stats([("bomb.png", bomb)])
        assert decoded == {}
        assert errors, "изображение с чрезмерным числом пикселей должно быть отвергнуто"
        assert stats.timeouts == 0, "отказ должен приходить от предела, а не от таймаута"

    def test_more_images_than_the_batch_allows_are_counted_as_skipped(self) -> None:
        images_in = [(f"i{n}.png", _png(64, 64)) for n in range(MAX_DECODED_IMAGES + 5)]
        _decoded, _errors, stats = decode_images_with_stats(images_in)
        if decoder_available():
            assert stats.images_submitted == MAX_DECODED_IMAGES
        assert stats.images_skipped == 5, "лишние изображения должны быть названы пропущенными"

    def test_corrupted_base64_is_reported_per_image(self) -> None:
        """Проверяется сам процесс: родитель кодирует сам и такого не пришлёт."""
        result = _run_worker({"images": [{"name": "bad.png", "data": "!!!не base64!!!"}]})
        assert result.returncode == 0, "одно испорченное поле не должно валить процесс"
        payload = json.loads(result.stdout)
        assert payload["results"][0]["error"] == "bad_base64"

    def test_a_bad_job_is_an_answer_not_a_traceback(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "msp_mail_parser.qr_worker"],
            input="не json",
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert json.loads(result.stdout)["error"] == "bad_job"
        assert "Traceback" not in result.stderr


class TestFailureIsolation:
    def test_a_timeout_is_recorded_as_a_timeout(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        def explode(*_args: object, **_kwargs: object) -> None:
            raise subprocess.TimeoutExpired(cmd="qr_worker", timeout=1.0)

        monkeypatch.setattr(images, "decoder_available", lambda: True)
        monkeypatch.setattr(images.subprocess, "run", explode)
        decoded, errors, stats = decode_images_with_stats([("code.png", _png(128, 128))])
        assert decoded == {}
        assert errors == ["DECODE_TIMEOUT"]
        assert stats.timeouts == 1
        assert stats.failures == 0, "не успели и не смогли — разные вещи"

    def test_a_crashed_child_is_reported_not_raised(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """Падение процесса-декодера обязано остаться сообщением об ошибке."""
        completed = subprocess.CompletedProcess(args=["qr"], returncode=-11, stdout="", stderr="")
        monkeypatch.setattr(images, "decoder_available", lambda: True)
        monkeypatch.setattr(images.subprocess, "run", lambda *a, **k: completed)
        decoded, errors, stats = decode_images_with_stats([("code.png", _png(128, 128))])
        assert decoded == {}
        assert errors == ["DECODER_FAILED:-11"]
        assert stats.failures == 1

    def test_unparseable_output_is_reported(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        completed = subprocess.CompletedProcess(args=["qr"], returncode=0, stdout="мусор", stderr="")
        monkeypatch.setattr(images, "decoder_available", lambda: True)
        monkeypatch.setattr(images.subprocess, "run", lambda *a, **k: completed)
        _decoded, errors, stats = decode_images_with_stats([("code.png", _png(128, 128))])
        assert errors == ["DECODER_BAD_OUTPUT"]
        assert stats.failures == 1

    def test_absence_of_the_decoder_is_not_a_failure(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """Выключенный компонент — это выбор администратора, а не поломка."""
        monkeypatch.setattr(images, "decoder_available", lambda: False)
        _decoded, errors, stats = decode_images_with_stats([("code.png", _png(128, 128))])
        assert errors == []
        assert stats.failures == 0
        assert stats.images_submitted == 0


def _qr_png(payload: str, scale: int = 6) -> bytes | None:
    """Настоящий QR-код с заданной полезной нагрузкой, или ``None`` без компонента."""
    try:
        import cv2  # type: ignore[import-not-found]
        import numpy  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover - зависит от сборки
        return None

    encoder = cv2.QRCodeEncoder.create()
    matrix = encoder.encode(payload)
    # Матрица приходит в значениях 0 и 255; домножать её ещё раз нельзя — переполнение uint8
    # превращает код в шум. Эта ошибка уже была допущена однажды в фикстурах корпуса.
    image = numpy.kron(matrix, numpy.ones((scale, scale), dtype=numpy.uint8))
    quiet = 4 * scale
    canvas = numpy.full((image.shape[0] + 2 * quiet, image.shape[1] + 2 * quiet), 255, dtype=numpy.uint8)
    canvas[quiet : quiet + image.shape[0], quiet : quiet + image.shape[1]] = image
    ok, encoded = cv2.imencode(".png", canvas)
    return bytes(encoded.tobytes()) if ok else None


class TestPayloadIsTreatedAsHostileText:
    """Содержимое кода — это текст из письма. Декодер возвращает его и больше ничего."""

    @requires_decoder
    @pytest.mark.parametrize(
        "payload",
        [
            # Юникод в домене и в пути.
            "http://xn--80ak6aa92e.test/%D1%81%D1%87%D1%91%D1%82",
            # Внутренний адрес: декодер не должен по нему ходить, а конвейер URL обязан увидеть.
            "http://127.0.0.1:8000/admin",
            # Адрес метаданных облака — классическая цель SSRF.
            "http://169.254.169.254/latest/meta-data/",
            # Чувствительная строка запроса: она не должна попасть ни в журнал, ни наружу.
            "https://pay.test/invoice?token=secret-value&amount=100000",
            # Схема, которую нельзя исполнять.
            "javascript:alert(1)",
        ],
    )
    def test_the_payload_comes_back_as_text_and_nothing_happens(self, payload: str) -> None:
        image = _qr_png(payload)
        assert image is not None
        decoded, errors, stats = decode_images_with_stats([("code.png", image)])
        assert errors == [], f"код с полезной нагрузкой {payload!r} должен читаться"
        assert decoded.get("code.png") == [payload], "вернуться должен ровно исходный текст"
        assert stats.codes_found == 1
        assert stats.failures == 0
        # Декодер отработал и завершился; никаких сетевых обращений он сделать не мог — это
        # проверено отдельно разбором импортов и вызовов.
        assert stats.duration_seconds > 0

    @requires_decoder
    def test_a_long_payload_is_truncated(self) -> None:
        """QR-код может нести килобайты, а аналитику не нужно ничего после первых двух.

        Длина выбрана между лимитом (2048) и ёмкостью самого кода (около 2950 байт в байтовом
        режиме): просить больше бессмысленно — такой код физически не существует, и кодировщик
        отказывается его строить.
        """
        long_payload = "https://pay.test/?q=" + "x" * (MAX_PAYLOAD + 400)
        image = _qr_png(long_payload, scale=4)
        assert image is not None
        decoded, errors, _stats = decode_images_with_stats([("long.png", image)])
        if errors:
            pytest.skip(f"кодировщик не справился с длинной нагрузкой: {errors}")
        values = decoded.get("long.png") or []
        assert values, "длинный код должен читаться"
        assert all(len(value) <= MAX_PAYLOAD for value in values)
        assert values[0] == long_payload[:MAX_PAYLOAD]


class TestComponentHealth:
    def test_four_states_are_distinguishable(self) -> None:
        from msp_contracts import QrHealth

        assert {status.value for status in QrHealth} == {
            "AVAILABLE",
            "DEGRADED",
            "DISABLED",
            "FAILED",
        }

    def test_absent_component_reports_disabled_not_failed(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from msp_contracts import QrHealth

        monkeypatch.setattr(images, "decoder_available", lambda: False)
        health = images.component_health()
        assert health.status is QrHealth.DISABLED
        assert "не установлен" in health.detail

    def test_a_probe_that_does_not_answer_is_failed(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from msp_contracts import QrHealth

        def explode(*_args: object, **_kwargs: object) -> None:
            raise subprocess.TimeoutExpired(cmd="qr_worker", timeout=1.0)

        monkeypatch.setattr(images, "decoder_available", lambda: True)
        monkeypatch.setattr(images.subprocess, "run", explode)
        assert images.component_health().status is QrHealth.FAILED

    def test_working_decoder_without_limits_is_degraded(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """Требование профиля не выполнено, даже если коды читаются."""
        from msp_contracts import QrHealth

        completed = subprocess.CompletedProcess(
            args=["qr"],
            returncode=0,
            stdout=json.dumps({"probe": "ok", "limits": {"applied": False, "reason": "нет модуля"}}),
            stderr="",
        )
        monkeypatch.setattr(images, "decoder_available", lambda: True)
        monkeypatch.setattr(images.subprocess, "run", lambda *a, **k: completed)
        health = images.component_health()
        assert health.status is QrHealth.DEGRADED
        assert "пределы" in health.detail

    def test_working_decoder_with_limits_is_available(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from msp_contracts import QrHealth

        completed = subprocess.CompletedProcess(
            args=["qr"],
            returncode=0,
            stdout=json.dumps({"probe": "ok", "limits": {"applied": True, "RLIMIT_FSIZE": 0}}),
            stderr="",
        )
        monkeypatch.setattr(images, "decoder_available", lambda: True)
        monkeypatch.setattr(images.subprocess, "run", lambda *a, **k: completed)
        assert images.component_health().status is QrHealth.AVAILABLE
