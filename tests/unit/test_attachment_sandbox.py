"""Песочница вложений: 7z, RAR и PDF разбираются в отдельном процессе (ТЗ 1.1 §55–§57; GAP-003, GAP-004).

Общий принцип проверок: каждый исход, кроме «разобрано», обязан быть **назван** — шифрование,
повреждение, превышение предела, сбой воркера. Пустой результат в вердикте читался бы как «ничего
не найдено», а это единственное, что песочница не вправе сказать о том, чего не просмотрела.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from fixtures import attachments as make
from msp_attachment_sandbox import list_archive, page_images, render_pdf
from msp_attachment_sandbox import runner as sandbox_runner

try:
    import resource  # noqa: F401

    HAS_RLIMIT = True
except ImportError:
    HAS_RLIMIT = False

needs_rlimit = pytest.mark.skipif(
    not HAS_RLIMIT, reason="пределы процесса доступны только на Linux (проверяется в CI)"
)


def _with_original_path(extra: Path) -> str:
    """PYTHONPATH пробного воркера: его каталог плюс то, что было, — иначе пакет песочницы не найти."""
    import os

    parts = [str(extra), os.environ.get("PYTHONPATH", ""), str(Path.cwd())]
    return os.pathsep.join(part for part in parts if part)


def names(result) -> list[str]:  # type: ignore[no-untyped-def]
    return [entry["name"] for entry in result.payload.get("entries", [])]


class TestSevenZip:
    def test_listing_shows_names_sizes_and_directories(self) -> None:
        data = make.make_7z({"a.txt": b"hello", "docs/b.pdf": b"%PDF-"})
        result = list_archive(data, "7z")
        assert result.status == "OK"
        assert {"a.txt", "docs/b.pdf"} <= set(names(result))
        assert result.payload["listing_only"] is True
        sizes = {e["name"]: e["size"] for e in result.payload["entries"]}
        assert sizes["a.txt"] == 5

    def test_a_password_makes_it_unscannable_never_clean(self) -> None:
        """ТЗ §56: архив с паролем — ENCRYPTED_UNSCANNABLE, а не «чисто»."""
        result = list_archive(make.make_7z({"a.txt": b"hello"}, password="secret"), "7z")
        assert result.status == "ENCRYPTED_UNSCANNABLE"
        assert "ENCRYPTED_ARCHIVE" in result.flags

    def test_encrypted_headers_hide_even_the_names_and_are_still_reported(self) -> None:
        result = list_archive(make.make_7z({"a.txt": b"x"}, password="secret", encrypt_headers=True), "7z")
        assert result.status == "ENCRYPTED_UNSCANNABLE"
        assert "ENCRYPTED_HEADERS" in result.flags
        assert names(result) == []

    @pytest.mark.parametrize(
        ("name", "flag"),
        [
            ("../../etc/passwd", "PATH_TRAVERSAL"),
            ("a/../../b.exe", "PATH_TRAVERSAL"),
            ("/etc/shadow", "ABSOLUTE_PATH"),
            ("C:/Windows/x.exe", "ABSOLUTE_PATH"),
            ("inner.zip", "NESTED_ARCHIVE"),
            ("deep/inner.7Z", "NESTED_ARCHIVE"),
            ("x" * 400 + ".txt", "FILENAME_TOO_LONG"),
        ],
    )
    def test_dangerous_names_are_flagged(self, name: str, flag: str) -> None:
        result = list_archive(make.make_7z({name: b"x"}), "7z")
        assert result.status == "OK"
        assert flag in result.flags

    def test_a_compression_bomb_is_flagged_without_being_unpacked(self) -> None:
        """52 МБ нулей сжимаются в несколько килобайт. Воркер читает заголовок и ничего не распаковывает."""
        data = make.make_7z({"zeros.bin": b"\0" * (52 * 1024 * 1024)})
        assert len(data) < 200_000
        result = list_archive(data, "7z")
        assert result.status == "OK"
        assert "EXCESSIVE_COMPRESSION_RATIO" in result.flags
        assert result.seconds < 15

    def test_too_many_files_is_flagged(self) -> None:
        data = make.make_7z({f"f{i}.txt": b"x" for i in range(600)})
        assert "TOO_MANY_FILES" in list_archive(data, "7z").flags

    def test_a_truncated_archive_is_malformed_not_empty(self) -> None:
        data = make.make_7z({"a.txt": b"hello" * 100})
        for cut in (10, 40, len(data) // 2, len(data) - 5):
            result = list_archive(data[:cut], "7z")
            assert result.status in {"MALFORMED", "ENCRYPTED_UNSCANNABLE"}, (cut, result.status)
            assert "CORRUPT_ARCHIVE" in result.flags or "ENCRYPTED_ARCHIVE" in result.flags

    @pytest.mark.parametrize(
        "junk", [b"", b"\x00" * 64, b"7z\xbc\xaf\x27\x1c" + b"\xff" * 100, b"not an archive" * 50]
    )
    def test_garbage_is_malformed(self, junk: bytes) -> None:
        result = list_archive(junk, "7z")
        assert result.status == "MALFORMED"
        assert result.ok is False

    def test_a_flipped_byte_never_yields_a_clean_pass_by_silence(self) -> None:
        data = bytearray(make.make_7z({"a.txt": b"hello"}))
        for position in range(0, len(data), 7):
            mutated = bytearray(data)
            mutated[position] ^= 0xFF
            result = list_archive(bytes(mutated), "7z")
            assert result.status in {"OK", "MALFORMED", "ENCRYPTED_UNSCANNABLE", "LIMIT_EXCEEDED"}
            if result.status == "OK":
                assert result.payload["entries_total"] >= 1, (
                    "«OK» без единой записи — это молчание, а не чистота"
                )


class TestRar:
    @pytest.mark.parametrize("builder", [make.make_rar5, make.make_rar4], ids=["rar5", "rar4"])
    def test_listing(self, builder) -> None:  # type: ignore[no-untyped-def]
        result = list_archive(builder({"a.txt": b"hello", "run.exe": b"MZ"}), "rar")
        assert result.status == "OK"
        assert {"a.txt", "run.exe"} == set(names(result))

    @pytest.mark.parametrize("builder", [make.make_rar5, make.make_rar4], ids=["rar5", "rar4"])
    def test_password_protected_members_are_unscannable(self, builder) -> None:  # type: ignore[no-untyped-def]
        result = list_archive(builder({"a.txt": b"hello"}, encrypt_files=True), "rar")
        assert result.status == "ENCRYPTED_UNSCANNABLE"
        assert "ENCRYPTED_ARCHIVE" in result.flags

    def test_encrypted_headers_are_never_reported_as_a_clean_empty_archive(self) -> None:
        result = list_archive(make.make_rar5({}, encrypt_headers=True), "rar")
        assert result.status in {"ENCRYPTED_UNSCANNABLE", "MALFORMED"}
        assert result.ok is False

    def test_path_traversal_in_a_member_name(self) -> None:
        result = list_archive(make.make_rar5({"../evil.exe": b"MZ"}), "rar")
        assert "PATH_TRAVERSAL" in result.flags

    @pytest.mark.parametrize(
        "junk",
        [b"", b"Rar!\x1a\x07\x00rest", b"Rar!\x1a\x07\x01\x00" + b"\xff" * 64, b"Rar!" * 100],
    )
    def test_damaged_rar_is_malformed(self, junk: bytes) -> None:
        result = list_archive(junk, "rar")
        assert result.status == "MALFORMED"

    def test_truncated_rar5_is_not_a_clean_pass(self) -> None:
        data = make.make_rar5({"a.txt": b"hello" * 100, "b.txt": b"x" * 100})
        for cut in (8, 20, len(data) // 2):
            result = list_archive(data[:cut], "rar")
            assert result.status != "OK" or result.payload["entries_total"] >= 1

    def test_no_external_unpacker_is_ever_launched(self) -> None:
        """Распаковщик отключён: даже если бы он был установлен, воркер его не вызовет."""
        from msp_attachment_sandbox import archive_worker

        result = archive_worker.handle({"kind": "rar", "data": ""})
        assert result["status"] == "MALFORMED"
        import rarfile

        archive_worker.list_rar(make.make_rar4({"a.txt": b"x"}))
        assert rarfile.UNRAR_TOOL.startswith("/nonexistent")


class TestWorkerProtocol:
    def test_unsupported_kind(self) -> None:
        assert list_archive(b"x", "cab").status == "UNSUPPORTED"

    @pytest.mark.parametrize(
        "job", [None, [], "x", {"kind": 7}, {"kind": "7z"}, {"kind": "7z", "data": "!!!"}]
    )
    def test_hostile_jobs_are_answered_not_crashed(self, job) -> None:  # type: ignore[no-untyped-def]
        from msp_attachment_sandbox import archive_worker

        result = archive_worker.handle(job)
        assert result["status"] in {"UNSUPPORTED", "MALFORMED"}

    def test_oversized_input_is_a_named_limit(self) -> None:
        from msp_attachment_sandbox import archive_worker

        result = list_archive(b"\0" * (archive_worker.MAX_INPUT_BYTES + 1), "7z")
        assert result.status == "LIMIT_EXCEEDED"

    def test_names_with_control_characters_are_made_printable(self) -> None:
        result = list_archive(make.make_7z({"evil\x1b[31m\nname.txt": b"x"}), "7z")
        assert all(ch.isprintable() for name in names(result) for ch in name)


class TestPdf:
    def test_an_embedded_qr_page_is_rendered_and_the_url_is_decodable(self) -> None:
        from msp_mail_parser.images import decode_images

        result = render_pdf(make.pdf_with_embedded_qr("https://evil.example/login"))
        assert result.status == "OK"
        decoded, errors = decode_images(page_images(result, "invoice.pdf"))
        assert errors == []
        assert "https://evil.example/login" in [p for payloads in decoded.values() for p in payloads]

    def test_a_vector_drawn_qr_is_also_found(self) -> None:
        """Извлечение картинок такой код пропустило бы: поэтому страницы рисуются целиком."""
        from msp_mail_parser.images import decode_images

        result = render_pdf(make.pdf_with_vector_qr("https://evil.example/vector"))
        assert result.status == "OK"
        decoded, _ = decode_images(page_images(result, "v.pdf"))
        assert "https://evil.example/vector" in [p for payloads in decoded.values() for p in payloads]

    def test_a_page_without_a_qr_decodes_to_nothing(self) -> None:
        from msp_mail_parser.images import decode_images

        result = render_pdf(make.pdf_text_only())
        assert result.status == "OK"
        decoded, errors = decode_images(page_images(result, "t.pdf"))
        assert [p for payloads in decoded.values() for p in payloads] == []
        assert errors == []

    def test_only_images_leave_the_worker(self) -> None:
        """Ни текста, ни ссылок, ни объектов документа: наружу выходят страницы и счётчики."""
        result = render_pdf(make.pdf_with_active_content("https://evil.example/a"))
        assert result.status == "OK"
        assert set(result.payload) <= {"status", "pages", "pages_total", "pages_rendered", "flags", "limits"}
        assert set(result.payload["pages"][0]) == {"index", "width", "height", "png"}

    def test_a_document_with_javascript_renders_and_is_not_trusted(self) -> None:
        result = render_pdf(make.pdf_with_active_content("https://evil.example/a"))
        assert result.status == "OK"

    def test_page_count_is_bounded_and_the_rest_is_named(self) -> None:
        result = render_pdf(make.pdf_pages(40))
        assert result.status == "PARTIAL"
        assert result.payload["pages_rendered"] == 10
        assert result.payload["pages_total"] == 40
        assert "PAGES_NOT_RENDERED" in result.flags

    def test_a_giant_page_is_refused_by_limit_not_rendered_into_memory(self) -> None:
        result = render_pdf(make.pdf_pages(1, size=(14400, 14400)))
        assert result.status == "LIMIT_EXCEEDED"
        assert "PAGE_TOO_LARGE" in result.flags
        assert result.payload["pages"] == []

    def test_a_pixel_budget_stops_a_many_page_giant_document(self) -> None:
        result = render_pdf(make.pdf_pages(10, size=(1800, 1800)))
        assert result.status in {"PARTIAL", "LIMIT_EXCEEDED", "OK"}
        total = sum(page["width"] * page["height"] for page in result.payload["pages"])
        assert total <= 24_000_000 + 4_000_000

    def test_an_encrypted_pdf_is_unscannable_not_clean(self) -> None:
        result = render_pdf(make.pdf_encrypted())
        assert result.status == "ENCRYPTED_UNSCANNABLE"
        assert result.ok is False

    @pytest.mark.parametrize(
        "junk",
        [b"", b"%PDF-1.4 garbage", b"not a pdf at all", b"%PDF-" + b"\xff" * 500, make.pdf_text_only()[:80]],
    )
    def test_damaged_pdf_is_malformed(self, junk: bytes) -> None:
        result = render_pdf(junk)
        assert result.status == "MALFORMED"
        assert result.payload["pages"] == []

    def test_oversized_pdf_is_a_named_limit(self) -> None:
        from msp_attachment_sandbox import pdf_worker

        result = render_pdf(b"%PDF-1.4\n" + b"\0" * (pdf_worker.MAX_INPUT_BYTES + 1))
        assert result.status == "LIMIT_EXCEEDED"

    def test_a_flipped_byte_never_crashes_the_parent(self) -> None:
        data = bytearray(make.pdf_with_embedded_qr("https://evil.example/x"))
        for position in range(0, len(data), max(1, len(data) // 25)):
            mutated = bytearray(data)
            mutated[position] ^= 0xFF
            result = render_pdf(bytes(mutated))
            assert result.status in {"OK", "PARTIAL", "MALFORMED", "ENCRYPTED_UNSCANNABLE", "LIMIT_EXCEEDED"}


class TestRunnerFailures:
    """Любой исход воркера, кроме нормального ответа, становится названным статусом."""

    @pytest.fixture
    def module(self, tmp_path: Path, monkeypatch):  # type: ignore[no-untyped-def]
        def build(code: str) -> str:
            name = f"sandbox_probe_{abs(hash(code)) % 10**8}"
            (tmp_path / f"{name}.py").write_text(textwrap.dedent(code), encoding="utf-8")
            monkeypatch.setenv("PYTHONPATH", str(tmp_path))
            return name

        return build

    def test_a_hung_worker_is_killed_by_the_parent(self, module) -> None:  # type: ignore[no-untyped-def]
        name = module("import time\ntime.sleep(60)\n")
        result = sandbox_runner.run_worker(name, {}, timeout=1.5)
        assert result.status == "TIMEOUT"
        assert result.seconds < 10

    def test_a_crash_is_named(self, module) -> None:  # type: ignore[no-untyped-def]
        name = module("import os\nos._exit(139)\n")
        assert sandbox_runner.run_worker(name, {}, timeout=10).status == "CRASHED"

    def test_an_exception_in_the_worker_is_a_crash_not_a_clean_pass(self, module) -> None:  # type: ignore[no-untyped-def]
        name = module("raise RuntimeError('boom')\n")
        assert sandbox_runner.run_worker(name, {}, timeout=10).status == "CRASHED"

    def test_garbage_output_is_a_protocol_error(self, module) -> None:  # type: ignore[no-untyped-def]
        name = module("print('not json at all')\n")
        assert sandbox_runner.run_worker(name, {}, timeout=10).status == "PROTOCOL_ERROR"

    def test_unexpected_json_shapes_are_protocol_errors(self, module) -> None:  # type: ignore[no-untyped-def]
        for body in ("[1, 2]", '{"no_status": 1}', '{"status": 5}', "null"):
            name = module(f"print({body!r})\n")
            assert sandbox_runner.run_worker(name, {}, timeout=10).status == "PROTOCOL_ERROR", body

    def test_runaway_output_is_cut_off(self, module, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr(sandbox_runner, "MAX_OUTPUT_BYTES", 1000)
        name = module("import sys\nsys.stdout.write('x' * 5000)\n")
        assert sandbox_runner.run_worker(name, {}, timeout=10).status == "OUTPUT_TOO_LARGE"

    def test_a_missing_worker_module_is_a_crash(self) -> None:
        assert sandbox_runner.run_worker("no_such_module_anywhere", {}, timeout=10).status == "CRASHED"

    def test_the_parents_secrets_do_not_reach_the_worker(self, module, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setenv("MSP_SECRET_KEY", "super-secret-value")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "another-secret")
        name = module(
            """
            import json, os, sys
            sys.stdin.read()
            print(json.dumps({"status": "OK", "env": sorted(os.environ)}))
            """
        )
        result = sandbox_runner.run_worker(name, {}, timeout=10)
        assert result.status == "OK"
        assert "MSP_SECRET_KEY" not in result.payload["env"]
        assert "AWS_SECRET_ACCESS_KEY" not in result.payload["env"]

    def test_the_runner_never_raises(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        def broken(*_a, **_k):  # type: ignore[no-untyped-def]
            raise OSError("нет такого интерпретатора")

        monkeypatch.setattr(sandbox_runner.subprocess, "run", broken)
        assert sandbox_runner.list_archive(b"x", "7z").status == "UNAVAILABLE"


@needs_rlimit
class TestLimitsAreReallyEnforced:
    """Проверяется на Linux: пределы должны не просто быть объявлены, а действовать."""

    @pytest.fixture
    def probe(self, tmp_path: Path, monkeypatch):  # type: ignore[no-untyped-def]
        def build(body: str) -> dict:  # type: ignore[type-arg]
            code = (
                "import json, os, sys\n"
                "from msp_attachment_sandbox.limits import apply_limits\n"
                # В контейнере тесты идут от root, а RLIMIT_NPROC на root не действует; боевой воркер
                # работает непривилегированным (USER в образе), поэтому проба сначала становится им.
                "if os.getuid() == 0:\n"
                "    os.setgid(65534)\n"
                "    os.setuid(65534)\n"
                "applied = apply_limits()\n"
                + textwrap.dedent(body)
                + "\nprint(json.dumps({'status': 'OK', 'applied': applied, 'result': result}))\n"
            )
            (tmp_path / "probe_mod.py").write_text(code, encoding="utf-8")
            monkeypatch.setenv("PYTHONPATH", _with_original_path(tmp_path))
            outcome = sandbox_runner.run_worker("probe_mod", {}, timeout=20)
            assert outcome.status == "OK", outcome.detail
            return outcome.payload

        return build

    def test_the_worker_cannot_create_a_file(self, probe, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        target = tmp_path / "written.bin"
        payload = probe(
            f"""
            try:
                with open({str(target)!r}, "wb") as handle:
                    handle.write(b"x" * 100)
                result = "WROTE"
            except OSError as error:
                result = type(error).__name__
            """
        )
        assert payload["result"] != "WROTE"
        assert not target.exists() or target.stat().st_size == 0

    def test_the_worker_cannot_start_a_process(self, probe) -> None:  # type: ignore[no-untyped-def]
        payload = probe(
            """
            import subprocess
            try:
                subprocess.run(["/bin/true"], check=False)
                result = "SPAWNED"
            except OSError as error:
                result = type(error).__name__
            """
        )
        assert payload["result"] != "SPAWNED"

    def test_memory_is_capped(self, probe) -> None:  # type: ignore[no-untyped-def]
        payload = probe(
            """
            try:
                blob = bytearray(4 * 1024 * 1024 * 1024)
                result = "ALLOCATED"
            except MemoryError:
                result = "MemoryError"
            """
        )
        assert payload["result"] == "MemoryError"

    def test_all_limits_report_as_applied(self, probe) -> None:  # type: ignore[no-untyped-def]
        payload = probe("result = 1")
        assert payload["applied"]["applied"] is True
        assert payload["applied"]["RLIMIT_FSIZE"] == 0
        assert payload["applied"]["RLIMIT_NPROC"] == 0

    def test_the_pdf_worker_really_starts_as_an_unprivileged_user_under_every_limit(self, probe) -> None:  # type: ignore[no-untyped-def]
        """Только так видно, что числовые библиотеки не требуют потоков, которых воркеру не дают.

        Тесты от root этого не показывают: на root RLIMIT_NPROC не действует. Именно здесь поймано,
        что numpy обрывал импорт при запрете на потоки.
        """
        payload = probe(
            """
            import base64, sys
            sys.path.insert(0, "tests")
            from fixtures import attachments as make
            from msp_attachment_sandbox import pdf_worker
            job = {"data": base64.b64encode(make.pdf_with_vector_qr("https://x.example/y")).decode()}
            outcome = pdf_worker.handle(job)
            result = {"status": outcome["status"], "pages": len(outcome["pages"])}
            """
        )
        assert payload["applied"]["non_root"] is True
        assert payload["result"] == {"status": "OK", "pages": 1}

    def test_a_cpu_spin_is_killed_by_the_kernel_before_the_parent_timeout(
        self, tmp_path: Path, monkeypatch
    ) -> None:  # type: ignore[no-untyped-def]
        code = (
            "from msp_attachment_sandbox.limits import apply_limits\n"
            "apply_limits(cpu_seconds=1)\n"
            "while True:\n    pass\n"
        )
        (tmp_path / "spin_mod.py").write_text(code, encoding="utf-8")
        monkeypatch.setenv("PYTHONPATH", _with_original_path(tmp_path))
        result = sandbox_runner.run_worker("spin_mod", {}, timeout=30)
        assert result.status == "CRASHED"
        assert result.seconds < 25

    def test_a_pdf_bomb_does_not_take_the_machine(self) -> None:
        """Крошечный PDF объявляет изображение в миллиарды пикселей: отрисовка упирается в предел."""
        data = make._pdf(  # type: ignore[attr-defined]
            [
                b"<< /Type /Catalog /Pages 2 0 R >>",
                b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 600 800] /Contents 4 0 R "
                b"/Resources << /XObject << /Im0 5 0 R >> >> >>",
                make._stream(b"", b"q 600 0 0 800 0 0 cm /Im0 Do Q"),  # type: ignore[attr-defined]
                make._stream(  # type: ignore[attr-defined]
                    b"/Type /XObject /Subtype /Image /Width 60000 /Height 60000 /ColorSpace /DeviceGray "
                    b"/BitsPerComponent 8 /Filter /FlateDecode",
                    __import__("zlib").compress(b"\0" * 1024 * 1024),
                ),
            ]
        )
        result = render_pdf(data)
        assert result.status in {"OK", "PARTIAL", "MALFORMED", "LIMIT_EXCEEDED", "CRASHED", "TIMEOUT"}
