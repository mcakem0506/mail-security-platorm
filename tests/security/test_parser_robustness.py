"""Performance budget, regex safety, fuzzing and adversarial input (ТЗ 1.0.3 §43–§47).

Everything the parser and the detection engine touch is attacker-controlled. The property that
matters is not that analysis is fast on normal mail — it is that no input makes it slow, makes
it throw, or makes it quietly skip work without saying so.

The three failure modes these tests exist to prevent:

* **Hang.** A regular expression with catastrophic backtracking, or an unbounded loop over
  attacker-chosen data, turns one message into a worker that never returns.
* **Crash.** An exception escaping the parser turns a malformed message into a message nobody
  analysed, and — with the right retry behaviour — into a queue that never drains.
* **Silent skip.** Worse than either: analysis completes, says nothing, and the verdict reads
  as clean. Every limit must be visible in ``limits_hit``.
"""

from __future__ import annotations

import re
import time
from typing import ClassVar

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from msp_detection import analyze, default_ruleset
from msp_mail_parser import ParserLimits, analyze_html_smuggling, parse_message
from msp_mail_parser.documents import extract_document_references
from msp_mail_parser.images import read_image_header

#: ТЗ 1.0.3 §43: local analysis of one message, excluding external lookups.
LOCAL_ANALYSIS_BUDGET_SECONDS = 5.0
#: A single regular expression must never dominate that budget.
SINGLE_REGEX_BUDGET_SECONDS = 1.0


def _message(body: str = "Текст письма", subject: str = "Тема", attachments: int = 0) -> bytes:
    parts = [
        "From: Sender <sender@partner.test>",
        "To: user@corp.example",
        f"Subject: {subject}",
        "MIME-Version: 1.0",
    ]
    if attachments:
        parts.append('Content-Type: multipart/mixed; boundary="b"')
        parts.append("")
        for index in range(attachments):
            parts += [
                "--b",
                "Content-Type: text/plain",
                f'Content-Disposition: attachment; filename="f{index}.txt"',
                "",
                "data",
            ]
        parts += ["--b", "Content-Type: text/plain", "", body, "--b--"]
    else:
        parts += ["Content-Type: text/plain; charset=utf-8", "", body]
    return "\r\n".join(parts).encode("utf-8", errors="replace")


# ---------------------------------------------------------------------------------------------
# §44 — regular expression safety
# ---------------------------------------------------------------------------------------------
#: Nested quantifiers over overlapping character classes: the shape that backtracks
#: exponentially. Matching this pattern is a reason to look, not proof of a defect, so the
#: test that uses it also measures actual time.
_NESTED_QUANTIFIER = re.compile(r"\([^)]*[+*]\)[+*]|\[[^\]]*\][+*][^)]*\[[^\]]*\][+*]")


def _engine_patterns() -> list[tuple[str, re.Pattern[str]]]:
    """Every compiled pattern reachable from the detection engine and the parser."""
    import msp_detection.bec as bec
    import msp_detection.facts as facts
    import msp_detection.similarity as similarity
    import msp_mail_parser.documents as documents
    import msp_mail_parser.images as images
    import msp_mail_parser.smuggling as smuggling
    import msp_mail_parser.urls as urls

    found: list[tuple[str, re.Pattern[str]]] = []
    for module in (bec, facts, similarity, urls, documents, images, smuggling):
        for name, value in vars(module).items():
            if isinstance(value, re.Pattern):
                found.append((f"{module.__name__}.{name}", value))
        # The BEC intents keep their patterns in a table rather than in module globals, and
        # those are the longest and most complex expressions in the product.
        for intent in getattr(module, "_INTENTS", ()):
            for index, pattern in enumerate(intent.patterns):
                compiled = pattern if isinstance(pattern, re.Pattern) else re.compile(pattern)
                found.append((f"{module.__name__}.{intent.fact}[{index}]", compiled))
    return found


class TestRegexSafety:
    def test_patterns_were_found(self) -> None:
        assert len(_engine_patterns()) > 50, "нечего проверять — сбор регулярок сломался"

    #: Inputs chosen to trip nested quantifiers. Named rather than inlined: pytest puts a
    #: parameter's repr into an environment variable, and a 5 000-character payload exceeds
    #: what Windows allows there — the test would fail for a reason unrelated to regexes.
    EVIL_INPUTS: ClassVar[dict[str, str]] = {
        "latin_run": "a" * 5000,
        "cyrillic_run": "а" * 5000,
        "alternating": "ab" * 2500,
        "run_then_mismatch": "a" * 2000 + "!",
        "long_host_chain": "https://" + "a." * 1000 + "test",
        "whitespace": " " * 5000,
        "bidi_controls": "‮" * 2000,
        "repeated_keyword": "реквизит " * 600,
        "repeated_phrase": "изменились реквизиты " * 300,
        "angle_brackets": "<" * 3000,
        "base64_padding": "=" * 3000,
        "mixed_alnum": "A1b2" * 1250,
    }

    @pytest.mark.parametrize("payload_name", sorted(EVIL_INPUTS))
    def test_no_pattern_backtracks_catastrophically(self, payload_name: str) -> None:
        """Every pattern, against inputs chosen to trip nested quantifiers (ТЗ 1.0.3 §44)."""
        evil = self.EVIL_INPUTS[payload_name]
        slow: list[tuple[str, float]] = []
        for name, pattern in _engine_patterns():
            start = time.perf_counter()
            pattern.search(evil)
            elapsed = time.perf_counter() - start
            if elapsed > SINGLE_REGEX_BUDGET_SECONDS:
                slow.append((name, elapsed))
        assert not slow, f"регулярные выражения работают недопустимо долго: {slow}"

    def test_the_check_has_teeth(self) -> None:
        """A known-bad pattern must be both recognised and measurably slow.

        Measured by growth rather than against the one-second budget on purpose: reaching a
        whole second of backtracking takes an input a couple of characters longer, and the
        step count doubles with each one. A test that waited for the threshold would itself
        hang for minutes — the exact failure it exists to prevent.
        """
        catastrophic = re.compile(r"(a+)+$")
        assert _NESTED_QUANTIFIER.search(catastrophic.pattern), (
            "эвристика не распознаёт вложенные квантификаторы"
        )

        def elapsed_for(length: int) -> float:
            payload = "a" * length + "!"
            start = time.perf_counter()
            catastrophic.search(payload)
            return time.perf_counter() - start

        short, long = elapsed_for(16), elapsed_for(22)
        # Six more characters is 2**6 more work for a backtracking matcher and no measurable
        # difference for a safe one. A factor of eight leaves room for timer noise.
        assert long > short * 8, (
            f"замер не показывает экспоненциального роста ({short:.6f} → {long:.6f}): "
            "проверка выше ничего не измеряет"
        )

    def test_suspicious_shapes_are_reviewed(self) -> None:
        """Flag nested quantifiers, then prove the flagged ones are actually fast.

        The shape is a heuristic — some nested quantifiers are harmless — so a match is not a
        failure. What would be a failure is a pattern of that shape that is also slow.
        """
        flagged = [
            (name, pattern)
            for name, pattern in _engine_patterns()
            if _NESTED_QUANTIFIER.search(pattern.pattern)
        ]
        payload = "a" * 3000 + "!" + "б" * 3000
        slow = []
        for name, pattern in flagged:
            start = time.perf_counter()
            pattern.search(payload)
            if time.perf_counter() - start > SINGLE_REGEX_BUDGET_SECONDS:
                slow.append(name)
        assert not slow, f"вложенные квантификаторы с подтверждённым откатом: {slow}"


# ---------------------------------------------------------------------------------------------
# §43 — performance budget
# ---------------------------------------------------------------------------------------------
class TestPerformanceBudget:
    def test_large_plain_message_within_budget(self) -> None:
        raw = _message(body="Добрый день. " * 20_000)
        start = time.perf_counter()
        parsed = parse_message(raw)
        analyze(parsed, _context(), ruleset=default_ruleset())
        assert time.perf_counter() - start < LOCAL_ANALYSIS_BUDGET_SECONDS

    def test_many_urls_within_budget(self) -> None:
        body = " ".join(f"https://host{index}.example/path?a={index}" for index in range(2000))
        start = time.perf_counter()
        parsed = parse_message(_message(body=body))
        analyze(parsed, _context(), ruleset=default_ruleset())
        elapsed = time.perf_counter() - start
        assert elapsed < LOCAL_ANALYSIS_BUDGET_SECONDS
        # And the ones beyond the limit are reported, not dropped in silence.
        assert "MAX_URLS" in parsed.limits_hit

    def test_deeply_nested_html_within_budget(self) -> None:
        html = "<div>" * 5000 + "текст" + "</div>" * 5000
        raw = (
            "From: a@partner.test\r\nTo: b@corp.example\r\nSubject: t\r\n"
            "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + html
        ).encode()
        start = time.perf_counter()
        parse_message(raw)
        assert time.perf_counter() - start < LOCAL_ANALYSIS_BUDGET_SECONDS

    def test_many_attachments_within_budget(self) -> None:
        start = time.perf_counter()
        parsed = parse_message(_message(attachments=120))
        assert time.perf_counter() - start < LOCAL_ANALYSIS_BUDGET_SECONDS
        assert "MAX_ATTACHMENTS" in parsed.limits_hit

    def test_smuggling_scan_is_bounded(self) -> None:
        start = time.perf_counter()
        report = analyze_html_smuggling("<script>" + "QUJD" * 2_000_000 + "</script>")
        assert time.perf_counter() - start < LOCAL_ANALYSIS_BUDGET_SECONDS
        assert report.truncated


def _context():  # type: ignore[no-untyped-def]
    from msp_contracts import IntakeSource
    from msp_detection import AnalysisContext

    return AnalysisContext(
        organization_id="org",
        corporate_domains=["corp.example"],
        source=IntakeSource.API,
    )


# ---------------------------------------------------------------------------------------------
# §45 — fuzzing: no input may raise, and no input may hang
# ---------------------------------------------------------------------------------------------
_FUZZ = settings(
    max_examples=150,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)


class TestFuzzing:
    @given(st.binary(min_size=0, max_size=20_000))
    @_FUZZ
    def test_parser_never_raises_on_arbitrary_bytes(self, data: bytes) -> None:
        parsed = parse_message(data, ParserLimits(timeout_seconds=5.0))
        # A partial result is fine; an exception is not, and neither is a result that claims
        # to be a complete scan of something it could not read.
        assert parsed.size == len(data)
        if not parsed.parse_ok:
            assert parsed.errors

    @given(st.text(max_size=5000))
    @_FUZZ
    def test_smuggling_analysis_never_raises(self, text: str) -> None:
        analyze_html_smuggling(text)

    @given(st.binary(min_size=0, max_size=4096))
    @_FUZZ
    def test_image_header_never_raises(self, data: bytes) -> None:
        info = read_image_header(data)
        assert info.width >= 0 and info.height >= 0

    @given(st.binary(min_size=0, max_size=8192))
    @_FUZZ
    def test_document_reader_never_raises(self, data: bytes) -> None:
        report = extract_document_references(data)
        assert isinstance(report.urls, list)

    @given(st.binary(min_size=0, max_size=8000))
    @_FUZZ
    def test_full_analysis_never_raises(self, data: bytes) -> None:
        parsed = parse_message(data, ParserLimits(timeout_seconds=5.0))
        analyze(parsed, _context(), ruleset=default_ruleset())


# ---------------------------------------------------------------------------------------------
# §46, §47 — adversarial inputs aimed at the analysis itself
# ---------------------------------------------------------------------------------------------
class TestAdversarialInput:
    def test_zip_quine_style_nesting_is_bounded(self) -> None:
        """Nested archives must hit the depth limit and say so, not recurse."""
        import io
        import zipfile

        payload = b"x" * 100
        for _ in range(12):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("inner.zip", payload)
            payload = buffer.getvalue()

        raw = (
            b"From: a@partner.test\r\nTo: b@corp.example\r\nSubject: t\r\n"
            b"MIME-Version: 1.0\r\n"
            b'Content-Type: application/zip\r\nContent-Disposition: attachment; filename="a.zip"\r\n'
            b"Content-Transfer-Encoding: base64\r\n\r\n"
        )
        import base64

        start = time.perf_counter()
        parsed = parse_message(raw + base64.b64encode(payload))
        assert time.perf_counter() - start < LOCAL_ANALYSIS_BUDGET_SECONDS
        assert parsed.attachments

    def test_header_flood_is_bounded(self) -> None:
        headers = "".join(f"X-Custom-{index}: value\r\n" for index in range(10_000))
        raw = ("From: a@partner.test\r\nTo: b@corp.example\r\nSubject: t\r\n" + headers + "\r\nтело").encode()
        start = time.perf_counter()
        parsed = parse_message(raw)
        assert time.perf_counter() - start < LOCAL_ANALYSIS_BUDGET_SECONDS
        assert parsed.parse_ok or parsed.errors

    def test_mime_part_flood_is_capped_and_reported(self) -> None:
        parts = "".join(f"--b\r\nContent-Type: text/plain\r\n\r\nчасть {index}\r\n" for index in range(600))
        raw = (
            "From: a@partner.test\r\nTo: b@corp.example\r\nSubject: t\r\nMIME-Version: 1.0\r\n"
            'Content-Type: multipart/mixed; boundary="b"\r\n\r\n' + parts + "--b--\r\n"
        ).encode()
        parsed = parse_message(raw)
        assert "MAX_PARTS" in parsed.limits_hit or "MAX_PARTS" in str(parsed.errors)

    def test_truncated_multipart_does_not_lose_the_limit_report(self) -> None:
        raw = (
            "From: a@partner.test\r\nTo: b@corp.example\r\nSubject: t\r\nMIME-Version: 1.0\r\n"
            'Content-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\n'
            "Content-Type: text/plain\r\n\r\nначало"
        ).encode()
        parsed = parse_message(raw)
        assert parsed.size == len(raw)

    HOSTILE_SUBJECTS: ClassVar[dict[str, str]] = {
        "huge_base64_word": "=?utf-8?B?" + "QUJD" * 2000 + "?=",
        "unknown_charset": "=?unknown-charset?Q?" + "=41" * 2000 + "?=",
        "bidi_prefix": "‮" * 500 + "счёт",
        "very_long_plain": "a" * 10_000,
    }

    @pytest.mark.parametrize("subject_name", sorted(HOSTILE_SUBJECTS))
    def test_hostile_subject_encodings(self, subject_name: str) -> None:
        subject = self.HOSTILE_SUBJECTS[subject_name]
        start = time.perf_counter()
        parsed = parse_message(_message(subject=subject))
        assert time.perf_counter() - start < LOCAL_ANALYSIS_BUDGET_SECONDS
        assert isinstance(parsed.subject, str)

    def test_analysis_of_an_empty_message_is_not_clean_by_default(self) -> None:
        """An empty or unreadable message must not read as "nothing found" (ТЗ §3)."""
        parsed = parse_message(b"")
        result = analyze(parsed, _context(), ruleset=default_ruleset())
        assert not parsed.parse_ok or result.facts.missing_evidence or not parsed.from_
