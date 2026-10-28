"""Журнальный отчёт Exchange: извлечение оригинала (MSP 1.3P, ТЗ 1.3P §6, §10, §15).

Exchange при журналировании присылает не само письмо, а *отчёт* о нём: письмо с заголовком ``X-MS-Journal-Report``, текстовой
частью (отправитель, получатели, идентификатор) и вложением ``message/rfc822`` — оригиналом. Анализировать надо оригинал, а не
отчёт: у отчёта свои заголовки и свой путь, и проверка по нему оценила бы письмо журнальной службы, а не письмо сотрудника.

Правила разбора:

* оригинал берётся только из вложения ``message/rfc822``; если его нет — отчёт непригоден, а не «чист»;
* оригинал сверх предела размера не усекается и не анализируется: вызывающий записывает его как непроверенный;
* отчёт внутри отчёта отвергается: так журнал, пересланный в журнал, не размножает письма по кругу;
* конверт из текстовой части сохраняется как происхождение, но решений не принимает: он сообщён отправителем отчёта;
* адреса из текстовой части очищаются от управляющих символов и ограничиваются по числу.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email import message_from_bytes, policy
from email.message import Message

JOURNAL_HEADER = "x-ms-journal-report"
MAX_ENVELOPE_ADDRESSES = 200

_ADDRESS = re.compile(r"[A-Za-z0-9._%+'\-]+@[A-Za-z0-9.\-]+")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

PROBLEM_NOT_A_REPORT = "NOT_A_JOURNAL_REPORT"
PROBLEM_NO_ORIGINAL = "NO_ORIGINAL_ATTACHMENT"
PROBLEM_MALFORMED = "MALFORMED_REPORT"
PROBLEM_NESTED = "NESTED_JOURNAL_REPORT"
PROBLEM_OVERSIZED = "ORIGINAL_OVERSIZED"
PROBLEM_MULTIPLE = "MULTIPLE_ORIGINALS"


@dataclass(frozen=True)
class JournalExtraction:
    """Результат разбора. ``usable`` — есть оригинал, который можно анализировать."""

    is_journal_report: bool
    original: bytes = b""
    original_size: int = 0
    envelope_sender: str = ""
    envelope_recipients: tuple[str, ...] = ()
    report_message_id: str = ""
    original_message_id: str = ""
    report_sha256: str = ""
    original_sha256: str = ""
    problems: tuple[str, ...] = field(default_factory=tuple)

    @property
    def usable(self) -> bool:
        return bool(self.original) and not self.problems_blocking

    @property
    def problems_blocking(self) -> bool:
        return any(
            p in self.problems
            for p in (
                PROBLEM_NOT_A_REPORT,
                PROBLEM_NO_ORIGINAL,
                PROBLEM_MALFORMED,
                PROBLEM_NESTED,
                PROBLEM_OVERSIZED,
            )
        )


def _addresses(text: str) -> list[str]:
    cleaned = _CONTROL.sub(" ", text)
    return [m.group(0).lower() for m in _ADDRESS.finditer(cleaned)]


def _envelope(text: str) -> tuple[str, tuple[str, ...]]:
    """Отправитель и получатели из строк ``Sender:`` и ``Recipient:`` текстовой части отчёта."""
    sender = ""
    recipients: list[str] = []
    for line in text.splitlines():
        head, _, value = line.partition(":")
        key = head.strip().lower()
        if key == "sender" and not sender:
            found = _addresses(value)
            sender = found[0] if found else ""
        elif key == "recipient":
            recipients.extend(_addresses(value))
    unique = tuple(dict.fromkeys(recipients))[:MAX_ENVELOPE_ADDRESSES]
    return sender, unique


def _first_text(message: Message) -> str:
    for part in message.walk():
        if part.get_content_type() == "text/plain" and not part.is_multipart():
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
    return ""


def _is_report(message: Message) -> bool:
    return any(str(name).lower() == JOURNAL_HEADER for name in message)


def extract_journal_report(raw: bytes, *, max_original_bytes: int) -> JournalExtraction:
    """Достать оригинал из журнального отчёта. Не бросает исключений: любой сбой — проблема в результате."""
    report_sha = hashlib.sha256(raw).hexdigest()
    try:
        report = message_from_bytes(raw, policy=policy.SMTP)
    except Exception:  # noqa: BLE001 - разбор постороннего письма не должен ронять приём
        return JournalExtraction(False, report_sha256=report_sha, problems=(PROBLEM_MALFORMED,))
    report_id = str(report.get("Message-ID", "")).strip()[:998]
    if not _is_report(report):
        return JournalExtraction(
            False, report_message_id=report_id, report_sha256=report_sha, problems=(PROBLEM_NOT_A_REPORT,)
        )

    sender, recipients = _envelope(_first_text(report))
    originals: list[Message] = []
    try:
        for part in report.walk():
            if part.get_content_type() == "message/rfc822":
                payload = part.get_payload()
                if isinstance(payload, list) and payload and isinstance(payload[0], Message):
                    originals.append(payload[0])
    except Exception:  # noqa: BLE001
        return JournalExtraction(
            True,
            envelope_sender=sender,
            envelope_recipients=recipients,
            report_message_id=report_id,
            report_sha256=report_sha,
            problems=(PROBLEM_MALFORMED,),
        )
    common = {
        "is_journal_report": True,
        "envelope_sender": sender,
        "envelope_recipients": recipients,
        "report_message_id": report_id,
        "report_sha256": report_sha,
    }
    if not originals:
        return JournalExtraction(problems=(PROBLEM_NO_ORIGINAL,), **common)  # type: ignore[arg-type]
    problems: list[str] = []
    if len(originals) > 1:
        problems.append(PROBLEM_MULTIPLE)
    first = originals[0]
    if _is_report(first):
        # Отчёт внутри отчёта: оригинал не извлекается, чтобы журнал не размножал сам себя.
        return JournalExtraction(problems=(PROBLEM_NESTED, *problems), **common)  # type: ignore[arg-type]
    try:
        original = first.as_bytes(policy=policy.SMTP)
    except Exception:  # noqa: BLE001
        return JournalExtraction(problems=(PROBLEM_MALFORMED, *problems), **common)  # type: ignore[arg-type]
    original_id = str(first.get("Message-ID", "")).strip()[:998]
    if len(original) > max_original_bytes:
        return JournalExtraction(
            original_size=len(original),
            original_message_id=original_id,
            problems=(PROBLEM_OVERSIZED, *problems),
            **common,  # type: ignore[arg-type]
        )
    return JournalExtraction(
        original=original,
        original_size=len(original),
        original_message_id=original_id,
        original_sha256=hashlib.sha256(original).hexdigest(),
        problems=tuple(problems),
        **common,  # type: ignore[arg-type]
    )
