"""Resource limits for safe parsing (ТЗ 8.2 / 8.3)."""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class ParserLimits:
    max_message_size: int = 25 * 1024 * 1024
    max_mime_depth: int = 12
    max_parts: int = 300
    max_attachments: int = 50
    max_attachment_size: int = 20 * 1024 * 1024
    max_urls: int = 500
    max_html_size: int = 5 * 1024 * 1024
    max_text_chars: int = 200_000
    timeout_seconds: float = 20.0
    # archives
    max_archive_depth: int = 3
    max_archive_files: int = 500
    max_extracted_total: int = 100 * 1024 * 1024
    max_extracted_file: int = 25 * 1024 * 1024
    max_compression_ratio: float = 150.0


class LimitExceeded(Exception):  # noqa: N818 - domain wording
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


class Deadline:
    """Cooperative deadline checked inside parser loops."""

    def __init__(self, seconds: float) -> None:
        self._end = time.monotonic() + seconds

    def check(self) -> None:
        if time.monotonic() > self._end:
            raise LimitExceeded("PARSER_TIMEOUT")

    @property
    def expired(self) -> bool:
        return time.monotonic() > self._end
