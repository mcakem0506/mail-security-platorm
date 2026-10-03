"""HTML smuggling signals (ТЗ 1.0.3 §40).

HTML smuggling delivers a file without the file ever crossing the gateway. The message carries
an HTML attachment — or a link to one — whose script assembles the payload in the browser from
text embedded in the page, then hands it to the user as a download. Every content scanner on the
path sees an HTML file with no attachment in it, and every one of them is right.

What can be detected is the *assembly machinery*, because it has to be present for the trick to
work: a large blob of encoded data, a decoder, a `Blob`/`File` construction, and something that
triggers a save. None of these is malicious on its own — plenty of legitimate pages build a CSV
client-side — so this module reports individual signals with evidence and leaves the decision to
the rules. A single signal is noise; a decoder plus a payload plus a forced download is not.

Nothing here executes or evaluates the page. The analysis is textual, and every scan is bounded
in both input size and work per pattern.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: How much HTML is examined. Smuggling payloads are large by nature, so the cap is generous,
#: but it is a cap: an attacker must not be able to spend a worker's time with a 200 MB page.
MAX_SCAN_BYTES = 4 * 1024 * 1024

#: A base64 run long enough to be a payload rather than an inline icon. 2 KB of base64 is about
#: 1.5 KB of data — far more than a sprite, far less than any real executable, which keeps the
#: signal early without making it trivial to trip.
_PAYLOAD_RUN = re.compile(r"[A-Za-z0-9+/=]{2048,}")
#: The same payload split across an array of chunks, which is how the obvious long-run check is
#: usually evaded.
_CHUNK_ARRAY = re.compile(
    r"""\[\s*(?:["'][A-Za-z0-9+/=]{24,}["']\s*,\s*){8,}["'][A-Za-z0-9+/=]{8,}["']""",
)
_DECODERS = (
    ("atob", re.compile(r"\batob\s*\(", re.IGNORECASE)),
    ("fromCharCode", re.compile(r"\bString\s*\.\s*fromCharCode\s*\(", re.IGNORECASE)),
    ("charCodeAt_loop", re.compile(r"\bcharCodeAt\s*\(", re.IGNORECASE)),
    ("decodeURIComponent_escape", re.compile(r"\bunescape\s*\(", re.IGNORECASE)),
    ("Uint8Array", re.compile(r"\bnew\s+Uint8Array\s*\(", re.IGNORECASE)),
    ("TextEncoder", re.compile(r"\bnew\s+TextEncoder\s*\(", re.IGNORECASE)),
)
_CONSTRUCTORS = (
    ("Blob", re.compile(r"\bnew\s+Blob\s*\(", re.IGNORECASE)),
    ("File", re.compile(r"\bnew\s+File\s*\(", re.IGNORECASE)),
    ("createObjectURL", re.compile(r"\bURL\s*\.\s*createObjectURL\s*\(", re.IGNORECASE)),
)
_TRIGGERS = (
    ("msSaveOrOpenBlob", re.compile(r"\bmsSaveOrOpenBlob\s*\(", re.IGNORECASE)),
    ("download_attribute", re.compile(r"<a[^>]{0,400}\sdownload\b", re.IGNORECASE)),
    ("programmatic_click", re.compile(r"\.click\s*\(\s*\)", re.IGNORECASE)),
    ("form_submit", re.compile(r"\.submit\s*\(\s*\)", re.IGNORECASE)),
    ("meta_refresh", re.compile(r"<meta[^>]{0,200}http-equiv\s*=\s*[\"']?refresh", re.IGNORECASE)),
)
#: A `data:` or `blob:` URI that carries a file rather than an image.
_FILE_DATA_URI = re.compile(
    r"""(?:href|src)\s*=\s*["']?\s*(?:data:(?:application/(?:octet-stream|zip|x-msdownload|"""
    r"""vnd\.openxmlformats[^;"'\s]*|pdf)|text/html)|blob:)""",
    re.IGNORECASE,
)
#: Password-protected archive built in the browser: the password is in the page, so the archive
#: defeats scanning while remaining openable by the victim.
_ARCHIVE_HINT = re.compile(
    r"\b(?:zip|7z|rar)\b[^<>{};]{0,80}\bpassword\b|\bpassword\b[^<>{};]{0,80}\b(?:zip|7z|rar)\b",
    re.IGNORECASE,
)
_SCRIPT_RE = re.compile(r"<script\b", re.IGNORECASE)
#: An iframe whose source is the page itself, used to hide the payload from a static view.
_SRCDOC_RE = re.compile(r"<iframe[^>]{0,400}\bsrcdoc\s*=", re.IGNORECASE)


@dataclass
class SmugglingReport:
    """Individual signals, their evidence and whether the page was fully examined."""

    decoders: list[str] = field(default_factory=list)
    constructors: list[str] = field(default_factory=list)
    triggers: list[str] = field(default_factory=list)
    payload_bytes: int = 0
    chunked_payload: bool = False
    file_data_uri: bool = False
    password_archive_hint: bool = False
    srcdoc_iframe: bool = False
    script_count: int = 0
    truncated: bool = False

    @property
    def has_payload(self) -> bool:
        return self.payload_bytes > 0 or self.chunked_payload

    @property
    def signal_count(self) -> int:
        return sum(
            (
                bool(self.decoders),
                bool(self.constructors),
                bool(self.triggers),
                self.has_payload,
                self.file_data_uri,
                self.password_archive_hint,
                self.srcdoc_iframe,
            )
        )

    @property
    def assembles_a_file(self) -> bool:
        """The full machinery: a payload, something to decode it, and something to save it.

        This is the combination worth acting on. Any one part of it appears in ordinary pages;
        all three together have no innocent reading in an email attachment.
        """
        return self.has_payload and bool(self.decoders) and bool(self.constructors or self.triggers)

    def as_dict(self) -> dict[str, object]:
        return {
            "decoders": self.decoders,
            "constructors": self.constructors,
            "triggers": self.triggers,
            "payload_bytes": self.payload_bytes,
            "chunked_payload": self.chunked_payload,
            "file_data_uri": self.file_data_uri,
            "password_archive_hint": self.password_archive_hint,
            "srcdoc_iframe": self.srcdoc_iframe,
            "script_count": self.script_count,
            "signal_count": self.signal_count,
            "assembles_a_file": self.assembles_a_file,
            "truncated": self.truncated,
        }

    def flags(self) -> list[str]:
        out: list[str] = []
        if self.assembles_a_file:
            out.append("HTML_SMUGGLING_ASSEMBLY")
        elif self.signal_count >= 2:
            out.append("HTML_SMUGGLING_PATTERN")
        if self.file_data_uri:
            out.append("HTML_FILE_DATA_URI")
        if self.password_archive_hint:
            out.append("HTML_PASSWORD_ARCHIVE")
        if self.truncated:
            out.append("HTML_NOT_FULLY_SCANNED")
        return out


def analyze_html_smuggling(html: str) -> SmugglingReport:
    """Report the smuggling machinery present in a page, without judging it (ТЗ 1.0.3 §40)."""
    report = SmugglingReport()
    if not html:
        return report
    if len(html) > MAX_SCAN_BYTES:
        html = html[:MAX_SCAN_BYTES]
        report.truncated = True

    report.script_count = len(_SCRIPT_RE.findall(html))

    longest = 0
    for match in _PAYLOAD_RUN.finditer(html):
        longest = max(longest, len(match.group(0)))
    report.payload_bytes = longest
    report.chunked_payload = _CHUNK_ARRAY.search(html) is not None

    report.decoders = [name for name, pattern in _DECODERS if pattern.search(html)]
    report.constructors = [name for name, pattern in _CONSTRUCTORS if pattern.search(html)]
    report.triggers = [name for name, pattern in _TRIGGERS if pattern.search(html)]
    report.file_data_uri = _FILE_DATA_URI.search(html) is not None
    report.password_archive_hint = _ARCHIVE_HINT.search(html) is not None
    report.srcdoc_iframe = _SRCDOC_RE.search(html) is not None
    return report
