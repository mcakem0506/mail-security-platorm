"""Links and remote references inside Office documents (ТЗ 1.0.3 §39).

A modern document-based attack rarely carries a macro. It carries a *reference*: a hyperlink to
a credential-harvesting page, or a template loaded from the attacker's server when the document
opens. Both live in the OOXML relationship files, so a platform that only looks at the message
body sees a clean attachment and says nothing.

Two deliberate design choices:

* **No XML parser.** The relationship parts are matched with bounded regular expressions over
  decoded text instead of being handed to ``xml.etree``. Entity expansion and deeply nested
  documents are a denial-of-service surface, and the thing being parsed here is an attacker's
  file. A regex over a size-capped string cannot be made to allocate a gigabyte.
* **Everything is capped.** The number of parts read, the size of each part and the number of
  URLs returned are all bounded, and reaching a bound is reported rather than silently
  truncating the answer — a URL nobody looked at must never look like a URL that was clean.
"""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field

from msp_contracts import ExtractedUrl

from .limits import ParserLimits
from .urls import normalize_url

#: Relationship parts hold every external reference a document makes.
_RELS_SUFFIX = ".rels"
#: Document bodies are read too: a hyperlink's display text lives there, and so do DDE fields.
_BODY_PARTS = (
    "word/document.xml",
    "word/settings.xml",
    "xl/workbook.xml",
    "ppt/presentation.xml",
)
#: How much of one part is examined. Enough for any realistic relationship file.
_MAX_PART_BYTES = 2 * 1024 * 1024
#: How many parts are examined at all, so a zip with 50 000 tiny members cannot stall a worker.
_MAX_PARTS = 400

_EXTERNAL_TARGET_RE = re.compile(
    r"""Target\s*=\s*["']([^"'<>]{1,2000})["'][^>]{0,400}?TargetMode\s*=\s*["']External["']"""
    r"""|TargetMode\s*=\s*["']External["'][^>]{0,400}?Target\s*=\s*["']([^"'<>]{1,2000})["']""",
    re.IGNORECASE | re.VERBOSE,
)
_RELATIONSHIP_TYPE_RE = re.compile(r"""Type\s*=\s*["']([^"'<>]{1,400})["']""", re.IGNORECASE)
#: Relationship types that cause a document to fetch something when it is opened, rather than
#: when the reader clicks. These are the dangerous ones.
_AUTOLOAD_TYPES = (
    "attachedtemplate",
    "frame",
    "subdocument",
    "oleobject",
    "externallink",
    "externallinkpath",
    "image",
    "slidemaster",
)
# ``DDEAUTO`` is unambiguous on its own. Bare ``DDE`` needs something after it to be a field
# code rather than the three letters appearing in prose — but the separator is as often an XML
# tag as a space, and requiring whitespace missed the field in every real document.
_DDE_RE = re.compile(r"\bDDEAUTO\b|\bDDE\b\s*[<\"'a-z]", re.IGNORECASE)
_MACRO_PARTS = ("vbaproject.bin", "vbadata.xml")


@dataclass
class DocumentReport:
    """What an Office document refers to, and what could not be examined."""

    urls: list[ExtractedUrl] = field(default_factory=list)
    #: References fetched automatically when the document opens (templates, frames, OLE).
    autoload_urls: list[str] = field(default_factory=list)
    has_macro: bool = False
    has_ole_object: bool = False
    has_dde_field: bool = False
    has_remote_template: bool = False
    #: UNC targets (``\\\\host\\share``). Opening the document authenticates to that host, so the
    #: credential leaves the organisation without anyone clicking anything.
    unc_references: list[str] = field(default_factory=list)
    external_reference_count: int = 0
    parts_examined: int = 0
    #: Non-empty when a cap was reached. The caller turns this into missing evidence rather
    #: than into silence.
    truncated: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def complete(self) -> bool:
        return not self.truncated and not self.error

    def flags(self) -> list[str]:
        """Attachment flags, in the vocabulary the rest of the platform already uses."""
        out: list[str] = []
        if self.has_macro:
            out.append("OFFICE_MACRO")
        if self.has_remote_template:
            out.append("OFFICE_REMOTE_TEMPLATE")
        if self.has_ole_object:
            out.append("OFFICE_OLE_OBJECT")
        if self.has_dde_field:
            out.append("OFFICE_DDE_FIELD")
        if self.unc_references:
            out.append("OFFICE_UNC_REFERENCE")
        if self.urls:
            out.append("OFFICE_EXTERNAL_LINK")
        if not self.complete:
            out.append("OFFICE_NOT_FULLY_PARSED")
        return out


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _is_unc(target: str) -> bool:
    stripped = target.strip()
    lowered = stripped.lower()
    return stripped.startswith("\\\\") or lowered.startswith("file://")


def _is_web(target: str) -> bool:
    lowered = target.strip().lower()
    return lowered.startswith(("http://", "https://", "//", "www."))


def extract_document_references(
    data: bytes, limits: ParserLimits | None = None, *, url_limit: int = 100
) -> DocumentReport:
    """Read the external references of an OOXML document (ТЗ 1.0.3 §39).

    Returns an empty report for anything that is not a readable OOXML container, with ``error``
    set — an unreadable document is a fact to report, not a document without links.
    """
    limits = limits or ParserLimits()
    report = DocumentReport()
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError, OSError):
        report.error = "NOT_OOXML"
        return report

    try:
        names = archive.namelist()
    except (zipfile.BadZipFile, OSError):
        report.error = "UNREADABLE_CONTAINER"
        return report

    if len(names) > _MAX_PARTS:
        report.truncated.append("MAX_PARTS")
        names = names[:_MAX_PARTS]

    lowered = [(name, name.lower()) for name in names]
    report.has_macro = any(low.endswith(_MACRO_PARTS) for _, low in lowered)

    seen: set[str] = set()
    for name, low in lowered:
        if not (low.endswith(_RELS_SUFFIX) or low in _BODY_PARTS):
            continue
        try:
            info = archive.getinfo(name)
        except KeyError:  # pragma: no cover - namelist and getinfo disagree only on broken zips
            continue
        if info.file_size > _MAX_PART_BYTES:
            report.truncated.append(f"PART_TOO_LARGE:{name[:80]}")
            continue
        try:
            with archive.open(info) as handle:
                raw = handle.read(_MAX_PART_BYTES)
        except (zipfile.BadZipFile, RuntimeError, OSError, EOFError) as exc:
            # A password-protected or corrupt part is reported, never skipped silently.
            report.truncated.append(f"PART_UNREADABLE:{type(exc).__name__}")
            continue

        report.parts_examined += 1
        text = _decode(raw)

        if low in _BODY_PARTS and _DDE_RE.search(text):
            report.has_dde_field = True

        if not low.endswith(_RELS_SUFFIX):
            continue

        for match in _EXTERNAL_TARGET_RE.finditer(text):
            target = (match.group(1) or match.group(2) or "").strip()
            if not target:
                continue
            report.external_reference_count += 1
            # The relationship type decides whether the reference is followed on open. It sits
            # in the same element, so the surrounding text is what tells them apart.
            start = max(0, match.start() - 400)
            element = text[start : match.end() + 400]
            type_match = _RELATIONSHIP_TYPE_RE.search(element)
            rel_type = (type_match.group(1).rsplit("/", 1)[-1].lower()) if type_match else ""
            autoload = rel_type in _AUTOLOAD_TYPES
            if rel_type == "attachedtemplate":
                report.has_remote_template = True
            if rel_type == "oleobject":
                report.has_ole_object = True

            if _is_unc(target):
                # A UNC target makes Windows authenticate to the attacker's host when the
                # document opens: the credential leaves the organisation before anything is
                # clicked. It is not a URL, so it is reported as its own reference.
                if target not in report.unc_references:
                    report.unc_references.append(target[:400])
                continue
            if not _is_web(target):
                continue

            if len(report.urls) >= url_limit:
                if "MAX_URLS" not in report.truncated:
                    report.truncated.append("MAX_URLS")
                continue

            parsed = normalize_url(target, source="office")
            if parsed.parse_error or not parsed.host:
                continue
            if parsed.normalized in seen:
                continue
            seen.add(parsed.normalized)
            report.urls.append(parsed)
            if autoload:
                report.autoload_urls.append(parsed.normalized)

    return report
