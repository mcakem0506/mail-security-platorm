"""Safe static archive inspection (ТЗ 8.3).

Nothing is ever written to disk and nothing is executed. Extraction happens in memory with
hard budgets that do not trust sizes declared in archive headers.
"""

from __future__ import annotations

import hashlib
import io
import posixpath
import stat
import zipfile
import zlib
from dataclasses import dataclass, field

from .filetype import ARCHIVE_TYPES, detect_type, last_extension, normalize_filename
from .limits import Deadline, ParserLimits

_CHUNK = 64 * 1024


@dataclass
class ArchiveEntry:
    name: str
    size: int
    compressed_size: int
    depth: int
    encrypted: bool = False
    is_dir: bool = False
    is_symlink: bool = False
    path_traversal: bool = False
    absolute_path: bool = False
    sha256: str | None = None
    detected_type: str | None = None
    category: str | None = None
    extension: str = ""
    extracted: bool = False
    details: list[str] = field(default_factory=list)


@dataclass
class ExtractedFile:
    entry: ArchiveEntry
    data: bytes


@dataclass
class ArchiveReport:
    format: str
    entries: list[ArchiveEntry] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)
    total_uncompressed: int = 0
    file_count: int = 0
    max_depth: int = 0
    extracted: list[ExtractedFile] = field(default_factory=list)

    @property
    def encrypted(self) -> bool:
        return "ENCRYPTED_ARCHIVE" in self.flags

    def summary(self) -> dict[str, object]:
        return {
            "format": self.format,
            "file_count": self.file_count,
            "total_uncompressed": self.total_uncompressed,
            "max_depth": self.max_depth,
            "flags": sorted(self.flags),
            "entries": [
                {
                    "name": e.name,
                    "size": e.size,
                    "depth": e.depth,
                    "encrypted": e.encrypted,
                    "type": e.detected_type,
                    "category": e.category,
                    "sha256": e.sha256,
                    "details": e.details,
                }
                for e in self.entries[:200]
            ],
        }


class _Budget:
    def __init__(self, limits: ParserLimits) -> None:
        self.remaining = limits.max_extracted_total
        self.files = 0


def _check_name(raw_name: str, entry: ArchiveEntry, report: ArchiveReport) -> None:
    name = raw_name.replace("\\", "/")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        entry.absolute_path = True
        report.flags.add("ABSOLUTE_PATH")
    normalized = posixpath.normpath(name)
    if normalized.startswith("../") or normalized == ".." or "/../" in f"/{name}/":
        entry.path_traversal = True
        report.flags.add("PATH_TRAVERSAL")


def _read_capped(zf: zipfile.ZipFile, info: zipfile.ZipInfo, cap: int) -> bytes | None:
    """Read at most ``cap`` bytes of real decompressed data; None if the cap is exceeded."""
    buf = io.BytesIO()
    with zf.open(info, "r") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            if buf.tell() + len(chunk) > cap:
                return None
            buf.write(chunk)
    return buf.getvalue()


def _inspect_zip(
    data: bytes, limits: ParserLimits, depth: int, budget: _Budget, report: ArchiveReport, deadline: Deadline
) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError, OSError):
        report.flags.add("CORRUPT_ARCHIVE")
        return
    with zf:
        for info in zf.infolist():
            deadline.check()
            budget.files += 1
            if budget.files > limits.max_archive_files:
                report.flags.add("TOO_MANY_FILES")
                return
            entry = ArchiveEntry(
                name=normalize_filename(info.filename) if not info.is_dir() else info.filename[:255],
                size=info.file_size,
                compressed_size=info.compress_size,
                depth=depth,
                is_dir=info.is_dir(),
                extension=last_extension(info.filename),
            )
            _check_name(info.filename, entry, report)
            mode = (info.external_attr >> 16) & 0xFFFF
            if mode and stat.S_ISLNK(mode):
                entry.is_symlink = True
                report.flags.add("SYMLINK")
            if info.flag_bits & 0x1:
                entry.encrypted = True
                report.flags.add("ENCRYPTED_ARCHIVE")
            report.entries.append(entry)
            if entry.is_dir:
                continue
            report.file_count += 1
            report.total_uncompressed += info.file_size
            ratio = info.file_size / max(info.compress_size, 1)
            if info.file_size > 1024 * 1024 and ratio > limits.max_compression_ratio:
                report.flags.add("EXCESSIVE_COMPRESSION_RATIO")
                entry.details.append("EXCESSIVE_COMPRESSION_RATIO")
                continue
            if info.file_size > limits.max_extracted_file or info.file_size > budget.remaining:
                report.flags.add("EXTRACTION_LIMIT")
                entry.details.append("NOT_EXTRACTED_SIZE")
                continue
            if entry.encrypted or entry.is_symlink:
                continue
            try:
                content = _read_capped(zf, info, min(limits.max_extracted_file, budget.remaining))
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError, zlib.error):
                report.flags.add("CORRUPT_ARCHIVE")
                entry.details.append("READ_ERROR")
                continue
            if content is None:
                # Real decompressed size exceeded what the header claimed: classic bomb.
                report.flags.add("ZIP_BOMB")
                entry.details.append("DECLARED_SIZE_LIE")
                continue
            budget.remaining -= len(content)
            entry.extracted = True
            entry.sha256 = hashlib.sha256(content).hexdigest()
            detected = detect_type(content, entry.name)
            entry.detected_type = detected.type
            entry.category = detected.category
            entry.details.extend(detected.details)
            report.extracted.append(ExtractedFile(entry, content))
            if detected.type in ARCHIVE_TYPES:
                report.flags.add("NESTED_ARCHIVE")
                if depth + 1 > limits.max_archive_depth:
                    report.flags.add("NESTING_LIMIT")
                    continue
                _inspect(content, detected.type, limits, depth + 1, budget, report, deadline)


def _inspect_gzip(
    data: bytes, limits: ParserLimits, depth: int, budget: _Budget, report: ArchiveReport, deadline: Deadline
) -> None:
    decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
    cap = min(limits.max_extracted_file, budget.remaining)
    try:
        out = decomp.decompress(data, cap + 1)
    except zlib.error:
        report.flags.add("CORRUPT_ARCHIVE")
        return
    if len(out) > cap:
        report.flags.add("ZIP_BOMB")
        return
    if len(data) and len(out) / max(len(data), 1) > limits.max_compression_ratio and len(out) > 1024 * 1024:
        report.flags.add("EXCESSIVE_COMPRESSION_RATIO")
    budget.remaining -= len(out)
    budget.files += 1
    entry = ArchiveEntry(name="(gzip member)", size=len(out), compressed_size=len(data), depth=depth)
    entry.sha256 = hashlib.sha256(out).hexdigest()
    detected = detect_type(out)
    entry.detected_type, entry.category, entry.extracted = detected.type, detected.category, True
    report.entries.append(entry)
    report.file_count += 1
    report.total_uncompressed += len(out)
    report.extracted.append(ExtractedFile(entry, out))
    if detected.type in ARCHIVE_TYPES:
        report.flags.add("NESTED_ARCHIVE")
        if depth + 1 > limits.max_archive_depth:
            report.flags.add("NESTING_LIMIT")
            return
        _inspect(out, detected.type, limits, depth + 1, budget, report, deadline)


def _inspect(
    data: bytes,
    fmt: str,
    limits: ParserLimits,
    depth: int,
    budget: _Budget,
    report: ArchiveReport,
    deadline: Deadline,
) -> None:
    report.max_depth = max(report.max_depth, depth)
    if fmt == "zip":
        _inspect_zip(data, limits, depth, budget, report, deadline)
    elif fmt == "gzip":
        _inspect_gzip(data, limits, depth, budget, report, deadline)
    else:
        # 7z / RAR / CAB: no safe in-process library is bundled in v1. Report, never execute.
        report.flags.add("UNSUPPORTED_ARCHIVE_FORMAT")


def inspect_archive(
    data: bytes, fmt: str, limits: ParserLimits | None = None, deadline: Deadline | None = None
) -> ArchiveReport:
    limits = limits or ParserLimits()
    deadline = deadline or Deadline(limits.timeout_seconds)
    report = ArchiveReport(format=fmt)
    try:
        _inspect(data, fmt, limits, 1, _Budget(limits), report, deadline)
    except RecursionError:
        report.flags.add("NESTING_LIMIT")
    return report
