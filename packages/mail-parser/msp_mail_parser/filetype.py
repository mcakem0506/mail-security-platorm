"""Static file-type detection by magic bytes and container structure (no execution)."""

from __future__ import annotations

import io
import unicodedata
import zipfile
from dataclasses import dataclass, field

EXECUTABLE_EXT = frozenset(
    "exe scr com pif cpl msi msp dll sys jar apk app elf bin gadget application appref-ms xll msix "
    "appx msixbundle appxbundle ocx drv".split()
)
SCRIPT_EXT = frozenset("js jse vbs vbe wsf wsh wsc ps1 psm1 psd1 bat cmd hta sh py pl reg vb mjs".split())
SHORTCUT_EXT = frozenset("lnk url scf website desktop library-ms searchconnector-ms settingcontent-ms".split())
MACRO_EXT = frozenset("docm dotm xlsm xltm xlam pptm potm ppam ppsm sldm xlsb".split())
DISK_IMAGE_EXT = frozenset("iso img vhd vhdx".split())
ARCHIVE_EXT = frozenset("zip 7z rar gz tgz tar cab ace arj bz2 xz z lzh".split())
HTML_EXT = frozenset("html htm shtml xhtml svg mht mhtml".split())
OFFICE_EXT = frozenset("doc docx xls xlsx ppt pptx rtf odt ods odp one pub dot dotx xlt xltx".split())
DOCUMENT_EXT = frozenset("pdf txt csv".split())
IMAGE_EXT = frozenset("png jpg jpeg gif bmp webp tif tiff".split())

_SIGNATURES: list[tuple[int, bytes, str]] = [
    (0, b"MZ", "pe_executable"),
    (0, b"\x7fELF", "elf_executable"),
    (0, b"\xcf\xfa\xed\xfe", "macho_executable"),
    (0, b"\xfe\xed\xfa\xcf", "macho_executable"),
    (0, b"%PDF-", "pdf"),
    (0, b"{\\rtf", "rtf"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (0, b"PK\x03\x04", "zip"),
    (0, b"PK\x05\x06", "zip"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z"),
    (0, b"Rar!\x1a\x07", "rar"),
    (0, b"\x1f\x8b", "gzip"),
    (0, b"MSCF", "cab"),
    (0, b"\x89PNG\r\n\x1a\n", "png"),
    (0, b"\xff\xd8\xff", "jpeg"),
    (0, b"GIF8", "gif"),
    (0, b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"),
    (0, bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3"), "onenote"),
    (0x8001, b"CD001", "iso"),
    (0, b"conectix", "vhd"),
    (0, b"vhdxfile", "vhdx"),
]

CATEGORY_BY_TYPE: dict[str, str] = {
    "pe_executable": "executable",
    "elf_executable": "executable",
    "macho_executable": "executable",
    "jar": "executable",
    "apk": "executable",
    "lnk": "shortcut",
    "pdf": "document",
    "rtf": "office",
    "ole": "office",
    "ole_macro": "office_macro",
    "ooxml": "office",
    "ooxml_macro": "office_macro",
    "onenote": "office",
    "zip": "archive",
    "7z": "archive",
    "rar": "archive",
    "gzip": "archive",
    "cab": "archive",
    "png": "image",
    "jpeg": "image",
    "gif": "image",
    "iso": "disk_image",
    "vhd": "disk_image",
    "vhdx": "disk_image",
    "html": "html",
    "svg": "html",
    "script": "script",
    "text": "text",
    "unknown": "unknown",
    "empty": "unknown",
}

ARCHIVE_TYPES = frozenset({"zip", "7z", "rar", "gzip", "cab"})

# Extension -> expected detected types, used for MIME / extension mismatch detection.
_EXPECTED_BY_EXT: dict[str, set[str]] = {
    "pdf": {"pdf"},
    "doc": {"ole", "ole_macro", "rtf"},
    "xls": {"ole", "ole_macro"},
    "ppt": {"ole", "ole_macro"},
    "docx": {"ooxml"},
    "xlsx": {"ooxml"},
    "pptx": {"ooxml"},
    "docm": {"ooxml_macro", "ooxml"},
    "xlsm": {"ooxml_macro", "ooxml"},
    "pptm": {"ooxml_macro", "ooxml"},
    "zip": {"zip", "ooxml", "ooxml_macro", "jar", "apk"},
    "7z": {"7z"},
    "rar": {"rar"},
    "gz": {"gzip"},
    "png": {"png"},
    "jpg": {"jpeg"},
    "jpeg": {"jpeg"},
    "gif": {"gif"},
    "rtf": {"rtf"},
    "txt": {"text", "unknown"},
    "csv": {"text", "unknown"},
    "html": {"html", "text"},
    "htm": {"html", "text"},
    "iso": {"iso"},
    "exe": {"pe_executable"},
    "dll": {"pe_executable"},
    "lnk": {"lnk"},
    "one": {"onenote"},
}


@dataclass
class DetectedType:
    type: str
    category: str
    details: list[str] = field(default_factory=list)  # e.g. EMBEDDED_OBJECTS, VBA_PROJECT


def normalize_filename(name: str) -> str:
    """NFKC-normalise, strip bidi/control characters and path components."""
    name = unicodedata.normalize("NFKC", name or "")
    name = "".join(ch for ch in name if unicodedata.category(ch) not in {"Cc", "Cf"})
    name = name.replace("\\", "/").split("/")[-1].strip().strip(".").strip()
    return name[:255] or "unnamed"


def extensions(filename: str) -> list[str]:
    """Return lower-case extension chain: 'a.pdf.exe' -> ['pdf', 'exe']."""
    base = normalize_filename(filename).lower()
    parts = [p.strip() for p in base.split(".")]
    if len(parts) <= 1:
        return []
    return [p for p in parts[1:] if p]


def last_extension(filename: str) -> str:
    exts = extensions(filename)
    return exts[-1] if exts else ""


def _refine_zip(data: bytes) -> DetectedType:
    details: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = [i.filename for i in zf.infolist()[:2000]]
    except (zipfile.BadZipFile, ValueError, RuntimeError, NotImplementedError, OSError):
        return DetectedType("zip", "archive", ["CORRUPT_ARCHIVE"])
    lower = [n.lower() for n in names]
    if "[content_types].xml" in lower:
        if any(n.endswith("vbaproject.bin") for n in lower):
            details.append("VBA_PROJECT")
        if any("/embeddings/" in n or "oleobject" in n for n in lower):
            details.append("EMBEDDED_OBJECTS")
        if any(n.endswith("activex.xml") or "/activex/" in n for n in lower):
            details.append("ACTIVEX")
        t = "ooxml_macro" if "VBA_PROJECT" in details else "ooxml"
        return DetectedType(t, CATEGORY_BY_TYPE[t], details)
    if "meta-inf/manifest.mf" in lower:
        return DetectedType("jar", "executable")
    if "androidmanifest.xml" in lower:
        return DetectedType("apk", "executable")
    return DetectedType("zip", "archive")


def _refine_ole(data: bytes) -> DetectedType:
    details: list[str] = []
    head = data[: 4 * 1024 * 1024]
    # Directory entry names are UTF-16LE; this is a heuristic, not a full CFB parser.
    if "_VBA_PROJECT".encode("utf-16-le") in head or b"_VBA_PROJECT" in head:
        details.append("VBA_PROJECT")
    if "\x01Ole10Native".encode("utf-16-le") in head or "ObjectPool".encode("utf-16-le") in head:
        details.append("EMBEDDED_OBJECTS")
    t = "ole_macro" if "VBA_PROJECT" in details else "ole"
    return DetectedType(t, CATEGORY_BY_TYPE[t], details)


def _sniff_text(data: bytes) -> DetectedType | None:
    head = data[:4096]
    if b"\x00" in head:
        return None
    try:
        text = head.decode("utf-8", errors="strict").lstrip("﻿ \t\r\n").lower()
    except UnicodeDecodeError:
        text = head.decode("latin-1").lstrip().lower()
    if text.startswith("<svg") or ("<svg" in text[:512] and text.startswith("<?xml")):
        return DetectedType("svg", "html")
    if text.startswith(("<!doctype html", "<html", "<head", "<body")) or "<script" in text or "<form" in text:
        return DetectedType("html", "html")
    return DetectedType("text", "text")


def detect_type(data: bytes, filename: str = "") -> DetectedType:
    if not data:
        return DetectedType("empty", "unknown")
    for offset, magic, t in _SIGNATURES:
        if data[offset : offset + len(magic)] == magic:
            if t == "zip":
                return _refine_zip(data)
            if t == "ole":
                return _refine_ole(data)
            return DetectedType(t, CATEGORY_BY_TYPE.get(t, "unknown"))
    sniffed = _sniff_text(data)
    ext = last_extension(filename)
    if sniffed is not None:
        if sniffed.type == "text" and ext in SCRIPT_EXT:
            return DetectedType("script", "script", [f"EXT_{ext.upper()}"])
        if sniffed.type == "text" and ext in SHORTCUT_EXT:
            return DetectedType("text", "shortcut", [f"EXT_{ext.upper()}"])
        return sniffed
    return DetectedType("unknown", "unknown")


def category_for_extension(ext: str) -> str:
    ext = ext.lower()
    if ext in EXECUTABLE_EXT:
        return "executable"
    if ext in SCRIPT_EXT:
        return "script"
    if ext in SHORTCUT_EXT:
        return "shortcut"
    if ext in MACRO_EXT:
        return "office_macro"
    if ext in DISK_IMAGE_EXT:
        return "disk_image"
    if ext in ARCHIVE_EXT:
        return "archive"
    if ext in HTML_EXT:
        return "html"
    if ext in OFFICE_EXT:
        return "office"
    if ext in DOCUMENT_EXT:
        return "document"
    if ext in IMAGE_EXT:
        return "image"
    return "unknown"


def extension_mismatch(ext: str, detected: DetectedType) -> bool:
    """True when the declared extension contradicts the detected content type."""
    expected = _EXPECTED_BY_EXT.get(ext.lower())
    if expected is None:
        # Unknown/benign-looking extension but executable content is always a mismatch.
        return detected.category == "executable" and ext.lower() not in EXECUTABLE_EXT
    return detected.type not in expected
