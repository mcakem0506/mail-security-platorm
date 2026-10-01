"""Safe MIME/EML parser for the Mail Security Platform."""

from .archive import ArchiveReport, inspect_archive
from .documents import DocumentReport, extract_document_references
from .domains import is_ip_literal, registrable_domain, split_domain, to_ascii, to_unicode
from .filetype import DetectedType, category_for_extension, detect_type, extensions, normalize_filename
from .html_safe import html_to_text, sanitize_html
from .images import ImageInfo, QrReport, inspect_images, read_image_header
from .limits import Deadline, LimitExceeded, ParserLimits
from .parser import ParsedAttachment, ParsedMessage, decode_header_value, parse_address_list, parse_message
from .smuggling import SmugglingReport, analyze_html_smuggling
from .urls import extract_urls_from_html, extract_urls_from_text, normalize_url

__all__ = [
    "ArchiveReport",
    "Deadline",
    "DetectedType",
    "DocumentReport",
    "ImageInfo",
    "LimitExceeded",
    "ParsedAttachment",
    "ParsedMessage",
    "ParserLimits",
    "QrReport",
    "SmugglingReport",
    "analyze_html_smuggling",
    "category_for_extension",
    "decode_header_value",
    "detect_type",
    "extensions",
    "extract_document_references",
    "extract_urls_from_html",
    "extract_urls_from_text",
    "html_to_text",
    "inspect_archive",
    "inspect_images",
    "is_ip_literal",
    "normalize_filename",
    "normalize_url",
    "parse_address_list",
    "parse_message",
    "read_image_header",
    "registrable_domain",
    "sanitize_html",
    "split_domain",
    "to_ascii",
    "to_unicode",
]
