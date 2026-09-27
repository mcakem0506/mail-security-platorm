"""Safe MIME/EML parser for the Mail Security Platform."""

from .archive import ArchiveReport, inspect_archive
from .domains import is_ip_literal, registrable_domain, split_domain, to_ascii, to_unicode
from .filetype import DetectedType, category_for_extension, detect_type, extensions, normalize_filename
from .html_safe import html_to_text, sanitize_html
from .limits import Deadline, LimitExceeded, ParserLimits
from .parser import ParsedAttachment, ParsedMessage, decode_header_value, parse_address_list, parse_message
from .urls import extract_urls_from_html, extract_urls_from_text, normalize_url

__all__ = [
    "ArchiveReport",
    "Deadline",
    "DetectedType",
    "LimitExceeded",
    "ParsedAttachment",
    "ParsedMessage",
    "ParserLimits",
    "category_for_extension",
    "decode_header_value",
    "detect_type",
    "extensions",
    "extract_urls_from_html",
    "extract_urls_from_text",
    "html_to_text",
    "inspect_archive",
    "is_ip_literal",
    "normalize_filename",
    "normalize_url",
    "parse_address_list",
    "parse_message",
    "registrable_domain",
    "sanitize_html",
    "split_domain",
    "to_ascii",
    "to_unicode",
]
