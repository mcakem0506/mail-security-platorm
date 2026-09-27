"""HTML sanitisation for safe preview and HTML-to-text conversion (ТЗ 8.2, 22.3).

The preview never executes JavaScript, never loads remote resources (no src/href/style/url()),
has no iframes/forms, and links are rendered non-clickable. The console additionally renders the
result inside a sandboxed iframe with a restrictive CSP.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

import nh3

_ALLOWED_TAGS = {
    "p", "br", "div", "span", "b", "i", "u", "s", "strong", "em", "small", "sub", "sup",
    "ul", "ol", "li", "dl", "dt", "dd",
    "table", "thead", "tbody", "tfoot", "tr", "td", "th", "caption",
    "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "code", "hr", "a", "font", "center",
}  # fmt: skip
_ALLOWED_ATTRS: dict[str, set[str]] = {"td": {"colspan", "rowspan"}, "th": {"colspan", "rowspan"}}
_BLOCK_TAGS = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "blockquote", "hr"}


def sanitize_html(html: str, max_size: int = 5 * 1024 * 1024) -> str:
    html = (html or "")[:max_size]
    return nh3.clean(
        html,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        url_schemes=set(),
        strip_comments=True,
        link_rel=None,
        clean_content_tags={"script", "style", "title", "head", "noscript", "template", "object", "iframe"},
        generic_attribute_prefixes=set(),
    )


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "head", "noscript", "template"}:
            self._skip += 1
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "head", "noscript", "template"} and self._skip:
            self._skip -= 1
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    ex = _TextExtractor()
    try:
        ex.feed(html or "")
        ex.close()
    except (AssertionError, ValueError):  # pragma: no cover
        pass
    return "".join(ex.parts)


def normalize_whitespace(text: str, max_chars: int = 200_000) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t ​‌‍﻿]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n\n", text)
    return text.strip()[:max_chars]
