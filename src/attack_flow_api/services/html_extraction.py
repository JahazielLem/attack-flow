from dataclasses import dataclass
from html.parser import HTMLParser

from attack_flow_api.services.text_normalization import (
    NORMALIZATION_VERSION_V1,
    normalize_raw_text,
)


_BLOCK_TAGS = {
    "p",
    "li",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "blockquote",
    "pre",
    "article",
    "section",
    "main",
    "div",
}

_IGNORE_SUBTREES = {
    "script",
    "style",
    "noscript",
    "nav",
    "header",
    "footer",
    "aside",
    "form",
    "svg",
}


@dataclass(frozen=True, slots=True)
class HtmlExtractionResult:
    raw_extracted_text: str
    normalized_text: str
    normalized_char_count: int
    normalization_version: str = NORMALIZATION_VERSION_V1


def extract_readable_text_from_html(html: str) -> HtmlExtractionResult:
    parser = _ReadableHtmlParser()
    parser.feed(html)
    parser.close()

    raw_text = "\n\n".join(chunk for chunk in parser.text_chunks if chunk)
    normalized = normalize_raw_text(raw_text)
    return HtmlExtractionResult(
        raw_extracted_text=raw_text,
        normalized_text=normalized.text,
        normalized_char_count=len(normalized.text),
        normalization_version=normalized.version,
    )


class _ReadableHtmlParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_chunks: list[str] = []
        self._stack: list[str] = []
        self._ignore_depth = 0
        self._current_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs):  # noqa: ARG002
        lower_tag = tag.lower()
        self._stack.append(lower_tag)
        if lower_tag in _IGNORE_SUBTREES:
            self._ignore_depth += 1

    def handle_endtag(self, tag: str):
        lower_tag = tag.lower()
        if self._ignore_depth > 0 and lower_tag in _IGNORE_SUBTREES:
            self._ignore_depth -= 1

        if lower_tag in _BLOCK_TAGS and self._ignore_depth == 0:
            self._flush_current_block()

        if self._stack:
            self._stack.pop()

    def handle_data(self, data: str):
        if self._ignore_depth > 0:
            return
        if not self._stack:
            return
        current_tag = self._stack[-1]
        if current_tag not in _BLOCK_TAGS:
            return
        candidate = data.strip()
        if not candidate:
            return
        self._current_parts.append(candidate)

    def _flush_current_block(self) -> None:
        if not self._current_parts:
            return
        joined = " ".join(self._current_parts).strip()
        self._current_parts.clear()
        if joined:
            self.text_chunks.append(joined)
