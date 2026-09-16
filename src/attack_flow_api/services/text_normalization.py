from dataclasses import dataclass


NORMALIZATION_VERSION_V1 = "v1"


@dataclass(frozen=True, slots=True)
class TextNormalizationResult:
    text: str
    version: str = NORMALIZATION_VERSION_V1


def normalize_raw_text(raw_text: str) -> TextNormalizationResult:
    normalized = _normalize_line_endings(raw_text)
    normalized = _trim_line_trailing_whitespace(normalized)
    normalized = _collapse_repeated_blank_lines(normalized)
    normalized = normalized.strip()
    return TextNormalizationResult(text=normalized)


def _normalize_line_endings(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _trim_line_trailing_whitespace(value: str) -> str:
    return "\n".join(line.rstrip() for line in value.split("\n"))


def _collapse_repeated_blank_lines(value: str, max_consecutive_blank_lines: int = 1) -> str:
    lines = value.split("\n")
    output: list[str] = []
    blank_count = 0

    for line in lines:
        if line.strip() == "":
            blank_count += 1
            if blank_count <= max_consecutive_blank_lines:
                output.append("")
            continue

        blank_count = 0
        output.append(line)

    return "\n".join(output)
