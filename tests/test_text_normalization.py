from attack_flow_api.services.text_normalization import (
    NORMALIZATION_VERSION_V1,
    normalize_raw_text,
)


def test_normalize_raw_text_normalizes_line_endings():
    value = "alpha\r\nbeta\rgamma\n"

    result = normalize_raw_text(value)

    assert result.text == "alpha\nbeta\ngamma"


def test_normalize_raw_text_trims_surrounding_whitespace_without_semantic_rewrite():
    value = "\n\n   first line\nsecond line   \n\n"

    result = normalize_raw_text(value)

    assert result.text == "first line\nsecond line"


def test_normalize_raw_text_collapses_obvious_repeated_blank_lines():
    value = "a\n\n\n\n\nb\n\n\n\nc"

    result = normalize_raw_text(value)

    assert result.text == "a\n\nb\n\nc"


def test_normalize_raw_text_preserves_paragraph_boundaries():
    value = "Paragraph 1 line 1\nParagraph 1 line 2\n\n\nParagraph 2"

    result = normalize_raw_text(value)

    assert result.text == "Paragraph 1 line 1\nParagraph 1 line 2\n\nParagraph 2"


def test_normalize_raw_text_is_deterministic():
    value = "\nA\r\n\r\n\r\nB   \n"

    first = normalize_raw_text(value)
    second = normalize_raw_text(value)

    assert first == second
    assert first.version == NORMALIZATION_VERSION_V1
