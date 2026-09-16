import pytest

from attack_flow_api.services.plaintext_extraction import (
    PlaintextExtractionError,
    extract_plaintext_content,
)


def test_extract_plaintext_content_decodes_utf8_and_normalizes_deterministically():
    result = extract_plaintext_content(b"\xef\xbb\xbfalpha  \r\n\r\n\r\nbeta\t\n")

    assert result.extracted_text == "alpha  \r\n\r\n\r\nbeta\t\n"
    assert result.normalized_text == "alpha\n\nbeta"
    assert result.normalized_char_count == len("alpha\n\nbeta")
    assert result.normalization_version == "v1"


def test_extract_plaintext_content_fails_clearly_for_non_utf8_bytes():
    with pytest.raises(PlaintextExtractionError) as exc:
        extract_plaintext_content(b"\xff\xfe\x00\x00")

    assert exc.value.code == "plaintext_decode_failed"
    assert "UTF-8" in exc.value.message
