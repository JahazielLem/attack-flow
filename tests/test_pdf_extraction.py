import pytest

from attack_flow_api.services import pdf_extraction
from attack_flow_api.services.pdf_extraction import PdfExtractionError, extract_pdf_text_content


def test_extract_pdf_text_content_normalizes_text(monkeypatch):
    monkeypatch.setattr(
        pdf_extraction,
        "_extract_with_pypdf",
        lambda _bytes: "alpha  \r\n\r\n\r\nbeta\t\n",
    )

    result = extract_pdf_text_content(b"%PDF-1.7 mock")

    assert result.extracted_text == "alpha  \r\n\r\n\r\nbeta\t\n"
    assert result.normalized_text == "alpha\n\nbeta"
    assert result.normalized_char_count == len("alpha\n\nbeta")
    assert result.normalization_version == "v1"


def test_extract_pdf_text_content_fails_clearly_when_no_text(monkeypatch):
    monkeypatch.setattr(pdf_extraction, "_extract_with_pypdf", lambda _bytes: "\n\n")

    with pytest.raises(PdfExtractionError) as exc:
        extract_pdf_text_content(b"%PDF-1.7 mock")

    assert exc.value.code == "pdf_extraction_failed"
    assert "no readable text" in exc.value.message


def test_extract_pdf_text_content_fails_clearly_when_empty_file():
    with pytest.raises(PdfExtractionError) as exc:
        extract_pdf_text_content(b"")

    assert exc.value.code == "pdf_extraction_failed"
    assert "empty" in exc.value.message
