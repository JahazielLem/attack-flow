from dataclasses import dataclass
from io import BytesIO

from pypdf import PdfReader

from attack_flow_api.services.text_normalization import NORMALIZATION_VERSION_V1, normalize_raw_text


class PdfExtractionError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class PdfExtractionResult:
    extracted_text: str
    normalized_text: str
    normalized_char_count: int
    normalization_version: str = NORMALIZATION_VERSION_V1


def extract_pdf_text_content(file_bytes: bytes) -> PdfExtractionResult:
    if not file_bytes:
        raise PdfExtractionError("pdf_extraction_failed", "pdf file is empty")

    raw_text = _extract_with_pypdf(file_bytes)
    if not raw_text.strip():
        raise PdfExtractionError("pdf_extraction_failed", "pdf text extraction produced no readable text")

    normalized = normalize_raw_text(raw_text)
    return PdfExtractionResult(
        extracted_text=raw_text,
        normalized_text=normalized.text,
        normalized_char_count=len(normalized.text),
        normalization_version=normalized.version,
    )


def _extract_with_pypdf(file_bytes: bytes) -> str:
    try:
        reader = PdfReader(BytesIO(file_bytes), strict=False)
    except Exception as exc:
        raise PdfExtractionError("pdf_extraction_failed", "unable to parse pdf file") from exc

    page_text: list[str] = []
    for page in reader.pages:
        extracted = page.extract_text() or ""
        page_text.append(extracted)

    return "\n\n".join(page_text)
