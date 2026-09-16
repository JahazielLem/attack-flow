from dataclasses import dataclass

from attack_flow_api.services.text_normalization import NORMALIZATION_VERSION_V1, normalize_raw_text


class PlaintextExtractionError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class PlaintextExtractionResult:
    extracted_text: str
    normalized_text: str
    normalized_char_count: int
    normalization_version: str = NORMALIZATION_VERSION_V1


def extract_plaintext_content(file_bytes: bytes) -> PlaintextExtractionResult:
    if not file_bytes:
        raw_text = ""
    else:
        try:
            raw_text = file_bytes.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise PlaintextExtractionError(
                "plaintext_decode_failed",
                "plaintext file must be valid UTF-8",
            ) from exc

    normalized = normalize_raw_text(raw_text)
    return PlaintextExtractionResult(
        extracted_text=raw_text,
        normalized_text=normalized.text,
        normalized_char_count=len(normalized.text),
        normalization_version=normalized.version,
    )
