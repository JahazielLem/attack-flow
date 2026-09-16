import json
from dataclasses import dataclass


SUPPORTED_FILE_CLASSES = {"plaintext", "pdf", "stix_json"}

_TEXT_EXTENSIONS = {"txt", "text", "md", "log", "csv"}
_JSON_EXTENSIONS = {"json"}
_PDF_EXTENSIONS = {"pdf"}


@dataclass(frozen=True, slots=True)
class FileRoutingResult:
    file_class: str
    is_supported: bool
    stix_json_kind: str | None
    unsupported_reason: str | None


def classify_file_for_routing(
    *,
    original_filename: str | None,
    declared_mime_type: str | None,
    detected_mime_type: str | None,
    file_bytes: bytes,
) -> FileRoutingResult:
    extension = _extract_extension(original_filename)
    declared = _normalize_mime(declared_mime_type)
    detected = _normalize_mime(detected_mime_type)

    if _looks_like_pdf(extension=extension, declared=declared, detected=detected):
        return FileRoutingResult(
            file_class="pdf",
            is_supported=True,
            stix_json_kind=None,
            unsupported_reason=None,
        )

    if _looks_like_plaintext(extension=extension, declared=declared, detected=detected):
        return FileRoutingResult(
            file_class="plaintext",
            is_supported=True,
            stix_json_kind=None,
            unsupported_reason=None,
        )

    if _looks_like_json(extension=extension, declared=declared, detected=detected):
        stix_kind = _classify_stix_json_shape(file_bytes)
        if stix_kind is not None:
            return FileRoutingResult(
                file_class="stix_json",
                is_supported=True,
                stix_json_kind=stix_kind,
                unsupported_reason=None,
            )
        return FileRoutingResult(
            file_class="unsupported",
            is_supported=False,
            stix_json_kind=None,
            unsupported_reason="json_not_stix_bundle_shape",
        )

    return FileRoutingResult(
        file_class="unsupported",
        is_supported=False,
        stix_json_kind=None,
        unsupported_reason="unrecognized_file_type",
    )


def _normalize_mime(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip().lower()
    if not candidate:
        return None
    return candidate.split(";", 1)[0].strip()


def _extract_extension(filename: str | None) -> str | None:
    if not filename or "." not in filename:
        return None
    extension = filename.rsplit(".", 1)[1].strip().lower()
    if not extension:
        return None
    return extension


def _looks_like_pdf(*, extension: str | None, declared: str | None, detected: str | None) -> bool:
    return extension in _PDF_EXTENSIONS or declared == "application/pdf" or detected == "application/pdf"


def _looks_like_plaintext(*, extension: str | None, declared: str | None, detected: str | None) -> bool:
    return extension in _TEXT_EXTENSIONS or declared == "text/plain" or detected == "text/plain"


def _looks_like_json(*, extension: str | None, declared: str | None, detected: str | None) -> bool:
    return extension in _JSON_EXTENSIONS or declared == "application/json" or detected == "application/json"


def _classify_stix_json_shape(file_bytes: bytes) -> str | None:
    try:
        parsed = json.loads(file_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

    if not isinstance(parsed, dict):
        return None
    if parsed.get("type") != "bundle":
        return None
    objects = parsed.get("objects")
    if not isinstance(objects, list):
        return None
    return "bundle_candidate"
