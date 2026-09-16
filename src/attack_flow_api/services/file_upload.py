from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path


class FileUploadValidationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class FileUploadValidationResult:
    sanitized_original_name: str | None
    detected_mime_type: str
    file_class: str
    preferred_extension: str | None
    size_bytes: int
    sha256_hex: str


_EXT_TO_CLASS = {
    "pdf": "pdf",
    "txt": "plaintext",
    "text": "plaintext",
    "md": "plaintext",
    "json": "stix_json",
}

_MIME_TO_CLASS = {
    "application/pdf": "pdf",
    "text/plain": "plaintext",
    "application/json": "stix_json",
}

_CLASS_TO_EXT = {
    "pdf": "pdf",
    "plaintext": "txt",
    "stix_json": "json",
}


def validate_and_describe_upload(
    *,
    file_bytes: bytes,
    original_name: str | None,
    declared_mime_type: str | None,
    upload_max_bytes: int,
    allowed_file_classes: set[str],
    allowed_mime_types: set[str],
) -> FileUploadValidationResult:
    size_bytes = len(file_bytes)
    if size_bytes > upload_max_bytes:
        raise FileUploadValidationError(
            "file_too_large",
            f"uploaded file exceeds maximum size of {upload_max_bytes} bytes",
        )

    sanitized_name = _sanitize_original_name(original_name)
    extension = _extract_extension(sanitized_name)
    ext_class = _EXT_TO_CLASS.get(extension) if extension else None

    declared_mime = _normalize_declared_mime(declared_mime_type)
    if declared_mime is not None and declared_mime not in allowed_mime_types:
        raise FileUploadValidationError(
            "unsupported_file_mime_type",
            f"declared mime type is not allowed: {declared_mime}",
        )
    declared_class = _MIME_TO_CLASS.get(declared_mime) if declared_mime else None

    detected_mime = _detect_mime_type(file_bytes)
    detected_class = _MIME_TO_CLASS.get(detected_mime)

    if detected_class is None:
        raise FileUploadValidationError(
            "unsupported_file_type",
            f"unable to classify file type from detected mime type: {detected_mime}",
        )

    if ext_class is not None and ext_class != detected_class:
        raise FileUploadValidationError(
            "conflicting_file_type_signals",
            "file extension does not match detected file type",
        )
    if declared_class is not None and declared_class != detected_class:
        raise FileUploadValidationError(
            "conflicting_file_type_signals",
            "declared mime type does not match detected file type",
        )
    if detected_class not in allowed_file_classes:
        raise FileUploadValidationError(
            "unsupported_file_class",
            f"file class is not allowed: {detected_class}",
        )

    sha = sha256(file_bytes).hexdigest()
    preferred_extension = _CLASS_TO_EXT.get(detected_class)

    return FileUploadValidationResult(
        sanitized_original_name=sanitized_name,
        detected_mime_type=detected_mime,
        file_class=detected_class,
        preferred_extension=preferred_extension,
        size_bytes=size_bytes,
        sha256_hex=sha,
    )


def _sanitize_original_name(original_name: str | None) -> str | None:
    if not original_name:
        return None
    candidate = Path(original_name).name.strip()
    if not candidate:
        return None
    return candidate[:255]


def _extract_extension(filename: str | None) -> str | None:
    if not filename or "." not in filename:
        return None
    extension = filename.rsplit(".", 1)[1].strip().lower()
    if not extension:
        return None
    return extension


def _normalize_declared_mime(declared_mime_type: str | None) -> str | None:
    if not declared_mime_type:
        return None
    lower = declared_mime_type.strip().lower()
    if not lower:
        return None
    return lower.split(";", 1)[0].strip()


def _detect_mime_type(file_bytes: bytes) -> str:
    if file_bytes.startswith(b"%PDF-"):
        return "application/pdf"

    sample = file_bytes[:4096].lstrip()
    if sample.startswith(b"{") or sample.startswith(b"["):
        return "application/json"

    if _looks_like_text(file_bytes[:4096]):
        return "text/plain"

    return "application/octet-stream"


def _looks_like_text(sample: bytes) -> bool:
    if not sample:
        return True
    try:
        decoded = sample.decode("utf-8")
    except UnicodeDecodeError:
        return False

    allowed_controls = {"\n", "\r", "\t"}
    non_printable = 0
    for char in decoded:
        if char.isprintable() or char in allowed_controls:
            continue
        non_printable += 1

    return non_printable == 0
