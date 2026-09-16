from __future__ import annotations

from collections.abc import Mapping, Sequence

_SAFE_SCALAR_KEYS = {
    "attack_action_count",
    "attack_condition_count",
    "attack_operator_count",
    "attack_ref_count",
    "attempt_count",
    "bundle_id",
    "completed_at",
    "content_budget_chars",
    "content_type",
    "current_stage",
    "current_status",
    "deterministic_input_sufficient",
    "detected_mime_type",
    "edge_count",
    "entity_count",
    "endpoint_redacted",
    "error_category",
    "error_code",
    "file_class",
    "fusion_validation_state",
    "input_source_id",
    "is_supported",
    "job_id",
    "model_used",
    "normalized_char_count",
    "normalized_source_type",
    "node_count",
    "object_count",
    "pipeline_version",
    "previous_stage",
    "previous_status",
    "progress_percent",
    "provider_id",
    "provider_invoked",
    "provider_source",
    "provider_type",
    "relationship_count",
    "requested_model",
    "requested_provider_id",
    "request_id",
    "retryable",
    "size_bytes",
    "source_type",
    "spec_version",
    "stage",
    "status",
    "status_code",
    "stix_json_kind",
    "stix_json_valid",
    "unsupported_reason",
    "valid",
    "validation_error_count",
    "validation_state",
    "worker_id",
}

_SENSITIVE_KEY_PARTS = (
    "api_key",
    "authorization",
    "body",
    "content",
    "cookie",
    "data",
    "headers",
    "html",
    "input",
    "metadata",
    "output",
    "payload",
    "prompt",
    "raw",
    "request",
    "response",
    "secret",
    "text",
    "token",
    "url",
)

_MAX_SAFE_STRING_LENGTH = 256


def sanitize_audit_details(details: Mapping[str, object]) -> tuple[dict[str, object], bool]:
    sanitized: dict[str, object] = {}
    redacted = False

    for key, value in details.items():
        sanitized_value, value_redacted = _sanitize_value(str(key), value)
        sanitized[str(key)] = sanitized_value
        redacted = redacted or value_redacted

    return sanitized, redacted


def _sanitize_value(key: str, value: object) -> tuple[object, bool]:
    normalized_key = key.lower()
    if _is_sensitive_key(normalized_key):
        return "[redacted]", True

    if value is None or isinstance(value, (bool, int, float)):
        return value, False

    if isinstance(value, str):
        if len(value) > _MAX_SAFE_STRING_LENGTH:
            return f"[redacted length={len(value)}]", True
        return value, False

    if isinstance(value, Mapping):
        sanitized: dict[str, object] = {}
        redacted = False
        for child_key, child_value in value.items():
            child_sanitized, child_redacted = _sanitize_value(str(child_key), child_value)
            sanitized[str(child_key)] = child_sanitized
            redacted = redacted or child_redacted
        return sanitized, redacted

    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        sanitized_items = []
        redacted = False
        for item in value:
            item_sanitized, item_redacted = _sanitize_value(key, item)
            sanitized_items.append(item_sanitized)
            redacted = redacted or item_redacted
        return sanitized_items, redacted

    return "[redacted]", True


def _is_sensitive_key(key: str) -> bool:
    if key in _SAFE_SCALAR_KEYS:
        return False
    return any(part in key for part in _SENSITIVE_KEY_PARTS)
