import json
from dataclasses import dataclass
from datetime import UTC
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, ValidationError
from starlette.datastructures import UploadFile

from attack_flow_api.errors import BadRequestError, ConflictError, NotFoundError, PayloadTooLargeError
from attack_flow_api.audit.audit_contracts import JobAuditResponse
from attack_flow_api.providers.contracts import RuntimeProviderOverride
from attack_flow_api.services.file_upload import FileUploadValidationError, validate_and_describe_upload
from attack_flow_api.services.stix_json_validation import (
    StixJsonValidationError,
    validate_stix_json_bundle_shape,
)
from attack_flow_api.services.text_normalization import normalize_raw_text
from attack_flow_api.storage.repositories import InputSourceCreate, JobCreate


router = APIRouter(tags=["jobs"])


class JobSubmissionRequest(BaseModel):
    input_type: str
    text: str | None = None
    url: str | None = None
    metadata: dict[str, Any] | None = None
    options: dict[str, Any] | None = None

    model_config = ConfigDict(extra="forbid")


class JobSubmissionResponse(BaseModel):
    job_id: str
    status: str
    submitted_at: str
    poll_url: str
    request_id: str


class JobInputSummary(BaseModel):
    input_type: str | None = None
    original_filename: str | None = None
    title: str | None = None


class JobArtifactOutcomeSummary(BaseModel):
    valid: bool | None = None
    validation_state: str | None = None
    export_status: str | None = None
    validation_error_count: int | None = None
    checksum: str | None = None
    size_bytes: int | None = None
    created_at: str | None = None
    error_code: str | None = None
    error_message: str | None = None


class JobArtifactsSummary(BaseModel):
    has_stix: bool
    has_afb: bool
    stix_url: str | None = None
    afb_url: str | None = None
    stix_outcome: JobArtifactOutcomeSummary | None = None
    afb_outcome: JobArtifactOutcomeSummary | None = None


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    stage: str
    created_at: str
    updated_at: str
    completed_at: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    input: JobInputSummary
    artifacts: JobArtifactsSummary
    request_id: str


class JobDeleteResponse(BaseModel):
    job_id: str
    deleted: bool
    request_id: str


class JobResultResponse(BaseModel):
    job_id: str
    status: str
    result: dict[str, Any]
    error_code: str | None = None
    error_message: str | None = None
    artifacts: JobArtifactsSummary | None = None
    request_id: str


@dataclass(slots=True)
class SubmissionPayload:
    source_type: str
    source_url: str | None = None
    content_text: str | None = None
    raw_text: str | None = None
    normalized_text: str | None = None
    normalized_char_count: int | None = None
    normalization_version: str | None = None
    original_name: str | None = None
    storage_path: str | None = None
    mime_type: str | None = None
    size_bytes: int | None = None
    metadata: dict[str, Any] | None = None
    options: dict[str, Any] | None = None
    provider_id: str | None = None
    runtime_provider_override: RuntimeProviderOverride | None = None
    model: str | None = None
    title: str | None = None
    case_id: str | None = None
    source_name: str | None = None
    stored_filename: str | None = None
    detected_mime_type: str | None = None
    file_class: str | None = None
    stix_json_kind: str | None = None
    stix_json_valid: bool | None = None
    ingestion_error_code: str | None = None
    ingestion_error_message: str | None = None
    sha256: str | None = None


@router.post("/jobs", response_model=JobSubmissionResponse, status_code=202)
async def submit_job(request: Request) -> JobSubmissionResponse:
    """Submit a job from JSON text/url input or multipart file upload.

    Supported modes:
    - `application/json` with `input_type=text` and non-empty `text`
    - `application/json` with `input_type=url` and non-empty `url`
    - `multipart/form-data` with required `file` and optional `metadata`/`options`

    Multipart file behavior:
    - Supported file classes: PDF, plaintext/markdown text, and STIX JSON bundle uploads.
    - Upload size is enforced using configured byte limits.
    - Files are stored with server-generated names; client filenames are metadata only.
    - Plaintext and PDF inputs are extracted and normalized asynchronously for narrative processing.
    - STIX 2.1 bundle JSON is parsed deterministically after routing as `stix_json`.
    - OpenCTI-style custom properties are tolerated when core bundle/object structure is valid.
    - Explicit ATT&CK references are extracted deterministically when present in source data.
    - Relevant entities and explicit relationships are extracted into a structured payload.
    - Narrative text from report/note/description fields is captured for downstream processing.
    - Unsupported file types or malformed payloads fail with structured error responses.

    Canonical normalization behavior:
    - Supported input classes (text, URL-derived narrative, document-derived narrative, STIX/OpenCTI)
      produce a canonical normalized representation for downstream stages.
    - Narrative inputs contribute normalized narrative text.
    - STIX/OpenCTI inputs consume deterministic structured extraction outputs.
    - Explicit ATT&CK refs, entities, relationships, and provenance are preserved in the
      canonical normalized package.
    - Content budgeting/truncation is applied explicitly to canonical normalized text where needed.

    STIX export behavior:
    - Canonical constrained flow models are exported downstream as STIX 2.1 bundles.
    - Attack Flow extension objects are used where appropriate.
    - Only explicit ATT&CK techniques from source are exported as technique mappings.
    - Steps without ATT&CK mappings are allowed.
    - Descriptions remain verbatim source excerpts.
    - Only `AND`/`OR` operators and `true`/`false` conditions are exported.
    - Source-grounded attachment semantics are preserved.

    Shared export finalization behavior:
    - Exporters validate output before success is finalized.
    - Valid STIX/AFB artifacts are persisted with practical metadata.
    - Invalid/incomplete artifacts are not exposed as successful downloads.
    - Export validation failures are visible through existing job status/result/audit surfaces where practical.
    - Partial export success is not treated as overall success: all requested exports are attempted, but the job fails if any export is invalid.

    Text submission behavior:
    - Raw text is normalized deterministically (line endings/whitespace) before processing.
    - Maximum text size is enforced via configured character limit.
    - Normalized text is persisted for downstream pipeline stages.

    URL submission behavior:
    - URL jobs are fetched asynchronously by the worker after queuing.
    - Only `http` and `https` URLs are supported.
    - Unsafe/internal destinations are blocked during URL safety checks.
    - Redirect count, connect/read timeouts, and response size are bounded.
    - HTML content is extracted into normalized text for downstream stages.
    - Unsupported content types are marked failed during async processing.

    Optional `metadata` and `options` are persisted when provided.

    Runtime provider override behavior:
    - `options.provider_id` selects a configured provider for the job.
    - `options.provider_override` supplies safe runtime provider metadata for per-job use.
    - `provider_id` and `provider_override` are mutually exclusive.
    - Supported runtime provider types are `openai`, `openai_compatible`, `azure_openai`,
      `anthropic`, and `gemini`.
    - Gemini runtime overrides use API-key-based endpoint mode only.
    - Runtime API keys and secret-bearing header values are not persisted.
    - Persisted runtime metadata is redacted to provider source/type, redacted endpoint,
      model/deployment, API version, and header names only.

    Submission is non-blocking: this endpoint queues work and returns `202 Accepted`.
    An in-process worker advances queued jobs asynchronously through lifecycle stages.
    """
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("application/json"):
        payload = await _parse_json_payload(request)
        submission = _submission_from_json(
            payload,
            raw_text_max_chars=request.app.state.settings.raw_text_max_chars,
        )
    elif content_type.startswith("multipart/form-data"):
        submission = await _submission_from_multipart(request)
    else:
        raise BadRequestError(
            code="unsupported_content_type",
            message="Content-Type must be application/json or multipart/form-data",
            details=[],
        )

    persistence_service = request.app.state.persistence_service
    input_source_id = str(uuid4())
    input_source = persistence_service.create_input_source(
        InputSourceCreate(
            id=input_source_id,
            type=submission.source_type,
            source_url=submission.source_url,
            content_text=submission.content_text,
            raw_text=submission.raw_text,
            normalized_text=submission.normalized_text,
            normalized_char_count=submission.normalized_char_count,
            normalization_version=submission.normalization_version,
            original_name=submission.original_name,
            storage_path=submission.storage_path,
            mime_type=submission.mime_type,
            size_bytes=submission.size_bytes,
            metadata_json=_serialize_optional_json(submission.metadata),
            options_json=_serialize_optional_json(submission.options),
            title=submission.title,
            case_id=submission.case_id,
            source_name=submission.source_name,
            stored_filename=submission.stored_filename,
            detected_mime_type=submission.detected_mime_type,
            file_class=submission.file_class,
            stix_json_kind=submission.stix_json_kind,
            stix_json_valid=submission.stix_json_valid,
            ingestion_error_code=submission.ingestion_error_code,
            ingestion_error_message=submission.ingestion_error_message,
            sha256=submission.sha256,
        )
    )
    return _create_queued_job_response(
        request,
        input_source.id,
        provider_id=submission.provider_id,
        model=submission.model,
        runtime_provider_override=submission.runtime_provider_override,
    )


async def _parse_json_payload(request: Request) -> JobSubmissionRequest:
    try:
        raw_payload = await request.json()
    except Exception as exc:
        raise RequestValidationError([]) from exc

    try:
        return JobSubmissionRequest.model_validate(raw_payload)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc


def _submission_from_json(payload: JobSubmissionRequest, raw_text_max_chars: int) -> SubmissionPayload:
    normalized_input_type = payload.input_type.strip().lower()
    raw_text = payload.text if isinstance(payload.text, str) else None
    text = raw_text.strip() if isinstance(raw_text, str) else None
    url = payload.url.strip() if isinstance(payload.url, str) else None

    if normalized_input_type not in {"text", "url"}:
        raise BadRequestError(
            code="invalid_input_type",
            message="input_type must be one of: text, url",
            details=[],
        )

    if normalized_input_type == "text":
        if not text:
            raise BadRequestError(
                code="invalid_text_input",
                message="text input requires a non-empty text value",
                details=[],
            )
        if len(text) > raw_text_max_chars:
            raise PayloadTooLargeError(
                code="text_too_large",
                message=f"text input exceeds maximum size of {raw_text_max_chars} characters",
                details=[],
            )
        if url:
            raise BadRequestError(
                code="conflicting_input_fields",
                message="url must not be provided when input_type is text",
                details=[],
            )

    if normalized_input_type == "url":
        if not url:
            raise BadRequestError(
                code="invalid_url_input",
                message="url input requires a non-empty url value",
                details=[],
            )
        parsed_url = urlsplit(url)
        if parsed_url.scheme.lower() not in {"http", "https"}:
            raise BadRequestError(
                code="invalid_url_scheme",
                message="url scheme must be http or https",
                details=[],
            )
        if text:
            raise BadRequestError(
                code="conflicting_input_fields",
                message="text must not be provided when input_type is url",
                details=[],
            )

    normalized_text = None
    normalized_char_count = None
    normalization_version = None
    title = _coerce_optional_metadata_str(payload.metadata, "title")
    case_id = _coerce_optional_metadata_str(payload.metadata, "case_id")
    source_name = _coerce_optional_metadata_str(payload.metadata, "source_name")
    safe_options, provider_id, model, runtime_provider_override = _normalize_submission_options(payload.options)
    if normalized_input_type == "text" and raw_text is not None:
        normalized_result = normalize_raw_text(raw_text)
        normalized_text = normalized_result.text
        normalized_char_count = len(normalized_text)
        normalization_version = normalized_result.version

    return SubmissionPayload(
        source_type=normalized_input_type,
        source_url=url if normalized_input_type == "url" else None,
        content_text=normalized_text,
        raw_text=(raw_text if normalized_input_type == "text" else None),
        normalized_text=normalized_text,
        normalized_char_count=normalized_char_count,
        normalization_version=normalization_version,
        metadata=payload.metadata,
        options=safe_options,
        provider_id=provider_id,
        runtime_provider_override=runtime_provider_override,
        model=model,
        title=title,
        case_id=case_id,
        source_name=source_name,
    )


def _coerce_optional_metadata_str(metadata: dict[str, Any] | None, key: str) -> str | None:
    if metadata is None:
        return None
    value = metadata.get(key)
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    return candidate


async def _submission_from_multipart(request: Request) -> SubmissionPayload:
    form_data = await request.form()
    if (
        form_data.get("input_type") is not None
        or form_data.get("text") is not None
        or form_data.get("url") is not None
    ):
        raise BadRequestError(
            code="conflicting_input_fields",
            message="multipart submission supports file input only",
            details=[],
        )

    upload_file = form_data.get("file")
    if not isinstance(upload_file, UploadFile):
        raise BadRequestError(
            code="missing_file",
            message="multipart submission requires a file field",
            details=[],
        )

    metadata = _parse_optional_json_object(form_data.get("metadata"), "metadata")
    options = _parse_optional_json_object(form_data.get("options"), "options")
    safe_options, provider_id, model, runtime_provider_override = _normalize_submission_options(options)

    file_bytes = await upload_file.read()
    settings = request.app.state.settings
    try:
        upload_info = validate_and_describe_upload(
            file_bytes=file_bytes,
            original_name=upload_file.filename,
            declared_mime_type=upload_file.content_type,
            upload_max_bytes=settings.upload_max_bytes,
            allowed_file_classes=_split_csv_lower(settings.upload_allowed_file_classes),
            allowed_mime_types=_split_csv_lower(settings.upload_allowed_mime_types),
        )
    except FileUploadValidationError as exc:
        if exc.code == "file_too_large":
            raise PayloadTooLargeError(code=exc.code, message=exc.message, details=[])
        raise BadRequestError(code=exc.code, message=exc.message, details=[])

    file_storage = request.app.state.file_storage
    stored_file = file_storage.write_upload(file_bytes, extension=upload_info.preferred_extension)

    stix_json_kind = None
    stix_json_valid = None
    ingestion_error_code = None
    ingestion_error_message = None
    if upload_info.file_class == "stix_json":
        try:
            stix_validation = validate_stix_json_bundle_shape(file_bytes)
            stix_json_kind = stix_validation.stix_json_kind
            stix_json_valid = stix_validation.stix_json_valid
        except StixJsonValidationError as exc:
            raise BadRequestError(code=exc.code, message=exc.message, details=[])

    return SubmissionPayload(
        source_type="file",
        original_name=upload_info.sanitized_original_name,
        mime_type=upload_file.content_type,
        size_bytes=stored_file.size_bytes,
        storage_path=stored_file.relative_path,
        stored_filename=stored_file.filename,
        detected_mime_type=upload_info.detected_mime_type,
        file_class=upload_info.file_class,
        stix_json_kind=stix_json_kind,
        stix_json_valid=stix_json_valid,
        ingestion_error_code=ingestion_error_code,
        ingestion_error_message=ingestion_error_message,
        sha256=upload_info.sha256_hex,
        raw_text=None,
        normalized_text=None,
        normalized_char_count=None,
        normalization_version=None,
        metadata=metadata,
        options=safe_options,
        provider_id=provider_id,
        runtime_provider_override=runtime_provider_override,
        model=model,
        source_name=None,
        title=None,
        case_id=None,
    )


def _split_csv_lower(value: str) -> set[str]:
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def _parse_optional_json_object(raw_value: object, field_name: str) -> dict[str, Any] | None:
    if raw_value is None:
        return None
    if not isinstance(raw_value, str):
        raise BadRequestError(
            code="invalid_multipart_field",
            message=f"{field_name} must be a JSON object string",
            details=[],
        )
    try:
        parsed = json.loads(raw_value)
    except json.JSONDecodeError:
        raise BadRequestError(
            code="invalid_json_field",
            message=f"{field_name} must be valid JSON",
            details=[],
        )
    if not isinstance(parsed, dict):
        raise BadRequestError(
            code="invalid_json_field",
            message=f"{field_name} must be a JSON object",
            details=[],
        )
    return parsed


def _normalize_submission_options(
    options: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, str | None, str | None, RuntimeProviderOverride | None]:
    if options is None:
        return None, None, None, None

    safe_options = dict(options)
    has_provider_id = "provider_id" in safe_options and safe_options.get("provider_id") is not None
    has_provider_override = "provider_override" in safe_options and safe_options.get("provider_override") is not None

    if has_provider_id and has_provider_override:
        raise BadRequestError(
            code="invalid_provider_selection",
            message="options must include only one of provider_id or provider_override",
            details=[],
        )

    model = _coerce_optional_options_str(safe_options, "model")
    if has_provider_id:
        provider_id_value = safe_options.get("provider_id")
        if not isinstance(provider_id_value, str) or not provider_id_value.strip():
            raise BadRequestError(
                code="invalid_provider_id",
                message="options.provider_id must be a non-empty string",
                details=[],
            )
        provider_id = provider_id_value.strip()
        safe_options["provider_id"] = provider_id
        if model is not None:
            safe_options["model"] = model
        return safe_options, provider_id, model, None

    if has_provider_override:
        try:
            runtime_override = RuntimeProviderOverride.model_validate(safe_options.get("provider_override"))
        except ValidationError:
            raise BadRequestError(
                code="invalid_provider_override",
                message="options.provider_override is invalid",
                details=[],
            ) from None

        safe_metadata = runtime_override.safe_metadata().model_dump(mode="json")
        safe_options["provider_override"] = safe_metadata
        return (
            safe_options,
            f"runtime-{runtime_override.provider_type}",
            runtime_override.deployment or runtime_override.model,
            runtime_override,
        )

    if model is not None:
        safe_options["model"] = model
    return safe_options, None, model, None


def _coerce_optional_options_str(options: dict[str, Any], key: str) -> str | None:
    value = options.get(key)
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    return candidate


def _serialize_optional_json(value: dict[str, Any] | None) -> str | None:
    if value is None:
        return None
    return json.dumps(value)


def _create_queued_job_response(
    request: Request,
    input_source_id: str,
    *,
    provider_id: str | None = None,
    model: str | None = None,
    runtime_provider_override: RuntimeProviderOverride | None = None,
) -> JobSubmissionResponse:
    persistence_service = request.app.state.persistence_service
    job = persistence_service.create_job(
        JobCreate(
            id=str(uuid4()),
            status="queued",
            stage="queued",
            provider_id=provider_id,
            model=model,
            input_source_id=input_source_id,
            request_id=request.state.request_id,
        )
    )
    input_source = persistence_service.get_input_source(input_source_id)
    if input_source is not None:
        persistence_service.record_job_submitted(
            job=job,
            input_source_id=input_source_id,
            source_type=input_source.type,
            request_id=request.state.request_id,
        )
        runtime_provider_metadata = _runtime_provider_metadata_from_options(input_source.options_json)
        if runtime_provider_metadata is not None:
            persistence_service.record_job_event(
                job=job,
                event_type="runtime_provider_override_received",
                source_component="api",
                message="runtime provider override received",
                request_id=request.state.request_id,
                details=runtime_provider_metadata,
            )
    persistence_service.record_job_queued(job=job, request_id=request.state.request_id)
    if runtime_provider_override is not None:
        request.app.state.job_worker.set_runtime_provider_override(job.id, runtime_provider_override)
    if input_source is not None and input_source.type == "text" and input_source.normalized_text is not None:
        persistence_service.record_job_event(
            job=job,
            event_type="text_normalized",
            source_component="api",
            message="text normalized",
            details={
                "input_source_id": input_source.id,
                "source_type": input_source.type,
                "normalized_char_count": input_source.normalized_char_count,
                "normalization_version": input_source.normalization_version,
            },
        )
    settings = request.app.state.settings
    submitted_at = job.created_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return JobSubmissionResponse(
        job_id=job.id,
        status=job.status,
        submitted_at=submitted_at,
        poll_url=f"{settings.api_prefix}/jobs/{job.id}",
        request_id=request.state.request_id,
    )


def _runtime_provider_metadata_from_options(options_json: str | None) -> dict[str, object] | None:
    if not options_json:
        return None
    try:
        options = json.loads(options_json)
    except json.JSONDecodeError:
        return None
    if not isinstance(options, dict):
        return None
    provider_override = options.get("provider_override")
    if not isinstance(provider_override, dict):
        return None
    return dict(provider_override)


submit_job.openapi_extra = {
    "requestBody": {
        "required": True,
        "content": {
            "application/json": {
                "schema": {
                    "oneOf": [
                        {
                            "type": "object",
                            "required": ["input_type", "text"],
                            "properties": {
                                "input_type": {"type": "string", "enum": ["text"]},
                                "text": {"type": "string", "minLength": 1},
                                "metadata": {"type": "object", "additionalProperties": True},
                                "options": {"type": "object", "additionalProperties": True},
                            },
                            "additionalProperties": False,
                        },
                        {
                            "type": "object",
                            "required": ["input_type", "url"],
                            "properties": {
                                "input_type": {"type": "string", "enum": ["url"]},
                                "url": {"type": "string", "minLength": 1},
                                "metadata": {"type": "object", "additionalProperties": True},
                                "options": {"type": "object", "additionalProperties": True},
                            },
                            "additionalProperties": False,
                        },
                    ]
                },
                "examples": {
                    "text_submission": {
                        "summary": "JSON text submission",
                        "value": {
                            "input_type": "text",
                            "text": "investigation content",
                            "metadata": {"source": "manual"},
                            "options": {"priority": "normal"},
                        },
                    },
                    "url_submission": {
                        "summary": "JSON URL submission",
                        "value": {
                            "input_type": "url",
                            "url": "https://example.com/report",
                            "metadata": {"source": "feed"},
                            "options": {"priority": "normal"},
                        },
                    },
                    "runtime_provider_override": {
                        "summary": "Text submission with runtime provider override",
                        "value": {
                            "input_type": "text",
                            "text": "investigation content",
                            "options": {
                                "provider_override": {
                                    "provider_type": "openai_compatible",
                                    "endpoint": "https://compatible.example/v1",
                                    "api_key": "<runtime-api-key>",
                                    "model": "model-a",
                                }
                            },
                        },
                    },
                    "runtime_anthropic_override": {
                        "summary": "Text submission with Anthropic runtime provider override",
                        "value": {
                            "input_type": "text",
                            "text": "investigation content",
                            "options": {
                                "provider_override": {
                                    "provider_type": "anthropic",
                                    "endpoint": "https://api.anthropic.com/v1",
                                    "api_key": "<runtime-api-key>",
                                    "model": "claude-3-5-haiku-latest",
                                }
                            },
                        },
                    },
                    "runtime_gemini_override": {
                        "summary": "Text submission with Gemini runtime provider override",
                        "value": {
                            "input_type": "text",
                            "text": "investigation content",
                            "options": {
                                "provider_override": {
                                    "provider_type": "gemini",
                                    "endpoint": "https://generativelanguage.googleapis.com/v1beta",
                                    "api_key": "<runtime-api-key>",
                                    "model": "gemini-1.5-flash",
                                }
                            },
                        },
                    },
                },
            },
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "required": ["file"],
                    "properties": {
                        "file": {
                            "type": "string",
                            "format": "binary",
                            "description": (
                                "Supported classes: PDF, plaintext/markdown text, and STIX JSON bundles. "
                                "Upload size limits are enforced."
                            ),
                        },
                        "metadata": {
                            "type": "string",
                            "description": "Optional JSON object string",
                        },
                        "options": {
                            "type": "string",
                            "description": "Optional JSON object string",
                        },
                    },
                    "additionalProperties": False,
                },
                "encoding": {
                    "metadata": {"contentType": "application/json"},
                    "options": {"contentType": "application/json"},
                },
                "examples": {
                    "file_submission": {
                        "summary": "Multipart file submission",
                        "value": {
                            "file": "<binary>",
                            "metadata": '{"source":"upload"}',
                            "options": '{"priority":"high"}',
                        },
                    },
                    "file_submission_runtime_provider": {
                        "summary": "Multipart file submission with runtime provider override",
                        "value": {
                            "file": "<binary>",
                            "metadata": '{"source":"upload"}',
                            "options": (
                                '{"provider_override":{"provider_type":"azure_openai",'
                                '"endpoint":"https://example.openai.azure.com/openai",'
                                '"api_key":"<runtime-api-key>",'
                                '"api_version":"2024-10-21",'
                                '"deployment":"deployment-a"}}'
                            ),
                        },
                    }
                },
            },
        },
    },
    "responses": {
        "413": {
            "description": "Submission payload exceeds configured size limits",
            "content": {
                "application/json": {
                    "examples": {
                        "text_too_large": {
                            "value": {
                                "error": {
                                    "code": "text_too_large",
                                    "message": "text input exceeds maximum size of <N> characters",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                        "file_too_large": {
                            "value": {
                                "error": {
                                    "code": "file_too_large",
                                    "message": "file upload exceeds maximum size of <N> bytes",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                    }
                }
            },
        },
        "400": {
            "description": "Structured validation errors for invalid submission shape, unsupported files, malformed STIX JSON, or invalid STIX bundle structure",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_url_input": {
                            "value": {
                                "error": {
                                    "code": "invalid_url_input",
                                    "message": "url input requires a non-empty url value",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                        "unsupported_file_type": {
                            "value": {
                                "error": {
                                    "code": "unsupported_file_type",
                                    "message": "uploaded file type is not supported",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                        "stix_json_malformed": {
                            "value": {
                                "error": {
                                    "code": "stix_json_malformed",
                                    "message": "stix json payload is malformed",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                        "stix_json_invalid_bundle_structure": {
                            "value": {
                                "error": {
                                    "code": "stix_json_invalid_bundle_structure",
                                    "message": "stix json bundle must include an objects array",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        }
                    }
                }
            },
        }
    },
}


@router.get(
    "/jobs/{job_id}",
    response_model=JobStatusResponse,
    responses={
        404: {
            "description": "Job not found",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "job_not_found",
                            "message": "Job not found",
                            "details": [],
                        },
                        "request_id": "<request-id>",
                    }
                }
            },
        }
    },
)
def get_job_status(request: Request, job_id: str) -> JobStatusResponse:
    """Retrieve current job state.

    Jobs progress asynchronously through lifecycle stages:
    queued, fetching, extracting, normalizing, ai_extraction,
    flow_building, exporting, completed, failed.

    Failed jobs include failure state via status/stage and are surfaced by this endpoint.

    For URL jobs, async worker processing may fail due to URL safety checks, bounded fetch
    limits (redirects/timeouts/size), or unsupported content type.

    For file jobs, async worker processing may fail due to extraction/validation issues
    (for example decode failures, unreadable PDFs, or malformed STIX JSON).

    For STIX file jobs, asynchronous processing performs deterministic bundle parsing,
    inventory/entity/relationship extraction, explicit ATT&CK reference extraction,
    and narrative text capture from report/note/description fields.

    During `ai_extraction`, orchestration consumes canonical normalized package input
    and may run in `full_extraction` or `enrichment` mode. Deterministic STIX/OpenCTI
    findings remain authoritative and can reduce or bypass provider invocation when
    sufficient. Intermediate extraction output is constrained to the pinned Attack
    Flow v2-compatible export shape with grounded-only ATT&CK mappings, verbatim
    action excerpts, AND/OR operators, and true/false condition values. Downstream
    export may persist both STIX and AFB artifacts when available. Export finalization
    is shared: valid artifacts are persisted with metadata, invalid artifacts are
    suppressed from downloads, and any invalid export fails the job.

    Artifact visibility is pragmatic: the response summarizes whether STIX/AFB
    artifacts are downloadable and surfaces concise outcome metadata where available.

    Downstream processing should read canonical normalized package content when available
    instead of re-reading source-specific raw fields ad hoc.
    """
    persistence_service = request.app.state.persistence_service
    job = _get_job_or_404(persistence_service, job_id)

    input_summary = JobInputSummary()
    if job.input_source_id is not None:
        input_source = persistence_service.get_input_source(job.input_source_id)
        if input_source is not None:
            input_summary = JobInputSummary(
                input_type=input_source.type,
                original_filename=input_source.original_name,
                title=input_source.title,
            )

    artifacts = persistence_service.list_artifacts(job_id=job.id)
    artifacts_summary = _build_job_artifacts_summary(request, job.id, artifacts)

    return JobStatusResponse(
        job_id=job.id,
        status=job.status,
        stage=job.stage,
        created_at=_to_utc_z(job.created_at),
        updated_at=_to_utc_z(job.updated_at),
        completed_at=_to_utc_z(job.completed_at),
        error_code=job.error_code,
        error_message=job.error_message,
        input=input_summary,
        artifacts=artifacts_summary,
        request_id=request.state.request_id,
    )


@router.delete(
    "/jobs/{job_id}",
    response_model=JobDeleteResponse,
    responses={
        404: {
            "description": "Job not found",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "job_not_found",
                            "message": "Job not found",
                            "details": [],
                        },
                        "request_id": "<request-id>",
                    }
                }
            },
        }
    },
)
def delete_job(request: Request, job_id: str) -> JobDeleteResponse:
    persistence_service = request.app.state.persistence_service
    file_storage = request.app.state.file_storage

    job = _get_job_or_404(persistence_service, job_id)

    artifact_paths = [artifact.path for artifact in persistence_service.list_artifacts(job_id=job.id)]
    input_storage_path = None
    if job.input_source_id is not None:
        input_source = persistence_service.get_input_source(job.input_source_id)
        if input_source is not None:
            input_storage_path = input_source.storage_path

    for artifact_path in artifact_paths:
        try:
            file_storage.delete_stored_file(artifact_path)
        except FileNotFoundError:
            pass

    if input_storage_path:
        try:
            file_storage.delete_stored_file(input_storage_path)
        except FileNotFoundError:
            pass

    persistence_service.delete_artifacts_for_job(job.id)
    persistence_service.delete_audit_events_for_job(job.id)
    persistence_service.delete_job(job.id)
    if job.input_source_id is not None and persistence_service.count_jobs_by_input_source(job.input_source_id) == 0:
        persistence_service.delete_input_source(job.input_source_id)

    return JobDeleteResponse(job_id=job.id, deleted=True, request_id=request.state.request_id)


@router.get(
    "/jobs/{job_id}/artifacts/stix",
    responses={
        200: {
            "description": "Download STIX artifact as JSON file",
            "content": {"application/json": {}},
        },
        404: {
            "description": "Job or STIX artifact not found",
            "content": {
                "application/json": {
                    "examples": {
                        "job_not_found": {
                            "value": {
                                "error": {
                                    "code": "job_not_found",
                                    "message": "Job not found",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                        "artifact_not_found": {
                            "value": {
                                "error": {
                                    "code": "artifact_not_found",
                                    "message": "stix artifact not found",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                    }
                }
            },
        },
    },
)
def download_job_stix_artifact(request: Request, job_id: str) -> FileResponse:
    return _download_job_artifact(
        request,
        job_id=job_id,
        artifact_type="stix",
        download_extension="json",
    )


@router.get(
    "/jobs/{job_id}/artifacts/afb",
    responses={
        200: {
            "description": "Download AFB artifact as file (.afb filename)",
            "content": {"application/json": {}},
        },
        404: {
            "description": "Job or AFB artifact not found",
            "content": {
                "application/json": {
                    "examples": {
                        "job_not_found": {
                            "value": {
                                "error": {
                                    "code": "job_not_found",
                                    "message": "Job not found",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                        "artifact_not_found": {
                            "value": {
                                "error": {
                                    "code": "artifact_not_found",
                                    "message": "afb artifact not found",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                    }
                }
            },
        },
    },
)
def download_job_afb_artifact(request: Request, job_id: str) -> FileResponse:
    return _download_job_artifact(
        request,
        job_id=job_id,
        artifact_type="afb",
        download_extension="afb",
    )


@router.get(
    "/jobs/{job_id}/artifacts/ai-trace",
    responses={
        200: {
            "description": "Download AI trace artifact as JSON file",
            "content": {"application/json": {}},
        },
        404: {
            "description": "Job or AI trace artifact not found",
            "content": {
                "application/json": {
                    "examples": {
                        "job_not_found": {
                            "value": {
                                "error": {
                                    "code": "job_not_found",
                                    "message": "Job not found",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                        "artifact_not_found": {
                            "value": {
                                "error": {
                                    "code": "artifact_not_found",
                                    "message": "ai trace artifact not found",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                    }
                }
            },
        },
    },
)
def download_job_ai_trace_artifact(request: Request, job_id: str) -> FileResponse:
    label = request.query_params.get("label")
    return _download_job_trace_artifact(
        request,
        job_id=job_id,
        label=label,
        download_extension="json",
    )


def _download_job_artifact(
    request: Request,
    job_id: str,
    artifact_type: str,
    download_extension: str,
) -> FileResponse:
    persistence_service = request.app.state.persistence_service
    file_storage = request.app.state.file_storage

    job = _get_job_or_404(persistence_service, job_id)

    artifact = _get_artifact_or_404(persistence_service, job.id, artifact_type)
    absolute_path = _resolve_artifact_path_or_404(file_storage, artifact.path, artifact_type)

    return FileResponse(
        path=absolute_path,
        media_type="application/json",
        filename=f"{job.id}-{artifact_type}.{download_extension}",
    )


def _download_job_trace_artifact(
    request: Request,
    job_id: str,
    label: str | None,
    download_extension: str,
) -> FileResponse:
    persistence_service = request.app.state.persistence_service
    file_storage = request.app.state.file_storage

    job = _get_job_or_404(persistence_service, job_id)

    artifact = _get_ai_trace_artifact_or_404(persistence_service, job.id, label)
    absolute_path = _resolve_artifact_path_or_404(file_storage, artifact.path, "ai trace")
    suffix = f"-ai-trace-{label}" if label else "-ai-trace"

    return FileResponse(
        path=absolute_path,
        media_type="application/json",
        filename=f"{job.id}{suffix}.{download_extension}",
    )


@router.get(
    "/jobs/{job_id}/result",
    response_model=JobResultResponse,
    responses={
        404: {
            "description": "Job not found",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "job_not_found",
                            "message": "Job not found",
                            "details": [],
                        },
                        "request_id": "<request-id>",
                    }
                }
            },
        },
        409: {
            "description": "Result not ready",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "result_not_ready",
                            "message": "Result is not ready",
                            "details": [],
                        },
                        "request_id": "<request-id>",
                    }
                }
            },
        },
    },
)
def get_job_result(request: Request, job_id: str) -> JobResultResponse:
    """Retrieve structured result when available.

    Returns `409` while asynchronous processing is still in progress or result data
    is not yet available.

    Note: before final result materialization, normalized canonical source packages are
    persisted per input source and used by downstream orchestration/extraction stages.
    Result payloads in this phase represent intermediate constrained extraction output
    rather than final flow graph/export artifacts.

    The response also includes concise export artifact visibility where available,
    mirroring the job status endpoint.
    """
    persistence_service = request.app.state.persistence_service
    job = _get_job_or_404(persistence_service, job_id)

    if not job.result_json:
        raise ConflictError(code="result_not_ready", message="Result is not ready", details=[])

    try:
        parsed_result = json.loads(job.result_json)
    except json.JSONDecodeError:
        raise ConflictError(code="result_not_ready", message="Result is not ready", details=[])

    if not isinstance(parsed_result, dict):
        raise ConflictError(code="result_not_ready", message="Result is not ready", details=[])

    artifacts = persistence_service.list_artifacts(job_id=job.id)
    artifacts_summary = _build_job_artifacts_summary(request, job.id, artifacts)

    return JobResultResponse(
        job_id=job.id,
        status=job.status,
        result=parsed_result,
        error_code=job.error_code,
        error_message=job.error_message,
        artifacts=artifacts_summary,
        request_id=request.state.request_id,
    )


@router.get(
    "/jobs/{job_id}/audit",
    response_model=JobAuditResponse,
    responses={
        404: {
            "description": "Job not found",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "job_not_found",
                            "message": "Job not found",
                            "details": [],
                        },
                        "request_id": "<request-id>",
                    }
                }
            },
        }
    },
)
def get_job_audit(request: Request, job_id: str) -> JobAuditResponse:
    """Retrieve the current job snapshot and ordered audit history for debugging/support.

    The response is sanitized for safe support use: secrets and raw incident content
    are redacted or suppressed before persistence/serialization.
    """
    retrieval_service = request.app.state.audit_retrieval_service
    result = retrieval_service.get_job_audit(job_id, request.state.request_id)
    if not result.found or result.response is None:
        raise NotFoundError(code="job_not_found", message="Job not found", details=[])
    return result.response


def _get_job_or_404(persistence_service: Any, job_id: str) -> Any:
    job = persistence_service.get_job(job_id)
    if job is None:
        raise NotFoundError(code="job_not_found", message="Job not found", details=[])
    return job


def _get_artifact_or_404(persistence_service: Any, job_id: str, artifact_type: str) -> Any:
    artifacts = persistence_service.list_artifacts(job_id=job_id, artifact_type=artifact_type)
    for artifact in artifacts:
        if _artifact_is_downloadable(artifact):
            return artifact
    if not artifacts:
        raise NotFoundError(
            code="artifact_not_found",
            message=f"{artifact_type} artifact not found",
            details=[],
        )
    raise NotFoundError(
        code="artifact_not_found",
        message=f"{artifact_type} artifact not found",
        details=[],
    )


def _get_ai_trace_artifact_or_404(persistence_service: Any, job_id: str, label: str | None = None) -> Any:
    artifacts = persistence_service.list_artifacts(job_id=job_id, artifact_type="ai_trace")
    if label is not None:
        matching = [artifact for artifact in artifacts if _artifact_trace_label(artifact) == label]
    else:
        matching = artifacts

    if matching:
        return matching[-1]

    raise NotFoundError(
        code="artifact_not_found",
        message="ai trace artifact not found",
        details=[],
    )


def _latest_artifact(artifacts: list[Any], artifact_type: str) -> Any | None:
    matching = [artifact for artifact in artifacts if getattr(artifact, "type", None) == artifact_type]
    if not matching:
        return None
    return matching[-1]


def _latest_downloadable_artifact(artifacts: list[Any], artifact_type: str) -> Any | None:
    matching = [artifact for artifact in artifacts if getattr(artifact, "type", None) == artifact_type]
    for artifact in reversed(matching):
        if _artifact_is_downloadable(artifact):
            return artifact
    return None


def _build_job_artifacts_summary(request: Request, job_id: str, artifacts: list[Any]) -> JobArtifactsSummary:
    api_prefix = request.app.state.settings.api_prefix
    stix_downloadable = _latest_downloadable_artifact(artifacts, "stix")
    afb_downloadable = _latest_downloadable_artifact(artifacts, "afb")
    return JobArtifactsSummary(
        has_stix=stix_downloadable is not None,
        has_afb=afb_downloadable is not None,
        stix_url=f"{api_prefix}/jobs/{job_id}/artifacts/stix" if stix_downloadable is not None else None,
        afb_url=f"{api_prefix}/jobs/{job_id}/artifacts/afb" if afb_downloadable is not None else None,
        stix_outcome=_build_artifact_outcome_summary(_latest_artifact(artifacts, "stix")),
        afb_outcome=_build_artifact_outcome_summary(_latest_artifact(artifacts, "afb")),
    )


def _build_artifact_outcome_summary(artifact: Any | None) -> JobArtifactOutcomeSummary | None:
    if artifact is None:
        return None

    metadata = _artifact_metadata(artifact)
    validation_state = _artifact_value(artifact, "validation_state", metadata)
    export_status = _artifact_value(artifact, "export_status", metadata)
    validation_errors = _artifact_validation_errors(artifact, metadata)
    checksum = _artifact_value(artifact, "sha256", metadata)
    size_bytes = _artifact_value(artifact, "size_bytes", metadata)
    created_at = _artifact_value(artifact, "created_at", metadata)
    if created_at is not None:
        created_at = _to_utc_z(created_at)

    valid = None
    if validation_state is not None or export_status is not None:
        valid = validation_state == "valid" and export_status == "completed"

    return JobArtifactOutcomeSummary(
        valid=valid,
        validation_state=validation_state,
        export_status=export_status,
        validation_error_count=len(validation_errors) if validation_errors is not None else None,
        checksum=checksum,
        size_bytes=size_bytes,
        created_at=created_at,
        error_code=_artifact_value(artifact, "error_code", metadata),
        error_message=_artifact_value(artifact, "error_message", metadata),
    )


def _artifact_metadata(artifact: Any) -> dict[str, Any]:
    metadata_json = getattr(artifact, "metadata_json", None)
    if not metadata_json:
        return {}
    try:
        parsed = json.loads(metadata_json)
    except json.JSONDecodeError:
        return {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def _artifact_validation_errors(artifact: Any, metadata: dict[str, Any]) -> list[dict[str, Any]] | None:
    validation_errors_json = getattr(artifact, "validation_errors_json", None)
    if validation_errors_json is None:
        validation_errors_json = metadata.get("validation_errors")
    if validation_errors_json is None:
        return None
    if isinstance(validation_errors_json, list):
        return validation_errors_json
    if not isinstance(validation_errors_json, str):
        return None
    try:
        parsed = json.loads(validation_errors_json)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, list):
        return parsed
    return None


def _artifact_value(artifact: Any, field_name: str, metadata: dict[str, Any]) -> Any:
    value = getattr(artifact, field_name, None)
    if value is not None:
        return value
    return metadata.get(field_name)


def _artifact_trace_label(artifact: Any) -> str | None:
    metadata = _artifact_metadata(artifact)
    label = metadata.get("label")
    if isinstance(label, str) and label.strip():
        return label.strip()
    return None


def _artifact_is_downloadable(artifact: Any) -> bool:
    validation_state = getattr(artifact, "validation_state", None)
    export_status = getattr(artifact, "export_status", None)
    if validation_state is not None or export_status is not None:
        return validation_state == "valid" and export_status == "completed"

    metadata_json = getattr(artifact, "metadata_json", None)
    if metadata_json is None:
        return False

    try:
        metadata = json.loads(metadata_json)
    except json.JSONDecodeError:
        return False

    if not isinstance(metadata, dict):
        return False

    return metadata.get("validation_state") == "valid" and metadata.get("export_status") == "completed"


def _resolve_artifact_path_or_404(file_storage: Any, relative_path: str, artifact_type: str):
    try:
        absolute_path = file_storage.resolve_stored_path(relative_path)
    except (FileNotFoundError, ValueError):
        raise NotFoundError(
            code="artifact_not_found",
            message=f"{artifact_type} artifact not found",
            details=[],
        ) from None

    if not absolute_path.exists() or not absolute_path.is_file():
        raise NotFoundError(
            code="artifact_not_found",
            message=f"{artifact_type} artifact not found",
            details=[],
        )
    return absolute_path


def _to_utc_z(value: Any) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
