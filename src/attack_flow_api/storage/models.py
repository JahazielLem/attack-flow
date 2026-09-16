from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class Job:
    id: str
    status: str
    stage: str
    provider_id: str | None
    model: str | None
    input_source_id: str | None
    result_json: str | None
    fusion_result_json: str | None
    fusion_validation_state: str | None
    fusion_provenance_json: str | None
    fusion_conflicts_json: str | None
    fusion_attack_refs_json: str | None
    fusion_entities_json: str | None
    fusion_relationships_json: str | None
    canonical_flow_json: str | None
    canonical_flow_validation_state: str | None
    canonical_flow_provenance_json: str | None
    canonical_flow_conflicts_json: str | None
    canonical_flow_validation_errors_json: str | None
    extraction_mode: str | None
    provider_invoked: bool | None
    extraction_result_json: str | None
    extraction_validation_state: str | None
    extraction_repair_attempted: bool | None
    extraction_provenance_classification: str | None
    extraction_authors_json: str | None
    extraction_external_references_json: str | None
    progress_percent: int | None
    started_at: datetime | None
    last_heartbeat_at: datetime | None
    worker_id: str | None
    attempt_count: int
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None
    error_code: str | None
    error_message: str | None
    request_id: str | None


@dataclass(slots=True)
class InputSource:
    id: str
    type: str
    original_name: str | None
    source_url: str | None
    fetch_final_url: str | None
    fetch_status_code: int | None
    fetch_content_type: str | None
    fetch_size_bytes: int | None
    fetch_error_code: str | None
    fetch_error_message: str | None
    content_text: str | None
    raw_text: str | None
    normalized_text: str | None
    normalized_char_count: int | None
    was_truncated: bool | None
    normalization_version: str | None
    storage_path: str | None
    metadata_json: str | None
    options_json: str | None
    mime_type: str | None
    size_bytes: int | None
    sha256: str | None
    title: str | None
    case_id: str | None
    source_name: str | None
    stored_filename: str | None
    detected_mime_type: str | None
    file_class: str | None
    stix_json_kind: str | None
    stix_json_valid: bool | None
    stix_bundle_id: str | None
    stix_spec_version: str | None
    stix_source_type: str | None
    stix_object_count: int | None
    stix_relationship_count: int | None
    stix_attack_ref_count: int | None
    stix_summary_json: str | None
    stix_entities_json: str | None
    stix_relationships_json: str | None
    stix_attack_refs_json: str | None
    stix_provenance_json: str | None
    stix_parse_error_code: str | None
    stix_parse_error_message: str | None
    normalized_source_type: str | None
    normalized_package_json: str | None
    normalized_stats_json: str | None
    normalized_content_chars: int | None
    normalized_content_was_truncated: bool | None
    normalized_content_budget_chars: int | None
    normalized_pipeline_version: str | None
    ingestion_error_code: str | None
    ingestion_error_message: str | None
    created_at: datetime


@dataclass(slots=True)
class Artifact:
    id: str
    job_id: str
    type: str
    path: str
    sha256: str | None
    size_bytes: int | None
    metadata_json: str | None
    validation_state: str | None
    validation_errors_json: str | None
    export_status: str | None
    error_code: str | None
    error_message: str | None
    created_at: datetime


@dataclass(slots=True)
class AuditEvent:
    id: str
    job_id: str | None
    sequence: int | None
    request_id: str | None
    event_type: str
    timestamp: datetime
    status: str | None
    stage: str | None
    source_component: str | None
    message: str | None
    details_json: str | None
    redacted: bool | None
