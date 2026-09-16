from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from attack_flow_api.storage.database import create_connection
from attack_flow_api.storage.models import Artifact, AuditEvent, InputSource, Job


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _parse_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _require_datetime(value: str | None, field_name: str) -> datetime:
    parsed = _parse_datetime(value)
    if parsed is None:
        raise ValueError(f"Missing required datetime field: {field_name}")
    return parsed


def _row_to_bool(value: object) -> bool | None:
    if value is None:
        return None
    return bool(value)


def _audit_details_json(row: object) -> str | None:
    details_json = row["details_json"]
    if details_json is not None:
        return details_json
    return row["metadata_json"]


@dataclass(slots=True)
class JobCreate:
    id: str
    status: str
    stage: str
    provider_id: str | None = None
    model: str | None = None
    input_source_id: str | None = None
    result_json: str | None = None
    fusion_result_json: str | None = None
    fusion_validation_state: str | None = None
    fusion_provenance_json: str | None = None
    fusion_conflicts_json: str | None = None
    fusion_attack_refs_json: str | None = None
    fusion_entities_json: str | None = None
    fusion_relationships_json: str | None = None
    canonical_flow_json: str | None = None
    canonical_flow_validation_state: str | None = None
    canonical_flow_provenance_json: str | None = None
    canonical_flow_conflicts_json: str | None = None
    canonical_flow_validation_errors_json: str | None = None
    extraction_mode: str | None = None
    provider_invoked: bool | None = None
    extraction_result_json: str | None = None
    extraction_validation_state: str | None = None
    extraction_repair_attempted: bool | None = None
    extraction_provenance_classification: str | None = None
    extraction_authors_json: str | None = None
    extraction_external_references_json: str | None = None
    request_id: str | None = None


@dataclass(slots=True)
class JobUpdate:
    status: str | None = None
    stage: str | None = None
    progress_percent: int | None = None
    started_at: datetime | None = None
    last_heartbeat_at: datetime | None = None
    worker_id: str | None = None
    attempt_count: int | None = None
    provider_id: str | None = None
    model: str | None = None
    input_source_id: str | None = None
    result_json: str | None = None
    fusion_result_json: str | None = None
    fusion_validation_state: str | None = None
    fusion_provenance_json: str | None = None
    fusion_conflicts_json: str | None = None
    fusion_attack_refs_json: str | None = None
    fusion_entities_json: str | None = None
    fusion_relationships_json: str | None = None
    canonical_flow_json: str | None = None
    canonical_flow_validation_state: str | None = None
    canonical_flow_provenance_json: str | None = None
    canonical_flow_conflicts_json: str | None = None
    canonical_flow_validation_errors_json: str | None = None
    extraction_mode: str | None = None
    provider_invoked: bool | None = None
    extraction_result_json: str | None = None
    extraction_validation_state: str | None = None
    extraction_repair_attempted: bool | None = None
    extraction_provenance_classification: str | None = None
    extraction_authors_json: str | None = None
    extraction_external_references_json: str | None = None
    completed_at: datetime | None = None
    error_code: str | None = None
    error_message: str | None = None
    request_id: str | None = None


@dataclass(slots=True)
class JobExtractionUpdate:
    extraction_mode: str | None = None
    provider_invoked: bool | None = None
    provider_id: str | None = None
    model: str | None = None
    extraction_result_json: str | None = None
    extraction_validation_state: str | None = None
    extraction_repair_attempted: bool | None = None
    extraction_provenance_classification: str | None = None
    extraction_authors_json: str | None = None
    extraction_external_references_json: str | None = None


@dataclass(slots=True)
class JobFusionUpdate:
    fusion_result_json: str | None = None
    fusion_validation_state: str | None = None
    fusion_provenance_json: str | None = None
    fusion_conflicts_json: str | None = None
    fusion_attack_refs_json: str | None = None
    fusion_entities_json: str | None = None
    fusion_relationships_json: str | None = None


@dataclass(slots=True)
class JobCanonicalFlowUpdate:
    canonical_flow_json: str | None = None
    canonical_flow_validation_state: str | None = None
    canonical_flow_provenance_json: str | None = None
    canonical_flow_conflicts_json: str | None = None
    canonical_flow_validation_errors_json: str | None = None


@dataclass(slots=True)
class InputSourceCreate:
    id: str
    type: str
    original_name: str | None = None
    source_url: str | None = None
    fetch_final_url: str | None = None
    fetch_status_code: int | None = None
    fetch_content_type: str | None = None
    fetch_size_bytes: int | None = None
    fetch_error_code: str | None = None
    fetch_error_message: str | None = None
    content_text: str | None = None
    raw_text: str | None = None
    normalized_text: str | None = None
    normalized_char_count: int | None = None
    was_truncated: bool | None = None
    normalization_version: str | None = None
    storage_path: str | None = None
    metadata_json: str | None = None
    options_json: str | None = None
    mime_type: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    title: str | None = None
    case_id: str | None = None
    source_name: str | None = None
    stored_filename: str | None = None
    detected_mime_type: str | None = None
    file_class: str | None = None
    stix_json_kind: str | None = None
    stix_json_valid: bool | None = None
    stix_bundle_id: str | None = None
    stix_spec_version: str | None = None
    stix_source_type: str | None = None
    stix_object_count: int | None = None
    stix_relationship_count: int | None = None
    stix_attack_ref_count: int | None = None
    stix_summary_json: str | None = None
    stix_entities_json: str | None = None
    stix_relationships_json: str | None = None
    stix_attack_refs_json: str | None = None
    stix_provenance_json: str | None = None
    stix_parse_error_code: str | None = None
    stix_parse_error_message: str | None = None
    normalized_source_type: str | None = None
    normalized_package_json: str | None = None
    normalized_stats_json: str | None = None
    normalized_content_chars: int | None = None
    normalized_content_was_truncated: bool | None = None
    normalized_content_budget_chars: int | None = None
    normalized_pipeline_version: str | None = None
    ingestion_error_code: str | None = None
    ingestion_error_message: str | None = None


@dataclass(slots=True)
class InputSourceTextUpdate:
    raw_text: str | None = None
    normalized_text: str | None = None
    normalized_char_count: int | None = None
    was_truncated: bool | None = None
    normalization_version: str | None = None


@dataclass(slots=True)
class InputSourceFetchUpdate:
    fetch_final_url: str | None = None
    fetch_status_code: int | None = None
    fetch_content_type: str | None = None
    fetch_size_bytes: int | None = None
    fetch_error_code: str | None = None
    fetch_error_message: str | None = None
    raw_text: str | None = None
    normalized_text: str | None = None
    normalized_char_count: int | None = None
    normalization_version: str | None = None
    content_text: str | None = None


@dataclass(slots=True)
class InputSourceFileUpdate:
    detected_mime_type: str | None = None
    file_class: str | None = None
    stix_json_kind: str | None = None
    stix_json_valid: bool | None = None
    stix_bundle_id: str | None = None
    stix_spec_version: str | None = None
    stix_source_type: str | None = None
    stix_object_count: int | None = None
    stix_relationship_count: int | None = None
    stix_attack_ref_count: int | None = None
    stix_summary_json: str | None = None
    stix_entities_json: str | None = None
    stix_relationships_json: str | None = None
    stix_attack_refs_json: str | None = None
    stix_provenance_json: str | None = None
    stix_parse_error_code: str | None = None
    stix_parse_error_message: str | None = None
    ingestion_error_code: str | None = None
    ingestion_error_message: str | None = None
    raw_text: str | None = None
    normalized_text: str | None = None
    normalized_char_count: int | None = None
    normalization_version: str | None = None
    content_text: str | None = None


@dataclass(slots=True)
class ArtifactCreate:
    id: str
    job_id: str
    type: str
    path: str
    sha256: str | None = None
    size_bytes: int | None = None
    metadata_json: str | None = None
    validation_state: str | None = None
    validation_errors_json: str | None = None
    export_status: str | None = None
    error_code: str | None = None
    error_message: str | None = None


@dataclass(slots=True)
class ArtifactUpdate:
    path: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None
    metadata_json: str | None = None
    validation_state: str | None = None
    validation_errors_json: str | None = None
    export_status: str | None = None
    error_code: str | None = None
    error_message: str | None = None


@dataclass(slots=True)
class InputSourceStixUpdate:
    stix_json_kind: str | None = None
    stix_json_valid: bool | None = None
    stix_bundle_id: str | None = None
    stix_spec_version: str | None = None
    stix_source_type: str | None = None
    stix_object_count: int | None = None
    stix_relationship_count: int | None = None
    stix_attack_ref_count: int | None = None
    stix_summary_json: str | None = None
    stix_entities_json: str | None = None
    stix_relationships_json: str | None = None
    stix_attack_refs_json: str | None = None
    stix_provenance_json: str | None = None
    stix_parse_error_code: str | None = None
    stix_parse_error_message: str | None = None


@dataclass(slots=True)
class InputSourceNormalizedUpdate:
    normalized_source_type: str | None = None
    normalized_package_json: str | None = None
    normalized_stats_json: str | None = None
    normalized_content_chars: int | None = None
    normalized_content_was_truncated: bool | None = None
    normalized_content_budget_chars: int | None = None
    normalized_pipeline_version: str | None = None


@dataclass(slots=True)
class AuditEventCreate:
    id: str
    event_type: str
    job_id: str | None = None
    sequence: int | None = None
    timestamp: datetime | None = None
    status: str | None = None
    stage: str | None = None
    request_id: str | None = None
    source_component: str | None = None
    message: str | None = None
    details_json: str | None = None
    redacted: bool | None = None


class PersistenceRepository:
    def __init__(self, sqlite_path: Path):
        self.sqlite_path = sqlite_path

    def create_job(self, payload: JobCreate) -> Job:
        now = _utcnow_iso()
        with create_connection(self.sqlite_path) as connection:
            connection.execute(
                """
                INSERT INTO jobs (
                    id, status, stage, provider_id, model, input_source_id,
                    result_json, fusion_result_json, fusion_validation_state,
                    fusion_provenance_json, fusion_conflicts_json, fusion_attack_refs_json,
                    fusion_entities_json, fusion_relationships_json,
                    canonical_flow_json, canonical_flow_validation_state,
                    canonical_flow_provenance_json, canonical_flow_conflicts_json,
                    canonical_flow_validation_errors_json,
                    extraction_mode, provider_invoked, extraction_result_json,
                    extraction_validation_state, extraction_repair_attempted,
                    extraction_provenance_classification, extraction_authors_json,
                    extraction_external_references_json,
                    progress_percent, started_at, last_heartbeat_at,
                    worker_id, attempt_count, created_at, updated_at, request_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.id,
                    payload.status,
                    payload.stage,
                    payload.provider_id,
                    payload.model,
                    payload.input_source_id,
                    payload.result_json,
                    payload.fusion_result_json,
                    payload.fusion_validation_state,
                    payload.fusion_provenance_json,
                    payload.fusion_conflicts_json,
                    payload.fusion_attack_refs_json,
                    payload.fusion_entities_json,
                    payload.fusion_relationships_json,
                    payload.canonical_flow_json,
                    payload.canonical_flow_validation_state,
                    payload.canonical_flow_provenance_json,
                    payload.canonical_flow_conflicts_json,
                    payload.canonical_flow_validation_errors_json,
                    payload.extraction_mode,
                    int(payload.provider_invoked) if payload.provider_invoked is not None else None,
                    payload.extraction_result_json,
                    payload.extraction_validation_state,
                    int(payload.extraction_repair_attempted)
                    if payload.extraction_repair_attempted is not None
                    else None,
                    payload.extraction_provenance_classification,
                    payload.extraction_authors_json,
                    payload.extraction_external_references_json,
                    None,
                    None,
                    None,
                    None,
                    0,
                    now,
                    now,
                    payload.request_id,
                ),
            )
        created = self.get_job(payload.id)
        if created is None:
            raise RuntimeError("Failed to create job")
        return created

    def update_job(self, job_id: str, payload: JobUpdate) -> Job | None:
        updates: dict[str, object] = {}
        for field_name in (
            "status",
            "stage",
            "progress_percent",
            "worker_id",
            "attempt_count",
            "provider_id",
            "model",
            "input_source_id",
            "result_json",
            "fusion_result_json",
            "fusion_validation_state",
            "fusion_provenance_json",
            "fusion_conflicts_json",
            "fusion_attack_refs_json",
            "fusion_entities_json",
            "fusion_relationships_json",
            "canonical_flow_json",
            "canonical_flow_validation_state",
            "canonical_flow_provenance_json",
            "canonical_flow_conflicts_json",
            "canonical_flow_validation_errors_json",
            "extraction_mode",
            "provider_invoked",
            "extraction_result_json",
            "extraction_validation_state",
            "extraction_repair_attempted",
            "extraction_provenance_classification",
            "extraction_authors_json",
            "extraction_external_references_json",
            "error_code",
            "error_message",
            "request_id",
        ):
            value = getattr(payload, field_name)
            if value is not None:
                if field_name in {"provider_invoked", "extraction_repair_attempted"}:
                    updates[field_name] = int(bool(value))
                else:
                    updates[field_name] = value

        if payload.completed_at is not None:
            updates["completed_at"] = payload.completed_at.isoformat().replace("+00:00", "Z")
        if payload.started_at is not None:
            updates["started_at"] = payload.started_at.isoformat().replace("+00:00", "Z")
        if payload.last_heartbeat_at is not None:
            updates["last_heartbeat_at"] = payload.last_heartbeat_at.isoformat().replace("+00:00", "Z")

        updates["updated_at"] = _utcnow_iso()
        set_clause = ", ".join([f"{key} = ?" for key in updates])
        params = list(updates.values()) + [job_id]

        with create_connection(self.sqlite_path) as connection:
            result = connection.execute(
                f"UPDATE jobs SET {set_clause} WHERE id = ?",  # noqa: S608
                params,
            )
            if result.rowcount == 0:
                return None

        return self.get_job(job_id)

    def get_job(self, job_id: str) -> Job | None:
        with create_connection(self.sqlite_path) as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            return None
        return Job(
            id=row["id"],
            status=row["status"],
            stage=row["stage"],
            provider_id=row["provider_id"],
            model=row["model"],
            input_source_id=row["input_source_id"],
            result_json=row["result_json"],
            fusion_result_json=row["fusion_result_json"],
            fusion_validation_state=row["fusion_validation_state"],
            fusion_provenance_json=row["fusion_provenance_json"],
            fusion_conflicts_json=row["fusion_conflicts_json"],
            fusion_attack_refs_json=row["fusion_attack_refs_json"],
            fusion_entities_json=row["fusion_entities_json"],
            fusion_relationships_json=row["fusion_relationships_json"],
            canonical_flow_json=row["canonical_flow_json"],
            canonical_flow_validation_state=row["canonical_flow_validation_state"],
            canonical_flow_provenance_json=row["canonical_flow_provenance_json"],
            canonical_flow_conflicts_json=row["canonical_flow_conflicts_json"],
            canonical_flow_validation_errors_json=row["canonical_flow_validation_errors_json"],
            extraction_mode=row["extraction_mode"],
            provider_invoked=bool(row["provider_invoked"]) if row["provider_invoked"] is not None else None,
            extraction_result_json=row["extraction_result_json"],
            extraction_validation_state=row["extraction_validation_state"],
            extraction_repair_attempted=bool(row["extraction_repair_attempted"])
            if row["extraction_repair_attempted"] is not None
            else None,
            extraction_provenance_classification=row["extraction_provenance_classification"],
            extraction_authors_json=row["extraction_authors_json"],
            extraction_external_references_json=row["extraction_external_references_json"],
            progress_percent=row["progress_percent"],
            started_at=_parse_datetime(row["started_at"]),
            last_heartbeat_at=_parse_datetime(row["last_heartbeat_at"]),
            worker_id=row["worker_id"],
            attempt_count=int(row["attempt_count"] or 0),
            created_at=_require_datetime(row["created_at"], "created_at"),
            updated_at=_require_datetime(row["updated_at"], "updated_at"),
            completed_at=_parse_datetime(row["completed_at"]),
            error_code=row["error_code"],
            error_message=row["error_message"],
            request_id=row["request_id"],
        )

    def claim_next_queued_job(self, worker_id: str) -> Job | None:
        now = _utcnow_iso()
        with create_connection(self.sqlite_path) as connection:
            row = connection.execute(
                """
                SELECT id
                FROM jobs
                WHERE status = ?
                ORDER BY created_at ASC
                LIMIT 1
                """,
                ("queued",),
            ).fetchone()
            if row is None:
                return None

            job_id = str(row["id"])
            result = connection.execute(
                """
                UPDATE jobs
                SET status = ?,
                    stage = ?,
                    updated_at = ?,
                    started_at = COALESCE(started_at, ?),
                    last_heartbeat_at = ?,
                    worker_id = ?,
                    progress_percent = ?,
                    attempt_count = attempt_count + 1
                WHERE id = ? AND status = ?
                """,
                (
                    "fetching",
                    "fetching",
                    now,
                    now,
                    now,
                    worker_id,
                    10,
                    job_id,
                    "queued",
                ),
            )
            if result.rowcount == 0:
                return None

        return self.get_job(job_id)

    def update_job_lifecycle(
        self,
        job_id: str,
        *,
        status: str,
        stage: str,
        progress_percent: int | None = None,
        worker_id: str | None = None,
    ) -> Job | None:
        return self.update_job(
            job_id,
            JobUpdate(
                status=status,
                stage=stage,
                progress_percent=progress_percent,
                worker_id=worker_id,
                last_heartbeat_at=_utcnow(),
            ),
        )

    def update_job_extraction(self, job_id: str, payload: JobExtractionUpdate) -> Job | None:
        return self.update_job(
            job_id,
            JobUpdate(
                extraction_mode=payload.extraction_mode,
                provider_invoked=payload.provider_invoked,
                provider_id=payload.provider_id,
                model=payload.model,
                extraction_result_json=payload.extraction_result_json,
                extraction_validation_state=payload.extraction_validation_state,
                extraction_repair_attempted=payload.extraction_repair_attempted,
                extraction_provenance_classification=payload.extraction_provenance_classification,
                extraction_authors_json=payload.extraction_authors_json,
                extraction_external_references_json=payload.extraction_external_references_json,
            ),
        )

    def update_job_fusion(self, job_id: str, payload: JobFusionUpdate) -> Job | None:
        return self.update_job(
            job_id,
            JobUpdate(
                fusion_result_json=payload.fusion_result_json,
                fusion_validation_state=payload.fusion_validation_state,
                fusion_provenance_json=payload.fusion_provenance_json,
                fusion_conflicts_json=payload.fusion_conflicts_json,
                fusion_attack_refs_json=payload.fusion_attack_refs_json,
                fusion_entities_json=payload.fusion_entities_json,
                fusion_relationships_json=payload.fusion_relationships_json,
            ),
        )

    def update_job_canonical_flow(self, job_id: str, payload: JobCanonicalFlowUpdate) -> Job | None:
        return self.update_job(
            job_id,
            JobUpdate(
                canonical_flow_json=payload.canonical_flow_json,
                canonical_flow_validation_state=payload.canonical_flow_validation_state,
                canonical_flow_provenance_json=payload.canonical_flow_provenance_json,
                canonical_flow_conflicts_json=payload.canonical_flow_conflicts_json,
                canonical_flow_validation_errors_json=payload.canonical_flow_validation_errors_json,
            ),
        )

    def mark_job_completed(self, job_id: str) -> Job | None:
        now = _utcnow()
        return self.update_job(
            job_id,
            JobUpdate(
                status="completed",
                stage="completed",
                progress_percent=100,
                completed_at=now,
                last_heartbeat_at=now,
            ),
        )

    def mark_job_failed(self, job_id: str, error_code: str, error_message: str) -> Job | None:
        now = _utcnow()
        return self.update_job(
            job_id,
            JobUpdate(
                status="failed",
                stage="failed",
                completed_at=now,
                last_heartbeat_at=now,
                error_code=error_code,
                error_message=error_message,
            ),
        )

    def create_input_source(self, payload: InputSourceCreate) -> InputSource:
        now = _utcnow_iso()
        with create_connection(self.sqlite_path) as connection:
            connection.execute(
                """
                INSERT INTO input_sources (
                    id, type, original_name, source_url,
                    fetch_final_url, fetch_status_code, fetch_content_type,
                    fetch_size_bytes, fetch_error_code, fetch_error_message,
                    content_text,
                    raw_text, normalized_text, normalized_char_count, was_truncated,
                    normalization_version, storage_path, metadata_json, options_json,
                    mime_type, size_bytes, sha256, title, case_id, source_name,
                    stored_filename, detected_mime_type, file_class, stix_json_kind, stix_json_valid,
                    stix_bundle_id, stix_spec_version, stix_source_type,
                    stix_object_count, stix_relationship_count, stix_attack_ref_count,
                    stix_summary_json, stix_entities_json, stix_relationships_json,
                    stix_attack_refs_json, stix_provenance_json,
                    stix_parse_error_code, stix_parse_error_message,
                    normalized_source_type, normalized_package_json, normalized_stats_json,
                    normalized_content_chars, normalized_content_was_truncated,
                    normalized_content_budget_chars, normalized_pipeline_version,
                    ingestion_error_code, ingestion_error_message, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.id,
                    payload.type,
                    payload.original_name,
                    payload.source_url,
                    payload.fetch_final_url,
                    payload.fetch_status_code,
                    payload.fetch_content_type,
                    payload.fetch_size_bytes,
                    payload.fetch_error_code,
                    payload.fetch_error_message,
                    payload.content_text,
                    payload.raw_text,
                    payload.normalized_text,
                    payload.normalized_char_count,
                    int(payload.was_truncated) if payload.was_truncated is not None else None,
                    payload.normalization_version,
                    payload.storage_path,
                    payload.metadata_json,
                    payload.options_json,
                    payload.mime_type,
                    payload.size_bytes,
                    payload.sha256,
                    payload.title,
                    payload.case_id,
                    payload.source_name,
                    payload.stored_filename,
                    payload.detected_mime_type,
                    payload.file_class,
                    payload.stix_json_kind,
                    int(payload.stix_json_valid) if payload.stix_json_valid is not None else None,
                    payload.stix_bundle_id,
                    payload.stix_spec_version,
                    payload.stix_source_type,
                    payload.stix_object_count,
                    payload.stix_relationship_count,
                    payload.stix_attack_ref_count,
                    payload.stix_summary_json,
                    payload.stix_entities_json,
                    payload.stix_relationships_json,
                    payload.stix_attack_refs_json,
                    payload.stix_provenance_json,
                    payload.stix_parse_error_code,
                    payload.stix_parse_error_message,
                    payload.normalized_source_type,
                    payload.normalized_package_json,
                    payload.normalized_stats_json,
                    payload.normalized_content_chars,
                    (
                        int(payload.normalized_content_was_truncated)
                        if payload.normalized_content_was_truncated is not None
                        else None
                    ),
                    payload.normalized_content_budget_chars,
                    payload.normalized_pipeline_version,
                    payload.ingestion_error_code,
                    payload.ingestion_error_message,
                    now,
                ),
            )
        return self.get_input_source(payload.id)

    def update_input_source_file(
        self,
        input_source_id: str,
        payload: InputSourceFileUpdate,
    ) -> InputSource | None:
        updates: dict[str, object] = {}
        for field_name in (
            "detected_mime_type",
            "file_class",
            "stix_json_kind",
            "stix_bundle_id",
            "stix_spec_version",
            "stix_source_type",
            "stix_object_count",
            "stix_relationship_count",
            "stix_attack_ref_count",
            "stix_summary_json",
            "stix_entities_json",
            "stix_relationships_json",
            "stix_attack_refs_json",
            "stix_provenance_json",
            "stix_parse_error_code",
            "stix_parse_error_message",
            "ingestion_error_code",
            "ingestion_error_message",
            "raw_text",
            "normalized_text",
            "normalized_char_count",
            "normalization_version",
            "content_text",
        ):
            value = getattr(payload, field_name)
            if value is not None:
                updates[field_name] = value

        if payload.stix_json_valid is not None:
            updates["stix_json_valid"] = int(payload.stix_json_valid)

        if not updates:
            return self.get_input_source(input_source_id)

        set_clause = ", ".join([f"{key} = ?" for key in updates])
        params = list(updates.values()) + [input_source_id]

        with create_connection(self.sqlite_path) as connection:
            result = connection.execute(
                f"UPDATE input_sources SET {set_clause} WHERE id = ?",  # noqa: S608
                params,
            )
            if result.rowcount == 0:
                return None

        return self.get_input_source(input_source_id)

    def update_input_source_stix(
        self,
        input_source_id: str,
        payload: InputSourceStixUpdate,
    ) -> InputSource | None:
        updates: dict[str, object] = {}
        for field_name in (
            "stix_json_kind",
            "stix_bundle_id",
            "stix_spec_version",
            "stix_source_type",
            "stix_object_count",
            "stix_relationship_count",
            "stix_attack_ref_count",
            "stix_summary_json",
            "stix_entities_json",
            "stix_relationships_json",
            "stix_attack_refs_json",
            "stix_provenance_json",
            "stix_parse_error_code",
            "stix_parse_error_message",
        ):
            value = getattr(payload, field_name)
            if value is not None:
                updates[field_name] = value

        if payload.stix_json_valid is not None:
            updates["stix_json_valid"] = int(payload.stix_json_valid)

        if not updates:
            return self.get_input_source(input_source_id)

        set_clause = ", ".join([f"{key} = ?" for key in updates])
        params = list(updates.values()) + [input_source_id]

        with create_connection(self.sqlite_path) as connection:
            result = connection.execute(
                f"UPDATE input_sources SET {set_clause} WHERE id = ?",  # noqa: S608
                params,
            )
            if result.rowcount == 0:
                return None

        return self.get_input_source(input_source_id)

    def update_input_source_normalized(
        self,
        input_source_id: str,
        payload: InputSourceNormalizedUpdate,
    ) -> InputSource | None:
        updates: dict[str, object] = {}
        for field_name in (
            "normalized_source_type",
            "normalized_package_json",
            "normalized_stats_json",
            "normalized_content_chars",
            "normalized_content_budget_chars",
            "normalized_pipeline_version",
        ):
            value = getattr(payload, field_name)
            if value is not None:
                updates[field_name] = value

        if payload.normalized_content_was_truncated is not None:
            updates["normalized_content_was_truncated"] = int(payload.normalized_content_was_truncated)

        if not updates:
            return self.get_input_source(input_source_id)

        set_clause = ", ".join([f"{key} = ?" for key in updates])
        params = list(updates.values()) + [input_source_id]

        with create_connection(self.sqlite_path) as connection:
            result = connection.execute(
                f"UPDATE input_sources SET {set_clause} WHERE id = ?",  # noqa: S608
                params,
            )
            if result.rowcount == 0:
                return None

        return self.get_input_source(input_source_id)

    def update_input_source_fetch(
        self,
        input_source_id: str,
        payload: InputSourceFetchUpdate,
    ) -> InputSource | None:
        updates: dict[str, object] = {}
        for field_name in (
            "fetch_final_url",
            "fetch_status_code",
            "fetch_content_type",
            "fetch_size_bytes",
            "fetch_error_code",
            "fetch_error_message",
            "raw_text",
            "normalized_text",
            "normalized_char_count",
            "normalization_version",
            "content_text",
        ):
            value = getattr(payload, field_name)
            if value is not None:
                updates[field_name] = value

        if not updates:
            return self.get_input_source(input_source_id)

        set_clause = ", ".join([f"{key} = ?" for key in updates])
        params = list(updates.values()) + [input_source_id]

        with create_connection(self.sqlite_path) as connection:
            result = connection.execute(
                f"UPDATE input_sources SET {set_clause} WHERE id = ?",  # noqa: S608
                params,
            )
            if result.rowcount == 0:
                return None

        return self.get_input_source(input_source_id)

    def update_input_source_text(self, input_source_id: str, payload: InputSourceTextUpdate) -> InputSource | None:
        updates: dict[str, object] = {}
        for field_name in (
            "raw_text",
            "normalized_text",
            "normalized_char_count",
            "normalization_version",
        ):
            value = getattr(payload, field_name)
            if value is not None:
                updates[field_name] = value

        if payload.was_truncated is not None:
            updates["was_truncated"] = int(payload.was_truncated)

        if not updates:
            return self.get_input_source(input_source_id)

        set_clause = ", ".join([f"{key} = ?" for key in updates])
        params = list(updates.values()) + [input_source_id]

        with create_connection(self.sqlite_path) as connection:
            result = connection.execute(
                f"UPDATE input_sources SET {set_clause} WHERE id = ?",  # noqa: S608
                params,
            )
            if result.rowcount == 0:
                return None

        return self.get_input_source(input_source_id)

    def get_input_source(self, input_source_id: str) -> InputSource | None:
        with create_connection(self.sqlite_path) as connection:
            row = connection.execute(
                "SELECT * FROM input_sources WHERE id = ?", (input_source_id,)
            ).fetchone()
        if row is None:
            return None
        return InputSource(
            id=row["id"],
            type=row["type"],
            original_name=row["original_name"],
            source_url=row["source_url"],
            fetch_final_url=row["fetch_final_url"],
            fetch_status_code=row["fetch_status_code"],
            fetch_content_type=row["fetch_content_type"],
            fetch_size_bytes=row["fetch_size_bytes"],
            fetch_error_code=row["fetch_error_code"],
            fetch_error_message=row["fetch_error_message"],
            content_text=row["content_text"],
            raw_text=row["raw_text"],
            normalized_text=row["normalized_text"],
            normalized_char_count=row["normalized_char_count"],
            was_truncated=(None if row["was_truncated"] is None else bool(row["was_truncated"])),
            normalization_version=row["normalization_version"],
            storage_path=row["storage_path"],
            metadata_json=row["metadata_json"],
            options_json=row["options_json"],
            mime_type=row["mime_type"],
            size_bytes=row["size_bytes"],
            sha256=row["sha256"],
            title=row["title"],
            case_id=row["case_id"],
            source_name=row["source_name"],
            stored_filename=row["stored_filename"],
            detected_mime_type=row["detected_mime_type"],
            file_class=row["file_class"],
            stix_json_kind=row["stix_json_kind"],
            stix_json_valid=(None if row["stix_json_valid"] is None else bool(row["stix_json_valid"])),
            stix_bundle_id=row["stix_bundle_id"],
            stix_spec_version=row["stix_spec_version"],
            stix_source_type=row["stix_source_type"],
            stix_object_count=row["stix_object_count"],
            stix_relationship_count=row["stix_relationship_count"],
            stix_attack_ref_count=row["stix_attack_ref_count"],
            stix_summary_json=row["stix_summary_json"],
            stix_entities_json=row["stix_entities_json"],
            stix_relationships_json=row["stix_relationships_json"],
            stix_attack_refs_json=row["stix_attack_refs_json"],
            stix_provenance_json=row["stix_provenance_json"],
            stix_parse_error_code=row["stix_parse_error_code"],
            stix_parse_error_message=row["stix_parse_error_message"],
            normalized_source_type=row["normalized_source_type"],
            normalized_package_json=row["normalized_package_json"],
            normalized_stats_json=row["normalized_stats_json"],
            normalized_content_chars=row["normalized_content_chars"],
            normalized_content_was_truncated=(
                None
                if row["normalized_content_was_truncated"] is None
                else bool(row["normalized_content_was_truncated"])
            ),
            normalized_content_budget_chars=row["normalized_content_budget_chars"],
            normalized_pipeline_version=row["normalized_pipeline_version"],
            ingestion_error_code=row["ingestion_error_code"],
            ingestion_error_message=row["ingestion_error_message"],
            created_at=_require_datetime(row["created_at"], "created_at"),
        )

    def create_artifact(self, payload: ArtifactCreate) -> Artifact:
        now = _utcnow_iso()
        with create_connection(self.sqlite_path) as connection:
            connection.execute(
                """
                INSERT INTO artifacts (
                    id, job_id, type, path, sha256, size_bytes, metadata_json,
                    validation_state, validation_errors_json, export_status,
                    error_code, error_message, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.id,
                    payload.job_id,
                    payload.type,
                    payload.path,
                    payload.sha256,
                    payload.size_bytes,
                    payload.metadata_json,
                    payload.validation_state,
                    payload.validation_errors_json,
                    payload.export_status,
                    payload.error_code,
                    payload.error_message,
                    now,
                ),
            )
        created = self.get_artifact_by_id(payload.id)
        if created is None:
            raise RuntimeError("Failed to create artifact")
        return created

    def update_artifact(self, artifact_id: str, payload: ArtifactUpdate) -> Artifact | None:
        updates: dict[str, object] = {}
        for field_name in (
            "path",
            "sha256",
            "size_bytes",
            "metadata_json",
            "validation_state",
            "validation_errors_json",
            "export_status",
            "error_code",
            "error_message",
        ):
            value = getattr(payload, field_name)
            if value is not None:
                updates[field_name] = value

        if not updates:
            return self.get_artifact_by_id(artifact_id)

        set_clause = ", ".join([f"{key} = ?" for key in updates])
        params = list(updates.values()) + [artifact_id]

        with create_connection(self.sqlite_path) as connection:
            result = connection.execute(
                f"UPDATE artifacts SET {set_clause} WHERE id = ?",  # noqa: S608
                params,
            )
            if result.rowcount == 0:
                return None

        return self.get_artifact_by_id(artifact_id)

    def get_artifact_by_id(self, artifact_id: str) -> Artifact | None:
        with create_connection(self.sqlite_path) as connection:
            row = connection.execute(
                "SELECT * FROM artifacts WHERE id = ?", (artifact_id,)
            ).fetchone()
        if row is None:
            return None
        return Artifact(
            id=row["id"],
            job_id=row["job_id"],
            type=row["type"],
            path=row["path"],
            sha256=row["sha256"],
            size_bytes=row["size_bytes"],
            metadata_json=row["metadata_json"],
            validation_state=row["validation_state"],
            validation_errors_json=row["validation_errors_json"],
            export_status=row["export_status"],
            error_code=row["error_code"],
            error_message=row["error_message"],
            created_at=_require_datetime(row["created_at"], "created_at"),
        )

    def list_artifacts(self, job_id: str | None = None, artifact_type: str | None = None) -> list[Artifact]:
        query = "SELECT * FROM artifacts"
        clauses: list[str] = []
        params: list[object] = []

        if job_id is not None:
            clauses.append("job_id = ?")
            params.append(job_id)
        if artifact_type is not None:
            clauses.append("type = ?")
            params.append(artifact_type)
        if clauses:
            query = f"{query} WHERE {' AND '.join(clauses)}"
        query = f"{query} ORDER BY created_at ASC"

        with create_connection(self.sqlite_path) as connection:
            rows = connection.execute(query, params).fetchall()

        return [
            Artifact(
                id=row["id"],
                job_id=row["job_id"],
                type=row["type"],
                path=row["path"],
                sha256=row["sha256"],
                size_bytes=row["size_bytes"],
                metadata_json=row["metadata_json"],
                validation_state=row["validation_state"],
                validation_errors_json=row["validation_errors_json"],
                export_status=row["export_status"],
                error_code=row["error_code"],
                error_message=row["error_message"],
                created_at=_require_datetime(row["created_at"], "created_at"),
            )
            for row in rows
        ]

    def create_audit_event(self, payload: AuditEventCreate) -> AuditEvent:
        with create_connection(self.sqlite_path) as connection:
            sequence = payload.sequence
            if sequence is None and payload.job_id is not None:
                row = connection.execute(
                    "SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence FROM audit_events WHERE job_id = ?",
                    (payload.job_id,),
                ).fetchone()
                sequence = int(row["next_sequence"]) if row is not None else 1

            timestamp = payload.timestamp or _utcnow()
            details_json = payload.details_json
            connection.execute(
                """
                INSERT INTO audit_events (
                    id, job_id, sequence, request_id, event_type, created_at,
                    status, stage, source_component, message, details_json, metadata_json, redacted
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.id,
                    payload.job_id,
                    sequence,
                    payload.request_id,
                    payload.event_type,
                    timestamp.isoformat().replace("+00:00", "Z"),
                    payload.status,
                    payload.stage,
                    payload.source_component,
                    payload.message,
                    details_json,
                    details_json,
                    int(payload.redacted) if payload.redacted is not None else None,
                ),
            )

        with create_connection(self.sqlite_path) as connection:
            row = connection.execute("SELECT * FROM audit_events WHERE id = ?", (payload.id,)).fetchone()

        if row is None:
            raise RuntimeError("Failed to create audit event")

        return AuditEvent(
            id=row["id"],
            job_id=row["job_id"],
            sequence=row["sequence"],
            request_id=row["request_id"],
            event_type=row["event_type"],
            timestamp=_require_datetime(row["created_at"], "created_at"),
            status=row["status"],
            stage=row["stage"],
            source_component=row["source_component"],
            message=row["message"],
            details_json=_audit_details_json(row),
            redacted=_row_to_bool(row["redacted"]),
        )

    def list_audit_events(self, job_id: str) -> list[AuditEvent]:
        with create_connection(self.sqlite_path) as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM audit_events
                WHERE job_id = ?
                ORDER BY CASE WHEN sequence IS NULL THEN 1 ELSE 0 END, sequence ASC, created_at ASC, id ASC
                """,
                (job_id,),
            ).fetchall()

        return [
            AuditEvent(
                id=row["id"],
                job_id=row["job_id"],
                sequence=row["sequence"],
                request_id=row["request_id"],
                event_type=row["event_type"],
                timestamp=_require_datetime(row["created_at"], "created_at"),
                status=row["status"],
                stage=row["stage"],
                source_component=row["source_component"],
                message=row["message"],
                details_json=_audit_details_json(row),
                redacted=_row_to_bool(row["redacted"]),
            )
            for row in rows
        ]

    def is_database_ready(self) -> bool:
        with create_connection(self.sqlite_path) as connection:
            row = connection.execute("SELECT 1 AS ready").fetchone()
        return bool(row is not None and row["ready"] == 1)

    def get_job_status_counts(self) -> dict[str, int]:
        with create_connection(self.sqlite_path) as connection:
            rows = connection.execute(
                "SELECT status, COUNT(*) AS count FROM jobs GROUP BY status"
            ).fetchall()

        counts: dict[str, int] = {}
        for row in rows:
            status = row["status"]
            if status is None:
                continue
            counts[str(status)] = int(row["count"])
        return counts

    def delete_artifacts_for_job(self, job_id: str) -> int:
        with create_connection(self.sqlite_path) as connection:
            result = connection.execute("DELETE FROM artifacts WHERE job_id = ?", (job_id,))
        return int(result.rowcount)

    def delete_audit_events_for_job(self, job_id: str) -> int:
        with create_connection(self.sqlite_path) as connection:
            result = connection.execute("DELETE FROM audit_events WHERE job_id = ?", (job_id,))
        return int(result.rowcount)

    def delete_job(self, job_id: str) -> bool:
        with create_connection(self.sqlite_path) as connection:
            result = connection.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
        return result.rowcount > 0

    def count_jobs_by_input_source(self, input_source_id: str) -> int:
        with create_connection(self.sqlite_path) as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM jobs WHERE input_source_id = ?",
                (input_source_id,),
            ).fetchone()
        if row is None:
            return 0
        return int(row["count"])

    def delete_input_source(self, input_source_id: str) -> bool:
        with create_connection(self.sqlite_path) as connection:
            result = connection.execute("DELETE FROM input_sources WHERE id = ?", (input_source_id,))
        return result.rowcount > 0
