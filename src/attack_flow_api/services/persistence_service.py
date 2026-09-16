import hashlib
import json
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel

from attack_flow_api.audit.audit_redaction import sanitize_audit_details
from attack_flow_api.storage.models import Artifact, AuditEvent, InputSource, Job
from attack_flow_api.storage.repositories import (
    ArtifactCreate,
    ArtifactUpdate,
    AuditEventCreate,
    JobCanonicalFlowUpdate,
    InputSourceCreate,
    InputSourceFileUpdate,
    InputSourceFetchUpdate,
    InputSourceNormalizedUpdate,
    InputSourceStixUpdate,
    InputSourceTextUpdate,
    JobCreate,
    JobExtractionUpdate,
    JobFusionUpdate,
    JobUpdate,
    PersistenceRepository,
)
from attack_flow_api.services.afb_fusion_assembler import FusedOutputCandidate
from attack_flow_api.services.afb_export_contracts import AfbExportArtifactMetadata
from attack_flow_api.services.canonical_flow_contracts import CanonicalFlowOutput
from attack_flow_api.services.stix_export_contracts import StixExportArtifactMetadata


class PersistenceService:
    def __init__(self, sqlite_path: Path):
        self.repository = PersistenceRepository(sqlite_path)

    def create_job(self, payload: JobCreate) -> Job:
        return self.repository.create_job(payload)

    def update_job(self, job_id: str, payload: JobUpdate) -> Job | None:
        return self.repository.update_job(job_id, payload)

    def get_job(self, job_id: str) -> Job | None:
        return self.repository.get_job(job_id)

    def create_input_source(self, payload: InputSourceCreate) -> InputSource:
        return self.repository.create_input_source(payload)

    def get_input_source(self, input_source_id: str) -> InputSource | None:
        return self.repository.get_input_source(input_source_id)

    def resolve_canonical_text_for_job(self, job_id: str) -> str | None:
        normalized_package = self.resolve_normalized_package_for_job(job_id)
        if normalized_package is not None:
            normalized_text = normalized_package.get("normalized_text")
            if isinstance(normalized_text, str):
                return normalized_text

        input_source = self._resolve_input_source_for_job(job_id)
        return self.resolve_canonical_text_for_input_source(input_source)

    def resolve_canonical_text_for_input_source(self, input_source: InputSource | None) -> str | None:
        if input_source is None:
            return None
        if input_source.type not in {"text", "url"}:
            return None

        if input_source.normalized_text is not None:
            return input_source.normalized_text
        if input_source.content_text is not None:
            return input_source.content_text
        return input_source.raw_text

    def resolve_normalized_package_for_job(self, job_id: str) -> dict[str, object] | None:
        input_source = self._resolve_input_source_for_job(job_id)
        return self.resolve_normalized_package_for_input_source(input_source)

    def resolve_normalized_package_for_input_source(
        self, input_source: InputSource | None
    ) -> dict[str, object] | None:
        if input_source is None or input_source.normalized_package_json is None:
            return None
        try:
            parsed = json.loads(input_source.normalized_package_json)
        except json.JSONDecodeError:
            return None
        if not isinstance(parsed, dict):
            return None
        return parsed

    def _resolve_input_source_for_job(self, job_id: str) -> InputSource | None:
        job = self.get_job(job_id)
        if job is None or job.input_source_id is None:
            return None
        return self.get_input_source(job.input_source_id)

    def update_input_source_text(
        self, input_source_id: str, payload: InputSourceTextUpdate
    ) -> InputSource | None:
        return self.repository.update_input_source_text(input_source_id, payload)

    def update_input_source_fetch(
        self,
        input_source_id: str,
        payload: InputSourceFetchUpdate,
    ) -> InputSource | None:
        return self.repository.update_input_source_fetch(input_source_id, payload)

    def update_input_source_file(
        self,
        input_source_id: str,
        payload: InputSourceFileUpdate,
    ) -> InputSource | None:
        return self.repository.update_input_source_file(input_source_id, payload)

    def update_input_source_stix(
        self,
        input_source_id: str,
        payload: InputSourceStixUpdate,
    ) -> InputSource | None:
        return self.repository.update_input_source_stix(input_source_id, payload)

    def update_input_source_normalized(
        self,
        input_source_id: str,
        payload: InputSourceNormalizedUpdate,
    ) -> InputSource | None:
        return self.repository.update_input_source_normalized(input_source_id, payload)

    def create_artifact(self, payload: ArtifactCreate) -> Artifact:
        artifact = self.repository.create_artifact(payload)
        job = self.get_job(payload.job_id)
        if job is not None:
            self.record_job_event(
                job=job,
                event_type="artifact_created",
                source_component="storage",
                message="artifact created",
                details={
                    "artifact_id": artifact.id,
                    "artifact_type": artifact.type,
                    "path": artifact.path,
                    "size_bytes": artifact.size_bytes,
                },
        )
        return artifact

    def update_artifact(self, artifact_id: str, payload: ArtifactUpdate) -> Artifact | None:
        return self.repository.update_artifact(artifact_id, payload)

    def create_stix_export_artifact(
        self,
        *,
        job_id: str,
        path: str,
        size_bytes: int | None = None,
        sha256: str | None = None,
        metadata: StixExportArtifactMetadata | None = None,
    ) -> Artifact:
        return self._create_export_artifact(
            job_id=job_id,
            artifact_type="stix",
            path=path,
            sha256=sha256,
            size_bytes=size_bytes,
            metadata_json=(metadata.model_dump_json() if metadata is not None else None),
            validation_state=(metadata.validation_state if metadata is not None else None),
            validation_errors_json=(
                json.dumps(metadata.validation_errors, sort_keys=True, separators=(",", ":"))
                if metadata is not None
                else None
            ),
            export_status=(metadata.export_status if metadata is not None else None),
            error_code=(metadata.error_code if metadata is not None else None),
            error_message=(metadata.error_message if metadata is not None else None),
        )

    def create_afb_export_artifact(
        self,
        *,
        job_id: str,
        path: str,
        size_bytes: int | None = None,
        sha256: str | None = None,
        metadata: AfbExportArtifactMetadata | None = None,
    ) -> Artifact:
        return self._create_export_artifact(
            job_id=job_id,
            artifact_type="afb",
            path=path,
            sha256=sha256,
            size_bytes=size_bytes,
            metadata_json=(metadata.model_dump_json() if metadata is not None else None),
            validation_state=(metadata.validation_state if metadata is not None else None),
            validation_errors_json=(
                json.dumps(metadata.validation_errors, sort_keys=True, separators=(",", ":"))
                if metadata is not None
                else None
            ),
            export_status=(metadata.export_status if metadata is not None else None),
            error_code=(metadata.error_code if metadata is not None else None),
            error_message=(metadata.error_message if metadata is not None else None),
        )

    def record_stix_export_completed(
        self,
        *,
        job: Job,
        artifact: Artifact,
        bundle_id: str,
        object_count: int,
        exported_at: str,
    ) -> AuditEvent | None:
        return self._record_export_event(
            job=job,
            event_type="stix_export_completed",
            message="stix export completed",
            artifact=artifact,
            bundle_id=bundle_id,
            object_count=object_count,
            exported_at=exported_at,
        )

    def record_stix_export_failed(
        self,
        *,
        job: Job,
        bundle_id: str | None,
        object_count: int | None,
        validation_errors: list[dict[str, object]],
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> AuditEvent | None:
        return self._record_export_event(
            job=job,
            event_type="stix_export_failed",
            message="stix export validation failed",
            bundle_id=bundle_id,
            object_count=object_count,
            validation_errors=validation_errors,
            error_code=error_code,
            error_message=error_message,
        )

    def record_afb_export_completed(
        self,
        *,
        job: Job,
        artifact: Artifact,
        bundle_id: str,
        object_count: int,
        exported_at: str,
        schema_version: str | None = None,
    ) -> AuditEvent | None:
        return self._record_export_event(
            job=job,
            event_type="afb_export_completed",
            message="afb export completed",
            artifact=artifact,
            bundle_id=bundle_id,
            object_count=object_count,
            exported_at=exported_at,
            schema_version=schema_version,
        )

    def record_afb_export_failed(
        self,
        *,
        job: Job,
        bundle_id: str | None,
        object_count: int | None,
        validation_errors: list[dict[str, object]],
        schema_version: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> AuditEvent | None:
        return self._record_export_event(
            job=job,
            event_type="afb_export_failed",
            message="afb export validation failed",
            bundle_id=bundle_id,
            object_count=object_count,
            validation_errors=validation_errors,
            schema_version=schema_version,
            error_code=error_code,
            error_message=error_message,
        )

    def _create_export_artifact(
        self,
        *,
        job_id: str,
        artifact_type: str,
        path: str,
        sha256: str | None,
        size_bytes: int | None,
        metadata_json: str | None,
        validation_state: str | None = None,
        validation_errors_json: str | None = None,
        export_status: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> Artifact:
        return self.create_artifact(
            ArtifactCreate(
                id=str(uuid4()),
                job_id=job_id,
                type=artifact_type,
                path=path,
                sha256=sha256,
                size_bytes=size_bytes,
                metadata_json=metadata_json,
                validation_state=validation_state,
                validation_errors_json=validation_errors_json,
                export_status=export_status,
                error_code=error_code,
                error_message=error_message,
            )
        )

    def _record_export_event(
        self,
        *,
        job: Job,
        event_type: str,
        message: str,
        bundle_id: str | None,
        object_count: int | None,
        validation_errors: list[dict[str, object]] | None = None,
        artifact: Artifact | None = None,
        exported_at: str | None = None,
        schema_version: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> AuditEvent | None:
        details: dict[str, object] = {
            "bundle_id": bundle_id,
            "object_count": object_count,
        }
        if validation_errors is not None:
            details["validation_errors"] = validation_errors
            details["validation_error_count"] = len(validation_errors)
        if artifact is None and (validation_errors is not None or error_code is not None or error_message is not None):
            details["artifact_valid"] = False
            details["export_status"] = "failed"
            details["validation_state"] = "invalid"
        if artifact is not None:
            validation_error_count = self._artifact_validation_error_count(artifact)
            details.update(
                {
                    "artifact_id": artifact.id,
                    "artifact_type": artifact.type,
                    "path": artifact.path,
                    "artifact_valid": artifact.validation_state == "valid"
                    and artifact.export_status == "completed",
                    "validation_state": artifact.validation_state,
                    "export_status": artifact.export_status,
                    "checksum": artifact.sha256,
                    "size_bytes": artifact.size_bytes,
                    "validation_error_count": validation_error_count,
                    "error_code": artifact.error_code,
                    "error_message": artifact.error_message,
                }
            )
        if exported_at is not None:
            details["exported_at"] = exported_at
        if schema_version is not None:
            details["schema_version"] = schema_version
        if error_code is not None:
            details["error_code"] = error_code
        if error_message is not None:
            details["error_message"] = error_message
        return self.record_job_event(
            job=job,
            event_type=event_type,
            message=message,
            details=details,
        )

    def _artifact_validation_error_count(self, artifact: Artifact) -> int | None:
        if artifact.validation_errors_json is not None:
            return self._validation_error_count_json(artifact.validation_errors_json)
        if artifact.metadata_json is None:
            return None
        try:
            parsed = json.loads(artifact.metadata_json)
        except json.JSONDecodeError:
            return None
        if isinstance(parsed, dict):
            validation_errors = parsed.get("validation_errors")
            if isinstance(validation_errors, list):
                return len(validation_errors)
        return None

    def _validation_error_count_json(self, validation_errors_json: str) -> int | None:
        try:
            parsed = json.loads(validation_errors_json)
        except json.JSONDecodeError:
            return None
        if isinstance(parsed, list):
            return len(parsed)
        return None

    def get_artifact_by_id(self, artifact_id: str) -> Artifact | None:
        return self.repository.get_artifact_by_id(artifact_id)

    def list_artifacts(
        self, job_id: str | None = None, artifact_type: str | None = None
    ) -> list[Artifact]:
        return self.repository.list_artifacts(job_id=job_id, artifact_type=artifact_type)

    def create_audit_event(self, payload: AuditEventCreate) -> AuditEvent:
        return self.repository.create_audit_event(payload)

    def record_job_event(
        self,
        *,
        job: Job,
        event_type: str,
        message: str,
        details: dict[str, object],
        status: str | None = None,
        stage: str | None = None,
        request_id: str | None = None,
        source_component: str = "worker",
        redacted: bool = False,
    ) -> AuditEvent | None:
        return self._record_job_event(
            job=job,
            event_type=event_type,
            status=status if status is not None else job.status,
            stage=stage if stage is not None else job.stage,
            request_id=request_id if request_id is not None else job.request_id,
            source_component=source_component,
            message=message,
            details=details,
            redacted=redacted,
        )

    def record_job_submitted(
        self,
        *,
        job: Job,
        input_source_id: str,
        source_type: str,
        request_id: str | None,
    ) -> AuditEvent | None:
        return self.record_job_event(
            job=job,
            event_type="job_submitted",
            request_id=request_id,
            source_component="api",
            message="job submitted",
            details={"input_source_id": input_source_id, "source_type": source_type},
        )

    def record_job_queued(self, *, job: Job, request_id: str | None) -> AuditEvent | None:
        return self.record_job_event(
            job=job,
            event_type="job_queued",
            request_id=request_id,
            source_component="api",
            message="job queued",
            details={"job_id": job.id},
        )

    def record_worker_claimed(self, *, job: Job, worker_id: str) -> AuditEvent | None:
        return self.record_job_event(
            job=job,
            event_type="worker_claimed",
            request_id=job.request_id,
            source_component="worker",
            message="worker claimed job",
            details={"worker_id": worker_id},
        )

    def record_stage_changed(
        self,
        *,
        previous_job: Job,
        current_job: Job,
        worker_id: str | None = None,
    ) -> AuditEvent | None:
        if previous_job.status == current_job.status and previous_job.stage == current_job.stage:
            return None

        details: dict[str, object] = {
            "previous_status": previous_job.status,
            "previous_stage": previous_job.stage,
            "current_status": current_job.status,
            "current_stage": current_job.stage,
        }
        if worker_id is not None:
            details["worker_id"] = worker_id

        return self.record_job_event(
            job=current_job,
            event_type="stage_changed",
            source_component="worker",
            message=f"job stage changed to {current_job.stage}",
            details=details,
        )

    def list_audit_events(self, job_id: str) -> list[AuditEvent]:
        return self.repository.list_audit_events(job_id)

    def is_database_ready(self) -> bool:
        return self.repository.is_database_ready()

    def get_job_status_counts(self) -> dict[str, int]:
        return self.repository.get_job_status_counts()

    def delete_artifacts_for_job(self, job_id: str) -> int:
        return self.repository.delete_artifacts_for_job(job_id)

    def delete_audit_events_for_job(self, job_id: str) -> int:
        return self.repository.delete_audit_events_for_job(job_id)

    def delete_job(self, job_id: str) -> bool:
        return self.repository.delete_job(job_id)

    def count_jobs_by_input_source(self, input_source_id: str) -> int:
        return self.repository.count_jobs_by_input_source(input_source_id)

    def delete_input_source(self, input_source_id: str) -> bool:
        return self.repository.delete_input_source(input_source_id)

    def claim_next_queued_job(self, worker_id: str) -> Job | None:
        job = self.repository.claim_next_queued_job(worker_id)
        if job is None:
            return None
        self.record_worker_claimed(job=job, worker_id=worker_id)
        return job

    def update_job_lifecycle(
        self,
        job_id: str,
        *,
        status: str,
        stage: str,
        progress_percent: int | None = None,
        worker_id: str | None = None,
    ) -> Job | None:
        previous_job = self.repository.get_job(job_id)
        updated_job = self.repository.update_job_lifecycle(
            job_id,
            status=status,
            stage=stage,
            progress_percent=progress_percent,
            worker_id=worker_id,
        )
        if previous_job is not None and updated_job is not None:
            self.record_stage_changed(previous_job=previous_job, current_job=updated_job, worker_id=worker_id)
        return updated_job

    def update_job_extraction(self, job_id: str, payload: JobExtractionUpdate) -> Job | None:
        return self.repository.update_job_extraction(job_id, payload)

    def update_job_fusion(self, job_id: str, payload: JobFusionUpdate) -> Job | None:
        return self.repository.update_job_fusion(job_id, payload)

    def update_job_canonical_flow(self, job_id: str, payload: JobCanonicalFlowUpdate) -> Job | None:
        return self.repository.update_job_canonical_flow(job_id, payload)

    def persist_fused_output_candidate(self, job_id: str, payload: FusedOutputCandidate) -> Job | None:
        updated_job = self.update_job_fusion(
            job_id,
            JobFusionUpdate(
                fusion_result_json=payload.model_dump_json(),
                fusion_validation_state=payload.fusion_validation_state,
                fusion_provenance_json=_json_dumps(payload.provenance),
                fusion_conflicts_json=_json_dumps_model_list(payload.conflicts),
                fusion_attack_refs_json=_json_dumps_model_list(payload.attack_refs),
                fusion_entities_json=_json_dumps_model_list(payload.entities),
                fusion_relationships_json=_json_dumps_model_list(payload.relationships),
            ),
        )
        if updated_job is not None:
            self.record_job_event(
                job=updated_job,
                event_type="fusion_completed",
                message="fusion completed",
                details={
                    "fusion_validation_state": payload.fusion_validation_state,
                    "attack_ref_count": len(payload.attack_refs),
                    "entity_count": len(payload.entities),
                    "relationship_count": len(payload.relationships),
                    "attack_action_count": len(payload.attack_actions),
                    "attack_condition_count": len(payload.attack_conditions),
                    "attack_operator_count": len(payload.attack_operators),
                },
            )
        return updated_job

    def persist_canonical_flow_output(self, job_id: str, payload: CanonicalFlowOutput) -> Job | None:
        updated_job = self.update_job_canonical_flow(
            job_id,
            JobCanonicalFlowUpdate(
                canonical_flow_json=payload.model_dump_json(),
                canonical_flow_validation_state=payload.validation_state,
                canonical_flow_provenance_json=_json_dumps(payload.provenance),
                canonical_flow_conflicts_json=_json_dumps_model_list(payload.conflicts),
                canonical_flow_validation_errors_json=_json_dumps_model_list(payload.validation_errors),
            ),
        )
        if updated_job is not None:
            self.record_job_event(
                job=updated_job,
                event_type="canonical_flow_created",
                message="canonical flow created",
                details={
                    "validation_state": payload.validation_state,
                    "node_count": len(payload.nodes),
                    "edge_count": len(payload.edges),
                    "attack_ref_count": len(payload.attack_refs),
                    "validation_error_count": len(payload.validation_errors),
                },
            )
        return updated_job

    def mark_job_completed(self, job_id: str) -> Job | None:
        job = self.repository.mark_job_completed(job_id)
        if job is not None:
            self.record_job_event(
                job=job,
                event_type="job_completed",
                source_component="worker",
                message="job completed",
                details={
                    "completed_at": job.completed_at.isoformat().replace("+00:00", "Z") if job.completed_at else None,
                    "progress_percent": job.progress_percent,
                },
            )
        return job

    def mark_job_failed(self, job_id: str, error_code: str, error_message: str) -> Job | None:
        job = self.repository.mark_job_failed(job_id, error_code=error_code, error_message=error_message)
        if job is not None:
            self.record_job_event(
                job=job,
                event_type="job_failed",
                source_component="worker",
                message="job failed",
                details={"error_code": error_code, "error_message": error_message},
            )
        return job

    def _record_job_event(
        self,
        *,
        job: Job,
        event_type: str,
        status: str | None,
        stage: str | None,
        request_id: str | None,
        source_component: str,
        message: str,
        details: dict[str, object],
        redacted: bool,
    ) -> AuditEvent:
        sanitized_details, details_redacted = sanitize_audit_details(details)
        details_json = _json_dumps_sorted(sanitized_details)
        fingerprint = hashlib.sha256(
            _json_dumps_sorted(
                {
                    "job_id": job.id,
                    "event_type": event_type,
                    "status": status,
                    "stage": stage,
                    "request_id": request_id,
                    "source_component": source_component,
                    "message": message,
                    "details": sanitized_details,
                }
            ).encode("utf-8")
        ).hexdigest()

        try:
            return self.create_audit_event(
                AuditEventCreate(
                    id=f"audit-{fingerprint}",
                    job_id=job.id,
                    event_type=event_type,
                    status=status,
                    stage=stage,
                    request_id=request_id,
                    source_component=source_component,
                    message=message,
                    details_json=details_json,
                    redacted=redacted or details_redacted,
                )
            )
        except Exception:
            return None


def _json_dumps(payload: object) -> str:
    return json.dumps(payload)


def _json_dumps_model_list(items: list[BaseModel]) -> str:
    return json.dumps([item.model_dump(mode="json") for item in items])


def _json_dumps_sorted(payload: dict[str, object]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))
