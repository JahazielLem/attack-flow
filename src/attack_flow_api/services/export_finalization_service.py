from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Callable, Sequence

from pydantic import BaseModel

from attack_flow_api.services.afb_export_contracts import (
    AfbExportArtifactMetadata,
    AfbExportBundle,
)
from attack_flow_api.services.export_finalization_contracts import (
    ExportArtifactType,
    ExportFinalizationResult,
    ExportStatus,
    ExportValidationError,
)
from attack_flow_api.services.persistence_service import PersistenceService
from attack_flow_api.services.stix_export_contracts import (
    StixExportArtifactMetadata,
    StixExportBundle,
)
from attack_flow_api.storage.filesystem import LocalFileStorage


class ExportFinalizationService:
    def __init__(
        self,
        *,
        file_storage: LocalFileStorage,
        persistence_service: PersistenceService,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.file_storage = file_storage
        self.persistence_service = persistence_service
        self.clock = clock or (lambda: datetime.now(UTC))

    def finalize_stix_export(
        self,
        *,
        job_id: str,
        bundle: StixExportBundle,
    ) -> ExportFinalizationResult:
        return self._finalize_successful_export(
            job_id=job_id,
            artifact_type="stix",
            content_bytes=bundle.to_json_bytes(),
            extension="json",
            bundle_id=bundle.metadata.id,
            object_count=bundle.metadata.object_count,
            validation_errors=[self._coerce_validation_error(error) for error in bundle.validation_errors],
            metadata=StixExportArtifactMetadata(
                validation_state="valid",
                bundle_id=bundle.metadata.id,
                object_count=bundle.metadata.object_count,
                exported_at=self._now_iso(),
                export_status="completed",
                validation_errors=[],
            ),
        )

    def finalize_afb_export(
        self,
        *,
        job_id: str,
        bundle: AfbExportBundle,
    ) -> ExportFinalizationResult:
        validation_errors = [self._coerce_validation_error(error) for error in bundle.validation_errors]
        if validation_errors:
            return ExportFinalizationResult(
                artifact_type="afb",
                valid=False,
                validation_errors=validation_errors,
                checksum=None,
                size_bytes=None,
                created_at=self.clock(),
                export_status="failed",
                error_code="export_validation_failed",
                error_message="export validation failed",
            )

        diagram_export = bundle.to_diagram_export_ready()
        import json

        content_bytes = json.dumps(diagram_export, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self._finalize_successful_export(
            job_id=job_id,
            artifact_type="afb",
            content_bytes=content_bytes,
            extension="afb",
            bundle_id=bundle.metadata.bundle_id,
            object_count=len(diagram_export.get("objects", [])),
            validation_errors=[],
            metadata=AfbExportArtifactMetadata(
                validation_state="valid",
                bundle_id=bundle.metadata.bundle_id,
                object_count=len(diagram_export.get("objects", [])),
                exported_at=self._now_iso(),
                export_status="completed",
                validation_errors=[],
            ),
        )

    def finalize_export_failure(
        self,
        *,
        artifact_type: ExportArtifactType,
        error_code: str,
        error_message: str,
        validation_errors: Sequence[ExportValidationError | dict[str, object]] | None = None,
    ) -> ExportFinalizationResult:
        normalized_errors = [self._coerce_validation_error(error) for error in validation_errors or []]
        return ExportFinalizationResult(
            artifact_type=artifact_type,
            valid=False,
            validation_errors=normalized_errors,
            checksum=None,
            size_bytes=None,
            created_at=self.clock(),
            export_status="failed",
            error_code=error_code,
            error_message=error_message,
        )

    def _finalize_successful_export(
        self,
        *,
        job_id: str,
        artifact_type: ExportArtifactType,
        content_bytes: bytes,
        extension: str,
        bundle_id: str | None,
        object_count: int | None,
        validation_errors: list[ExportValidationError],
        metadata: StixExportArtifactMetadata | AfbExportArtifactMetadata,
    ) -> ExportFinalizationResult:
        created_at = self.clock()
        checksum = hashlib.sha256(content_bytes).hexdigest()
        size_bytes = len(content_bytes)
        if validation_errors:
            return ExportFinalizationResult(
                artifact_type=artifact_type,
                valid=False,
                validation_errors=validation_errors,
                checksum=checksum,
                size_bytes=size_bytes,
                created_at=created_at,
                export_status="failed",
                error_code="export_validation_failed",
                error_message="export validation failed",
            )

        stored_file = self.file_storage.write_artifact(content_bytes, extension=extension)
        if artifact_type == "stix":
            export_metadata = metadata.model_copy(
                update={
                    "validation_state": "valid",
                    "bundle_id": bundle_id,
                    "object_count": object_count,
                    "exported_at": created_at.isoformat().replace("+00:00", "Z"),
                    "export_status": "completed",
                    "error_code": None,
                    "error_message": None,
                    "validation_errors": [],
                }
            )
            self.persistence_service.create_stix_export_artifact(
                job_id=job_id,
                path=stored_file.relative_path,
                sha256=checksum,
                size_bytes=stored_file.size_bytes,
                metadata=export_metadata,
            )
        else:
            export_metadata = metadata.model_copy(
                update={
                    "validation_state": "valid",
                    "bundle_id": bundle_id,
                    "object_count": object_count,
                    "exported_at": created_at.isoformat().replace("+00:00", "Z"),
                    "export_status": "completed",
                    "error_code": None,
                    "error_message": None,
                    "validation_errors": [],
                }
            )
            self.persistence_service.create_afb_export_artifact(
                job_id=job_id,
                path=stored_file.relative_path,
                sha256=checksum,
                size_bytes=stored_file.size_bytes,
                metadata=export_metadata,
            )

        return ExportFinalizationResult(
            artifact_type=artifact_type,
            valid=True,
            validation_errors=[],
            checksum=checksum,
            size_bytes=size_bytes,
            created_at=created_at,
            export_status="completed",
        )

    def _coerce_validation_error(
        self, value: ExportValidationError | dict[str, object]
    ) -> ExportValidationError:
        if isinstance(value, ExportValidationError):
            return value
        if isinstance(value, BaseModel):
            return ExportValidationError.model_validate(value.model_dump(mode="json"))
        return ExportValidationError.model_validate(value)

    def _now_iso(self) -> str:
        return self.clock().isoformat().replace("+00:00", "Z")
