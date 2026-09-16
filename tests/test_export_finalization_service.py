from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from attack_flow_api.services.afb_export_contracts import (
    AfbExportBundle,
    AfbExportBundleMetadata,
    AfbExportCompatibilityError,
)
from attack_flow_api.services.export_finalization_service import ExportFinalizationService
from attack_flow_api.services.persistence_service import PersistenceService
from attack_flow_api.services.stix_export_contracts import StixExportBundle, StixExportBundleMetadata
from attack_flow_api.storage.database import initialize_database
from attack_flow_api.storage.filesystem import StoredFile
from attack_flow_api.storage.repositories import JobCreate


@dataclass
class FakeFileStorage:
    calls: list[tuple[bytes, str | None]]

    def write_artifact(self, content: bytes, extension: str | None = None) -> StoredFile:
        self.calls.append((content, extension))
        return StoredFile(
            storage_type="artifact",
            filename=f"artifact.{extension or 'bin'}",
            relative_path=f"artifacts/2026/01/01/artifact.{extension or 'bin'}",
            absolute_path=Path("/tmp/artifact"),
            size_bytes=len(content),
        )


def test_finalizes_valid_stix_export_and_persists_artifact(tmp_path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    persistence = PersistenceService(db_path)
    persistence.create_job(JobCreate(id="job-1", status="queued", stage="created"))

    storage = FakeFileStorage(calls=[])
    service = ExportFinalizationService(
        file_storage=storage,
        persistence_service=persistence,
        clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
    )
    bundle = StixExportBundle(metadata=StixExportBundleMetadata(id="bundle--1"))

    result = service.finalize_stix_export(job_id="job-1", bundle=bundle)

    assert result.valid is True
    assert result.export_status == "completed"
    assert result.checksum is not None
    assert result.size_bytes == len(bundle.to_json_bytes())
    assert len(storage.calls) == 1
    assert persistence.list_artifacts(job_id="job-1", artifact_type="stix")


def test_invalid_afb_export_is_not_persisted(tmp_path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    persistence = PersistenceService(db_path)
    persistence.create_job(JobCreate(id="job-1", status="queued", stage="created"))

    storage = FakeFileStorage(calls=[])
    service = ExportFinalizationService(
        file_storage=storage,
        persistence_service=persistence,
        clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
    )
    bundle = AfbExportBundle(metadata=AfbExportBundleMetadata(bundle_id="bundle--2"))
    bundle.validation_errors = [
        AfbExportCompatibilityError(code="invalid", message="invalid bundle", details={})
    ]

    result = service.finalize_afb_export(job_id="job-1", bundle=bundle)

    assert result.valid is False
    assert result.export_status == "failed"
    assert len(storage.calls) == 0
    assert persistence.list_artifacts(job_id="job-1", artifact_type="afb") == []


def test_failed_export_is_reported_without_persisting(tmp_path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    persistence = PersistenceService(db_path)
    storage = FakeFileStorage(calls=[])
    service = ExportFinalizationService(
        file_storage=storage,
        persistence_service=persistence,
        clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
    )

    result = service.finalize_export_failure(
        artifact_type="stix",
        error_code="export_crashed",
        error_message="exporter crashed",
    )

    assert result.valid is False
    assert result.export_status == "failed"
    assert result.error_code == "export_crashed"
    assert len(storage.calls) == 0
