import re
import sqlite3
import stat
from pathlib import Path

import pytest

from attack_flow_api.config import ensure_runtime_directories
from attack_flow_api.storage.database import SCHEMA_VERSION, initialize_database
from attack_flow_api.storage.filesystem import LocalFileStorage
from attack_flow_api.storage.repositories import (
    ArtifactCreate,
    ArtifactUpdate,
    AuditEventCreate,
    InputSourceCreate,
    InputSourceFileUpdate,
    JobCreate,
    JobUpdate,
    PersistenceRepository,
)
from attack_flow_api.services.afb_export_contracts import AfbExportArtifactMetadata
from attack_flow_api.services.persistence_service import PersistenceService
from attack_flow_api.services.stix_export_contracts import StixExportArtifactMetadata


def test_database_initializes_and_creates_required_tables(tmp_path: Path):
    db_path = tmp_path / "db" / "attack-flow.db"

    initialize_database(db_path)

    assert db_path.exists()
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
        artifact_columns = connection.execute("PRAGMA table_info(artifacts)").fetchall()
    table_names = {row[0] for row in rows}
    assert "schema_migrations" in table_names
    assert "jobs" in table_names
    assert "input_sources" in table_names
    assert "artifacts" in table_names
    assert "audit_events" in table_names
    assert any(column[1] == "metadata_json" for column in artifact_columns)
    assert any(column[1] == "validation_state" for column in artifact_columns)
    assert any(column[1] == "export_status" for column in artifact_columns)


def test_initialize_database_can_be_called_twice(tmp_path: Path):
    db_path = tmp_path / "db" / "attack-flow.db"

    initialize_database(db_path)
    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        row = connection.execute("SELECT MAX(version) AS version FROM schema_migrations").fetchone()

    assert row is not None
    assert row[0] == SCHEMA_VERSION


def test_audit_events_can_be_created_and_listed_in_order(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    repository = PersistenceRepository(db_path)

    repository.create_job(JobCreate(id="job-1", status="queued", stage="created"))

    first = repository.create_audit_event(
        AuditEventCreate(
            id="audit-1",
            job_id="job-1",
            event_type="job.created",
            status="queued",
            stage="created",
            source_component="api",
            message="job created",
            details_json='{"job_id":"job-1"}',
        )
    )
    second = repository.create_audit_event(
        AuditEventCreate(
            id="audit-2",
            job_id="job-1",
            event_type="job.started",
            status="running",
            stage="processing",
            source_component="worker",
            message="job started",
            details_json='{"job_id":"job-1"}',
        )
    )

    assert first.sequence == 1
    assert second.sequence == 2

    events = repository.list_audit_events("job-1")
    assert [event.id for event in events] == ["audit-1", "audit-2"]
    assert events[0].details_json == '{"job_id":"job-1"}'
    assert events[0].timestamp is not None


def test_job_record_can_be_created_updated_and_fetched(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    repository = PersistenceRepository(db_path)

    input_source = repository.create_input_source(
        InputSourceCreate(id="input-1", type="text", title="Input")
    )

    created = repository.create_job(
        JobCreate(
            id="job-1",
            status="queued",
            stage="created",
            input_source_id=input_source.id,
            request_id="req-1",
        )
    )
    assert created.id == "job-1"
    assert created.status == "queued"
    assert created.stage == "created"

    updated = repository.update_job(
        "job-1", JobUpdate(status="running", stage="processing", provider_id="provider-a")
    )
    assert updated is not None
    assert updated.status == "running"
    assert updated.stage == "processing"
    assert updated.provider_id == "provider-a"

    fetched = repository.get_job("job-1")
    assert fetched is not None
    assert fetched.id == "job-1"
    assert fetched.status == "running"
    assert fetched.stage == "processing"


def test_create_job_enforces_foreign_keys(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    repository = PersistenceRepository(db_path)

    with pytest.raises(sqlite3.IntegrityError):
        repository.create_job(JobCreate(id="job-bad", status="queued", stage="created", input_source_id="missing-input"))


def test_artifact_metadata_can_be_created_and_retrieved(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    repository = PersistenceRepository(db_path)

    repository.create_job(JobCreate(id="job-1", status="queued", stage="created"))

    created_artifact = repository.create_artifact(
        ArtifactCreate(
            id="artifact-1",
            job_id="job-1",
            type="stix",
            path="artifacts/2026/01/01/abc123.json",
            size_bytes=128,
            validation_state="valid",
            validation_errors_json="[]",
            export_status="completed",
            error_code=None,
            error_message=None,
        )
    )
    assert created_artifact.id == "artifact-1"
    assert created_artifact.type == "stix"
    assert created_artifact.validation_state == "valid"
    assert created_artifact.export_status == "completed"

    fetched_by_id = repository.get_artifact_by_id("artifact-1")
    assert fetched_by_id is not None
    assert fetched_by_id.path == "artifacts/2026/01/01/abc123.json"
    assert fetched_by_id.validation_errors_json == "[]"

    fetched_list = repository.list_artifacts(job_id="job-1", artifact_type="stix")
    assert len(fetched_list) == 1
    assert fetched_list[0].id == "artifact-1"


def test_artifact_state_can_be_updated(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    repository = PersistenceRepository(db_path)

    repository.create_job(JobCreate(id="job-1", status="queued", stage="created"))
    repository.create_artifact(
        ArtifactCreate(
            id="artifact-1",
            job_id="job-1",
            type="afb",
            path="artifacts/2026/01/01/abc123.afb",
        )
    )

    updated = repository.update_artifact(
        "artifact-1",
        ArtifactUpdate(
            validation_state="invalid",
            validation_errors_json='[{"code":"x"}]',
            export_status="failed",
            error_code="artifact_invalid",
            error_message="artifact validation failed",
        ),
    )

    assert updated is not None
    assert updated.validation_state == "invalid"
    assert updated.validation_errors_json == '[{"code":"x"}]'
    assert updated.export_status == "failed"


def test_export_artifact_metadata_round_trips_artifact_state(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    service.create_job(JobCreate(id="job-3", status="queued", stage="created"))
    artifact = service.create_stix_export_artifact(
        job_id="job-3",
        path="artifacts/2026/01/01/export.json",
        size_bytes=256,
        metadata=StixExportArtifactMetadata(
            validation_state="valid",
            bundle_id="bundle--export-3",
            object_count=5,
            exported_at="2026-01-01T00:00:00Z",
            export_status="completed",
            validation_errors=[],
        ),
    )

    assert artifact.validation_state == "valid"
    assert artifact.export_status == "completed"
    assert artifact.validation_errors_json == "[]"


def test_artifact_creation_records_an_audit_event(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    service.create_job(JobCreate(id="job-1", status="queued", stage="created"))
    artifact = service.create_artifact(
        ArtifactCreate(
            id="artifact-1",
            job_id="job-1",
            type="stix",
            path="artifacts/2026/01/01/abc123.json",
            size_bytes=128,
        )
    )

    assert artifact.id == "artifact-1"

    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT event_type, message, details_json FROM audit_events WHERE job_id = ? ORDER BY sequence ASC",
            ("job-1",),
        ).fetchall()

    assert [row["event_type"] for row in rows] == ["artifact_created"]
    assert rows[0]["message"] == "artifact created"


def test_stix_export_artifact_metadata_round_trips(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    service.create_job(JobCreate(id="job-1", status="queued", stage="created"))
    artifact = service.create_stix_export_artifact(
        job_id="job-1",
        path="artifacts/2026/01/01/export.json",
        size_bytes=256,
        metadata=StixExportArtifactMetadata(
            validation_state="valid",
            bundle_id="bundle--export-1",
            object_count=5,
            exported_at="2026-01-01T00:00:00Z",
        ),
    )

    assert artifact.type == "stix"
    assert artifact.metadata_json is not None
    assert '"bundle_id":"bundle--export-1"' in artifact.metadata_json


def test_afb_export_artifact_metadata_round_trips(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    service.create_job(JobCreate(id="job-2", status="queued", stage="created"))
    artifact = service.create_afb_export_artifact(
        job_id="job-2",
        path="artifacts/2026/01/01/export.afb",
        size_bytes=256,
        metadata=AfbExportArtifactMetadata(
            validation_state="valid",
            bundle_id="bundle--export-2",
            object_count=5,
            exported_at="2026-01-01T00:00:00Z",
        ),
    )

    assert artifact.type == "afb"
    assert artifact.metadata_json is not None
    assert '"bundle_id":"bundle--export-2"' in artifact.metadata_json


def test_configured_directories_are_created(tmp_path: Path):
    data_dir = tmp_path / "data"
    upload_dir = data_dir / "uploads"
    artifact_dir = data_dir / "artifacts"
    sqlite_path = data_dir / "sqlite" / "attack-flow.db"

    runtime_paths = {
        "data_dir": data_dir,
        "upload_dir": upload_dir,
        "artifact_dir": artifact_dir,
        "sqlite_path": sqlite_path,
    }

    ensure_runtime_directories(runtime_paths)

    assert data_dir.is_dir()
    assert upload_dir.is_dir()
    assert artifact_dir.is_dir()
    assert sqlite_path.parent.is_dir()


def test_file_storage_uses_server_generated_names(tmp_path: Path):
    data_dir = tmp_path / "data"
    storage = LocalFileStorage(
        data_dir=data_dir,
        upload_dir=data_dir / "uploads",
        artifact_dir=data_dir / "artifacts",
    )

    stored = storage.write_upload(content=b"sample", extension="txt")

    assert stored.storage_type == "upload"
    assert stored.filename.endswith(".txt")
    assert re.fullmatch(r"[0-9a-f]{32}\.txt", stored.filename) is not None
    assert "client_filename" not in stored.filename
    assert stored.absolute_path.exists()
    assert stored.relative_path.startswith("uploads/")
    assert stat.S_IMODE(stored.absolute_path.stat().st_mode) == 0o600


def test_resolve_stored_path_rejects_path_traversal(tmp_path: Path):
    data_dir = tmp_path / "data"
    storage = LocalFileStorage(
        data_dir=data_dir,
        upload_dir=data_dir / "uploads",
        artifact_dir=data_dir / "artifacts",
    )

    with pytest.raises(ValueError):
        storage.resolve_stored_path("../../etc/passwd")


def test_delete_stored_file_returns_false_for_missing_file(tmp_path: Path):
    data_dir = tmp_path / "data"
    storage = LocalFileStorage(
        data_dir=data_dir,
        upload_dir=data_dir / "uploads",
        artifact_dir=data_dir / "artifacts",
    )

    assert storage.delete_stored_file("uploads/2026/01/01/missing.txt") is False


def test_delete_stored_file_rejects_directory_path(tmp_path: Path):
    data_dir = tmp_path / "data"
    storage = LocalFileStorage(
        data_dir=data_dir,
        upload_dir=data_dir / "uploads",
        artifact_dir=data_dir / "artifacts",
    )

    directory = data_dir / "uploads" / "2026" / "01" / "01"
    directory.mkdir(parents=True)

    with pytest.raises(ValueError, match="Refusing to delete directory path"):
        storage.delete_stored_file("uploads/2026/01/01")


def test_strict_mode_rejects_disallowed_extension(tmp_path: Path):
    data_dir = tmp_path / "data"
    storage = LocalFileStorage(
        data_dir=data_dir,
        upload_dir=data_dir / "uploads",
        artifact_dir=data_dir / "artifacts",
        strict_mode=True,
    )

    with pytest.raises(ValueError):
        storage.write_upload(content=b"x", extension="exe")


def test_non_strict_mode_maps_unknown_extension_to_bin(tmp_path: Path):
    data_dir = tmp_path / "data"
    storage = LocalFileStorage(
        data_dir=data_dir,
        upload_dir=data_dir / "uploads",
        artifact_dir=data_dir / "artifacts",
        strict_mode=False,
    )

    stored = storage.write_upload(content=b"x", extension="exe")
    assert stored.filename.endswith(".bin")


def test_storage_respects_max_file_size(tmp_path: Path):
    data_dir = tmp_path / "data"
    storage = LocalFileStorage(
        data_dir=data_dir,
        upload_dir=data_dir / "uploads",
        artifact_dir=data_dir / "artifacts",
        max_file_size_bytes=4,
    )

    with pytest.raises(ValueError):
        storage.write_upload(content=b"12345", extension="txt")


def test_strict_mode_rejects_symlinked_storage_chain(tmp_path: Path):
    data_dir = tmp_path / "data"
    storage = LocalFileStorage(
        data_dir=data_dir,
        upload_dir=data_dir / "uploads",
        artifact_dir=data_dir / "artifacts",
        strict_mode=True,
    )

    linked_dir = data_dir / "uploads" / "2026"
    target_dir = tmp_path / "linked-target"
    target_dir.mkdir(parents=True)
    linked_dir.symlink_to(target_dir, target_is_directory=True)

    with pytest.raises(ValueError, match="storage directory"):
        storage.write_upload(content=b"x", extension="txt")


def test_resolve_canonical_text_for_job_prefers_normalized_text(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    input_source = service.create_input_source(
        InputSourceCreate(
            id="input-1",
            type="text",
            raw_text="raw",
            content_text="content",
            normalized_text="normalized",
        )
    )
    service.create_job(
        JobCreate(
            id="job-1",
            status="queued",
            stage="queued",
            input_source_id=input_source.id,
        )
    )

    assert service.resolve_canonical_text_for_job("job-1") == "normalized"


def test_resolve_canonical_text_for_job_prefers_canonical_normalized_package(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    input_source = service.create_input_source(
        InputSourceCreate(
            id="input-2",
            type="text",
            raw_text="raw value",
            normalized_text="field normalized",
            normalized_package_json='{"source_type":"narrative_text","normalized_text":"package normalized"}',
        )
    )
    service.create_job(
        JobCreate(
            id="job-2",
            status="queued",
            stage="queued",
            input_source_id=input_source.id,
        )
    )

    assert service.resolve_canonical_text_for_job("job-2") == "package normalized"


def test_update_input_source_file_persists_plaintext_extraction_fields(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    created = service.create_input_source(
        InputSourceCreate(
            id="input-plain-1",
            type="file",
            original_name="notes.txt",
            storage_path="uploads/2026/01/01/abc123.txt",
            mime_type="text/plain",
            size_bytes=12,
        )
    )

    updated = service.update_input_source_file(
        created.id,
        InputSourceFileUpdate(
            raw_text="alpha  \r\n\r\n\r\nbeta\t\n",
            normalized_text="alpha\n\nbeta",
            normalized_char_count=len("alpha\n\nbeta"),
            normalization_version="v1",
            content_text="alpha\n\nbeta",
        ),
    )

    assert updated is not None
    assert updated.raw_text == "alpha  \r\n\r\n\r\nbeta\t\n"
    assert updated.normalized_text == "alpha\n\nbeta"
    assert updated.normalized_char_count == len("alpha\n\nbeta")
    assert updated.normalization_version == "v1"
    assert updated.content_text == "alpha\n\nbeta"


def test_update_input_source_file_persists_pdf_extraction_fields(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    created = service.create_input_source(
        InputSourceCreate(
            id="input-pdf-1",
            type="file",
            original_name="report.pdf",
            storage_path="uploads/2026/01/01/abc123.pdf",
            mime_type="application/pdf",
            size_bytes=321,
        )
    )

    updated = service.update_input_source_file(
        created.id,
        InputSourceFileUpdate(
            raw_text="Page One\r\n\r\n\r\nPage Two\n",
            normalized_text="Page One\n\nPage Two",
            normalized_char_count=len("Page One\n\nPage Two"),
            normalization_version="v1",
            content_text="Page One\n\nPage Two",
        ),
    )

    assert updated is not None
    assert updated.raw_text == "Page One\r\n\r\n\r\nPage Two\n"
    assert updated.normalized_text == "Page One\n\nPage Two"
    assert updated.normalized_char_count == len("Page One\n\nPage Two")
    assert updated.normalization_version == "v1"
    assert updated.content_text == "Page One\n\nPage Two"
