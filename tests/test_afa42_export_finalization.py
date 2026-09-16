from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from attack_flow_api.config import ProviderConfig
from attack_flow_api.main import create_app
import attack_flow_api.services.job_worker_service as job_worker_service
from attack_flow_api.providers.registry import ProviderRegistry
from attack_flow_api.services.afb_export_contracts import (
    AfbExportArtifactMetadata,
    AfbExportBundle,
    AfbExportBundleMetadata,
    AfbExportCompatibilityError,
)
from attack_flow_api.services.canonical_flow_contracts import (
    CanonicalFlowActionNode,
    CanonicalFlowAssetNode,
    CanonicalFlowMetadata,
    CanonicalFlowOutput,
)
from attack_flow_api.services.export_finalization_contracts import ExportValidationError
from attack_flow_api.services.export_finalization_service import ExportFinalizationService
from attack_flow_api.services.persistence_service import PersistenceService
from attack_flow_api.services.stix_export_contracts import (
    StixExportArtifactMetadata,
    StixExportBundle,
    StixExportBundleMetadata,
    StixExportValidationError,
)
from attack_flow_api.storage.database import initialize_database
from attack_flow_api.storage.filesystem import LocalFileStorage, StoredFile
from attack_flow_api.storage.repositories import ArtifactCreate, InputSourceCreate, JobCreate


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


def _make_service(tmp_path: Path) -> tuple[PersistenceService, FakeFileStorage, ExportFinalizationService]:
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
    return persistence, storage, service


def _make_client(monkeypatch, tmp_path: Path) -> TestClient:
    data_dir = tmp_path / "data"
    providers_path = tmp_path / "providers.yml"
    providers_path.write_text(
        """
providers:
  - provider_id: default-openai
    provider_type: openai
    enabled: true
    base_url: https://api.openai.com/v1
    api_key_env: OPENAI_API_KEY
    default_model: gpt-4.1-mini
    allowed_models:
      - gpt-4.1-mini
""".strip()
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("APP_NAME", "attack-flow-api")
    monkeypatch.setenv("API_PREFIX", "/api/v1")
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("SQLITE_PATH", str(data_dir / "attack-flow.db"))
    monkeypatch.setenv("UPLOAD_DIR", str(data_dir / "uploads"))
    monkeypatch.setenv("ARTIFACT_DIR", str(data_dir / "artifacts"))
    monkeypatch.setenv("PROVIDERS_CONFIG_PATH", str(providers_path))

    original_build_adapter = ProviderRegistry._build_adapter

    def _build_adapter(self, provider: ProviderConfig):
        if provider.provider_type == "openai":
            return _FakeOpenAIAdapter(provider.provider_id, provider.provider_type)
        return original_build_adapter(self, provider)

    monkeypatch.setattr(ProviderRegistry, "_build_adapter", _build_adapter)

    return TestClient(create_app())


class _FakeOpenAIAdapter:
    def __init__(self, provider_id: str, provider_type: str):
        self._provider_id = provider_id
        self._provider_type = provider_type

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def provider_type(self) -> str:
        return self._provider_type

    def generate_structured(self, request):
        return type(
            "_Result",
            (),
            {
                "provider_id": request.provider_id,
                "provider_type": request.provider_type,
                "model": request.model,
                "output_json": {
                    "validation_state": "valid",
                    "repair_attempted": False,
                    "provider_invoked": True,
                    "provider_id": request.provider_id,
                    "model": request.model,
                    "attack_flow": {
                        "id": "attack-flow--fake",
                        "name": "Fake extraction",
                        "scope": "incident",
                        "orchestration_mode": "ai_enrichment",
                        "source_classification": "document_extracted_text",
                        "authors": [],
                        "external_references": [],
                        "provenance": {},
                    },
                    "attack_actions": [],
                    "attack_conditions": [],
                    "attack_operators": [],
                    "attack_assets": [],
                    "deterministic_attack_refs": [],
                    "deterministic_entities": [],
                    "deterministic_relationships": [],
                },
                "output_text": None,
            },
        )()


def _valid_canonical_flow() -> CanonicalFlowOutput:
    return CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--export",
            name="Example flow",
            scope="incident",
            start_refs=["attack-action--1"],
        ),
        nodes=[
            CanonicalFlowActionNode(
                id="attack-action--1",
                name="Example step",
                description="Observed command exactly as reported.",
                asset_refs=["attack-asset--1"],
            ),
            CanonicalFlowAssetNode(
                id="attack-asset--1",
                name="Host asset",
                object_ref="malware--1",
            ),
        ],
        edges=[],
        provenance={"source": "fused"},
        conflicts=[],
        validation_errors=[],
    )


def test_valid_stix_export_finalization_persists_artifact_metadata_correctly(tmp_path: Path):
    persistence, storage, service = _make_service(tmp_path)

    bundle = StixExportBundle(metadata=StixExportBundleMetadata(id="bundle--stix"))
    result = service.finalize_stix_export(job_id="job-1", bundle=bundle)

    artifacts = persistence.list_artifacts(job_id="job-1", artifact_type="stix")
    assert len(artifacts) == 1
    artifact = artifacts[0]

    expected_bytes = bundle.to_json_bytes()
    assert result.valid is True
    assert result.artifact_type == "stix"
    assert result.export_status == "completed"
    assert result.checksum == hashlib.sha256(expected_bytes).hexdigest()
    assert result.size_bytes == len(expected_bytes)
    assert result.created_at == datetime(2026, 1, 1, tzinfo=UTC)

    assert artifact.type == "stix"
    assert artifact.path == "artifacts/2026/01/01/artifact.json"
    assert artifact.size_bytes == len(expected_bytes)
    assert artifact.sha256 == result.checksum
    assert artifact.created_at is not None
    assert artifact.validation_state == "valid"
    assert artifact.export_status == "completed"
    metadata = json.loads(artifact.metadata_json or "{}")
    assert metadata["validation_state"] == "valid"
    assert metadata["export_status"] == "completed"
    assert metadata["bundle_id"] == "bundle--stix"
    assert metadata["validation_errors"] == []
    assert len(storage.calls) == 1


def test_valid_afb_export_finalization_persists_artifact_metadata_correctly(tmp_path: Path):
    persistence, storage, service = _make_service(tmp_path)

    bundle = AfbExportBundle(metadata=AfbExportBundleMetadata(bundle_id="bundle--afb"))
    result = service.finalize_afb_export(job_id="job-1", bundle=bundle)

    artifacts = persistence.list_artifacts(job_id="job-1", artifact_type="afb")
    assert len(artifacts) == 1
    artifact = artifacts[0]

    expected_bytes = bundle.to_diagram_export_bytes()
    assert result.valid is True
    assert result.artifact_type == "afb"
    assert result.export_status == "completed"
    assert result.checksum == hashlib.sha256(expected_bytes).hexdigest()
    assert result.size_bytes == len(expected_bytes)
    assert result.created_at == datetime(2026, 1, 1, tzinfo=UTC)

    assert artifact.type == "afb"
    assert artifact.path == "artifacts/2026/01/01/artifact.afb"
    assert artifact.size_bytes == len(expected_bytes)
    assert artifact.sha256 == result.checksum
    assert artifact.created_at is not None
    assert artifact.validation_state == "valid"
    assert artifact.export_status == "completed"
    metadata = json.loads(artifact.metadata_json or "{}")
    assert metadata["validation_state"] == "valid"
    assert metadata["export_status"] == "completed"
    assert metadata["bundle_id"] == "bundle--afb"
    assert metadata["validation_errors"] == []
    assert len(storage.calls) == 1


def test_invalid_stix_export_is_not_exposed_as_successful_artifact(tmp_path: Path):
    persistence, storage, service = _make_service(tmp_path)

    bundle = StixExportBundle(metadata=StixExportBundleMetadata(id="bundle--stix-invalid"))
    bundle.validation_errors = [StixExportValidationError(code="invalid", message="invalid bundle")]

    result = service.finalize_stix_export(job_id="job-1", bundle=bundle)

    assert result.valid is False
    assert result.export_status == "failed"
    assert result.error_code == "export_validation_failed"
    assert len(storage.calls) == 0
    assert persistence.list_artifacts(job_id="job-1", artifact_type="stix") == []


def test_invalid_afb_export_is_not_exposed_as_successful_artifact(tmp_path: Path):
    persistence, storage, service = _make_service(tmp_path)

    bundle = AfbExportBundle(metadata=AfbExportBundleMetadata(bundle_id="bundle--afb-invalid"))
    bundle.validation_errors = [
        AfbExportCompatibilityError(code="invalid", message="invalid bundle", details={})
    ]

    result = service.finalize_afb_export(job_id="job-1", bundle=bundle)

    assert result.valid is False
    assert result.export_status == "failed"
    assert result.error_code == "export_validation_failed"
    assert len(storage.calls) == 0
    assert persistence.list_artifacts(job_id="job-1", artifact_type="afb") == []


def test_export_errors_are_represented_consistently_across_finalization_paths(tmp_path: Path):
    persistence, storage, service = _make_service(tmp_path)

    stix_failure = service.finalize_export_failure(
        artifact_type="stix",
        error_code="export_crashed",
        error_message="exporter crashed",
        validation_errors=[ExportValidationError(code="invalid", message="invalid bundle")],
    )
    afb_failure = service.finalize_export_failure(
        artifact_type="afb",
        error_code="export_crashed",
        error_message="exporter crashed",
        validation_errors=[ExportValidationError(code="invalid", message="invalid bundle")],
    )

    assert stix_failure.valid is False
    assert afb_failure.valid is False
    assert stix_failure.export_status == afb_failure.export_status == "failed"
    assert stix_failure.error_code == afb_failure.error_code == "export_crashed"
    assert stix_failure.error_message == afb_failure.error_message == "exporter crashed"
    assert stix_failure.validation_errors[0].code == afb_failure.validation_errors[0].code == "invalid"
    assert len(storage.calls) == 0
    assert persistence.list_artifacts(job_id="job-1") == []


def _prepare_worker_export_case(client: TestClient, *, invalid_export: str) -> str:
    worker = client.app.state.job_worker
    persistence = client.app.state.persistence_service

    input_source = persistence.create_input_source(InputSourceCreate(id=f"input-{invalid_export}", type="file"))
    canonical_flow = _valid_canonical_flow()
    job_id = f"job-{invalid_export}"
    persistence.create_job(
        JobCreate(
            id=job_id,
            status="exporting",
            stage="exporting",
            input_source_id=input_source.id,
            canonical_flow_json=canonical_flow.model_dump_json(),
        )
    )

    worker._processing_stages = ("flow_building",)
    return job_id


def test_export_validation_failures_are_surfaced_through_job_result_and_audit_visibility(monkeypatch, tmp_path: Path):
    with _make_client(monkeypatch, tmp_path) as client:
        job_id = _prepare_worker_export_case(client, invalid_export="stix")
        worker = client.app.state.job_worker
        persistence = client.app.state.persistence_service
        original_assemble_stix = job_worker_service.assemble_stix_export_bundle

        def invalid_stix_bundle(canonical_flow):
            bundle = original_assemble_stix(canonical_flow)
            bundle.validation_errors = [StixExportValidationError(code="forced_invalid", message="forced invalid export")]
            return bundle

        monkeypatch.setattr(job_worker_service, "assemble_stix_export_bundle", invalid_stix_bundle)

        asyncio.run(worker._process_claimed_job(job_id))

        status_payload = client.get(f"/api/v1/jobs/{job_id}").json()
        job_row = persistence.get_job(job_id)
        result_response = client.get(f"/api/v1/jobs/{job_id}/result")
        audit_payload = client.get(f"/api/v1/jobs/{job_id}/audit").json()

        assert status_payload["status"] == "failed"
        assert job_row is not None
        assert job_row.error_code == "export_validation_failed"
        assert status_payload["error_code"] == "export_validation_failed"
        assert status_payload["artifacts"]["has_afb"] is True
        assert status_payload["artifacts"]["afb_outcome"]["valid"] is True
        assert status_payload["artifacts"]["has_stix"] is False
        assert result_response.status_code == 409

        failed_event = next(event for event in audit_payload["events"] if event["event_type"] == "stix_export_failed")
        completed_event = next(event for event in audit_payload["events"] if event["event_type"] == "afb_export_completed")
        assert failed_event["details"]["artifact_valid"] is False
        assert failed_event["details"]["export_status"] == "failed"
        assert failed_event["details"]["validation_errors"]
        assert failed_event["details"]["error_code"] == "export_validation_failed"
        assert completed_event["details"]["artifact_valid"] is True
        assert completed_event["details"]["export_status"] == "completed"


def test_partial_export_failure_policy_is_applied_consistently(monkeypatch, tmp_path: Path):
    with _make_client(monkeypatch, tmp_path) as client:
        job_id = _prepare_worker_export_case(client, invalid_export="afb")
        worker = client.app.state.job_worker
        original_assemble_afb = job_worker_service.assemble_afb_export_bundle

        def invalid_afb_bundle(canonical_flow):
            bundle = original_assemble_afb(canonical_flow)
            bundle.validation_errors = [AfbExportCompatibilityError(code="forced_invalid", message="forced invalid export")]
            return bundle

        monkeypatch.setattr(job_worker_service, "assemble_afb_export_bundle", invalid_afb_bundle)

        asyncio.run(worker._process_claimed_job(job_id))

        status_payload = client.get(f"/api/v1/jobs/{job_id}").json()
        job_row = client.app.state.persistence_service.get_job(job_id)
        audit_payload = client.get(f"/api/v1/jobs/{job_id}/audit").json()

        assert status_payload["status"] == "failed"
        assert status_payload["error_code"] == "export_validation_failed"
        assert job_row is not None
        assert job_row.error_code == "export_validation_failed"
        assert status_payload["artifacts"]["has_stix"] is True
        assert status_payload["artifacts"]["stix_outcome"]["valid"] is True
        assert status_payload["artifacts"]["has_afb"] is False

        failed_event = next(event for event in audit_payload["events"] if event["event_type"] == "afb_export_failed")
        completed_event = next(event for event in audit_payload["events"] if event["event_type"] == "stix_export_completed")
        assert failed_event["details"]["artifact_valid"] is False
        assert failed_event["details"]["export_status"] == "failed"
        assert failed_event["details"]["validation_errors"]
        assert failed_event["details"]["error_code"] == "export_validation_failed"
        assert completed_event["details"]["artifact_valid"] is True
        assert completed_event["details"]["export_status"] == "completed"


@pytest.mark.parametrize(
    ("artifact_type", "metadata_kwargs"),
    [
        (
            "stix",
            {
                "metadata_json": StixExportArtifactMetadata(
                    validation_state="invalid",
                    bundle_id="bundle--invalid",
                    object_count=1,
                    exported_at="2026-01-01T00:00:00Z",
                    export_status="failed",
                    error_code="validation_failed",
                    error_message="export validation failed",
                    validation_errors=[{"code": "invalid"}],
                ).model_dump_json(),
                "validation_state": "invalid",
                "export_status": "failed",
                "error_code": "validation_failed",
                "error_message": "export validation failed",
            },
        ),
        (
            "afb",
            {
                "metadata_json": None,
                "validation_state": None,
                "export_status": None,
                "error_code": None,
                "error_message": None,
            },
        ),
    ],
)
def test_invalid_incomplete_artifact_retrieval_is_suppressed_correctly(
    monkeypatch,
    tmp_path: Path,
    artifact_type: str,
    metadata_kwargs: dict[str, object],
):
    with _make_client(monkeypatch, tmp_path) as client:
        persistence = client.app.state.persistence_service

        job = persistence.create_job(JobCreate(id="job-retrieval", status="completed", stage="completed"))
        artifact_file = client.app.state.file_storage.write_artifact(b"{}", extension="json")
        persistence.create_artifact(
            ArtifactCreate(
                id=f"artifact-{artifact_type}",
                job_id=job.id,
                type=artifact_type,
                path=artifact_file.relative_path,
                size_bytes=artifact_file.size_bytes,
                sha256="abc123" if artifact_type == "stix" else None,
                **metadata_kwargs,
            )
        )

        response = client.get(f"/api/v1/jobs/{job.id}/artifacts/{artifact_type}")

        payload = response.json()
        assert response.status_code == 404
        assert payload["error"]["code"] == "artifact_not_found"
        assert payload["error"]["message"] == f"{artifact_type} artifact not found"
