import asyncio
import json
import sqlite3
import time
from pathlib import Path
from types import MethodType, SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest

from attack_flow_api.main import create_app
from attack_flow_api.config import ProviderConfig
from attack_flow_api.providers.registry import ProviderRegistry
from attack_flow_api.services.ai_orchestration_service import AIOrchestrationExecutionResult
from attack_flow_api.services.job_worker_service import _AIExtractionJobProcessingError
from attack_flow_api.services.job_worker_service import assemble_afb_export_bundle as _assemble_afb_export_bundle
import attack_flow_api.services.job_worker_service as job_worker_service
from attack_flow_api.services.afb_extraction_contracts import (
    AfbExtractionResult,
    AttackFlowMetadata,
    ExtractionValidationState,
    OrchestrationMode,
    SourceClassification,
)
from attack_flow_api.services.afb_export_contracts import AfbExportCompatibilityError
from attack_flow_api.services.afb_fusion_assembler import build_fused_output_candidate
from attack_flow_api.services.afb_fusion_dedup import (
    MergedAttackAction,
    MergedAttackRef,
    MergedAttachmentBundle,
    MergedEntity,
    MergedRelationship,
)
from attack_flow_api.services.canonical_flow_contracts import (
    CanonicalFlowActionNode,
    CanonicalFlowAssetNode,
    CanonicalFlowMetadata,
    CanonicalFlowOutput,
)
from attack_flow_api.storage.repositories import InputSourceCreate, JobCreate
from attack_flow_api.services.plaintext_extraction import PlaintextExtractionError
from attack_flow_api.services.pdf_extraction import PdfExtractionResult
from attack_flow_api.services.url_fetch import UrlFetchError
from attack_flow_api.services.url_fetch import UrlFetchResult


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
        return SimpleNamespace(
            provider_id=request.provider_id,
            provider_type=request.provider_type,
            model=request.model,
            output_json={
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
            output_text=None,
        )


def _build_client(monkeypatch, tmp_path: Path) -> TestClient:
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


def _wait_for_status(client: TestClient, job_id: str, target_status: str, max_wait_seconds: float = 4.0):
    deadline = time.time() + max_wait_seconds
    while time.time() < deadline:
        payload = client.get(f"/api/v1/jobs/{job_id}").json()
        if payload["status"] == target_status:
            return payload
        time.sleep(0.05)
    return None


def test_worker_claims_queued_job_and_persists_claim_fields(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.job_worker.poll_interval_seconds = 0.01
        response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "claim test"},
        )
        job_id = response.json()["job_id"]

        claimed_payload = None
        for _ in range(40):
            payload = client.get(f"/api/v1/jobs/{job_id}").json()
            if payload["status"] != "queued":
                claimed_payload = payload
                break
            time.sleep(0.05)

        assert claimed_payload is not None
        assert claimed_payload["status"] in {
            "fetching",
            "extracting",
            "normalizing",
            "ai_extraction",
            "flow_building",
            "exporting",
            "completed",
        }

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT started_at, worker_id, attempt_count FROM jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
            assert row is not None
            assert row["started_at"] is not None
            assert row["worker_id"]
            assert row["attempt_count"] >= 1

            audit_rows = connection.execute(
                "SELECT event_type, details_json FROM audit_events WHERE job_id = ? ORDER BY sequence ASC",
                (job_id,),
            ).fetchall()
            assert [row["event_type"] for row in audit_rows[:4]] == [
                "job_submitted",
                "job_queued",
                "text_normalized",
                "worker_claimed",
            ]
            assert "stage_changed" in {row["event_type"] for row in audit_rows}
            worker_claim_event = next(row for row in audit_rows if row["event_type"] == "worker_claimed")
            assert json.loads(worker_claim_event["details_json"])["worker_id"]


def test_worker_progresses_through_expected_stages_in_order(monkeypatch, tmp_path: Path):
    expected = ["extracting", "normalizing", "ai_extraction", "flow_building", "exporting"]
    seen: list[str] = []

    with _build_client(monkeypatch, tmp_path) as client:
        worker = client.app.state.job_worker
        worker.poll_interval_seconds = 0.01
        original_advance = worker._advance_stage

        def recording_advance(self, job_id: str, stage: str) -> None:
            seen.append(stage)
            return original_advance(job_id, stage)

        worker._advance_stage = MethodType(recording_advance, worker)

        response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "stage order test"},
        )
        job_id = response.json()["job_id"]

        completed_payload = _wait_for_status(client, job_id, "completed")
        assert completed_payload is not None

    assert seen == expected


def test_worker_persists_intermediate_updates_and_completion(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        worker = client.app.state.job_worker
        worker.poll_interval_seconds = 0.01
        original_hook = worker._run_stage_hook

        async def delayed_hook(self, job_id: str, stage: str) -> None:
            await asyncio.sleep(0.05)
            await original_hook(job_id, stage)

        worker._run_stage_hook = MethodType(delayed_hook, worker)

        response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "persistence test"},
        )
        job_id = response.json()["job_id"]

        intermediate_seen = False
        for _ in range(40):
            with sqlite3.connect(client.app.state.sqlite_path) as connection:
                connection.row_factory = sqlite3.Row
                row = connection.execute(
                    "SELECT status, stage, progress_percent FROM jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()
            assert row is not None
            if row["status"] in {
                "fetching",
                "extracting",
                "normalizing",
                "ai_extraction",
                "flow_building",
                "exporting",
            }:
                intermediate_seen = True
                break
            time.sleep(0.03)
        assert intermediate_seen

        completed_payload = _wait_for_status(client, job_id, "completed")
        assert completed_payload is not None
        assert completed_payload["stage"] == "completed"
        assert completed_payload["completed_at"] is not None

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            audit_rows = connection.execute(
                "SELECT event_type FROM audit_events WHERE job_id = ? ORDER BY sequence ASC",
                (job_id,),
            ).fetchall()
            event_types = {row["event_type"] for row in audit_rows}
            assert {"stage_changed", "text_normalized", "normalized_package_created", "ai_extraction_input_prepared", "ai_extraction_result", "fusion_completed", "canonical_flow_created", "job_completed"}.issubset(event_types)
            row = connection.execute(
                "SELECT created_at, updated_at, completed_at FROM jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
            assert row is not None
            assert row["updated_at"] >= row["created_at"]
        assert row["completed_at"] is not None


def test_worker_persists_fused_output_after_ai_extraction(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        worker = client.app.state.job_worker
        persistence = client.app.state.persistence_service

        input_source = persistence.create_input_source(
            InputSourceCreate(
                id="input-1",
                type="file",
                file_class="stix_json",
                normalized_source_type="stix_structured",
                normalized_package_json=json.dumps(
                    {
                        "version": "v1",
                        "source_type": "stix_structured",
                        "metadata": {"authors": ["analyst-a"], "external_references": ["https://example.com/a"]},
                        "attack_refs": [{"technique_id": "T1059", "source_object_id": "attack-pattern--1"}],
                        "entities": [{"object_id": "malware--1", "object_type": "malware"}],
                        "relationships": [
                            {
                                "relationship_id": "relationship--1",
                                "relationship_type": "uses",
                                "source_ref": "threat-actor--1",
                                "target_ref": "malware--1",
                                "source_object_type": "threat-actor",
                            }
                        ],
                    }
                ),
            )
        )
        persistence.create_job(
            JobCreate(
                id="job-fusion-1",
                status="ai_extraction",
                stage="ai_extraction",
                input_source_id=input_source.id,
            )
        )

        extraction_result = AfbExtractionResult.model_validate(
            {
                "validation_state": ExtractionValidationState.VALID,
                "provider_invoked": True,
                "attack_flow": AttackFlowMetadata(
                    id="attack-flow--1",
                    name="Example flow",
                    scope="incident",
                    orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
                    source_classification=SourceClassification.STIX_STRUCTURED,
                ).model_dump(mode="json"),
                "attack_actions": [
                    {
                        "id": "attack-action--1",
                        "name": "Deterministic step",
                        "description": "Observed command exactly as reported.",
                        "confidence": 0.8,
                        "evidence": [
                            {
                                "source": "narrative",
                                "excerpt": "Observed command exactly as reported.",
                            }
                        ],
                    }
                ],
            }
        )
        execution = AIOrchestrationExecutionResult(
            succeeded=True,
            provider_invoked=True,
            provider_id="default-openai",
            model_used="gpt-4.1-mini",
            extraction_mode="ai_enrichment",
            extraction_payload_json=extraction_result.model_dump_json(),
            extraction_validation_state="valid",
            repair_attempted=False,
            provenance_classification="stix_structured",
            authors_json='["analyst-a"]',
            external_references_json='["https://example.com/a"]',
        )

        worker._ai_orchestration_service.run_for_job = lambda **kwargs: execution

        worker._run_ai_extraction_orchestration("job-fusion-1")

        updated = persistence.get_job("job-fusion-1")
        assert updated is not None
        assert updated.result_json is not None
        assert json.loads(updated.result_json)["schema_version"] == "afb-v2-fused-candidate"
        assert updated.fusion_result_json is not None
        assert json.loads(updated.fusion_result_json)["fusion_validation_state"] == "ready"
        assert json.loads(updated.fusion_provenance_json or "{}")


def test_worker_invokes_fusion_on_successful_ai_extraction(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        worker = client.app.state.job_worker
        persistence = client.app.state.persistence_service

        input_source = persistence.create_input_source(
            InputSourceCreate(
                id="input-2",
                type="file",
                file_class="stix_json",
                normalized_source_type="stix_structured",
                normalized_package_json=json.dumps(
                    {
                        "version": "v1",
                        "source_type": "stix_structured",
                        "metadata": {"authors": ["analyst-a"], "external_references": ["https://example.com/a"]},
                        "attack_refs": [{"technique_id": "T1059", "source_object_id": "attack-pattern--1"}],
                        "entities": [{"object_id": "malware--1", "object_type": "malware"}],
                    }
                ),
            )
        )
        persistence.create_job(
            JobCreate(
                id="job-fusion-2",
                status="ai_extraction",
                stage="ai_extraction",
                input_source_id=input_source.id,
            )
        )

        extraction_result = AfbExtractionResult.model_validate(
            {
                "validation_state": ExtractionValidationState.VALID,
                "provider_invoked": True,
                "attack_flow": AttackFlowMetadata(
                    id="attack-flow--2",
                    name="Example flow",
                    scope="incident",
                    orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
                    source_classification=SourceClassification.STIX_STRUCTURED,
                ).model_dump(mode="json"),
                "attack_actions": [
                    {
                        "id": "attack-action--2",
                        "name": "Deterministic step",
                        "description": "Observed command exactly as reported.",
                        "confidence": 0.8,
                        "evidence": [
                            {
                                "source": "narrative",
                                "excerpt": "Observed command exactly as reported.",
                            }
                        ],
                    }
                ],
            }
        )
        execution = AIOrchestrationExecutionResult(
            succeeded=True,
            provider_invoked=True,
            provider_id="default-openai",
            model_used="gpt-4.1-mini",
            extraction_mode="ai_enrichment",
            extraction_payload_json=extraction_result.model_dump_json(),
            extraction_validation_state="valid",
            repair_attempted=False,
            provenance_classification="stix_structured",
            authors_json='["analyst-a"]',
            external_references_json='["https://example.com/a"]',
        )
        candidate = build_fused_output_candidate(
            attack_flow=AttackFlowMetadata(
                id="attack-flow--2",
                name="Example flow",
                scope="incident",
                orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
                source_classification=SourceClassification.STIX_STRUCTURED,
            )
        )

        worker._ai_orchestration_service.run_for_job = lambda **kwargs: execution

        with patch("attack_flow_api.services.job_worker_service.build_fused_output_candidate_from_sources") as mocked_build:
            mocked_build.return_value = candidate
            worker._run_ai_extraction_orchestration("job-fusion-2")

        assert mocked_build.call_count == 1


def test_worker_preserves_provider_quota_exceeded_error_code(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        worker = client.app.state.job_worker
        persistence = client.app.state.persistence_service

        input_source = persistence.create_input_source(
            InputSourceCreate(
                id="input-rate-limit-1",
                type="file",
                file_class="stix_json",
                normalized_source_type="stix_structured",
                normalized_package_json=json.dumps({"version": "v1", "source_type": "stix_structured"}),
            )
        )
        persistence.create_job(
            JobCreate(
                id="job-rate-limit-1",
                status="queued",
                stage="queued",
                input_source_id=input_source.id,
            )
        )

        async def fake_stage_hook(self, job_id: str, stage: str) -> None:
            if stage == "ai_extraction":
                raise _AIExtractionJobProcessingError(
                    job_error_code="provider_quota_exceeded",
                    job_error_message="provider quota exceeded",
                )

        worker._run_stage_hook = MethodType(fake_stage_hook, worker)

        asyncio.run(worker._process_claimed_job("job-rate-limit-1"))

        failed_job = persistence.get_job("job-rate-limit-1")
        assert failed_job is not None
        assert failed_job.status == "failed"
        assert failed_job.error_code == "provider_quota_exceeded"
        assert failed_job.error_message == "provider quota exceeded"


def test_worker_builds_and_persists_canonical_flow_from_fused_output(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        worker = client.app.state.job_worker
        persistence = client.app.state.persistence_service

        input_source = persistence.create_input_source(
            InputSourceCreate(
                id="input-canonical-1",
                type="file",
                file_class="stix_json",
                normalized_source_type="stix_structured",
                normalized_package_json=json.dumps(
                    {
                        "version": "v1",
                        "source_type": "stix_structured",
                        "metadata": {"authors": ["analyst-a"], "external_references": ["https://example.com/a"]},
                        "attack_refs": [{"technique_id": "T1059", "source_object_id": "attack-pattern--1"}],
                        "entities": [{"object_id": "malware--1", "object_type": "malware"}],
                        "relationships": [
                            {
                                "relationship_id": "relationship--1",
                                "relationship_type": "uses",
                                "source_ref": "threat-actor--1",
                                "target_ref": "malware--1",
                                "source_object_type": "threat-actor",
                            }
                        ],
                    }
                ),
            )
        )
        persistence.create_job(
            JobCreate(
                id="job-canonical-1",
                status="flow_building",
                stage="flow_building",
                input_source_id=input_source.id,
            )
        )

        fused_candidate = build_fused_output_candidate(
            attack_flow=AttackFlowMetadata(
                id="attack-flow--1",
                name="Example flow",
                scope="incident",
                orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
                source_classification=SourceClassification.STIX_STRUCTURED,
                start_refs=["attack-action--1"],
                authors=["analyst-a"],
                external_references=["https://example.com/a"],
            ),
            attack_refs=[
                MergedAttackRef(
                    technique_id="T1059",
                    source_object_id="attack-pattern--1",
                    source_field="external_references[0]",
                    external_source_name="ATT&CK",
                    external_url="https://attack.mitre.org/techniques/T1059/",
                    confidence=1.0,
                    provenance=[
                        {
                            "kind": "deterministic",
                            "source_label": "deterministic",
                            "source_object_id": "attack-pattern--1",
                            "source_field": "external_references[0]",
                        }
                    ],
                )
            ],
            entities=[
                MergedEntity(
                    object_id="malware--1",
                    object_type="malware",
                    display_name="Malware",
                    confidence=0.8,
                    provenance=[
                        {
                            "kind": "deterministic",
                            "source_label": "narrative",
                            "source_object_id": "malware--1",
                        }
                    ],
                )
            ],
            relationships=[
                MergedRelationship(
                    relationship_id="relationship--1",
                    relationship_type="uses",
                    source_ref="threat-actor--1",
                    target_ref="malware--1",
                    source_object_type="threat-actor",
                )
            ],
            attack_actions=[
                MergedAttackAction(
                    id="attack-action--1",
                    name="Step",
                    description="Observed command exactly as reported.",
                    confidence=0.9,
                    asset_refs=["malware--1"],
                    provenance=[
                        {
                            "kind": "deterministic",
                            "source_label": "narrative",
                            "source_object_id": "report--1",
                        }
                    ],
                    evidence=[{"source": "narrative", "excerpt": "Observed command exactly as reported.", "source_object_id": "report--1"}],
                )
            ],
            attack_conditions=[],
            attack_operators=[],
            attachment_bundle=MergedAttachmentBundle(
                attack_flow_authors=["analyst-a"],
                attack_flow_external_references=["https://example.com/a"],
                preserved_object_refs=["malware--1", "threat-actor--1"],
                preserved_evidence_refs=["report--1"],
            ),
        )

        persistence.persist_fused_output_candidate("job-canonical-1", fused_candidate)
        asyncio.run(worker._run_stage_hook("job-canonical-1", "flow_building"))

        updated = persistence.get_job("job-canonical-1")
        assert updated is not None
        assert updated.canonical_flow_json is not None
        assert updated.canonical_flow_validation_state == "valid"
        assert json.loads(updated.canonical_flow_json)["schema_version"] == "attack-flow-canonical-v1"
        assert json.loads(updated.canonical_flow_provenance_json or "{}")


def test_worker_persists_stix_export_artifact_and_downloads_it(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        worker = client.app.state.job_worker
        persistence = client.app.state.persistence_service

        input_source = persistence.create_input_source(
            InputSourceCreate(
                id="input-export-1",
                type="file",
            )
        )
        canonical_flow = CanonicalFlowOutput(
            metadata=CanonicalFlowMetadata(
                flow_id="attack-flow--export-1",
                name="Example flow",
                scope="incident",
                start_refs=["attack-action--1"],
            ),
            nodes=[
                CanonicalFlowActionNode(
                    id="attack-action--1",
                    name="Example step",
                    description="Observed command exactly as reported.",
                    provenance=[
                        {
                            "source_label": "fused",
                            "source_object_id": "attack-action--1",
                        }
                    ],
                    evidence=[
                        {
                            "source": "narrative",
                            "excerpt": "Observed command exactly as reported.",
                        }
                    ],
                    asset_refs=["attack-asset--1"],
                ),
                CanonicalFlowAssetNode(
                    id="attack-asset--1",
                    name="Host asset",
                    object_ref="malware--1",
                    provenance=[
                        {
                            "source_label": "fused",
                            "source_object_id": "attack-asset--1",
                        }
                    ],
                ),
            ],
            edges=[],
            provenance={"source": "fused"},
            conflicts=[],
            validation_errors=[],
        )
        persistence.create_job(
            JobCreate(
                id="job-export-1",
                status="exporting",
                stage="exporting",
                input_source_id=input_source.id,
                canonical_flow_json=canonical_flow.model_dump_json(),
            )
        )

        worker._processing_stages = ("flow_building",)
        asyncio.run(worker._process_claimed_job("job-export-1"))

        updated = persistence.get_job("job-export-1")
        assert updated is not None
        assert updated.status == "completed"

        artifacts = persistence.list_artifacts(job_id="job-export-1", artifact_type="stix")
        assert len(artifacts) == 1
        artifact = artifacts[0]
        assert artifact.metadata_json is not None
        assert json.loads(artifact.metadata_json)["validation_state"] == "valid"

        afb_artifacts = persistence.list_artifacts(job_id="job-export-1", artifact_type="afb")
        assert len(afb_artifacts) == 1
        afb_artifact = afb_artifacts[0]
        assert afb_artifact.metadata_json is not None
        assert json.loads(afb_artifact.metadata_json)["validation_state"] == "valid"

        response = client.get("/api/v1/jobs/job-export-1/artifacts/stix")
        assert response.status_code == 200
        assert response.json()["type"] == "bundle"
        assert response.json()["objects"][0]["type"] == "attack-flow"

        status_response = client.get("/api/v1/jobs/job-export-1")
        status_payload = status_response.json()
        assert status_payload["artifacts"]["has_stix"] is True
        assert status_payload["artifacts"]["stix_outcome"]["valid"] is True
        assert status_payload["artifacts"]["stix_outcome"]["export_status"] == "completed"

        audit_response = client.get("/api/v1/jobs/job-export-1/audit")
        audit_payload = audit_response.json()
        stix_completed_event = next(
            event for event in audit_payload["events"] if event["event_type"] == "stix_export_completed"
        )
        assert stix_completed_event["details"]["artifact_valid"] is True
        assert stix_completed_event["details"]["export_status"] == "completed"
        assert stix_completed_event["details"]["validation_state"] == "valid"

        afb_response = client.get("/api/v1/jobs/job-export-1/artifacts/afb")
        assert afb_response.status_code == 200
        afb_payload = afb_response.json()
        assert afb_payload["schema"] == "attack_flow_v2"
        assert afb_payload["objects"][0]["id"] == "flow"
        assert afb_payload["objects"][0]["objects"][0] == "attack-action--1"


def test_worker_marks_failed_export_without_publishing_artifact(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        worker = client.app.state.job_worker
        persistence = client.app.state.persistence_service

        input_source = persistence.create_input_source(
            InputSourceCreate(
                id="input-export-2",
                type="file",
            )
        )
        canonical_flow = CanonicalFlowOutput(
            metadata=CanonicalFlowMetadata(
                flow_id="attack-flow--export-2",
                name="Example flow",
                scope="incident",
                start_refs=["attack-action--1"],
            ),
            nodes=[
                CanonicalFlowActionNode(
                    id="attack-action--1",
                    name="Example step",
                    description="Observed command exactly as reported.",
                    asset_refs=["attack-asset--missing"],
                )
            ],
            edges=[],
            provenance={"source": "fused"},
            conflicts=[],
            validation_errors=[],
        )
        persistence.create_job(
            JobCreate(
                id="job-export-2",
                status="exporting",
                stage="exporting",
                input_source_id=input_source.id,
                canonical_flow_json=canonical_flow.model_dump_json(),
            )
        )

        worker._processing_stages = ("flow_building",)
        asyncio.run(worker._process_claimed_job("job-export-2"))

        updated = persistence.get_job("job-export-2")
        assert updated is not None
        assert updated.status == "failed"
        assert updated.error_code == "export_validation_failed"

        artifacts = persistence.list_artifacts(job_id="job-export-2", artifact_type="stix")
        assert artifacts == []

        afb_artifacts = persistence.list_artifacts(job_id="job-export-2", artifact_type="afb")
        assert afb_artifacts == []

        response = client.get("/api/v1/jobs/job-export-2/artifacts/stix")
        assert response.status_code == 404

        audit_response = client.get("/api/v1/jobs/job-export-2/audit")
        audit_payload = audit_response.json()
        failed_event = next(
            event for event in audit_payload["events"] if event["event_type"] == "stix_export_failed"
        )
        assert failed_event["details"]["artifact_valid"] is False
        assert failed_event["details"]["export_status"] == "failed"
        assert failed_event["details"]["validation_errors"]
        assert failed_event["details"]["error_code"] == "export_validation_failed"
        assert failed_event["details"]["error_message"] == "export validation failed"


def test_worker_marks_failed_afb_export_without_publishing_artifact(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        worker = client.app.state.job_worker
        persistence = client.app.state.persistence_service

        input_source = persistence.create_input_source(
            InputSourceCreate(
                id="input-afb-export-1",
                type="file",
            )
        )
        canonical_flow = CanonicalFlowOutput(
            metadata=CanonicalFlowMetadata(
                flow_id="attack-flow--afb-export-1",
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
        persistence.create_job(
            JobCreate(
                id="job-afb-export-1",
                status="exporting",
                stage="exporting",
                input_source_id=input_source.id,
                canonical_flow_json=canonical_flow.model_dump_json(),
            )
        )

        def failing_assemble(canonical_flow):
            bundle = _assemble_afb_export_bundle(canonical_flow)
            bundle.validation_errors = [
                AfbExportCompatibilityError(code="forced_invalid", message="forced invalid export")
            ]
            return bundle

        monkeypatch.setattr(job_worker_service, "assemble_afb_export_bundle", failing_assemble)

        worker._processing_stages = ("flow_building",)
        asyncio.run(worker._process_claimed_job("job-afb-export-1"))

        updated = persistence.get_job("job-afb-export-1")
        assert updated is not None
        assert updated.status == "failed"
        assert updated.error_code == "export_validation_failed"

        artifacts = persistence.list_artifacts(job_id="job-afb-export-1", artifact_type="afb")
        assert artifacts == []

        stix_artifacts = persistence.list_artifacts(job_id="job-afb-export-1", artifact_type="stix")
        assert len(stix_artifacts) == 1

        response = client.get("/api/v1/jobs/job-afb-export-1/artifacts/afb")
        assert response.status_code == 404

        audit_response = client.get("/api/v1/jobs/job-afb-export-1/audit")
        audit_payload = audit_response.json()
        failed_event = next(
            event for event in audit_payload["events"] if event["event_type"] == "afb_export_failed"
        )
        assert failed_event["details"]["artifact_valid"] is False
        assert failed_event["details"]["export_status"] == "failed"
        assert failed_event["details"]["validation_errors"]
        assert failed_event["details"]["error_code"] == "export_validation_failed"
        assert failed_event["details"]["error_message"] == "export validation failed"


def test_worker_falls_back_to_afb_output_when_fused_output_missing(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        worker = client.app.state.job_worker
        persistence = client.app.state.persistence_service

        input_source = persistence.create_input_source(
            InputSourceCreate(
                id="input-canonical-2",
                type="file",
                file_class="stix_json",
                normalized_source_type="stix_structured",
                normalized_package_json=json.dumps(
                    {
                        "version": "v1",
                        "source_type": "stix_structured",
                        "metadata": {"authors": ["analyst-b"], "external_references": ["https://example.com/b"]},
                    }
                ),
            )
        )
        persistence.create_job(
            JobCreate(
                id="job-canonical-2",
                status="flow_building",
                stage="flow_building",
                input_source_id=input_source.id,
                extraction_result_json=AfbExtractionResult.model_validate(
                    {
                        "validation_state": ExtractionValidationState.VALID,
                        "provider_invoked": True,
                        "attack_flow": AttackFlowMetadata(
                            id="attack-flow--afb",
                            name="AFB flow",
                            scope="incident",
                            orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
                            source_classification=SourceClassification.STIX_STRUCTURED,
                            authors=["analyst-b"],
                            external_references=["https://example.com/b"],
                        ).model_dump(mode="json"),
                        "attack_actions": [
                            {
                                "id": "attack-action--afb",
                                "name": "AFB step",
                                "description": "Observed command exactly as reported.",
                                "confidence": 0.75,
                                "evidence": [
                                    {
                                        "source": "narrative",
                                        "excerpt": "Observed command exactly as reported.",
                                        "source_object_id": "report--2",
                                    }
                                ],
                            }
                        ],
                    }
                ).model_dump_json(),
            )
        )

        asyncio.run(worker._run_stage_hook("job-canonical-2", "flow_building"))

        updated = persistence.get_job("job-canonical-2")
        assert updated is not None
        assert updated.canonical_flow_json is not None
        assert updated.canonical_flow_validation_state == "valid"
        assert json.loads(updated.canonical_flow_json)["metadata"]["authors"] == ["analyst-b"]


def test_worker_failure_marks_failed_and_continues_with_next_job(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.job_worker.poll_interval_seconds = 0.01
        first = client.post("/api/v1/jobs", json={"input_type": "text", "text": "fail me"})
        first_job_id = first.json()["job_id"]
        client.app.state.job_worker.force_failure_for_job(first_job_id)

        second = client.post("/api/v1/jobs", json={"input_type": "text", "text": "complete me"})
        second_job_id = second.json()["job_id"]

        failed_payload = _wait_for_status(client, first_job_id, "failed")
        completed_payload = _wait_for_status(client, second_job_id, "completed")

        assert failed_payload is not None
        assert completed_payload is not None

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            failed_row = connection.execute(
                "SELECT error_code, error_message, completed_at, updated_at FROM jobs WHERE id = ?",
                (first_job_id,),
            ).fetchone()
            assert failed_row is not None
            assert failed_row["error_code"] == "worker_processing_error"
            assert failed_row["error_message"]
            assert failed_row["completed_at"] is not None
            assert failed_row["updated_at"] is not None

            failed_audit_rows = connection.execute(
                "SELECT event_type FROM audit_events WHERE job_id = ? ORDER BY sequence ASC",
                (first_job_id,),
            ).fetchall()
            assert "job_failed" in {row["event_type"] for row in failed_audit_rows}


def test_post_jobs_remains_non_blocking_while_worker_processes(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        worker = client.app.state.job_worker
        worker.poll_interval_seconds = 0.01
        original_hook = worker._run_stage_hook

        async def delayed_hook(self, job_id: str, stage: str) -> None:
            await asyncio.sleep(0.05)
            await original_hook(job_id, stage)

        worker._run_stage_hook = MethodType(delayed_hook, worker)

        start = time.perf_counter()
        response = client.post("/api/v1/jobs", json={"input_type": "text", "text": "async check"})
        elapsed = time.perf_counter() - start
        payload = response.json()

        assert response.status_code == 202
        assert elapsed < 0.2
        status_payload = _wait_for_status(client, payload["job_id"], "completed", max_wait_seconds=5.0)
        assert status_payload is not None
        assert status_payload["request_id"]


def test_worker_processes_url_job_and_persists_fetch_and_normalized_text(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.job_worker.poll_interval_seconds = 0.01

        with patch("attack_flow_api.services.job_worker_service.fetch_url_bounded") as mocked_fetch:
            mocked_fetch.return_value = UrlFetchResult(
                requested_url="https://example.com/report",
                final_url="https://example.com/report",
                status_code=200,
                content_type="text/html; charset=utf-8",
                size_bytes=87,
                body=(
                    b"<html><body><article><h1>Report</h1>"
                    b"<p>Initial access observed.</p></article></body></html>"
                ),
            )

            response = client.post(
                "/api/v1/jobs",
                json={"input_type": "url", "url": "https://example.com/report"},
            )
            job_id = response.json()["job_id"]

            completed_payload = _wait_for_status(client, job_id, "completed")
            assert completed_payload is not None

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            assert job_row is not None
            input_row = connection.execute(
                "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
            ).fetchone()
            assert input_row is not None
            assert input_row["fetch_final_url"] == "https://example.com/report"
            assert input_row["fetch_status_code"] == 200
            assert input_row["fetch_content_type"] == "text/html; charset=utf-8"
            assert input_row["fetch_size_bytes"] == 87
            assert input_row["normalized_text"] == "Report\n\nInitial access observed."
            assert input_row["content_text"] == "Report\n\nInitial access observed."
            assert input_row["normalized_char_count"] == len("Report\n\nInitial access observed.")

            audit_rows = connection.execute(
                "SELECT event_type FROM audit_events WHERE job_id = ? ORDER BY sequence ASC",
                (job_id,),
            ).fetchall()
            event_types = [row["event_type"] for row in audit_rows]
            assert event_types[:5] == [
                "job_submitted",
                "job_queued",
                "worker_claimed",
                "stage_changed",
                "url_validation_started",
            ]
            assert {"url_fetch_started", "url_fetch_completed", "text_normalized", "normalized_package_created", "ai_extraction_input_prepared", "ai_extraction_result", "fusion_completed", "canonical_flow_created", "job_completed"}.issubset(set(event_types))


def test_worker_fails_url_job_with_unsupported_content_type(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.job_worker.poll_interval_seconds = 0.01

        with patch("attack_flow_api.services.job_worker_service.fetch_url_bounded") as mocked_fetch:
            mocked_fetch.return_value = UrlFetchResult(
                requested_url="https://example.com/data",
                final_url="https://example.com/data",
                status_code=200,
                content_type="application/json",
                size_bytes=12,
                body=b'{"ok": true}',
            )

            response = client.post(
                "/api/v1/jobs",
                json={"input_type": "url", "url": "https://example.com/data"},
            )
            job_id = response.json()["job_id"]

            failed_payload = _wait_for_status(client, job_id, "failed")
            assert failed_payload is not None

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            assert job_row is not None
            assert job_row["error_code"] == "url_unsupported_content_type"
            input_row = connection.execute(
                "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
            ).fetchone()
            assert input_row is not None
            assert input_row["fetch_error_code"] == "unsupported_content_type"
            assert "unsupported content type" in input_row["fetch_error_message"]

            audit_rows = connection.execute(
                "SELECT event_type FROM audit_events WHERE job_id = ? ORDER BY sequence ASC",
                (job_id,),
            ).fetchall()
            event_types = {row["event_type"] for row in audit_rows}
            assert {"stage_changed", "url_validation_started", "url_fetch_started", "url_fetch_completed", "job_failed"}.issubset(event_types)


def test_worker_persists_url_fetch_failure_and_continues_next_job(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.job_worker.poll_interval_seconds = 0.01

        with patch("attack_flow_api.services.job_worker_service.fetch_url_bounded") as mocked_fetch:
            mocked_fetch.side_effect = UrlFetchError("fetch_timeout", "url fetch timed out")

            first = client.post(
                "/api/v1/jobs",
                json={"input_type": "url", "url": "https://example.com/slow"},
            )
            first_job_id = first.json()["job_id"]

            second = client.post(
                "/api/v1/jobs",
                json={"input_type": "text", "text": "complete me"},
            )
            second_job_id = second.json()["job_id"]

            failed_payload = _wait_for_status(client, first_job_id, "failed")
            completed_payload = _wait_for_status(client, second_job_id, "completed")

            assert failed_payload is not None
            assert completed_payload is not None

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            failed_job_row = connection.execute(
                "SELECT error_code, error_message FROM jobs WHERE id = ?",
                (first_job_id,),
            ).fetchone()
            assert failed_job_row is not None
            assert failed_job_row["error_code"] == "url_fetch_timeout"
            assert "timed out" in failed_job_row["error_message"]

            failed_audit_rows = connection.execute(
                "SELECT event_type FROM audit_events WHERE job_id = ? ORDER BY sequence ASC",
                (first_job_id,),
            ).fetchall()
            assert "job_failed" in {row["event_type"] for row in failed_audit_rows}

            input_source_id = connection.execute(
                "SELECT input_source_id FROM jobs WHERE id = ?",
                (first_job_id,),
            ).fetchone()["input_source_id"]
            input_row = connection.execute(
                "SELECT fetch_error_code, fetch_error_message FROM input_sources WHERE id = ?",
                (input_source_id,),
            ).fetchone()
            assert input_row is not None
            assert input_row["fetch_error_code"] == "fetch_timeout"
            assert "timed out" in input_row["fetch_error_message"]


def test_worker_marks_url_job_unsafe_when_fetch_blocks_private_destination(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.job_worker.poll_interval_seconds = 0.01

        with patch("attack_flow_api.services.job_worker_service.fetch_url_bounded") as mocked_fetch:
            mocked_fetch.side_effect = UrlFetchError("unsafe_destination", "destination resolves to private address")

            response = client.post(
                "/api/v1/jobs",
                json={"input_type": "url", "url": "https://blocked.example/report"},
            )
            job_id = response.json()["job_id"]

            failed_payload = _wait_for_status(client, job_id, "failed")
            assert failed_payload is not None

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            assert job_row is not None
            assert job_row["error_code"] == "url_destination_unsafe"
            assert "private address" in job_row["error_message"]

            input_row = connection.execute(
                "SELECT fetch_error_code, fetch_error_message FROM input_sources WHERE id = ?",
                (job_row["input_source_id"],),
            ).fetchone()
            assert input_row is not None
            assert input_row["fetch_error_code"] == "unsafe_destination"
            assert "private address" in input_row["fetch_error_message"]

            audit_rows = connection.execute(
                "SELECT event_type FROM audit_events WHERE job_id = ? ORDER BY sequence ASC",
                (job_id,),
            ).fetchall()
            assert "job_failed" in {row["event_type"] for row in audit_rows}


@pytest.mark.parametrize(
    ("fetch_error_code", "job_error_code"),
    [
        ("redirect_limit_exceeded", "url_redirect_limit_exceeded"),
        ("response_too_large", "url_response_too_large"),
        ("fetch_failed", "url_fetch_failed"),
    ],
)
def test_worker_maps_url_fetch_errors_to_job_errors(
    monkeypatch,
    tmp_path: Path,
    fetch_error_code: str,
    job_error_code: str,
):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.job_worker.poll_interval_seconds = 0.01

        with patch("attack_flow_api.services.job_worker_service.fetch_url_bounded") as mocked_fetch:
            mocked_fetch.side_effect = UrlFetchError(fetch_error_code, f"{fetch_error_code} message")

            response = client.post(
                "/api/v1/jobs",
                json={"input_type": "url", "url": "https://example.com/report"},
            )
            job_id = response.json()["job_id"]

            failed_payload = _wait_for_status(client, job_id, "failed")
            assert failed_payload is not None

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            assert job_row is not None
            assert job_row["error_code"] == job_error_code
            assert fetch_error_code in job_row["error_message"]

            input_row = connection.execute(
                "SELECT fetch_error_code, fetch_error_message FROM input_sources WHERE id = ?",
                (job_row["input_source_id"],),
            ).fetchone()
            assert input_row is not None
            assert input_row["fetch_error_code"] == fetch_error_code
            assert fetch_error_code in input_row["fetch_error_message"]


def test_non_http_https_url_is_rejected_before_worker_processing(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={"input_type": "url", "url": "ftp://example.com/report"},
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "invalid_url_scheme"


def test_worker_processes_plaintext_file_and_persists_normalized_output(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.job_worker.poll_interval_seconds = 0.01
        response = client.post(
            "/api/v1/jobs",
            files={"file": ("notes.txt", b"alpha  \r\n\r\n\r\nbeta\t\n", "text/plain")},
        )
        job_id = response.json()["job_id"]

        completed_payload = _wait_for_status(client, job_id, "completed")
        assert completed_payload is not None

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            assert job_row is not None
            input_row = connection.execute(
                "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
            ).fetchone()
            assert input_row is not None
            assert input_row["file_class"] == "plaintext"
            assert input_row["raw_text"] == "alpha  \r\n\r\n\r\nbeta\t\n"
            assert input_row["normalized_text"] == "alpha\n\nbeta"
            assert input_row["content_text"] == "alpha\n\nbeta"
            assert input_row["normalized_char_count"] == len("alpha\n\nbeta")
            assert input_row["normalization_version"] == "v1"
            assert input_row["normalized_source_type"] == "document_extracted_text"
            assert input_row["normalized_package_json"]


def test_worker_persists_canonical_normalized_package_for_text_job(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.job_worker.poll_interval_seconds = 0.01
        response = client.post(
            "/api/v1/jobs",
            json={
                "input_type": "text",
                "text": "Alpha\r\n\r\n\r\nBeta\n",
                "metadata": {"title": "Case A", "case_id": "CASE-1", "source_name": "analyst"},
            },
        )
        job_id = response.json()["job_id"]

        completed_payload = _wait_for_status(client, job_id, "completed")
        assert completed_payload is not None

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            assert job_row is not None
            input_row = connection.execute(
                "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
            ).fetchone()
            assert input_row is not None
            assert input_row["normalized_source_type"] == "narrative_text"
            assert input_row["normalized_content_chars"] == len("Alpha\n\nBeta")
            assert input_row["normalized_pipeline_version"] == "v1"
            assert input_row["normalized_package_json"]

        normalized_package = client.app.state.persistence_service.resolve_normalized_package_for_job(job_id)
        assert normalized_package is not None
        assert normalized_package["source_type"] == "narrative_text"
        assert normalized_package["normalized_text"] == "Alpha\n\nBeta"


def test_worker_persists_canonical_normalized_package_for_url_job(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.job_worker.poll_interval_seconds = 0.01

        with patch("attack_flow_api.services.job_worker_service.fetch_url_bounded") as mocked_fetch:
            mocked_fetch.return_value = UrlFetchResult(
                requested_url="https://example.com/report",
                final_url="https://example.com/report",
                status_code=200,
                content_type="text/html; charset=utf-8",
                size_bytes=120,
                body=(
                    b"<html><body><article><h1>Case Title</h1>"
                    b"<p>Observed activity details.</p></article></body></html>"
                ),
            )

            response = client.post(
                "/api/v1/jobs",
                json={"input_type": "url", "url": "https://example.com/report"},
            )
            job_id = response.json()["job_id"]

            completed_payload = _wait_for_status(client, job_id, "completed")
            assert completed_payload is not None

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            assert job_row is not None
            input_row = connection.execute(
                "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
            ).fetchone()
            assert input_row is not None
            assert input_row["normalized_source_type"] == "url_extracted_text"
            assert input_row["normalized_package_json"]

        normalized_package = client.app.state.persistence_service.resolve_normalized_package_for_job(job_id)
        assert normalized_package is not None
        assert normalized_package["source_type"] == "url_extracted_text"
        assert normalized_package["normalized_text"] == "Case Title\n\nObserved activity details."


def test_worker_processes_pdf_file_and_persists_extracted_output(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.job_worker.poll_interval_seconds = 0.01
        with patch("attack_flow_api.services.job_worker_service.extract_pdf_text_content") as mocked_extract_pdf:
            mocked_extract_pdf.return_value = PdfExtractionResult(
                extracted_text="Page One\r\n\r\n\r\nPage Two\n",
                normalized_text="Page One\n\nPage Two",
                normalized_char_count=len("Page One\n\nPage Two"),
                normalization_version="v1",
            )

            response = client.post(
                "/api/v1/jobs",
                files={"file": ("report.pdf", b"%PDF-1.7 sample", "application/pdf")},
            )
            job_id = response.json()["job_id"]

            completed_payload = _wait_for_status(client, job_id, "completed")
            assert completed_payload is not None

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            assert job_row is not None
            input_row = connection.execute(
                "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
            ).fetchone()
            assert input_row is not None
            assert input_row["file_class"] == "pdf"
            assert input_row["raw_text"] == "Page One\r\n\r\n\r\nPage Two\n"
            assert input_row["normalized_text"] == "Page One\n\nPage Two"
            assert input_row["content_text"] == "Page One\n\nPage Two"
            assert input_row["normalized_char_count"] == len("Page One\n\nPage Two")
            assert input_row["normalization_version"] == "v1"


def test_worker_persists_file_failure_details_and_continues_next_job(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.job_worker.poll_interval_seconds = 0.01

        with patch("attack_flow_api.services.job_worker_service.extract_plaintext_content") as mocked_extract:
            mocked_extract.side_effect = PlaintextExtractionError(
                "plaintext_decode_failed",
                "plaintext file must be valid UTF-8",
            )

            failing = client.post(
                "/api/v1/jobs",
                files={"file": ("broken.txt", b"safe-bytes", "text/plain")},
            )
            failing_job_id = failing.json()["job_id"]

            succeeding = client.post(
                "/api/v1/jobs",
                json={"input_type": "text", "text": "continue after file fail"},
            )
            succeeding_job_id = succeeding.json()["job_id"]

            failed_payload = _wait_for_status(client, failing_job_id, "failed")
            completed_payload = _wait_for_status(client, succeeding_job_id, "completed")
            assert failed_payload is not None
            assert completed_payload is not None

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            failed_row = connection.execute(
                "SELECT error_code, error_message, stage, completed_at FROM jobs WHERE id = ?",
                (failing_job_id,),
            ).fetchone()
            assert failed_row is not None
            assert failed_row["error_code"] == "plaintext_decode_failed"
            assert "UTF-8" in failed_row["error_message"]
            assert failed_row["stage"] == "failed"
            assert failed_row["completed_at"] is not None

            input_source_id = connection.execute(
                "SELECT input_source_id FROM jobs WHERE id = ?",
                (failing_job_id,),
            ).fetchone()["input_source_id"]
            input_row = connection.execute(
                "SELECT file_class, ingestion_error_code, ingestion_error_message FROM input_sources WHERE id = ?",
                (input_source_id,),
            ).fetchone()
            assert input_row is not None
            assert input_row["file_class"] == "plaintext"
            assert input_row["ingestion_error_code"] == "plaintext_decode_failed"
            assert "UTF-8" in input_row["ingestion_error_message"]


def test_worker_persists_structured_stix_extraction_package(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.job_worker.poll_interval_seconds = 0.01
        response = client.post(
            "/api/v1/jobs",
            files={
                "file": (
                    "bundle.json",
                    (
                        b'{"type":"bundle","id":"bundle--12345678-1234-1234-1234-123456789012",'
                        b'"spec_version":"2.1","objects":[{"type":"report","id":"report--1",'
                        b'"name":"Case Report","description":"Initial access via phishing."},'
                        b'{"type":"attack-pattern","id":"attack-pattern--1",'
                        b'"external_references":[{"source_name":"mitre-attack","external_id":"T1566"}]},'
                        b'{"type":"relationship","id":"relationship--1","relationship_type":"uses",'
                        b'"source_ref":"intrusion-set--1","target_ref":"malware--1"}]}'
                    ),
                    "application/json",
                )
            },
        )
        job_id = response.json()["job_id"]

        completed_payload = _wait_for_status(client, job_id, "completed")
        assert completed_payload is not None

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            assert job_row is not None
            input_row = connection.execute(
                "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
            ).fetchone()
            assert input_row is not None

            assert input_row["stix_bundle_id"] == "bundle--12345678-1234-1234-1234-123456789012"
            assert input_row["stix_spec_version"] == "2.1"
            assert input_row["stix_source_type"] == "stix_bundle"
            assert input_row["stix_object_count"] == 3
            assert input_row["stix_relationship_count"] == 1
            assert input_row["stix_attack_ref_count"] == 1
            assert input_row["normalized_text"] == "Initial access via phishing.\n\nCase Report"
            assert input_row["normalized_source_type"] == "stix_structured"
            assert input_row["normalized_package_json"]

            stix_summary = json.loads(input_row["stix_summary_json"])
            stix_entities = json.loads(input_row["stix_entities_json"])
            stix_relationships = json.loads(input_row["stix_relationships_json"])
            stix_attack_refs = json.loads(input_row["stix_attack_refs_json"])
            stix_provenance = json.loads(input_row["stix_provenance_json"])
            normalized_package = json.loads(input_row["normalized_package_json"])

            assert stix_summary["bundle_metadata"]["id"] == "bundle--12345678-1234-1234-1234-123456789012"
            assert stix_summary["inventory"]["object_count"] == 3
            assert stix_summary["narrative"]["normalized_text"] == "Initial access via phishing.\n\nCase Report"
            assert stix_attack_refs[0]["technique_id"] == "T1566"
            assert any(item["object_type"] == "report" for item in stix_entities)
            assert stix_relationships[0]["relationship_type"] == "uses"
            assert "report--1" in stix_provenance["narrative_source_object_ids"]
            assert normalized_package["source_type"] == "stix_structured"
            assert normalized_package["structured_summary"]["bundle_metadata"]["id"] == "bundle--12345678-1234-1234-1234-123456789012"

            audit_rows = connection.execute(
                "SELECT event_type FROM audit_events WHERE job_id = ? ORDER BY sequence ASC",
                (job_id,),
            ).fetchall()
            event_types = {row["event_type"] for row in audit_rows}
            assert {"file_validated", "file_classified", "stix_parsed", "normalized_package_created", "ai_extraction_input_prepared", "ai_extraction_result", "fusion_completed", "canonical_flow_created", "job_completed"}.issubset(event_types)

        resolved_package = client.app.state.persistence_service.resolve_normalized_package_for_job(job_id)
        assert resolved_package is not None
        assert resolved_package["source_type"] == "stix_structured"
        assert resolved_package["attack_refs"][0]["technique_id"] == "T1566"


def test_worker_persists_stix_extraction_failure_and_continues_next_job(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.job_worker.poll_interval_seconds = 0.01

        with patch(
            "attack_flow_api.services.job_worker_service.build_stix_bundle_inventory_and_narrative"
        ) as mocked_inventory:
            mocked_inventory.side_effect = RuntimeError("inventory boom")

            failing = client.post(
                "/api/v1/jobs",
                files={
                    "file": (
                        "bundle.json",
                        b'{"type":"bundle","id":"bundle--12345678-1234-1234-1234-123456789012","objects":[]}',
                        "application/json",
                    )
                },
            )
            failing_job_id = failing.json()["job_id"]

            succeeding = client.post(
                "/api/v1/jobs",
                json={"input_type": "text", "text": "still works"},
            )
            succeeding_job_id = succeeding.json()["job_id"]

            failed_payload = _wait_for_status(client, failing_job_id, "failed")
            completed_payload = _wait_for_status(client, succeeding_job_id, "completed")
            assert failed_payload is not None
            assert completed_payload is not None

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            failed_row = connection.execute(
                "SELECT error_code, error_message, stage, completed_at FROM jobs WHERE id = ?",
                (failing_job_id,),
            ).fetchone()
            assert failed_row is not None
            assert failed_row["error_code"] == "stix_extraction_failed"
            assert failed_row["error_message"] == "failed to extract structured stix content"
            assert failed_row["stage"] == "failed"
            assert failed_row["completed_at"] is not None

            input_source_id = connection.execute(
                "SELECT input_source_id FROM jobs WHERE id = ?",
                (failing_job_id,),
            ).fetchone()["input_source_id"]
            input_row = connection.execute(
                """
                SELECT file_class, stix_json_valid, stix_parse_error_code, stix_parse_error_message,
                       ingestion_error_code, ingestion_error_message
                FROM input_sources WHERE id = ?
                """,
                (input_source_id,),
            ).fetchone()
            assert input_row is not None
            assert input_row["file_class"] == "stix_json"
            assert input_row["stix_json_valid"] == 0
            assert input_row["stix_parse_error_code"] == "stix_extraction_failed"
            assert input_row["stix_parse_error_message"] == "failed to extract structured stix content"
            assert input_row["ingestion_error_code"] == "stix_extraction_failed"
            assert input_row["ingestion_error_message"] == "failed to extract structured stix content"

            audit_rows = connection.execute(
                "SELECT event_type FROM audit_events WHERE job_id = ? ORDER BY sequence ASC",
                (failing_job_id,),
            ).fetchall()
            event_types = {row["event_type"] for row in audit_rows}
            assert {"file_validated", "file_classified", "job_failed"}.issubset(event_types)


def test_worker_processes_stix_job_asynchronously_through_lifecycle_stages(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        worker = client.app.state.job_worker
        worker.poll_interval_seconds = 0.01
        original_hook = worker._run_stage_hook

        async def delayed_hook(self, job_id: str, stage: str) -> None:
            await asyncio.sleep(0.05)
            await original_hook(job_id, stage)

        worker._run_stage_hook = MethodType(delayed_hook, worker)

        start = time.perf_counter()
        response = client.post(
            "/api/v1/jobs",
            files={
                "file": (
                    "bundle.json",
                    (
                        b'{"type":"bundle","id":"bundle--12345678-1234-1234-1234-123456789012",'
                        b'"spec_version":"2.1","objects":[{"type":"report","id":"report--1",'
                        b'"name":"Case Report","description":"Initial access via phishing."}]}'
                    ),
                    "application/json",
                )
            },
        )
        elapsed = time.perf_counter() - start
        job_id = response.json()["job_id"]

        assert response.status_code == 202
        assert elapsed < 0.2

        saw_intermediate = False
        for _ in range(60):
            payload = client.get(f"/api/v1/jobs/{job_id}").json()
            if payload["status"] in {"extracting", "normalizing"}:
                saw_intermediate = True
                break
            time.sleep(0.03)
        assert saw_intermediate

        completed_payload = _wait_for_status(client, job_id, "completed", max_wait_seconds=6.0)
        assert completed_payload is not None
        assert completed_payload["stage"] == "completed"

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            audit_rows = connection.execute(
                "SELECT event_type FROM audit_events WHERE job_id = ? ORDER BY sequence ASC",
                (job_id,),
            ).fetchall()
            event_types = {row["event_type"] for row in audit_rows}
            assert {"file_validated", "file_classified", "stix_parsed", "normalized_package_created", "ai_extraction_input_prepared", "ai_extraction_result", "fusion_completed", "canonical_flow_created", "job_completed"}.issubset(event_types)
