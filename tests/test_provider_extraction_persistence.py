from pathlib import Path

import json

from attack_flow_api.services.canonical_flow_contracts import (
    CanonicalFlowActionNode,
    CanonicalFlowEdge,
    CanonicalFlowMetadata,
    CanonicalFlowOutput,
    CanonicalFlowProvenanceRecord,
)
from attack_flow_api.services.persistence_service import PersistenceService
from attack_flow_api.storage.database import initialize_database
from attack_flow_api.storage.repositories import JobCreate, JobExtractionUpdate, JobFusionUpdate


def test_update_job_extraction_persists_afb_intermediate_fields(tmp_path: Path) -> None:
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    created = service.create_job(
        JobCreate(
            id="job-afb-1",
            status="queued",
            stage="queued",
        )
    )
    assert created is not None

    extraction_payload = {
        "schema_version": "afb-v2-intermediate",
        "attack_flow": {"id": "attack-flow--1", "name": "Example flow", "scope": "incident", "start_refs": []},
        "attack_actions": [],
    }

    updated = service.update_job_extraction(
        "job-afb-1",
        JobExtractionUpdate(
            extraction_mode="ai_enrichment",
            provider_invoked=True,
            provider_id="default-openai",
            model="gpt-4.1-mini",
            extraction_result_json=json.dumps(extraction_payload),
            extraction_validation_state="valid",
            extraction_repair_attempted=True,
            extraction_provenance_classification="stix_structured",
            extraction_authors_json='["analyst-a"]',
            extraction_external_references_json='["https://example.com/report"]',
        ),
    )

    assert updated is not None
    assert updated.extraction_mode == "ai_enrichment"
    assert updated.provider_invoked is True
    assert updated.provider_id == "default-openai"
    assert updated.model == "gpt-4.1-mini"
    assert updated.extraction_validation_state == "valid"
    assert updated.extraction_repair_attempted is True
    assert updated.extraction_provenance_classification == "stix_structured"
    assert updated.extraction_authors_json == '["analyst-a"]'
    assert updated.extraction_external_references_json == '["https://example.com/report"]'
    assert json.loads(updated.extraction_result_json or "{}")["schema_version"] == "afb-v2-intermediate"


def test_update_job_fusion_persists_fusion_fields(tmp_path: Path) -> None:
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    created = service.create_job(
        JobCreate(
            id="job-fusion-1",
            status="queued",
            stage="queued",
        )
    )
    assert created is not None

    fusion_payload = {
        "schema_version": "attack-flow-fusion-v1",
        "fused": True,
    }

    updated = service.update_job_fusion(
        "job-fusion-1",
        JobFusionUpdate(
            fusion_result_json=json.dumps(fusion_payload),
            fusion_validation_state="pending",
            fusion_provenance_json='{"deterministic":1,"ai":2}',
            fusion_conflicts_json='[{"field":"attack_actions","resolution":"unresolved"}]',
            fusion_attack_refs_json='[{"technique_id":"T1059"}]',
            fusion_entities_json='[{"object_id":"malware--1"}]',
            fusion_relationships_json='[{"relationship_id":"relationship--1"}]',
        ),
    )

    assert updated is not None
    assert updated.fusion_validation_state == "pending"
    assert json.loads(updated.fusion_result_json or "{}") == fusion_payload
    assert updated.fusion_attack_refs_json == '[{"technique_id":"T1059"}]'
    assert updated.fusion_entities_json == '[{"object_id":"malware--1"}]'
    assert updated.fusion_relationships_json == '[{"relationship_id":"relationship--1"}]'


def test_update_job_canonical_flow_persists_canonical_flow_fields(tmp_path: Path) -> None:
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    created = service.create_job(
        JobCreate(
            id="job-canonical-1",
            status="queued",
            stage="queued",
        )
    )
    assert created is not None

    canonical_flow = CanonicalFlowOutput(
        validation_state="ready",
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--1",
            name="Example flow",
            scope="incident",
            authors=["analyst-a"],
            external_references=["https://example.com/report"],
            start_refs=["attack-action--1"],
        ),
        nodes=[
            CanonicalFlowActionNode(
                id="attack-action--1",
                name="Example step",
                description="Observed command exactly as reported.",
                provenance=[
                    CanonicalFlowProvenanceRecord(
                        source_label="fused_output",
                        source_kind="ai_derived",
                        source_object_id="attack-action--1",
                    )
                ],
            )
        ],
        edges=[
            CanonicalFlowEdge(
                source_ref="attack-action--1",
                target_ref="attack-condition--1",
                edge_type="effect",
            )
        ],
        provenance={"source": "fused_output"},
        conflicts=[
            {
                "category": "duplicate_step",
                "source_kind": "ai_afb_extraction",
                "message": "duplicate step",
                "unresolved": True,
            }
        ],
        validation_errors=[
            {
                "code": "example_error",
                "message": "example validation issue",
            }
        ],
    )

    updated = service.persist_canonical_flow_output("job-canonical-1", canonical_flow)

    assert updated is not None
    assert updated.canonical_flow_validation_state == "ready"
    assert json.loads(updated.canonical_flow_json or "{}")["schema_version"] == "attack-flow-canonical-v1"
    assert json.loads(updated.canonical_flow_provenance_json or "{}") == {"source": "fused_output"}
    assert json.loads(updated.canonical_flow_conflicts_json or "[]")[0]["category"] == "duplicate_step"
    assert json.loads(updated.canonical_flow_validation_errors_json or "[]")[0]["code"] == "example_error"
