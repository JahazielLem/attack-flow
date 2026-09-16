from attack_flow_api.services.afb_extraction_contracts import (
    AttackFlowMetadata,
    AttackActionNode,
    AfbExtractionResult,
    AttackAssetNode,
    AttackOperatorNode,
    OrchestrationMode,
    SourceClassification,
)
from attack_flow_api.services.afb_export_contracts import assemble_afb_export_bundle
from attack_flow_api.services.afb_fusion_assembler import (
    FusedOutputCandidate,
    build_fused_output_candidate,
    build_fused_output_candidate_from_sources,
)
from attack_flow_api.services.afb_fusion_contracts import (
    FusionConflictCategory,
    FusionConflictRecord,
    FusionInputSourceKind,
)
from attack_flow_api.services.afb_fusion_dedup import (
    MergedAttackAction,
    MergedAttackRef,
    MergedAttachmentBundle,
    MergedEntity,
    MergedRelationship,
    MergedOperator,
)
from attack_flow_api.services.ai_orchestration_planner import build_provider_orchestration_input
from attack_flow_api.services.ai_output_validation_service import parse_validate_and_repair_extraction_output
from attack_flow_api.services.ai_provider_invocation_service import ProviderInvocationResult
from attack_flow_api.services.canonical_flow_conversion_service import build_canonical_flow_output
from attack_flow_api.services.persistence_service import PersistenceService
from attack_flow_api.storage.database import initialize_database
from attack_flow_api.storage.repositories import JobCreate
from pathlib import Path


def test_build_fused_output_candidate_assembles_downstream_ready_shape() -> None:
    attack_flow = AttackFlowMetadata(
        id="attack-flow--1",
        name="Example flow",
        scope="incident",
        orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
        source_classification=SourceClassification.STIX_STRUCTURED,
        authors=["analyst-a"],
        external_references=["https://example.com/a"],
    )
    attack_refs = [
        MergedAttackRef(
            technique_id="T1059",
            source_object_id="attack-pattern--1",
            confidence=1.0,
        )
    ]
    entities = [
        MergedEntity(
            object_id="malware--1",
            object_type="malware",
            display_name="Malware",
            confidence=0.8,
        )
    ]
    relationships = [
        MergedRelationship(
            relationship_id="relationship--1",
            relationship_type="uses",
            source_ref="threat-actor--1",
            target_ref="malware--1",
            source_object_type="threat-actor",
            confidence=1.0,
        )
    ]
    actions = [
        MergedAttackAction(
            id="attack-action--1",
            name="Deterministic step",
            description="Observed command exactly as reported.",
            confidence=0.9,
            object_refs=["malware--1"],
            evidence=[
                {
                    "source": "narrative",
                    "excerpt": "Observed command exactly as reported.",
                }
            ],
        )
    ]
    attachment_bundle = MergedAttachmentBundle(
        attack_flow_authors=["analyst-a", "analyst-b"],
        attack_flow_external_references=["https://example.com/a", "https://example.com/b"],
        attack_actions=actions,
        attack_assets=entities,
        preserved_object_refs=["malware--1", "threat-actor--1"],
        preserved_evidence_refs=["report--1"],
    )

    candidate = build_fused_output_candidate(
        attack_flow=attack_flow,
        attack_refs=attack_refs,
        entities=entities,
        relationships=relationships,
        attack_actions=actions,
        attack_conditions=[],
        attack_operators=[],
        attachment_bundle=attachment_bundle,
        conflicts=[
            FusionConflictRecord(
                category=FusionConflictCategory.DUPLICATE_ATTACK_REF,
                source_kind=FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                message="duplicate attack ref",
                deterministic_ref="attack-pattern--1",
                unresolved=True,
            )
        ],
    )

    payload = candidate.to_json_ready()
    assert payload["schema_version"] == "afb-v2-fused-candidate"
    assert payload["fusion_validation_state"] == "ready"
    assert payload["attack_flow"]["authors"] == ["analyst-a", "analyst-b"]
    assert payload["attack_flow"]["external_references"] == ["https://example.com/a", "https://example.com/b"]
    assert payload["attack_refs"][0]["technique_id"] == "T1059"
    assert payload["entities"][0]["object_id"] == "malware--1"
    assert payload["relationships"][0]["relationship_id"] == "relationship--1"
    assert payload["attack_actions"][0]["description"] == "Observed command exactly as reported."
    assert payload["attack_assets"][0]["object_id"] == "malware--1"
    assert payload["source_grounded_attachments"]["preserved_object_refs"] == ["malware--1", "threat-actor--1"]
    assert payload["provenance"]["relationship_ids"] == ["relationship--1"]
    assert payload["conflicts"][0]["category"] == "duplicate_attack_ref"


def test_build_fused_output_candidate_accepts_attack_assets_without_object_type() -> None:
    attack_flow = AttackFlowMetadata(
        id="attack-flow--asset",
        name="Asset example",
        scope="incident",
        orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
        source_classification=SourceClassification.STIX_STRUCTURED,
    )

    extraction_result = AfbExtractionResult(
        validation_state="valid",
        provider_invoked=True,
        attack_flow=attack_flow,
        attack_assets=[
            AttackAssetNode(
                id="attack-asset--1",
                name="Runtime artifact",
                confidence=0.5,
            )
        ],
    )

    candidate = build_fused_output_candidate_from_sources(normalized_package={}, extraction_result=extraction_result)

    payload = candidate.to_json_ready()
    assert payload["attack_assets"][0]["object_type"] == "attack-asset"


def test_fusion_preserves_extracted_entity_details_for_action_assets() -> None:
    attack_flow = AttackFlowMetadata(
        id="attack-flow--entities",
        name="Entity example",
        scope="incident",
        orchestration_mode=OrchestrationMode.FULL_EXTRACTION,
        source_classification=SourceClassification.DOCUMENT_EXTRACTED_TEXT,
    )
    extraction_result = AfbExtractionResult(
        validation_state="valid",
        provider_invoked=True,
        attack_flow=attack_flow,
        attack_actions=[
            AttackActionNode(
                id="attack-action--1",
                name="Run PowerShell",
                description="The actor executed PowerShell.",
                confidence=0.9,
                object_refs=["software-1"],
            )
        ],
        deterministic_entities=[
            {
                "object_id": "software-1",
                "object_type": "software",
                "display_name": "PowerShell",
                "description": "Microsoft command-line shell used by the actor.",
            }
        ],
    )

    fused = build_fused_output_candidate_from_sources(
        normalized_package={},
        extraction_result=extraction_result,
    )
    canonical = build_canonical_flow_output(fused_output=fused)

    assert fused.entities[0].object_id == "software-1"
    assert fused.entities[0].display_name == "PowerShell"
    assert canonical is not None
    asset = next(node for node in canonical.nodes if node.id == "software-1")
    assert asset.name == "PowerShell"
    assert asset.description == "Microsoft command-line shell used by the actor."


def test_provider_assets_and_relationships_survive_fusion_and_canonical_conversion() -> None:
    packaged = build_provider_orchestration_input(
        {
            "source_type": "plaintext",
            "normalized_text": "The actor deployed Beacon to the target host.",
            "structured_summary": {},
        }
    )
    provider_output = {
        "validation_state": "valid",
        "provider_invoked": True,
        "attack_flow": {
            "id": "attack-flow--provider",
            "name": "Provider flow",
            "scope": "incident",
            "start_refs": ["attack-action--deploy"],
            "orchestration_mode": "full_extraction",
            "source_classification": "narrative_text",
        },
        "attack_actions": [
            {
                "id": "attack-action--deploy",
                "name": "Deploy Beacon",
                "description": "The actor deployed Beacon to the target host.",
                "confidence": 0.91,
                "asset_refs": ["attack-asset--beacon"],
                "evidence": [
                    {"source": "provider", "excerpt": "The actor deployed Beacon to the target host."}
                ],
            }
        ],
        "attack_assets": [
            {
                "id": "attack-asset--beacon",
                "name": "Beacon payload",
                "description": "Beacon",
                "object_ref": "malware--beacon",
                "tags": ["payload", "c2"],
                "confidence": 0.87,
                "evidence": [{"source": "provider", "excerpt": "Beacon"}],
            }
        ],
        "deterministic_entities": [
            {
                "object_id": "malware--beacon",
                "object_type": "malware",
                "display_name": "Beacon",
            },
            {
                "object_id": "threat-actor--operator",
                "object_type": "threat-actor",
                "display_name": "Operator",
            },
        ],
        "deterministic_relationships": [
            {
                "relationship_id": "relationship--uses-beacon",
                "relationship_type": "uses",
                "source_ref": "threat-actor--operator",
                "target_ref": "malware--beacon",
                "source_object_type": "threat-actor",
            }
        ],
    }
    validation = parse_validate_and_repair_extraction_output(
        invocation_result=ProviderInvocationResult(
            provider_invoked=True,
            provider_id="test-provider",
            model_used="test-model",
            deterministic_input_sufficient=False,
            output_json=provider_output,
        ),
        packaged_input=packaged,
    )

    assert validation.valid is True
    assert validation.extraction_result is not None
    fused = build_fused_output_candidate_from_sources(
        normalized_package={},
        extraction_result=validation.extraction_result,
    )
    canonical = build_canonical_flow_output(fused_output=fused)

    assert canonical is not None
    fused_asset = fused.attack_assets[0]
    assert fused_asset.object_id == "attack-asset--beacon"
    assert fused_asset.display_name == "Beacon payload"
    assert fused_asset.object_ref == "malware--beacon"
    assert fused_asset.tags == ["payload", "c2"]
    assert fused_asset.confidence == 0.87
    assert fused_asset.evidence[0]["excerpt"] == "Beacon"
    assert fused.attack_actions[0].asset_refs == ["attack-asset--beacon"]
    assert fused.relationships[0].relationship_id == "relationship--uses-beacon"

    asset = next(node for node in canonical.nodes if node.id == "attack-asset--beacon")
    assert asset.name == "Beacon payload"
    assert asset.object_ref == "malware--beacon"
    assert asset.tags == ["payload", "c2"]
    assert asset.confidence == 0.87
    assert asset.evidence[0].excerpt == "Beacon"
    assert any(
        edge.source_ref == "attack-action--deploy"
        and edge.target_ref == "attack-asset--beacon"
        and edge.edge_type.value == "asset"
        for edge in canonical.edges
    )
    assert any(
        edge.source_ref == "threat-actor--operator"
        and edge.target_ref == "malware--beacon"
        and edge.relationship_type == "uses"
        for edge in canonical.edges
    )
    diagram_export = assemble_afb_export_bundle(canonical).to_diagram_export_ready()
    assert "layout" not in diagram_export
    assert "generated_layout" not in diagram_export
    assert any(
        item.get("id") == "dynamic_line"
        and ["relationship_type", "uses"] in item.get("properties", [])
        for item in diagram_export["objects"]
    )


def test_fused_output_candidate_remains_compatible_with_constrained_canonical_model() -> None:
    attack_flow = AttackFlowMetadata(
        id="attack-flow--2",
        name="Example flow",
        scope="incident",
        orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
        source_classification=SourceClassification.STIX_STRUCTURED,
    )

    candidate = build_fused_output_candidate(attack_flow=attack_flow)
    round_tripped = FusedOutputCandidate.model_validate_json(candidate.model_dump_json())

    assert round_tripped.schema_version == "afb-v2-fused-candidate"
    assert round_tripped.fusion_validation_state == "ready"
    assert round_tripped.attack_flow.id == "attack-flow--2"


def test_build_fused_output_candidate_backfills_operator_provenance() -> None:
    attack_flow = AttackFlowMetadata(
        id="attack-flow--operator",
        name="Example flow",
        scope="incident",
        orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
        source_classification=SourceClassification.STIX_STRUCTURED,
    )

    extraction_result = AfbExtractionResult(
        validation_state="valid",
        provider_invoked=True,
        attack_flow=attack_flow,
        attack_operators=[
            AttackOperatorNode(
                id="operator--1",
                operator="OR",
                confidence=0.5,
                evidence=[{"source": "legacy_output", "excerpt": "A or B"}],
            )
        ],
    )

    candidate = build_fused_output_candidate_from_sources(normalized_package={}, extraction_result=extraction_result)

    payload = candidate.to_json_ready()
    assert payload["attack_operators"][0]["provenance"][0]["source_label"] == "ai_generated"


def test_persist_fused_output_candidate_writes_job_fusion_fields(tmp_path: Path) -> None:
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)
    service.create_job(JobCreate(id="job-1", status="queued", stage="queued"))

    attack_flow = AttackFlowMetadata(
        id="attack-flow--1",
        name="Example flow",
        scope="incident",
        orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
        source_classification=SourceClassification.STIX_STRUCTURED,
    )
    candidate = build_fused_output_candidate(attack_flow=attack_flow)

    updated = service.persist_fused_output_candidate("job-1", candidate)

    assert updated is not None
    assert updated.fusion_validation_state == "ready"
    assert updated.fusion_result_json is not None
    assert updated.fusion_result_json.startswith("{")
    assert updated.fusion_provenance_json is not None
    assert updated.fusion_conflicts_json == "[]"
