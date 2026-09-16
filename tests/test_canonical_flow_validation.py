from attack_flow_api.services.afb_extraction_contracts import (
    AfbExtractionResult,
    AttackActionNode,
    AttackConditionNode,
    AttackFlowMetadata,
    AttackOperatorNode,
    AttackOperatorType,
    ConditionValue,
    ExtractionValidationState,
    FactOrigin,
    OrchestrationMode,
    SourceClassification,
    TechniqueGrounding,
)
from attack_flow_api.services.afb_fusion_assembler import build_fused_output_candidate_from_sources
from attack_flow_api.services.afb_fusion_assembler import FusedOutputCandidate
from attack_flow_api.services.afb_fusion_contracts import FusionFindingProvenance, FusionProvenanceKind
from attack_flow_api.services.afb_fusion_dedup import MergedAttackAction, MergedAttackRef, MergedAttachmentBundle, MergedCondition, MergedEntity, MergedOperator, MergedRelationship
from attack_flow_api.services.canonical_flow_conversion_service import build_canonical_flow_output
from attack_flow_api.services.canonical_flow_contracts import CanonicalFlowEdge, CanonicalFlowEdgeKind
from attack_flow_api.services.canonical_flow_validation_service import validate_canonical_flow_output


def _build_fused_canonical() -> FusedOutputCandidate:
    return FusedOutputCandidate(
        attack_flow=AttackFlowMetadata(
            id="attack-flow--1",
            name="Example flow",
            scope="incident",
            description="Flow description.",
            orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
            source_classification=SourceClassification.STIX_STRUCTURED,
            start_refs=["attack-action--1"],
            authors=["analyst-a"],
            external_references=["https://example.com/report"],
            provenance={"source": "fused"},
        ),
        attack_refs=[
            MergedAttackRef(
                technique_id="T1059",
                source_object_id="attack-pattern--1",
                source_field="external_references[0]",
                external_source_name="ATT&CK",
                external_url="https://attack.mitre.org/techniques/T1059/",
                confidence=1.0,
                deterministic_confidence=0.87,
                ai_confidences=[],
                provenance=[
                    FusionFindingProvenance(
                        kind=FusionProvenanceKind.DETERMINISTIC,
                        source_label="deterministic-stix",
                        source_object_id="attack-pattern--1",
                        source_field="external_references[0]",
                        confidence=0.87,
                    )
                ],
            )
        ],
        entities=[
            MergedEntity(
                object_id="malware--1",
                object_type="malware",
                display_name="Malware",
                description="Asset description.",
                confidence=0.8,
                provenance=[
                    FusionFindingProvenance(
                        kind=FusionProvenanceKind.DETERMINISTIC,
                        source_label="deterministic-stix",
                        source_object_id="malware--1",
                    )
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
                confidence=1.0,
                provenance=[
                    FusionFindingProvenance(
                        kind=FusionProvenanceKind.DETERMINISTIC,
                        source_label="deterministic-stix",
                        source_object_id="relationship--1",
                    )
                ],
            )
        ],
        attack_actions=[
            MergedAttackAction(
                id="attack-action--1",
                name="Example step",
                description="Observed command exactly as reported.",
                confidence=0.9,
                asset_refs=["malware--1"],
                effect_refs=["attack-condition--1"],
                evidence=[{"source": "narrative", "excerpt": "Observed command exactly as reported."}],
                provenance=[
                    FusionFindingProvenance(
                        kind=FusionProvenanceKind.DETERMINISTIC,
                        source_label="deterministic-stix",
                        source_object_id="attack-action--1",
                    )
                ],
            )
        ],
        attack_conditions=[
            MergedCondition(
                id="attack-condition--1",
                description="Observed branch decision exactly as reported.",
                value="true",
                confidence=0.8,
                on_true_refs=["attack-operator--1"],
                evidence=[{"source": "narrative", "excerpt": "Observed branch decision exactly as reported."}],
                provenance=[
                    FusionFindingProvenance(
                        kind=FusionProvenanceKind.AI_DERIVED,
                        source_label="afb",
                        source_object_id="attack-condition--1",
                    )
                ],
            )
        ],
        attack_operators=[
            MergedOperator(
                id="attack-operator--1",
                operator="AND",
                confidence=0.7,
                effect_refs=["attack-action--1"],
                evidence=[{"source": "narrative", "excerpt": "Observed branching exactly as reported."}],
                provenance=[
                    FusionFindingProvenance(
                        kind=FusionProvenanceKind.AI_DERIVED,
                        source_label="afb",
                        source_object_id="attack-operator--1",
                    )
                ],
            )
        ],
        attack_assets=[],
        source_grounded_attachments=MergedAttachmentBundle(
            attack_flow_authors=["analyst-a"],
            attack_flow_external_references=["https://example.com/report"],
            attack_actions=[],
            attack_assets=[],
            preserved_object_refs=["malware--1"],
            preserved_evidence_refs=["report--1"],
        ),
        provenance={"source": "fused"},
        conflicts=[],
    )


def _build_afb_extraction_canonical() -> AfbExtractionResult:
    return AfbExtractionResult.model_validate(
        {
            "validation_state": ExtractionValidationState.VALID,
            "provider_invoked": True,
            "attack_flow": AttackFlowMetadata(
                id="attack-flow--afb",
                name="AFB flow",
                scope="incident",
                description="AFB flow description.",
                orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
                source_classification=SourceClassification.STIX_STRUCTURED,
                start_refs=["attack-action--afb"],
                authors=["analyst-b"],
                external_references=["https://example.com/afb"],
                provenance={"source": "afb"},
            ).model_dump(mode="json"),
            "attack_actions": [
                AttackActionNode(
                    id="attack-action--afb",
                    name="AFB step",
                    description="Observed command exactly as reported.",
                    confidence=0.75,
                    technique=TechniqueGrounding(
                        technique_id="T1059",
                        technique_name="Command and Scripting Interpreter",
                        confidence=0.75,
                        grounded_by="explicit_attack_id_in_source",
                    ),
                    evidence=[{"source": "narrative", "excerpt": "Observed command exactly as reported."}],
                    citations=["report-2"],
                    fact_origin=FactOrigin.DETERMINISTIC_SOURCE,
                ).model_dump(mode="json"),
            ],
            "attack_conditions": [
                AttackConditionNode(
                    id="attack-condition--afb",
                    description="Observed branch decision exactly as reported.",
                    value=ConditionValue.TRUE,
                    confidence=0.6,
                    on_true_refs=["attack-operator--afb"],
                    evidence=[{"source": "narrative", "excerpt": "Observed branch decision exactly as reported."}],
                    fact_origin=FactOrigin.AI_GENERATED,
                ).model_dump(mode="json"),
            ],
            "attack_operators": [
                AttackOperatorNode(
                    id="attack-operator--afb",
                    operator=AttackOperatorType.AND,
                    confidence=0.5,
                    effect_refs=["attack-action--afb"],
                    evidence=[{"source": "narrative", "excerpt": "Observed branching exactly as reported."}],
                    fact_origin=FactOrigin.AI_GENERATED,
                ).model_dump(mode="json"),
            ],
            "attack_assets": [],
            "deterministic_attack_refs": [{"technique_id": "T1059", "source_object_id": "attack-pattern--afb", "source_field": "external_references[0]"}],
            "deterministic_relationships": [{"relationship_id": "relationship--afb", "relationship_type": "uses", "source_ref": "threat-actor--afb", "target_ref": "malware--afb", "source_object_type": "threat-actor"}],
        }
    )


def test_canonical_flow_validation_passes_for_valid_fused_output() -> None:
    canonical = build_canonical_flow_output(fused_output=_build_fused_canonical())

    result = validate_canonical_flow_output(canonical)

    assert result.valid is True
    assert result.canonical_flow is not None
    assert result.errors == []


def test_canonical_flow_validation_rejects_invalid_start_ref() -> None:
    canonical = build_canonical_flow_output(fused_output=_build_fused_canonical())
    invalid = canonical.model_copy(update={"metadata": canonical.metadata.model_copy(update={"start_refs": ["attack-operator--1"]})})

    result = validate_canonical_flow_output(invalid)

    assert result.valid is False
    assert any(item.code == "start_ref_invalid_node_kind" for item in result.errors)


def test_canonical_flow_validation_rejects_edges_with_missing_nodes() -> None:
    canonical = build_canonical_flow_output(fused_output=_build_fused_canonical())
    invalid = canonical.model_copy(
        update={
            "edges": [
                *canonical.edges,
                CanonicalFlowEdge(
                    source_ref="attack-action--missing",
                    target_ref="attack-action--1",
                    edge_type=CanonicalFlowEdgeKind.EFFECT,
                ),
            ]
        }
    )

    result = validate_canonical_flow_output(invalid)

    assert result.valid is False
    assert any(item.code == "edge_source_missing_node" for item in result.errors)


def test_canonical_flow_validation_rejects_missing_action_provenance() -> None:
    canonical = build_canonical_flow_output(fused_output=_build_fused_canonical())
    invalid_nodes = list(canonical.nodes)
    invalid_nodes[1] = invalid_nodes[1].model_copy(update={"provenance": []})
    invalid = canonical.model_copy(update={"nodes": invalid_nodes})

    result = validate_canonical_flow_output(invalid)

    assert result.valid is False
    assert any(item.code == "action_missing_provenance" for item in result.errors)


def test_fused_action_without_explicit_provenance_is_backfilled_from_fact_origin() -> None:
    extraction = AfbExtractionResult.model_validate(
        {
            "validation_state": ExtractionValidationState.VALID,
            "provider_invoked": True,
            "attack_flow": AttackFlowMetadata(
                id="attack-flow--fused",
                name="Example flow",
                scope="incident",
                orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
                source_classification=SourceClassification.DOCUMENT_EXTRACTED_TEXT,
                start_refs=["attack-action--1"],
                provenance={"source": "ai"},
            ).model_dump(mode="json"),
            "attack_actions": [
                AttackActionNode(
                    id="attack-action--1",
                    name="Example step",
                    description="Observed command exactly as reported.",
                    confidence=0.5,
                    evidence=[{"source": "narrative", "excerpt": "Observed command exactly as reported."}],
                    fact_origin=FactOrigin.AI_GENERATED,
                ).model_dump(mode="json")
            ],
            "attack_conditions": [],
            "attack_operators": [],
            "attack_assets": [],
        }
    )

    fused = build_fused_output_candidate_from_sources(
        normalized_package={
            "authors": ["analyst-a"],
            "external_references": ["https://example.com/report"],
            "provenance": {"source": "normalized"},
        },
        extraction_result=extraction,
    )

    canonical = build_canonical_flow_output(fused_output=fused)
    result = validate_canonical_flow_output(canonical)

    assert result.valid is True
    assert canonical.nodes[0].provenance or canonical.nodes[1].provenance


def test_canonical_flow_validation_rejects_ungrounded_attachment_refs() -> None:
    canonical = build_canonical_flow_output(fused_output=_build_fused_canonical())
    invalid_nodes = list(canonical.nodes)
    invalid_nodes[1] = invalid_nodes[1].model_copy(update={"asset_refs": ["attack-asset--missing"]})
    invalid = canonical.model_copy(update={"nodes": invalid_nodes})

    result = validate_canonical_flow_output(invalid)

    assert result.valid is False
    assert any(item.code == "non_source_grounded_attachment" for item in result.errors)


def test_canonical_flow_validation_rejects_invalid_operator_and_condition_schema() -> None:
    canonical = build_canonical_flow_output(extraction_output=_build_afb_extraction_canonical())
    payload = canonical.model_dump(mode="json")
    payload["nodes"][2]["operator"] = "XOR"
    payload["nodes"][1]["condition_value"] = "maybe"

    result = validate_canonical_flow_output(payload)

    assert result.valid is False
    assert result.errors[0].code == "canonical_flow_schema_invalid"
