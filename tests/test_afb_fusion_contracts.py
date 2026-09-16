from attack_flow_api.services.afb_extraction_contracts import (
    AfbExtractionResult,
    AttackFlowMetadata,
    ExtractionValidationState,
    OrchestrationMode,
    SourceClassification,
)
from attack_flow_api.services.afb_fusion_contracts import (
    AiExtractionFusionInput,
    DeterministicFusionInput,
    FUSION_CONFLICT_CATEGORIES,
    FusionConflictCategory,
    FusionConflictRecord,
    FusionFindingProvenance,
    FusionInputBundle,
    FusionInputSourceKind,
    FusionProvenanceKind,
)


def _minimal_extraction() -> AfbExtractionResult:
    return AfbExtractionResult.model_validate(
        {
            "validation_state": ExtractionValidationState.VALID,
            "provider_invoked": True,
            "attack_flow": AttackFlowMetadata(
                id="attack-flow--1",
                name="Example flow",
                scope="incident",
                orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
                source_classification=SourceClassification.MIXED,
            ).model_dump(mode="json"),
        }
    )


def test_fusion_conflict_categories_are_explicit_and_stable() -> None:
    assert FUSION_CONFLICT_CATEGORIES == (
        FusionConflictCategory.DUPLICATE_ATTACK_REF,
        FusionConflictCategory.DUPLICATE_ENTITY,
        FusionConflictCategory.DUPLICATE_STEP,
        FusionConflictCategory.CONFLICTING_DESCRIPTION,
        FusionConflictCategory.CONFLICTING_ATTACHMENT,
        FusionConflictCategory.CONFLICTING_ORDERING,
        FusionConflictCategory.UNSUPPORTED_INFERRED_TECHNIQUE,
        FusionConflictCategory.UNSUPPORTED_BRANCHING_OPERATOR_TYPE,
    )


def test_fusion_input_bundle_preserves_distinct_provenance() -> None:
    deterministic = DeterministicFusionInput(
        provenance={"source": "stix"},
        attack_refs=[{"technique_id": "T1059", "fact_origin": "deterministic_source"}],
    )
    ai = AiExtractionFusionInput(extraction=_minimal_extraction())
    conflict = FusionConflictRecord(
        category=FusionConflictCategory.CONFLICTING_DESCRIPTION,
        source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION,
        message="description differs",
        provenance=[
            FusionFindingProvenance(
                kind=FusionProvenanceKind.DETERMINISTIC,
                source_label="stix",
            ),
            FusionFindingProvenance(
                kind=FusionProvenanceKind.AI_DERIVED,
                source_label="afb",
            ),
        ],
    )

    bundle = FusionInputBundle(deterministic=deterministic, ai=ai, conflicts=[conflict])

    assert bundle.deterministic.source_kind == FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI
    assert bundle.ai.source_kind == FusionInputSourceKind.AI_AFB_EXTRACTION
    assert bundle.conflicts[0].unresolved is True
    assert bundle.conflicts[0].provenance[0].kind == FusionProvenanceKind.DETERMINISTIC
