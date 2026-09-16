from pydantic import ValidationError

from attack_flow_api.services.canonical_flow_contracts import (
    CanonicalFlowActionNode,
    CanonicalFlowAssetNode,
    CanonicalFlowConditionNode,
    CanonicalFlowEdge,
    CanonicalFlowEdgeKind,
    CanonicalFlowMetadata,
    CanonicalFlowNode,
    CanonicalFlowNodeKind,
    CanonicalFlowOperatorNode,
    CanonicalFlowOutput,
    CanonicalFlowProvenanceKind,
    CanonicalFlowProvenanceRecord,
    CanonicalFlowSourceClassification,
    CanonicalFlowValidationCategory,
    CanonicalFlowValidationError,
    CanonicalFlowTechniqueReference,
)


def test_canonical_flow_contract_supports_afb_compatible_node_shapes() -> None:
    metadata = CanonicalFlowMetadata(
        flow_id="attack-flow--1",
        name="Example flow",
        scope="incident",
        start_refs=["attack-action--1"],
        authors=["analyst-a"],
        external_references=["https://example.com/report"],
        provenance={"source_type": "stix_structured"},
    )

    action = CanonicalFlowActionNode(
        id="attack-action--1",
        name="Example step",
        description="Observed command exactly as reported.",
        confidence=0.9,
        technique=CanonicalFlowTechniqueReference(
            technique_id="T1059",
            source_object_id="attack-pattern--1",
            source_classification=CanonicalFlowSourceClassification.STIX_STRUCTURED,
            provenance=[
                CanonicalFlowProvenanceRecord(
                    source_label="deterministic",
                    source_kind=CanonicalFlowProvenanceKind.DETERMINISTIC_SOURCE_FACT,
                    source_object_id="attack-pattern--1",
                )
            ],
        ),
        evidence=[
            {
                "source": "narrative",
                "excerpt": "Observed command exactly as reported.",
            }
        ],
        provenance=[
            CanonicalFlowProvenanceRecord(
                source_label="fused",
                source_kind=CanonicalFlowProvenanceKind.FUSED_CANONICALIZED_OUTPUT,
            )
        ],
    )

    condition = CanonicalFlowConditionNode(
        id="attack-condition--1",
        name="Branch condition",
        description="Observed branch decision exactly as reported.",
        confidence=0.8,
        condition_value="true",
        on_true_refs=["attack-operator--1"],
        evidence=[
            {
                "source": "narrative",
                "excerpt": "Observed branch decision exactly as reported.",
            }
        ],
    )

    operator = CanonicalFlowOperatorNode(
        id="attack-operator--1",
        name="AND branch",
        confidence=0.7,
        operator="AND",
        effect_refs=["attack-action--1"],
    )

    asset = CanonicalFlowAssetNode(
        id="attack-asset--1",
        name="Host asset",
        object_ref="malware--1",
        confidence=0.6,
    )

    output = CanonicalFlowOutput(
        metadata=metadata,
        nodes=[action, condition, operator, asset],
        edges=[
            CanonicalFlowEdge(
                source_ref="attack-action--1",
                target_ref="attack-condition--1",
                edge_type=CanonicalFlowEdgeKind.EFFECT,
            )
        ],
        validation_state="pending",
        provenance={"source": "fused_output"},
        conflicts=[],
        validation_errors=[
            CanonicalFlowValidationError(
                code="example_validation_error",
                message="example validation issue",
                category=CanonicalFlowValidationCategory.INVALID_REFERENCE,
            )
        ],
    )

    payload = output.to_json_ready()

    assert payload["metadata"]["start_refs"] == ["attack-action--1"]
    assert payload["metadata"]["authors"] == ["analyst-a"]
    assert payload["metadata"]["external_references"] == ["https://example.com/report"]
    assert payload["nodes"][0]["node_kind"] == CanonicalFlowNodeKind.ATTACK_ACTION.value
    assert payload["nodes"][1]["condition_value"] == "true"
    assert payload["nodes"][2]["operator"] == "AND"
    assert payload["edges"][0]["edge_type"] == CanonicalFlowEdgeKind.EFFECT.value
    assert payload["validation_errors"][0]["category"] == CanonicalFlowValidationCategory.INVALID_REFERENCE.value
    assert payload["nodes"][0]["technique"]["confidence"] == 1.0


def test_canonical_flow_provenance_kinds_are_explicit() -> None:
    assert CanonicalFlowProvenanceKind.DETERMINISTIC_SOURCE_FACT.value == "deterministic_source_fact"
    assert CanonicalFlowProvenanceKind.AI_ASSISTED_ADDITION.value == "ai_assisted_addition"
    assert CanonicalFlowProvenanceKind.FUSED_CANONICALIZED_OUTPUT.value == "fused_canonicalized_output"
    assert CanonicalFlowProvenanceKind.USER_METADATA.value == "user_metadata"


def test_canonical_flow_operator_and_condition_constraints_are_explicit() -> None:
    try:
        CanonicalFlowOperatorNode(id="attack-operator--2", operator="XOR", confidence=0.5)
        raise AssertionError("operator validation should have failed")
    except ValidationError:
        pass

    try:
        CanonicalFlowConditionNode(
            id="attack-condition--2",
            condition_value="maybe",
            confidence=0.5,
        )
        raise AssertionError("condition validation should have failed")
    except ValidationError:
        pass
