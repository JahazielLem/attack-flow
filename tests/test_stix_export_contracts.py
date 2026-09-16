import json

from attack_flow_api.services.stix_export_contracts import (
    StixExportAttackAssetObject,
    StixExportAttackConditionObject,
    StixExportAttackOperatorObject,
    StixExportAttackActionObject,
    StixExportAttackFlowObject,
    StixExportBundle,
    StixExportBundleMetadata,
    StixExportObjectCollection,
    StixExportValidationError,
    build_attack_action_objects,
    build_attack_asset_objects,
    build_attack_condition_objects,
    build_attack_flow_root_object,
    build_attack_operator_objects,
    assemble_stix_export_bundle,
    build_stix_export_bundle,
    build_stix_export_bundle_metadata,
    validate_stix_export_bundle,
)
from attack_flow_api.services.canonical_flow_contracts import (
    CanonicalFlowActionNode,
    CanonicalFlowAssetNode,
    CanonicalFlowConditionNode,
    CanonicalFlowMetadata,
    CanonicalFlowOutput,
    CanonicalFlowOperatorNode,
    CanonicalFlowTechniqueReference,
)


def test_build_stix_export_bundle_metadata_sets_bundle_shape() -> None:
    metadata = build_stix_export_bundle_metadata("bundle--export-1")

    assert metadata.type == "bundle"
    assert metadata.id == "bundle--export-1"
    assert metadata.spec_version == "2.1"


def test_build_stix_export_bundle_initializes_empty_objects() -> None:
    bundle = build_stix_export_bundle("bundle--export-1")

    assert isinstance(bundle, StixExportBundle)
    assert isinstance(bundle.metadata, StixExportBundleMetadata)
    assert isinstance(bundle.objects, StixExportObjectCollection)
    assert bundle.objects.objects == []
    assert bundle.validation_errors == []
    assert bundle.to_json_ready() == {
        "type": "bundle",
        "id": "bundle--export-1",
        "spec_version": "2.1",
        "objects": [],
    }


def test_build_stix_export_bundle_metadata_preserves_context_when_provided() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--ctx",
            name="Example flow",
            scope="incident",
            authors=["analyst-a"],
            external_references=["https://example.com/report"],
            start_refs=[],
        ),
        nodes=[
            CanonicalFlowAssetNode(
                id="attack-asset--ctx",
                name="Host asset",
                object_ref="malware--ctx",
            )
        ],
        edges=[],
        provenance={"source": "fused"},
        conflicts=[],
        validation_errors=[],
    )

    metadata = build_stix_export_bundle_metadata("bundle--export-ctx", canonical_flow=canonical)

    assert metadata.authors == ["analyst-a"]
    assert metadata.external_references == ["https://example.com/report"]
    assert metadata.provenance == {"source": "fused"}
    assert metadata.supporting_object_refs == ["malware--ctx"]


def test_stix_export_validation_error_model_is_explicit() -> None:
    error = StixExportValidationError(code="bundle_invalid", message="bundle shape invalid")

    assert error.code == "bundle_invalid"
    assert error.message == "bundle shape invalid"
    assert error.details == {}


def test_build_attack_flow_root_object_maps_metadata_conservatively() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--1",
            name="Example flow",
            scope="incident",
            description="  Example flow description.  ",
            external_references=["https://example.com/report"],
            start_refs=["attack-action--1"],
        ),
        nodes=[],
        edges=[],
        provenance={},
        conflicts=[],
        validation_errors=[],
    )

    root = build_attack_flow_root_object(canonical)

    assert isinstance(root, StixExportAttackFlowObject)
    assert root.type == "attack-flow"
    assert root.spec_version == "2.1"
    assert root.id == "attack-flow--1"
    assert root.name == "Example flow"
    assert root.description == "Example flow description."
    assert root.scope == "incident"
    assert root.start_refs == []
    assert root.external_references == [
        {
            "source_name": "example.com",
            "url": "https://example.com/report",
        }
    ]
    assert root.extensions == {
        "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4": {
            "extension_type": "new-sdo"
        }
    }


def test_build_attack_flow_root_object_omits_blank_description() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--2",
            name="Example flow",
            scope="incident",
            description="   ",
            start_refs=[],
        ),
        nodes=[],
        edges=[],
        provenance={},
        conflicts=[],
        validation_errors=[],
    )

    root = build_attack_flow_root_object(canonical)

    assert root.description is None


def test_build_attack_action_objects_preserves_explicit_fields() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--1",
            name="Example flow",
            scope="incident",
            start_refs=[],
        ),
        nodes=[
            CanonicalFlowActionNode(
                id="attack-action--1",
                name="Example step",
                description="Observed command exactly as reported.",
                technique=CanonicalFlowTechniqueReference(
                    technique_id="T1059",
                    technique_ref="attack-pattern--1",
                    source_object_id="attack-pattern--1",
                ),
                tactic_ref="x-mitre-tactic--1",
                asset_refs=["attack-asset--1"],
                effect_refs=["condition-1"],
            )
        ],
        edges=[],
        provenance={},
        conflicts=[],
        validation_errors=[],
    )

    actions = build_attack_action_objects(canonical)

    assert len(actions) == 1
    action = actions[0]
    assert isinstance(action, StixExportAttackActionObject)
    assert action.id == "attack-action--1"
    assert action.name == "Example step"
    assert action.description == "Observed command exactly as reported."
    assert action.technique_id == "T1059"
    assert action.technique_ref == "attack-pattern--1"
    assert action.tactic_id is None
    assert action.tactic_ref == "x-mitre-tactic--1"
    assert action.asset_refs == ["attack-asset--1"]
    assert action.effect_refs == ["condition-1"]
    assert action.extensions == {
        "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4": {
            "extension_type": "new-sdo"
        }
    }


def test_build_attack_action_objects_allows_missing_technique_mapping() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--2",
            name="Example flow",
            scope="incident",
            start_refs=[],
        ),
        nodes=[
            CanonicalFlowActionNode(
                id="attack-action--2",
                name="Unmapped step",
                description="Observed command exactly as reported.",
                asset_refs=[],
                effect_refs=[],
            )
        ],
        edges=[],
        provenance={},
        conflicts=[],
        validation_errors=[],
    )

    actions = build_attack_action_objects(canonical)

    assert len(actions) == 1
    action = actions[0]
    assert action.technique_id is None
    assert action.technique_ref is None
    assert action.description == "Observed command exactly as reported."
    assert action.asset_refs == []
    assert action.effect_refs == []


def test_build_attack_condition_objects_preserves_branching_refs() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--3",
            name="Example flow",
            scope="incident",
            start_refs=[],
        ),
        nodes=[
            CanonicalFlowConditionNode(
                id="attack-condition--1",
                description="Observed branch decision exactly as reported.",
                condition_value="true",
                on_true_refs=["operator-1"],
                on_false_refs=["action-2"],
            )
        ],
        edges=[],
        provenance={},
        conflicts=[],
        validation_errors=[],
    )

    conditions = build_attack_condition_objects(canonical)

    assert len(conditions) == 1
    condition = conditions[0]
    assert isinstance(condition, StixExportAttackConditionObject)
    assert condition.id == "attack-condition--1"
    assert condition.description == "Observed branch decision exactly as reported."
    assert condition.on_true_refs == ["operator-1"]
    assert condition.on_false_refs == ["action-2"]
    assert condition.extensions == {
        "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4": {
            "extension_type": "new-sdo"
        }
    }


def test_build_attack_operator_objects_preserves_boolean_operator() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--4",
            name="Example flow",
            scope="incident",
            start_refs=[],
        ),
        nodes=[
            CanonicalFlowOperatorNode(
                id="attack-operator--1",
                operator="AND",
                effect_refs=["action-1"],
            )
        ],
        edges=[],
        provenance={},
        conflicts=[],
        validation_errors=[],
    )

    operators = build_attack_operator_objects(canonical)

    assert len(operators) == 1
    operator = operators[0]
    assert isinstance(operator, StixExportAttackOperatorObject)
    assert operator.id == "attack-operator--1"
    assert operator.operator == "AND"
    assert operator.effect_refs == ["action-1"]


def test_build_attack_operator_objects_allows_or_operator() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--4b",
            name="Example flow",
            scope="incident",
            start_refs=[],
        ),
        nodes=[
            CanonicalFlowOperatorNode(
                id="attack-operator--2",
                operator="OR",
                effect_refs=["attack-condition--1"],
            )
        ],
        edges=[],
        provenance={},
        conflicts=[],
        validation_errors=[],
    )

    operators = build_attack_operator_objects(canonical)

    assert len(operators) == 1
    assert operators[0].operator == "OR"


def test_build_attack_asset_objects_preserves_object_ref_context() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--5",
            name="Example flow",
            scope="incident",
            start_refs=[],
        ),
        nodes=[
            CanonicalFlowAssetNode(
                id="attack-asset--1",
                name="Host asset",
                description="Observed asset context exactly as reported.",
                object_ref="malware--1",
            )
        ],
        edges=[],
        provenance={},
        conflicts=[],
        validation_errors=[],
    )

    assets = build_attack_asset_objects(canonical)

    assert len(assets) == 1
    asset = assets[0]
    assert isinstance(asset, StixExportAttackAssetObject)
    assert asset.id == "attack-asset--1"
    assert asset.name == "Host asset"
    assert asset.description == "Observed asset context exactly as reported."
    assert asset.object_ref == "malware--1"


def test_build_attack_action_objects_preserves_explicit_technique_ref_without_inference() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--6",
            name="Example flow",
            scope="incident",
            start_refs=[],
        ),
        nodes=[
            CanonicalFlowActionNode(
                id="attack-action--3",
                name="Technique-ref only",
                description="Observed command exactly as reported.",
                technique=CanonicalFlowTechniqueReference(
                    technique_ref="attack-pattern--explicit",
                    source_object_id="attack-pattern--explicit",
                ),
            )
        ],
        edges=[],
        provenance={},
        conflicts=[],
        validation_errors=[],
    )

    actions = build_attack_action_objects(canonical)

    assert len(actions) == 1
    assert actions[0].technique_id is None
    assert actions[0].technique_ref == "attack-pattern--explicit"


def test_assemble_stix_export_bundle_serializes_to_valid_json_and_counts_objects() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--bundle-json",
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

    bundle = assemble_stix_export_bundle(canonical)
    payload = json.loads(bundle.to_json_bytes().decode("utf-8"))

    assert payload == bundle.to_json_ready()
    assert bundle.metadata.object_count == 3
    assert payload["objects"][0]["start_refs"] == ["attack-action--1"]
    assert payload["objects"][1]["asset_refs"] == ["attack-asset--1"]


def test_validate_stix_export_bundle_rejects_missing_root_object() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--bundle-invalid",
            name="Example flow",
            scope="incident",
            start_refs=["attack-action--1"],
        ),
        nodes=[
            CanonicalFlowActionNode(
                id="attack-action--1",
                name="Example step",
                description="Observed command exactly as reported.",
            )
        ],
        edges=[],
        provenance={},
        conflicts=[],
        validation_errors=[],
    )

    bundle = assemble_stix_export_bundle(canonical)
    bundle.objects.objects = bundle.objects.objects[1:]

    result = validate_stix_export_bundle(bundle)

    assert result.valid is False
    assert any(error.code == "attack_flow_missing" for error in result.errors)


def test_assemble_stix_export_bundle_produces_json_ready_bundle() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--bundle",
            name="Example flow",
            scope="incident",
            description="Example flow description.",
            authors=["analyst-a"],
            external_references=["https://example.com/report"],
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

    bundle = assemble_stix_export_bundle(canonical)

    assert bundle.metadata.id.startswith("bundle--")
    assert bundle.metadata.object_count == 3
    assert bundle.validation_errors == []
    assert bundle.objects.objects[0]["type"] == "attack-flow"
    assert bundle.objects.objects[0]["start_refs"] == ["attack-action--1"]
    assert bundle.objects.objects[1]["type"] == "attack-action"
    assert bundle.objects.objects[2]["type"] == "attack-asset"
    assert bundle.to_json_ready()["type"] == "bundle"
    assert bundle.to_json_bytes().startswith(b"{")


def test_validate_stix_export_bundle_reports_broken_references() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--bundle-2",
            name="Example flow",
            scope="incident",
            start_refs=["attack-action--missing"],
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
        provenance={},
        conflicts=[],
        validation_errors=[],
    )

    bundle = assemble_stix_export_bundle(canonical)
    result = validate_stix_export_bundle(bundle)

    assert result.valid is False
    assert any(error.code == "attack_action_asset_ref_invalid" for error in result.errors)


def test_assemble_stix_export_bundle_preserves_long_action_refs_from_legacy_operator() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--legacy-operator",
            name="Example flow",
            scope="incident",
            start_refs=["attack-action--1"],
        ),
        nodes=[
            CanonicalFlowActionNode(
                id="attack-action--1",
                name="Example step",
                description="Observed command exactly as reported.",
            ),
            CanonicalFlowOperatorNode(
                id="op--1",
                operator="AND",
                effect_refs=["attack-action--1"],
            ),
        ],
        edges=[],
        provenance={},
        conflicts=[],
        validation_errors=[],
    )

    bundle = assemble_stix_export_bundle(canonical)
    operator = next(item for item in bundle.objects.objects if item["type"] == "attack-operator")

    assert operator["effect_refs"] == ["attack-action--1"]
    assert bundle.validation_errors == []
