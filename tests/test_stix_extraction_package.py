from attack_flow_api.services.stix_attack_refs import StixAttackRef
from attack_flow_api.services.stix_bundle_inventory import StixBundleInventoryResult, StixNarrativeChunk
from attack_flow_api.services.stix_entities import StixEntity
from attack_flow_api.services.stix_extraction_package import build_stix_extraction_package
from attack_flow_api.services.stix_json_validation import StixJsonValidationResult
from attack_flow_api.services.stix_relationships import StixRelationship


def test_build_stix_extraction_package_assembles_deterministic_payload_shape():
    package = build_stix_extraction_package(
        validation=StixJsonValidationResult(
            stix_json_kind="bundle",
            stix_json_valid=True,
            bundle_id="bundle--1",
            spec_version="2.1",
            object_count=2,
        ),
        inventory=StixBundleInventoryResult(
            object_count=2,
            object_counts_by_type={"report": 1, "relationship": 1},
            has_reports=True,
            has_notes=False,
            has_relationships=True,
            has_attack_patterns=False,
            narrative_raw_text="Raw report",
            narrative_normalized_text="Raw report",
            narrative_normalized_char_count=len("Raw report"),
            narrative_normalization_version="v1",
            narrative_chunks=[
                StixNarrativeChunk(
                    source_object_id="report--1",
                    source_object_type="report",
                    field_name="description",
                    raw_text="Raw report",
                    normalized_text="Raw report",
                )
            ],
        ),
        attack_refs=[
            StixAttackRef(
                technique_id="T1059",
                source_object_id="attack-pattern--1",
                source_object_type="attack-pattern",
                source_field="external_references[0]",
                external_source_name="mitre-attack",
                external_url="https://attack.mitre.org/techniques/T1059/",
            )
        ],
        entities=[
            StixEntity(
                object_id="report--1",
                object_type="report",
                display_name="R1",
                description="Raw report",
                labels=[],
                first_seen=None,
                last_seen=None,
                confidence=None,
                pattern=None,
                source_ref=None,
                target_ref=None,
                observed_data_refs=[],
                created_by_ref=None,
                provenance={"display_name": "name"},
                stix_properties={},
            )
        ],
        relationships=[
            StixRelationship(
                relationship_id="relationship--1",
                relationship_type="uses",
                source_ref="intrusion-set--1",
                target_ref="malware--1",
                source_object_type="relationship",
                provenance={"source_ref": "source_ref", "target_ref": "target_ref"},
            )
        ],
    )

    payload = package.to_json_ready()
    assert payload["bundle_metadata"]["id"] == "bundle--1"
    assert payload["inventory"]["object_count"] == 2
    assert payload["narrative"]["normalized_text"] == "Raw report"
    assert payload["attack_refs"][0]["technique_id"] == "T1059"
    assert payload["entities"][0]["object_id"] == "report--1"
    assert payload["relationships"][0]["relationship_id"] == "relationship--1"
    assert payload["provenance"]["narrative_source_object_ids"] == ["report--1"]
