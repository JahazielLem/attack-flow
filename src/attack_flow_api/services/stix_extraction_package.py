from dataclasses import dataclass
from typing import Any

from attack_flow_api.services.stix_attack_refs import StixAttackRef
from attack_flow_api.services.stix_bundle_inventory import StixBundleInventoryResult
from attack_flow_api.services.stix_entities import StixEntity
from attack_flow_api.services.stix_relationships import StixRelationship
from attack_flow_api.services.stix_json_validation import StixJsonValidationResult


@dataclass(frozen=True, slots=True)
class StixExtractionPackage:
    bundle_metadata: dict[str, Any]
    inventory: dict[str, Any]
    narrative: dict[str, Any]
    attack_refs: list[dict[str, Any]]
    entities: list[dict[str, Any]]
    relationships: list[dict[str, Any]]
    provenance: dict[str, Any]

    def to_json_ready(self) -> dict[str, Any]:
        return {
            "bundle_metadata": self.bundle_metadata,
            "inventory": self.inventory,
            "narrative": self.narrative,
            "attack_refs": self.attack_refs,
            "entities": self.entities,
            "relationships": self.relationships,
            "provenance": self.provenance,
        }


def build_stix_extraction_package(
    *,
    validation: StixJsonValidationResult,
    inventory: StixBundleInventoryResult,
    attack_refs: list[StixAttackRef],
    entities: list[StixEntity],
    relationships: list[StixRelationship],
) -> StixExtractionPackage:
    attack_ref_payload = [
        {
            "technique_id": item.technique_id,
            "source_object_id": item.source_object_id,
            "source_object_type": item.source_object_type,
            "source_field": item.source_field,
            "external_source_name": item.external_source_name,
            "external_url": item.external_url,
        }
        for item in attack_refs
    ]

    entity_payload = [
        {
            "object_id": item.object_id,
            "object_type": item.object_type,
            "display_name": item.display_name,
            "description": item.description,
            "labels": item.labels,
            "first_seen": item.first_seen,
            "last_seen": item.last_seen,
            "confidence": item.confidence,
            "pattern": item.pattern,
            "source_ref": item.source_ref,
            "target_ref": item.target_ref,
            "observed_data_refs": item.observed_data_refs,
            "created_by_ref": item.created_by_ref,
            "stix_properties": item.stix_properties,
            "provenance": item.provenance,
        }
        for item in entities
    ]

    relationship_payload = [
        {
            "relationship_id": item.relationship_id,
            "relationship_type": item.relationship_type,
            "source_ref": item.source_ref,
            "target_ref": item.target_ref,
            "source_object_type": item.source_object_type,
            "provenance": item.provenance,
        }
        for item in relationships
    ]

    return StixExtractionPackage(
        bundle_metadata={
            "id": validation.bundle_id,
            "spec_version": validation.spec_version,
            "kind": validation.stix_json_kind,
            "stix_json_valid": validation.stix_json_valid,
            "object_count": validation.object_count,
        },
        inventory={
            "object_count": inventory.object_count,
            "object_counts_by_type": inventory.object_counts_by_type,
            "has_reports": inventory.has_reports,
            "has_notes": inventory.has_notes,
            "has_relationships": inventory.has_relationships,
            "has_attack_patterns": inventory.has_attack_patterns,
        },
        narrative={
            "raw_text": inventory.narrative_raw_text,
            "normalized_text": inventory.narrative_normalized_text,
            "normalized_char_count": inventory.narrative_normalized_char_count,
            "normalization_version": inventory.narrative_normalization_version,
            "chunks": [
                {
                    "source_object_id": chunk.source_object_id,
                    "source_object_type": chunk.source_object_type,
                    "field_name": chunk.field_name,
                    "raw_text": chunk.raw_text,
                    "normalized_text": chunk.normalized_text,
                }
                for chunk in inventory.narrative_chunks
            ],
        },
        attack_refs=attack_ref_payload,
        entities=entity_payload,
        relationships=relationship_payload,
        provenance={
            "attack_ref_source_object_ids": sorted(
                {item.source_object_id for item in attack_refs if item.source_object_id is not None}
            ),
            "entity_object_ids": sorted(
                {item.object_id for item in entities if item.object_id is not None}
            ),
            "relationship_ids": sorted(
                {item.relationship_id for item in relationships if item.relationship_id is not None}
            ),
            "narrative_source_object_ids": sorted(
                {
                    chunk.source_object_id
                    for chunk in inventory.narrative_chunks
                    if chunk.source_object_id is not None
                }
            ),
        },
    )
