from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class StixRelationship:
    relationship_id: str | None
    relationship_type: str
    source_ref: str
    target_ref: str
    source_object_type: str
    provenance: dict[str, str]


def extract_stix_relationships(bundle: dict[str, Any]) -> list[StixRelationship]:
    objects_value = bundle.get("objects")
    if not isinstance(objects_value, list):
        return []

    relationships: list[StixRelationship] = []
    for obj in objects_value:
        if not isinstance(obj, dict):
            continue

        object_type = _coerce_non_empty_str(obj.get("type"))
        if object_type is None:
            continue

        relationship_id = _coerce_non_empty_str(obj.get("id"))

        if object_type == "relationship":
            source_ref = _coerce_non_empty_str(obj.get("source_ref"))
            target_ref = _coerce_non_empty_str(obj.get("target_ref"))
            relationship_type = _coerce_non_empty_str(obj.get("relationship_type"))
            if source_ref is None or target_ref is None or relationship_type is None:
                continue
            relationships.append(
                StixRelationship(
                    relationship_id=relationship_id,
                    relationship_type=relationship_type,
                    source_ref=source_ref,
                    target_ref=target_ref,
                    source_object_type=object_type,
                    provenance={
                        "relationship_id": "id",
                        "relationship_type": "relationship_type",
                        "source_ref": "source_ref",
                        "target_ref": "target_ref",
                    },
                )
            )
            continue

        if object_type == "sighting":
            source_ref = _coerce_non_empty_str(obj.get("sighting_of_ref"))
            target_ref = _coerce_non_empty_str(obj.get("where_sighted_refs"))
            if source_ref is not None and target_ref is not None:
                relationships.append(
                    StixRelationship(
                        relationship_id=relationship_id,
                        relationship_type="sighting-of",
                        source_ref=source_ref,
                        target_ref=target_ref,
                        source_object_type=object_type,
                        provenance={
                            "relationship_id": "id",
                            "relationship_type": "sighting_of_ref+where_sighted_refs",
                            "source_ref": "sighting_of_ref",
                            "target_ref": "where_sighted_refs",
                        },
                    )
                )

            where_sighted_refs = obj.get("where_sighted_refs")
            if isinstance(where_sighted_refs, list):
                for index, ref in enumerate(where_sighted_refs):
                    target_ref_item = _coerce_non_empty_str(ref)
                    sighting_of_ref = _coerce_non_empty_str(obj.get("sighting_of_ref"))
                    if sighting_of_ref is None or target_ref_item is None:
                        continue
                    relationships.append(
                        StixRelationship(
                            relationship_id=relationship_id,
                            relationship_type="sighting-of",
                            source_ref=sighting_of_ref,
                            target_ref=target_ref_item,
                            source_object_type=object_type,
                            provenance={
                                "relationship_id": "id",
                                "relationship_type": "sighting_of_ref+where_sighted_refs[]",
                                "source_ref": "sighting_of_ref",
                                "target_ref": f"where_sighted_refs[{index}]",
                            },
                        )
                    )

    unique: dict[tuple[str | None, str, str, str, str], StixRelationship] = {}
    for item in relationships:
        key = (
            item.relationship_id,
            item.relationship_type,
            item.source_ref,
            item.target_ref,
            item.source_object_type,
        )
        unique[key] = item

    return sorted(
        unique.values(),
        key=lambda item: (
            item.relationship_type,
            item.source_ref,
            item.target_ref,
            item.relationship_id or "",
            item.source_object_type,
        ),
    )


def _coerce_non_empty_str(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    return candidate
