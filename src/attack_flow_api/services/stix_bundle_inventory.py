from collections import Counter
from dataclasses import dataclass
from typing import Any

from attack_flow_api.services.text_normalization import (
    NORMALIZATION_VERSION_V1,
    normalize_raw_text,
)


@dataclass(frozen=True, slots=True)
class StixNarrativeChunk:
    source_object_id: str | None
    source_object_type: str
    field_name: str
    raw_text: str
    normalized_text: str


@dataclass(frozen=True, slots=True)
class StixBundleInventoryResult:
    object_count: int
    object_counts_by_type: dict[str, int]
    has_reports: bool
    has_notes: bool
    has_relationships: bool
    has_attack_patterns: bool
    narrative_raw_text: str
    narrative_normalized_text: str
    narrative_normalized_char_count: int
    narrative_normalization_version: str
    narrative_chunks: list[StixNarrativeChunk]


def build_stix_bundle_inventory_and_narrative(bundle: dict[str, Any]) -> StixBundleInventoryResult:
    objects_value = bundle.get("objects")
    objects: list[dict[str, Any]] = []
    if isinstance(objects_value, list):
        objects = [item for item in objects_value if isinstance(item, dict)]

    type_counter: Counter[str] = Counter()
    chunks: list[StixNarrativeChunk] = []

    for obj in objects:
        object_type = _coerce_non_empty_str(obj.get("type"))
        if object_type is None:
            continue
        type_counter[object_type] += 1

        source_object_id = _coerce_non_empty_str(obj.get("id"))
        for field_name in _narrative_fields_for_object_type(object_type):
            field_value = obj.get(field_name)
            for raw_candidate in _iter_text_values(field_value):
                normalized = normalize_raw_text(raw_candidate)
                if not normalized.text:
                    continue
                chunks.append(
                    StixNarrativeChunk(
                        source_object_id=source_object_id,
                        source_object_type=object_type,
                        field_name=field_name,
                        raw_text=raw_candidate,
                        normalized_text=normalized.text,
                    )
                )

    chunks.sort(
        key=lambda item: (
            item.source_object_type,
            item.source_object_id or "",
            item.field_name,
            item.normalized_text,
        )
    )

    narrative_raw_text = "\n\n".join(chunk.raw_text for chunk in chunks)
    narrative_normalized_text = "\n\n".join(chunk.normalized_text for chunk in chunks)

    return StixBundleInventoryResult(
        object_count=len(objects),
        object_counts_by_type=dict(sorted(type_counter.items())),
        has_reports=type_counter.get("report", 0) > 0,
        has_notes=type_counter.get("note", 0) > 0,
        has_relationships=type_counter.get("relationship", 0) > 0,
        has_attack_patterns=type_counter.get("attack-pattern", 0) > 0,
        narrative_raw_text=narrative_raw_text,
        narrative_normalized_text=narrative_normalized_text,
        narrative_normalized_char_count=len(narrative_normalized_text),
        narrative_normalization_version=NORMALIZATION_VERSION_V1,
        narrative_chunks=chunks,
    )


def _narrative_fields_for_object_type(object_type: str) -> tuple[str, ...]:
    if object_type == "report":
        return ("name", "description", "x_opencti_content")
    if object_type == "note":
        return ("abstract", "content", "x_opencti_content")
    return ("description",)


def _coerce_non_empty_str(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    return candidate


def _iter_text_values(value: object) -> list[str]:
    if isinstance(value, str):
        candidate = value.strip()
        return [value] if candidate else []

    if isinstance(value, list):
        output: list[str] = []
        for item in value:
            if not isinstance(item, str):
                continue
            if not item.strip():
                continue
            output.append(item)
        return output

    return []
