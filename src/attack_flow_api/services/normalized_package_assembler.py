import json

from attack_flow_api.services.normalized_package_models import (
    NORMALIZED_SOURCE_TYPE_STIX,
    NORMALIZED_SOURCE_TYPE_DOCUMENT,
    NORMALIZED_SOURCE_TYPE_TEXT,
    NORMALIZED_SOURCE_TYPE_URL,
    NormalizedAttackRef,
    NormalizedContentStats,
    NormalizedEntity,
    NormalizedRelationship,
    NormalizedStructuredSummary,
    NormalizedTruncation,
    build_canonical_normalized_package,
)
from attack_flow_api.storage.models import InputSource
from attack_flow_api.storage.repositories import InputSourceNormalizedUpdate


def build_narrative_normalized_update(
    input_source: InputSource,
    *,
    pipeline_version: str,
    content_budget_chars: int,
) -> InputSourceNormalizedUpdate | None:
    source_type = _map_narrative_source_type(input_source)
    if source_type is None:
        return None

    normalized_text = input_source.normalized_text
    if normalized_text is None:
        normalized_text = input_source.content_text
    if normalized_text is None:
        normalized_text = input_source.raw_text
    if normalized_text is None:
        return None

    raw_count = len(input_source.raw_text) if input_source.raw_text is not None else None
    budgeted_text, budget_was_truncated, original_char_count = _apply_content_budget(
        normalized_text,
        content_budget_chars,
    )
    normalized_count = len(budgeted_text)
    source_was_truncated = bool(input_source.was_truncated) if input_source.was_truncated is not None else False
    was_truncated = source_was_truncated or budget_was_truncated

    package = build_canonical_normalized_package(
        source_type=source_type,
        metadata={
            "input_source_type": input_source.type,
            "title": input_source.title,
            "case_id": input_source.case_id,
            "source_name": input_source.source_name,
            "source_url": input_source.source_url,
            "original_name": input_source.original_name,
            "file_class": input_source.file_class,
            "mime_type": input_source.mime_type,
        },
        normalized_text=budgeted_text,
        content_stats=NormalizedContentStats(
            normalized_char_count=normalized_count,
            raw_char_count=raw_count,
        ),
        truncation=NormalizedTruncation(
            was_truncated=was_truncated,
            budget_chars=content_budget_chars,
            original_char_count=original_char_count,
        ),
        version=pipeline_version,
    )

    payload = package.to_json_ready()
    return InputSourceNormalizedUpdate(
        normalized_source_type=source_type,
        normalized_package_json=json.dumps(payload),
        normalized_stats_json=json.dumps(payload["content_stats"]),
        normalized_content_chars=normalized_count,
        normalized_content_was_truncated=was_truncated,
        normalized_content_budget_chars=content_budget_chars,
        normalized_pipeline_version=pipeline_version,
    )


def _map_narrative_source_type(input_source: InputSource) -> str | None:
    if input_source.type == "text":
        return NORMALIZED_SOURCE_TYPE_TEXT
    if input_source.type == "url":
        return NORMALIZED_SOURCE_TYPE_URL
    if input_source.type == "file" and input_source.file_class in {"plaintext", "pdf"}:
        return NORMALIZED_SOURCE_TYPE_DOCUMENT
    return None


def build_structured_stix_normalized_update(
    input_source: InputSource,
    *,
    pipeline_version: str,
    content_budget_chars: int,
) -> InputSourceNormalizedUpdate | None:
    if input_source.type != "file" or input_source.file_class != "stix_json":
        return None

    summary = _load_json_object(input_source.stix_summary_json)
    entities_raw = _load_json_list(input_source.stix_entities_json)
    relationships_raw = _load_json_list(input_source.stix_relationships_json)
    attack_refs_raw = _load_json_list(input_source.stix_attack_refs_json)
    provenance = _load_json_object(input_source.stix_provenance_json)

    if summary is None:
        return None

    bundle_metadata = _coerce_dict(summary.get("bundle_metadata"))
    inventory = _coerce_dict(summary.get("inventory"))
    narrative = _coerce_dict(summary.get("narrative"))

    normalized_text = input_source.normalized_text or input_source.content_text or ""
    raw_count = len(input_source.raw_text) if input_source.raw_text is not None else None
    budgeted_text, budget_was_truncated, original_char_count = _apply_content_budget(
        normalized_text,
        content_budget_chars,
    )
    normalized_count = len(budgeted_text)
    source_was_truncated = bool(input_source.was_truncated) if input_source.was_truncated is not None else False
    was_truncated = source_was_truncated or budget_was_truncated

    attack_refs = [
        NormalizedAttackRef(
            technique_id=str(item.get("technique_id", "")),
            source_object_id=_as_optional_str(item.get("source_object_id")),
            source_object_type=_as_optional_str(item.get("source_object_type")),
            source_field=_as_optional_str(item.get("source_field")),
            external_source_name=_as_optional_str(item.get("external_source_name")),
            external_url=_as_optional_str(item.get("external_url")),
        )
        for item in _iter_dict_items(attack_refs_raw)
        if str(item.get("technique_id", "")).strip()
    ]

    entities = [
        NormalizedEntity(
            object_id=_as_optional_str(item.get("object_id")),
            object_type=str(item.get("object_type", "")).strip(),
            display_name=_as_optional_str(item.get("display_name")),
            description=_as_optional_str(item.get("description")),
            labels=_as_str_list(item.get("labels")),
            first_seen=_as_optional_str(item.get("first_seen")),
            last_seen=_as_optional_str(item.get("last_seen")),
            confidence=item.get("confidence") if isinstance(item.get("confidence"), int) else None,
            pattern=_as_optional_str(item.get("pattern")),
            source_ref=_as_optional_str(item.get("source_ref")),
            target_ref=_as_optional_str(item.get("target_ref")),
            observed_data_refs=_as_str_list(item.get("observed_data_refs")),
            created_by_ref=_as_optional_str(item.get("created_by_ref")),
            stix_properties=_coerce_dict(item.get("stix_properties")),
            provenance=_coerce_str_dict(item.get("provenance")),
        )
        for item in _iter_dict_items(entities_raw)
        if str(item.get("object_type", "")).strip()
    ]

    relationships = [
        NormalizedRelationship(
            relationship_id=_as_optional_str(item.get("relationship_id")),
            relationship_type=str(item.get("relationship_type", "")).strip(),
            source_ref=str(item.get("source_ref", "")).strip(),
            target_ref=str(item.get("target_ref", "")).strip(),
            source_object_type=_as_optional_str(item.get("source_object_type")),
            provenance=_coerce_str_dict(item.get("provenance")),
        )
        for item in _iter_dict_items(relationships_raw)
        if str(item.get("relationship_type", "")).strip()
        and str(item.get("source_ref", "")).strip()
        and str(item.get("target_ref", "")).strip()
    ]

    package = build_canonical_normalized_package(
        source_type=NORMALIZED_SOURCE_TYPE_STIX,
        metadata={
            "input_source_type": input_source.type,
            "title": input_source.title,
            "case_id": input_source.case_id,
            "source_name": input_source.source_name,
            "file_class": input_source.file_class,
            "mime_type": input_source.mime_type,
            "stix_bundle_id": input_source.stix_bundle_id,
            "stix_spec_version": input_source.stix_spec_version,
            "stix_source_type": input_source.stix_source_type,
        },
        normalized_text=budgeted_text,
        content_stats=NormalizedContentStats(
            normalized_char_count=normalized_count,
            raw_char_count=raw_count,
        ),
        truncation=NormalizedTruncation(
            was_truncated=was_truncated,
            budget_chars=content_budget_chars,
            original_char_count=original_char_count,
        ),
        structured_summary=NormalizedStructuredSummary(
            bundle_metadata=bundle_metadata,
            inventory=inventory,
            narrative=narrative,
        ),
        attack_refs=attack_refs,
        entities=entities,
        relationships=relationships,
        provenance=provenance,
        version=pipeline_version,
    )

    payload = package.to_json_ready()
    return InputSourceNormalizedUpdate(
        normalized_source_type=NORMALIZED_SOURCE_TYPE_STIX,
        normalized_package_json=json.dumps(payload),
        normalized_stats_json=json.dumps(payload["content_stats"]),
        normalized_content_chars=normalized_count,
        normalized_content_was_truncated=was_truncated,
        normalized_content_budget_chars=content_budget_chars,
        normalized_pipeline_version=pipeline_version,
    )


def _apply_content_budget(text: str, budget_chars: int) -> tuple[str, bool, int]:
    original_char_count = len(text)
    if budget_chars <= 0:
        return "", original_char_count > 0, original_char_count
    if original_char_count <= budget_chars:
        return text, False, original_char_count
    return text[:budget_chars], True, original_char_count


def _load_json_object(raw_value: str | None) -> dict[str, object] | None:
    if raw_value is None:
        return None
    try:
        parsed = json.loads(raw_value)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def _load_json_list(raw_value: str | None) -> list[object]:
    if raw_value is None:
        return []
    try:
        parsed = json.loads(raw_value)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return parsed


def _iter_dict_items(values: list[object]) -> list[dict[str, object]]:
    return [item for item in values if isinstance(item, dict)]


def _coerce_dict(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return value
    return {}


def _coerce_str_dict(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            continue
        output[key] = item
    return output


def _as_optional_str(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    return candidate


def _as_str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    output: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        candidate = item.strip()
        if not candidate:
            continue
        output.append(candidate)
    return output
