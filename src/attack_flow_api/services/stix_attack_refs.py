import re
from dataclasses import dataclass
from typing import Any


_ATTACK_ID_PATTERN = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class StixAttackRef:
    technique_id: str
    source_object_id: str | None
    source_object_type: str
    source_field: str
    external_source_name: str | None
    external_url: str | None


def extract_explicit_attack_refs(bundle: dict[str, Any]) -> list[StixAttackRef]:
    objects_value = bundle.get("objects")
    if not isinstance(objects_value, list):
        return []

    refs: list[StixAttackRef] = []
    for obj in objects_value:
        if not isinstance(obj, dict):
            continue
        object_type = _coerce_non_empty_str(obj.get("type"))
        if object_type is None:
            continue

        source_object_id = _coerce_non_empty_str(obj.get("id"))

        refs.extend(
            _extract_from_external_references(
                obj=obj,
                source_object_id=source_object_id,
                source_object_type=object_type,
            )
        )

        if object_type == "attack-pattern":
            refs.extend(
                _extract_from_attack_pattern_fields(
                    obj=obj,
                    source_object_id=source_object_id,
                    source_object_type=object_type,
                )
            )

    unique: dict[tuple[str, str | None, str, str, str | None, str | None], StixAttackRef] = {}
    for ref in refs:
        key = (
            ref.technique_id,
            ref.source_object_id,
            ref.source_object_type,
            ref.source_field,
            ref.external_source_name,
            ref.external_url,
        )
        unique[key] = ref

    return sorted(
        unique.values(),
        key=lambda item: (
            item.technique_id,
            item.source_object_type,
            item.source_object_id or "",
            item.source_field,
            item.external_source_name or "",
            item.external_url or "",
        ),
    )


def _extract_from_external_references(
    *,
    obj: dict[str, Any],
    source_object_id: str | None,
    source_object_type: str,
) -> list[StixAttackRef]:
    value = obj.get("external_references")
    if not isinstance(value, list):
        return []

    refs: list[StixAttackRef] = []
    emitted_external: set[tuple[str, str | None, str | None]] = set()
    for index, ext in enumerate(value):
        if not isinstance(ext, dict):
            continue

        source_name = _coerce_non_empty_str(ext.get("source_name"))
        source_name_lc = source_name.lower() if source_name else ""
        external_id = _coerce_non_empty_str(ext.get("external_id"))
        url = _coerce_non_empty_str(ext.get("url"))
        description = _coerce_non_empty_str(ext.get("description"))

        is_attack_reference = (
            "attack" in source_name_lc
            or (url is not None and "attack.mitre.org" in url.lower())
            or (external_id is not None and _find_attack_ids(external_id))
        )
        if not is_attack_reference:
            continue

        matched_ids: list[str] = []
        if external_id is not None:
            matched_ids.extend(_find_attack_ids(external_id))
        if description is not None:
            matched_ids.extend(_find_attack_ids(description))

        for technique_id in _dedupe_preserve_order(matched_ids):
            dedupe_key = (technique_id, source_name, url)
            if dedupe_key in emitted_external:
                continue
            emitted_external.add(dedupe_key)
            refs.append(
                StixAttackRef(
                    technique_id=technique_id,
                    source_object_id=source_object_id,
                    source_object_type=source_object_type,
                    source_field=f"external_references[{index}]",
                    external_source_name=source_name,
                    external_url=url,
                )
            )
    return refs


def _extract_from_attack_pattern_fields(
    *,
    obj: dict[str, Any],
    source_object_id: str | None,
    source_object_type: str,
) -> list[StixAttackRef]:
    refs: list[StixAttackRef] = []
    for field_name in ("name", "description", "x_mitre_detection"):
        value = _coerce_non_empty_str(obj.get(field_name))
        if value is None:
            continue
        for technique_id in _dedupe_preserve_order(_find_attack_ids(value)):
            refs.append(
                StixAttackRef(
                    technique_id=technique_id,
                    source_object_id=source_object_id,
                    source_object_type=source_object_type,
                    source_field=field_name,
                    external_source_name=None,
                    external_url=None,
                )
            )
    return refs


def _find_attack_ids(value: str) -> list[str]:
    return [match.group(1).upper() for match in _ATTACK_ID_PATTERN.finditer(value)]


def _coerce_non_empty_str(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    return candidate


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output
