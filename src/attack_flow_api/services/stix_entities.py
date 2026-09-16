from dataclasses import dataclass, field
from typing import Any


_SUPPORTED_ENTITY_TYPES = {
    "campaign",
    "intrusion-set",
    "malware",
    "tool",
    "identity",
    "infrastructure",
    "indicator",
    "attack-pattern",
    "report",
    "note",
    "observed-data",
    "sighting",
    "artifact",
    "autonomous-system",
    "directory",
    "domain-name",
    "email-addr",
    "email-message",
    "file",
    "ipv4-addr",
    "ipv6-addr",
    "mac-addr",
    "mutex",
    "network-traffic",
    "process",
    "software",
    "url",
    "user-account",
    "windows-registry-key",
    "x509-certificate",
}

_NORMALIZED_ENTITY_FIELDS = {
    "type",
    "id",
    "description",
    "labels",
    "first_seen",
    "last_seen",
    "confidence",
    "pattern",
    "source_ref",
    "target_ref",
    "observed_data_refs",
    "created_by_ref",
}


@dataclass(frozen=True, slots=True)
class StixEntity:
    object_id: str | None
    object_type: str
    display_name: str | None
    description: str | None
    labels: list[str]
    first_seen: str | None
    last_seen: str | None
    confidence: int | None
    pattern: str | None
    source_ref: str | None
    target_ref: str | None
    observed_data_refs: list[str]
    created_by_ref: str | None
    provenance: dict[str, str]
    stix_properties: dict[str, Any] = field(default_factory=dict)


def extract_stix_entities(bundle: dict[str, Any]) -> list[StixEntity]:
    objects_value = bundle.get("objects")
    if not isinstance(objects_value, list):
        return []

    entities: list[StixEntity] = []
    for obj in objects_value:
        if not isinstance(obj, dict):
            continue

        object_type = _coerce_non_empty_str(obj.get("type"))
        if object_type is None or object_type not in _SUPPORTED_ENTITY_TYPES:
            continue

        object_id = _coerce_non_empty_str(obj.get("id"))
        provenance = _build_provenance(obj)

        entities.append(
            StixEntity(
                object_id=object_id,
                object_type=object_type,
                display_name=_derive_display_name(obj),
                description=_coerce_non_empty_str(obj.get("description"))
                or _coerce_non_empty_str(obj.get("content")),
                labels=_coerce_string_list(obj.get("labels")),
                first_seen=_coerce_non_empty_str(obj.get("first_seen")),
                last_seen=_coerce_non_empty_str(obj.get("last_seen")),
                confidence=_coerce_int(obj.get("confidence")),
                pattern=_coerce_non_empty_str(obj.get("pattern")),
                source_ref=_coerce_non_empty_str(obj.get("source_ref")),
                target_ref=_coerce_non_empty_str(obj.get("target_ref")),
                observed_data_refs=_coerce_string_list(obj.get("observed_data_refs")),
                created_by_ref=_coerce_non_empty_str(obj.get("created_by_ref")),
                provenance=provenance,
                stix_properties=_extract_stix_properties(obj),
            )
        )

    return sorted(
        entities,
        key=lambda item: (
            item.object_type,
            item.object_id or "",
            item.display_name or "",
        ),
    )


def _derive_display_name(obj: dict[str, Any]) -> str | None:
    object_type = _coerce_non_empty_str(obj.get("type"))
    fields = ["name", "title", "abstract"]
    if object_type in {"domain-name", "email-addr", "ipv4-addr", "ipv6-addr", "mac-addr", "url"}:
        fields.append("value")
    elif object_type == "directory":
        fields.append("path")
    elif object_type == "email-message":
        fields.append("subject")
    elif object_type == "process":
        fields.append("command_line")
    elif object_type == "user-account":
        fields.extend(("display_name", "account_login"))
    elif object_type == "windows-registry-key":
        fields.append("key")
    elif object_type == "x509-certificate":
        fields.extend(("subject", "serial_number"))

    for field_name in fields:
        candidate = _coerce_non_empty_str(obj.get(field_name))
        if candidate is not None:
            return candidate
    return None


def _extract_stix_properties(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        key: obj[key]
        for key in sorted(obj)
        if key not in _NORMALIZED_ENTITY_FIELDS
    }


def _build_provenance(obj: dict[str, Any]) -> dict[str, str]:
    provenance: dict[str, str] = {}
    object_id = _coerce_non_empty_str(obj.get("id"))
    if object_id is not None:
        provenance["object_id"] = "id"
    object_type = _coerce_non_empty_str(obj.get("type"))
    if object_type is not None:
        provenance["object_type"] = "type"

    for logical_name, source_field in (
        ("display_name", "name"),
        ("display_name", "title"),
        ("display_name", "abstract"),
        ("description", "description"),
        ("description", "content"),
        ("labels", "labels"),
        ("first_seen", "first_seen"),
        ("last_seen", "last_seen"),
        ("confidence", "confidence"),
        ("pattern", "pattern"),
        ("source_ref", "source_ref"),
        ("target_ref", "target_ref"),
        ("observed_data_refs", "observed_data_refs"),
        ("created_by_ref", "created_by_ref"),
    ):
        if logical_name in provenance:
            continue
        if source_field not in obj:
            continue
        value = obj.get(source_field)
        if source_field in {"labels", "observed_data_refs"} and _coerce_string_list(value):
            provenance[logical_name] = source_field
            continue
        if source_field == "confidence" and _coerce_int(value) is not None:
            provenance[logical_name] = source_field
            continue
        if _coerce_non_empty_str(value) is not None:
            provenance[logical_name] = source_field

    return provenance


def _coerce_non_empty_str(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    return candidate


def _coerce_string_list(value: object) -> list[str]:
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


def _coerce_int(value: object) -> int | None:
    if isinstance(value, int):
        return value
    return None
