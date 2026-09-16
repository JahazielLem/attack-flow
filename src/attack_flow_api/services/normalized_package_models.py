from dataclasses import asdict, dataclass, field
from typing import Any


NORMALIZED_PACKAGE_VERSION_V1 = "v1"

NORMALIZED_SOURCE_TYPE_TEXT = "narrative_text"
NORMALIZED_SOURCE_TYPE_URL = "url_extracted_text"
NORMALIZED_SOURCE_TYPE_DOCUMENT = "document_extracted_text"
NORMALIZED_SOURCE_TYPE_STIX = "stix_structured"

ALLOWED_NORMALIZED_SOURCE_TYPES = {
    NORMALIZED_SOURCE_TYPE_TEXT,
    NORMALIZED_SOURCE_TYPE_URL,
    NORMALIZED_SOURCE_TYPE_DOCUMENT,
    NORMALIZED_SOURCE_TYPE_STIX,
}


@dataclass(frozen=True, slots=True)
class NormalizedContentStats:
    normalized_char_count: int
    raw_char_count: int | None = None


@dataclass(frozen=True, slots=True)
class NormalizedTruncation:
    was_truncated: bool
    budget_chars: int | None = None
    original_char_count: int | None = None


@dataclass(frozen=True, slots=True)
class NormalizedAttackRef:
    technique_id: str
    source_object_id: str | None = None
    source_object_type: str | None = None
    source_field: str | None = None
    external_source_name: str | None = None
    external_url: str | None = None


@dataclass(frozen=True, slots=True)
class NormalizedEntity:
    object_id: str | None
    object_type: str
    display_name: str | None = None
    description: str | None = None
    labels: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    confidence: int | None = None
    pattern: str | None = None
    source_ref: str | None = None
    target_ref: str | None = None
    observed_data_refs: list[str] = field(default_factory=list)
    created_by_ref: str | None = None
    stix_properties: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class NormalizedRelationship:
    relationship_id: str | None
    relationship_type: str
    source_ref: str
    target_ref: str
    source_object_type: str | None = None
    provenance: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class NormalizedStructuredSummary:
    bundle_metadata: dict[str, Any] = field(default_factory=dict)
    inventory: dict[str, Any] = field(default_factory=dict)
    narrative: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CanonicalNormalizedPackage:
    version: str
    source_type: str
    metadata: dict[str, Any]
    normalized_text: str
    content_stats: NormalizedContentStats
    truncation: NormalizedTruncation
    structured_summary: NormalizedStructuredSummary = field(default_factory=NormalizedStructuredSummary)
    attack_refs: list[NormalizedAttackRef] = field(default_factory=list)
    entities: list[NormalizedEntity] = field(default_factory=list)
    relationships: list[NormalizedRelationship] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_json_ready(self) -> dict[str, Any]:
        payload = asdict(self)
        for entity in payload["entities"]:
            stix_properties = entity.pop("stix_properties", {})
            for key, value in stix_properties.items():
                entity.setdefault(key, value)
        return payload


def build_canonical_normalized_package(
    *,
    source_type: str,
    metadata: dict[str, Any],
    normalized_text: str,
    content_stats: NormalizedContentStats,
    truncation: NormalizedTruncation,
    structured_summary: NormalizedStructuredSummary | None = None,
    attack_refs: list[NormalizedAttackRef] | None = None,
    entities: list[NormalizedEntity] | None = None,
    relationships: list[NormalizedRelationship] | None = None,
    provenance: dict[str, Any] | None = None,
    version: str = NORMALIZED_PACKAGE_VERSION_V1,
) -> CanonicalNormalizedPackage:
    if source_type not in ALLOWED_NORMALIZED_SOURCE_TYPES:
        raise ValueError(f"unsupported normalized source_type: {source_type}")

    return CanonicalNormalizedPackage(
        version=version,
        source_type=source_type,
        metadata=metadata,
        normalized_text=normalized_text,
        content_stats=content_stats,
        truncation=truncation,
        structured_summary=structured_summary or NormalizedStructuredSummary(),
        attack_refs=attack_refs or [],
        entities=entities or [],
        relationships=relationships or [],
        provenance=provenance or {},
    )
