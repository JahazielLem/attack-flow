import pytest

from attack_flow_api.services.normalized_package_models import (
    NORMALIZED_SOURCE_TYPE_STIX,
    NORMALIZED_SOURCE_TYPE_TEXT,
    NormalizedAttackRef,
    NormalizedContentStats,
    NormalizedEntity,
    NormalizedRelationship,
    NormalizedStructuredSummary,
    NormalizedTruncation,
    build_canonical_normalized_package,
)


def test_build_canonical_normalized_package_for_narrative_source():
    package = build_canonical_normalized_package(
        source_type=NORMALIZED_SOURCE_TYPE_TEXT,
        metadata={"title": "Incident A", "source_name": "analyst"},
        normalized_text="line 1\n\nline 2",
        content_stats=NormalizedContentStats(normalized_char_count=len("line 1\n\nline 2"), raw_char_count=20),
        truncation=NormalizedTruncation(was_truncated=False, budget_chars=100000, original_char_count=20),
    )

    payload = package.to_json_ready()
    assert payload["source_type"] == NORMALIZED_SOURCE_TYPE_TEXT
    assert payload["metadata"]["title"] == "Incident A"
    assert payload["normalized_text"] == "line 1\n\nline 2"
    assert payload["content_stats"]["normalized_char_count"] == len("line 1\n\nline 2")
    assert payload["truncation"]["was_truncated"] is False


def test_build_canonical_normalized_package_for_stix_structured_source():
    package = build_canonical_normalized_package(
        source_type=NORMALIZED_SOURCE_TYPE_STIX,
        metadata={"title": "Bundle X", "case_id": "CASE-42"},
        normalized_text="Initial access via phishing.",
        content_stats=NormalizedContentStats(normalized_char_count=28, raw_char_count=31),
        truncation=NormalizedTruncation(was_truncated=False, budget_chars=50000, original_char_count=31),
        structured_summary=NormalizedStructuredSummary(
            bundle_metadata={"id": "bundle--1", "spec_version": "2.1"},
            inventory={"object_count": 3, "has_reports": True},
            narrative={"normalized_char_count": 28},
        ),
        attack_refs=[
            NormalizedAttackRef(
                technique_id="T1566",
                source_object_id="attack-pattern--1",
                source_object_type="attack-pattern",
                source_field="external_references[0]",
            )
        ],
        entities=[
            NormalizedEntity(
                object_id="report--1",
                object_type="report",
                display_name="Case Report",
                provenance={"display_name": "name"},
            )
        ],
        relationships=[
            NormalizedRelationship(
                relationship_id="relationship--1",
                relationship_type="uses",
                source_ref="intrusion-set--1",
                target_ref="malware--1",
                source_object_type="relationship",
            )
        ],
        provenance={"entity_object_ids": ["report--1"]},
    )

    payload = package.to_json_ready()
    assert payload["source_type"] == NORMALIZED_SOURCE_TYPE_STIX
    assert payload["structured_summary"]["bundle_metadata"]["id"] == "bundle--1"
    assert payload["attack_refs"][0]["technique_id"] == "T1566"
    assert payload["entities"][0]["object_type"] == "report"
    assert payload["relationships"][0]["relationship_type"] == "uses"
    assert payload["provenance"]["entity_object_ids"] == ["report--1"]


def test_build_canonical_normalized_package_rejects_unknown_source_type():
    with pytest.raises(ValueError):
        build_canonical_normalized_package(
            source_type="unknown_source",
            metadata={},
            normalized_text="x",
            content_stats=NormalizedContentStats(normalized_char_count=1),
            truncation=NormalizedTruncation(was_truncated=False),
        )
