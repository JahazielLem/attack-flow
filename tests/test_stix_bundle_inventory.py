from attack_flow_api.services.stix_bundle_inventory import build_stix_bundle_inventory_and_narrative


def test_build_stix_bundle_inventory_extracts_type_counts_and_presence_flags():
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "report", "id": "report--1", "name": "Campaign A"},
            {"type": "note", "id": "note--1", "content": "Operator notes"},
            {"type": "relationship", "id": "relationship--1"},
            {"type": "attack-pattern", "id": "attack-pattern--1"},
            {"type": "indicator", "id": "indicator--1", "description": "IOC text"},
        ],
    }

    result = build_stix_bundle_inventory_and_narrative(bundle)

    assert result.object_count == 5
    assert result.object_counts_by_type == {
        "attack-pattern": 1,
        "indicator": 1,
        "note": 1,
        "relationship": 1,
        "report": 1,
    }
    assert result.has_reports is True
    assert result.has_notes is True
    assert result.has_relationships is True
    assert result.has_attack_patterns is True


def test_build_stix_bundle_inventory_extracts_narrative_and_provenance_deterministically():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "report",
                "id": "report--a",
                "name": "  Executive Summary  ",
                "description": "Initial access\r\n\r\n\r\nvia phishing",
                "x_opencti_content": "OpenCTI custom body",
            },
            {
                "type": "note",
                "id": "note--a",
                "abstract": " Analyst abstract ",
                "content": "Analyst line 1\n\n\nAnalyst line 2",
            },
            {
                "type": "malware",
                "id": "malware--a",
                "description": "   Malware description   ",
            },
        ],
    }

    result = build_stix_bundle_inventory_and_narrative(bundle)

    assert len(result.narrative_chunks) == 6
    assert all(chunk.source_object_id is not None for chunk in result.narrative_chunks)
    assert all(chunk.field_name for chunk in result.narrative_chunks)
    assert result.narrative_normalization_version == "v1"

    assert result.narrative_normalized_text == (
        "Malware description\n\n"
        "Analyst abstract\n\n"
        "Analyst line 1\n\nAnalyst line 2\n\n"
        "Initial access\n\nvia phishing\n\n"
        "Executive Summary\n\n"
        "OpenCTI custom body"
    )
    assert result.narrative_normalized_char_count == len(result.narrative_normalized_text)


def test_build_stix_bundle_inventory_ignores_empty_or_non_string_narrative_fields():
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "note", "id": "note--1", "content": "   "},
            {"type": "report", "id": "report--1", "name": ["valid", 42, " "]},
            {"type": "indicator", "id": "indicator--1", "description": None},
            {"type": "attack-pattern", "id": "attack-pattern--1", "description": "Tactic detail"},
        ],
    }

    result = build_stix_bundle_inventory_and_narrative(bundle)

    assert result.object_count == 4
    assert result.narrative_normalized_text == "Tactic detail\n\nvalid"
    assert [chunk.source_object_type for chunk in result.narrative_chunks] == ["attack-pattern", "report"]
