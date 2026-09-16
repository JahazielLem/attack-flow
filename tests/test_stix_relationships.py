from attack_flow_api.services.stix_relationships import extract_stix_relationships


def test_extract_stix_relationships_from_relationship_objects():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--1",
                "target_ref": "malware--1",
            },
            {
                "type": "relationship",
                "id": "relationship--2",
                "relationship_type": "targets",
                "source_ref": "malware--1",
                "target_ref": "identity--1",
            },
        ],
    }

    relationships = extract_stix_relationships(bundle)

    assert [
        (item.relationship_id, item.relationship_type, item.source_ref, item.target_ref)
        for item in relationships
    ] == [
        ("relationship--2", "targets", "malware--1", "identity--1"),
        ("relationship--1", "uses", "intrusion-set--1", "malware--1"),
    ]


def test_extract_stix_relationships_includes_sighting_links_where_present():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "sighting",
                "id": "sighting--1",
                "sighting_of_ref": "indicator--1",
                "where_sighted_refs": ["identity--a", "identity--b"],
            }
        ],
    }

    relationships = extract_stix_relationships(bundle)

    assert [
        (item.relationship_id, item.relationship_type, item.source_ref, item.target_ref)
        for item in relationships
    ] == [
        ("sighting--1", "sighting-of", "indicator--1", "identity--a"),
        ("sighting--1", "sighting-of", "indicator--1", "identity--b"),
    ]
    assert relationships[0].provenance["source_ref"] == "sighting_of_ref"
    assert relationships[0].provenance["target_ref"] == "where_sighted_refs[0]"


def test_extract_stix_relationships_ignores_incomplete_relationships_and_is_deterministic():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "relationship",
                "id": "relationship--skip",
                "relationship_type": "uses",
                "source_ref": "tool--1",
            },
            {
                "type": "relationship",
                "id": "relationship--ok",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--1",
                "target_ref": "tool--1",
            },
            {
                "type": "sighting",
                "id": "sighting--skip",
                "where_sighted_refs": ["identity--1"],
            },
        ],
    }

    relationships = extract_stix_relationships(bundle)

    assert len(relationships) == 1
    assert relationships[0].relationship_id == "relationship--ok"
    assert relationships[0].source_object_type == "relationship"
