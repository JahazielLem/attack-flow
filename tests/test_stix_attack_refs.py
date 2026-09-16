from attack_flow_api.services.stix_attack_refs import extract_explicit_attack_refs


def test_extract_explicit_attack_refs_from_attack_external_references():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059.001",
                        "url": "https://attack.mitre.org/techniques/T1059/001/",
                    }
                ],
            }
        ],
    }

    refs = extract_explicit_attack_refs(bundle)

    assert len(refs) == 1
    assert refs[0].technique_id == "T1059.001"
    assert refs[0].source_object_id == "attack-pattern--1"
    assert refs[0].source_object_type == "attack-pattern"
    assert refs[0].source_field == "external_references[0]"
    assert refs[0].external_source_name == "mitre-attack"


def test_extract_explicit_attack_refs_from_attack_pattern_text_fields():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2",
                "name": "Technique T1566",
                "description": "Related to t1059.003 and T1059.003",
                "x_mitre_detection": "Track T1204",
            }
        ],
    }

    refs = extract_explicit_attack_refs(bundle)

    ids = [item.technique_id for item in refs]
    assert ids == ["T1059.003", "T1204", "T1566"]
    assert all(item.source_object_id == "attack-pattern--2" for item in refs)


def test_extract_explicit_attack_refs_ignores_non_attack_references():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1",
                "external_references": [
                    {
                        "source_name": "cve",
                        "external_id": "CVE-2024-12345",
                        "url": "https://example.com/advisory",
                    }
                ],
            }
        ],
    }

    refs = extract_explicit_attack_refs(bundle)

    assert refs == []


def test_extract_explicit_attack_refs_is_deterministic_and_deduplicated():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--z",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1003"},
                    {"source_name": "mitre-attack", "external_id": "T1003"},
                ],
                "description": "also mentions T1003",
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--a",
                "description": "mentions T1059",
            },
        ],
    }

    refs = extract_explicit_attack_refs(bundle)

    assert [(item.technique_id, item.source_object_id, item.source_field) for item in refs] == [
        ("T1003", "attack-pattern--z", "description"),
        ("T1003", "attack-pattern--z", "external_references[0]"),
        ("T1059", "attack-pattern--a", "description"),
    ]
