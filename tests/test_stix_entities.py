from attack_flow_api.services.stix_entities import extract_stix_entities


def test_extract_stix_entities_extracts_supported_types_with_core_fields():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "campaign",
                "id": "campaign--1",
                "name": "Spring Offensive",
                "description": "Campaign description",
                "labels": ["apt", "high-priority"],
                "created_by_ref": "identity--author",
            },
            {
                "type": "indicator",
                "id": "indicator--1",
                "name": "Suspicious Hash",
                "pattern": "[file:hashes.'SHA-256' = 'abc']",
                "confidence": 70,
            },
            {
                "type": "sighting",
                "id": "sighting--1",
                "source_ref": "identity--sensor",
                "target_ref": "indicator--1",
                "observed_data_refs": ["observed-data--1"],
                "first_seen": "2026-01-01T00:00:00Z",
                "last_seen": "2026-01-02T00:00:00Z",
            },
            {
                "type": "observed-data",
                "id": "observed-data--1",
                "first_observed": "2026-01-01T00:00:00Z",
            },
            {
                "type": "marking-definition",
                "id": "marking-definition--skip",
                "definition_type": "tlp",
            },
        ],
    }

    entities = extract_stix_entities(bundle)

    assert [entity.object_type for entity in entities] == [
        "campaign",
        "indicator",
        "observed-data",
        "sighting",
    ]

    campaign = entities[0]
    assert campaign.object_id == "campaign--1"
    assert campaign.display_name == "Spring Offensive"
    assert campaign.description == "Campaign description"
    assert campaign.labels == ["apt", "high-priority"]
    assert campaign.created_by_ref == "identity--author"

    indicator = entities[1]
    assert indicator.pattern == "[file:hashes.'SHA-256' = 'abc']"
    assert indicator.confidence == 70

    sighting = entities[3]
    assert sighting.source_ref == "identity--sensor"
    assert sighting.target_ref == "indicator--1"
    assert sighting.observed_data_refs == ["observed-data--1"]


def test_extract_stix_entities_uses_fallback_name_fields_and_provenance():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "report",
                "id": "report--1",
                "title": "Executive Report",
                "description": "Report body",
            },
            {
                "type": "note",
                "id": "note--1",
                "abstract": "Analyst Note",
                "content": "Detailed note content",
            },
        ],
    }

    entities = extract_stix_entities(bundle)

    note = entities[0]
    report = entities[1]

    assert note.object_type == "note"
    assert note.display_name == "Analyst Note"
    assert note.description == "Detailed note content"
    assert note.provenance["display_name"] == "abstract"
    assert note.provenance["description"] == "content"

    assert report.object_type == "report"
    assert report.display_name == "Executive Report"
    assert report.provenance["display_name"] == "title"


def test_extract_stix_entities_is_deterministic_and_ignores_empty_values():
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "tool", "id": "tool--b", "name": "  "},
            {"type": "tool", "id": "tool--a", "name": "Recon Toolkit", "labels": ["  ", "ops"]},
            {"type": "malware", "id": "malware--1", "description": "payload"},
        ],
    }

    entities = extract_stix_entities(bundle)

    assert [(entity.object_type, entity.object_id) for entity in entities] == [
        ("malware", "malware--1"),
        ("tool", "tool--a"),
        ("tool", "tool--b"),
    ]
    assert entities[1].labels == ["ops"]
    assert entities[2].display_name is None


def test_extract_stix_entities_retains_supported_cyber_observable_types():
    supported_types = [
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
    ]
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": object_type, "id": f"{object_type}--1"}
            for object_type in reversed(supported_types)
        ],
    }

    entities = extract_stix_entities(bundle)

    assert [entity.object_type for entity in entities] == supported_types


def test_extract_stix_entities_preserves_sco_properties_and_defanged_values():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "observed-data",
                "id": "observed-data--1",
                "object_refs": ["file--1", "url--1", "domain-name--1", "ipv4-addr--1"],
                "number_observed": 1,
            },
            {
                "type": "file",
                "id": "file--1",
                "name": "payload.exe",
                "hashes": {"SHA-256": "abc123"},
            },
            {"type": "url", "id": "url--1", "value": "hxxps[:]//evil[.]example/path"},
            {"type": "domain-name", "id": "domain-name--1", "value": "evil[.]example"},
            {"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "192[.]0[.]2[.]10"},
            {"type": "process", "id": "process--1", "command_line": "cmd.exe /c whoami"},
            {
                "type": "software",
                "id": "software--1",
                "name": "Example App",
                "vendor": "Example Corp",
                "version": "4.2",
                "cpe": "cpe:2.3:a:example:app:4.2:*:*:*:*:*:*:*",
            },
            {
                "type": "user-account",
                "id": "user-account--1",
                "account_login": "analyst",
                "display_name": "SOC Analyst",
                "is_privileged": False,
            },
            {
                "type": "windows-registry-key",
                "id": "windows-registry-key--1",
                "key": "HKEY_LOCAL_MACHINE\\Software\\Example",
                "values": [{"name": "Enabled", "data": "1", "data_type": "REG_DWORD"}],
            },
        ],
    }

    entities = {entity.object_id: entity for entity in extract_stix_entities(bundle)}

    assert entities["file--1"].stix_properties["hashes"] == {"SHA-256": "abc123"}
    assert entities["url--1"].stix_properties["value"] == "hxxps[:]//evil[.]example/path"
    assert entities["domain-name--1"].stix_properties["value"] == "evil[.]example"
    assert entities["ipv4-addr--1"].stix_properties["value"] == "192[.]0[.]2[.]10"
    assert entities["process--1"].stix_properties["command_line"] == "cmd.exe /c whoami"
    assert entities["software--1"].stix_properties["vendor"] == "Example Corp"
    assert entities["software--1"].stix_properties["version"] == "4.2"
    assert entities["software--1"].stix_properties["cpe"].startswith("cpe:2.3:a:")
    assert entities["user-account--1"].stix_properties["account_login"] == "analyst"
    assert entities["user-account--1"].stix_properties["is_privileged"] is False
    assert entities["windows-registry-key--1"].stix_properties["key"].startswith("HKEY_LOCAL_MACHINE")
    assert entities["observed-data--1"].stix_properties["object_refs"] == [
        "file--1",
        "url--1",
        "domain-name--1",
        "ipv4-addr--1",
    ]
