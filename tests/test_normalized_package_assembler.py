import json

from attack_flow_api.services.normalized_package_assembler import build_narrative_normalized_update
from attack_flow_api.storage.database import initialize_database
from attack_flow_api.storage.repositories import InputSourceCreate, PersistenceRepository


def test_build_narrative_normalized_update_for_text_source(tmp_path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    repository = PersistenceRepository(db_path)
    created = repository.create_input_source(
        InputSourceCreate(
            id="input-1",
            type="text",
            raw_text="Alpha  \r\n\r\n\r\nBeta\n",
            normalized_text="Alpha\n\nBeta",
            normalized_char_count=len("Alpha\n\nBeta"),
            normalization_version="v1",
            content_text="Alpha\n\nBeta",
            title="Case A",
            case_id="CASE-1",
            source_name="analyst",
        )
    )

    update = build_narrative_normalized_update(
        created,
        pipeline_version="v1",
        content_budget_chars=100000,
    )

    assert update is not None
    assert update.normalized_source_type == "narrative_text"
    assert update.normalized_content_chars == len("Alpha\n\nBeta")
    payload = json.loads(update.normalized_package_json)
    assert payload["metadata"]["title"] == "Case A"
    assert payload["metadata"]["case_id"] == "CASE-1"
    assert payload["normalized_text"] == "Alpha\n\nBeta"


def test_build_narrative_normalized_update_applies_content_budget(tmp_path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    repository = PersistenceRepository(db_path)
    created = repository.create_input_source(
        InputSourceCreate(
            id="input-budget",
            type="text",
            raw_text="0123456789",
            normalized_text="0123456789",
            content_text="0123456789",
        )
    )

    update = build_narrative_normalized_update(
        created,
        pipeline_version="v1",
        content_budget_chars=5,
    )

    assert update is not None
    assert update.normalized_content_chars == 5
    assert update.normalized_content_was_truncated is True
    payload = json.loads(update.normalized_package_json)
    assert payload["normalized_text"] == "01234"
    assert payload["truncation"]["was_truncated"] is True
    assert payload["truncation"]["original_char_count"] == 10


def test_build_narrative_normalized_update_for_url_and_document_sources(tmp_path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    repository = PersistenceRepository(db_path)

    url_source = repository.create_input_source(
        InputSourceCreate(
            id="input-url",
            type="url",
            source_url="https://example.com/report",
            normalized_text="Report body",
            content_text="Report body",
        )
    )
    file_source = repository.create_input_source(
        InputSourceCreate(
            id="input-file",
            type="file",
            file_class="pdf",
            normalized_text="PDF body",
            content_text="PDF body",
            original_name="report.pdf",
        )
    )

    url_update = build_narrative_normalized_update(
        url_source,
        pipeline_version="v1",
        content_budget_chars=100000,
    )
    file_update = build_narrative_normalized_update(
        file_source,
        pipeline_version="v1",
        content_budget_chars=100000,
    )

    assert url_update is not None
    assert url_update.normalized_source_type == "url_extracted_text"
    assert file_update is not None
    assert file_update.normalized_source_type == "document_extracted_text"


def test_build_narrative_normalized_update_skips_non_narrative_or_empty_text(tmp_path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    repository = PersistenceRepository(db_path)

    stix_source = repository.create_input_source(
        InputSourceCreate(
            id="input-stix",
            type="file",
            file_class="stix_json",
            stix_json_kind="bundle",
        )
    )

    update = build_narrative_normalized_update(
        stix_source,
        pipeline_version="v1",
        content_budget_chars=100000,
    )
    assert update is None


def test_build_structured_stix_normalized_update_maps_existing_stix_outputs(tmp_path):
    from attack_flow_api.services.normalized_package_assembler import build_structured_stix_normalized_update

    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    repository = PersistenceRepository(db_path)

    stix_source = repository.create_input_source(
        InputSourceCreate(
            id="input-stix",
            type="file",
            file_class="stix_json",
            stix_bundle_id="bundle--1",
            stix_spec_version="2.1",
            stix_source_type="stix_bundle",
            normalized_text="Narrative body",
            stix_summary_json='{"bundle_metadata":{"id":"bundle--1"},"inventory":{"object_count":3},"narrative":{"normalized_text":"Narrative body"}}',
            stix_entities_json='[{"object_id":"report--1","object_type":"report","display_name":"Case Report"}]',
            stix_relationships_json='[{"relationship_id":"relationship--1","relationship_type":"uses","source_ref":"intrusion-set--1","target_ref":"malware--1"}]',
            stix_attack_refs_json='[{"technique_id":"T1566","source_object_id":"attack-pattern--1"}]',
            stix_provenance_json='{"entity_object_ids":["report--1"]}',
        )
    )

    update = build_structured_stix_normalized_update(
        stix_source,
        pipeline_version="v1",
        content_budget_chars=100000,
    )

    assert update is not None
    assert update.normalized_source_type == "stix_structured"
    payload = json.loads(update.normalized_package_json)
    assert payload["structured_summary"]["bundle_metadata"]["id"] == "bundle--1"
    assert payload["attack_refs"][0]["technique_id"] == "T1566"
    assert payload["entities"][0]["object_type"] == "report"
    assert payload["relationships"][0]["relationship_type"] == "uses"
    assert payload["provenance"]["entity_object_ids"] == ["report--1"]


def test_build_structured_stix_normalized_update_truncates_narrative_only(tmp_path):
    from attack_flow_api.services.normalized_package_assembler import build_structured_stix_normalized_update

    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    repository = PersistenceRepository(db_path)

    stix_source = repository.create_input_source(
        InputSourceCreate(
            id="input-stix-budget",
            type="file",
            file_class="stix_json",
            normalized_text="ABCDEFGHIJ",
            stix_summary_json='{"bundle_metadata":{"id":"bundle--1"},"inventory":{"object_count":1},"narrative":{"normalized_text":"ABCDEFGHIJ"}}',
            stix_entities_json='[{"object_id":"report--1","object_type":"report"}]',
            stix_relationships_json='[]',
            stix_attack_refs_json='[]',
            stix_provenance_json='{"entity_object_ids":["report--1"]}',
        )
    )

    update = build_structured_stix_normalized_update(
        stix_source,
        pipeline_version="v1",
        content_budget_chars=4,
    )

    assert update is not None
    assert update.normalized_content_chars == 4
    assert update.normalized_content_was_truncated is True
    payload = json.loads(update.normalized_package_json)
    assert payload["normalized_text"] == "ABCD"
    assert payload["entities"][0]["object_id"] == "report--1"
    assert payload["structured_summary"]["bundle_metadata"]["id"] == "bundle--1"


def test_build_structured_stix_normalized_update_exposes_sco_properties_downstream(tmp_path):
    from attack_flow_api.services.normalized_package_assembler import build_structured_stix_normalized_update

    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    repository = PersistenceRepository(db_path)
    stix_source = repository.create_input_source(
        InputSourceCreate(
            id="input-stix-scos",
            type="file",
            file_class="stix_json",
            stix_summary_json='{"bundle_metadata":{"id":"bundle--1"},"inventory":{},"narrative":{}}',
            stix_entities_json=json.dumps(
                [
                    {
                        "object_id": "file--1",
                        "object_type": "file",
                        "display_name": "payload.exe",
                        "stix_properties": {
                            "name": "payload.exe",
                            "hashes": {"SHA-256": "abc123"},
                        },
                    },
                    {
                        "object_id": "process--1",
                        "object_type": "process",
                        "stix_properties": {"command_line": "cmd.exe /c whoami"},
                    },
                ]
            ),
            stix_relationships_json="[]",
            stix_attack_refs_json="[]",
            stix_provenance_json="{}",
        )
    )

    update = build_structured_stix_normalized_update(
        stix_source,
        pipeline_version="v1",
        content_budget_chars=100000,
    )

    assert update is not None
    entities = {item["object_id"]: item for item in json.loads(update.normalized_package_json)["entities"]}
    assert entities["file--1"]["hashes"] == {"SHA-256": "abc123"}
    assert entities["file--1"]["name"] == "payload.exe"
    assert entities["process--1"]["command_line"] == "cmd.exe /c whoami"
    assert "stix_properties" not in entities["file--1"]
