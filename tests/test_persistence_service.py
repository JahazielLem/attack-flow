import json
from pathlib import Path

from attack_flow_api.services.persistence_service import PersistenceService
from attack_flow_api.storage.database import initialize_database
from attack_flow_api.storage.repositories import InputSourceCreate, JobCreate


def test_resolve_normalized_package_for_input_source_handles_invalid_payloads(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    valid = service.create_input_source(
        InputSourceCreate(
            id="input-valid",
            type="text",
            normalized_package_json='{"source_type":"narrative_text","normalized_text":"alpha"}',
        )
    )
    malformed = service.create_input_source(
        InputSourceCreate(id="input-malformed", type="text", normalized_package_json="{not-json")
    )
    non_dict = service.create_input_source(
        InputSourceCreate(id="input-non-dict", type="text", normalized_package_json="[]")
    )

    assert service.resolve_normalized_package_for_input_source(valid) == {
        "source_type": "narrative_text",
        "normalized_text": "alpha",
    }
    assert service.resolve_normalized_package_for_input_source(malformed) is None
    assert service.resolve_normalized_package_for_input_source(non_dict) is None
    assert service.resolve_normalized_package_for_input_source(None) is None


def test_resolve_canonical_text_for_input_source_prefers_normalized_then_content_then_raw(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    normalized = service.create_input_source(
        InputSourceCreate(id="input-1", type="text", raw_text="raw", content_text="content", normalized_text="normalized")
    )
    content_only = service.create_input_source(
        InputSourceCreate(id="input-2", type="text", raw_text="raw", content_text="content")
    )
    raw_only = service.create_input_source(InputSourceCreate(id="input-3", type="text", raw_text="raw"))
    unsupported = service.create_input_source(
        InputSourceCreate(id="input-4", type="file", raw_text="raw", content_text="content", normalized_text="normalized")
    )

    assert service.resolve_canonical_text_for_input_source(normalized) == "normalized"
    assert service.resolve_canonical_text_for_input_source(content_only) == "content"
    assert service.resolve_canonical_text_for_input_source(raw_only) == "raw"
    assert service.resolve_canonical_text_for_input_source(unsupported) is None
    assert service.resolve_canonical_text_for_input_source(None) is None


def test_resolve_canonical_text_for_job_falls_back_when_normalized_package_is_invalid(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    input_source = service.create_input_source(
        InputSourceCreate(
            id="input-5",
            type="text",
            raw_text="raw fallback",
            content_text="content fallback",
            normalized_package_json=json.dumps("not-a-dict"),
        )
    )
    service.create_job(
        JobCreate(
            id="job-5",
            status="queued",
            stage="queued",
            input_source_id=input_source.id,
        )
    )

    assert service.resolve_canonical_text_for_job("job-5") == "content fallback"
