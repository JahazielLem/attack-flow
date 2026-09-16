import json
import sqlite3
import re
import time
import os
from pathlib import Path
from uuid import uuid4
from types import SimpleNamespace

from fastapi.testclient import TestClient

from attack_flow_api.main import create_app
from attack_flow_api.config import ProviderConfig
from attack_flow_api.providers.registry import ProviderRegistry
from attack_flow_api.services.afb_export_contracts import AfbExportArtifactMetadata
from attack_flow_api.services.stix_export_contracts import StixExportArtifactMetadata
from attack_flow_api.storage.repositories import ArtifactCreate, InputSourceCreate, JobCreate, JobUpdate


class _FakeOpenAIAdapter:
    def __init__(self, provider_id: str, provider_type: str):
        self._provider_id = provider_id
        self._provider_type = provider_type

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def provider_type(self) -> str:
        return self._provider_type

    def generate_structured(self, request):
        return SimpleNamespace(
            provider_id=request.provider_id,
            provider_type=request.provider_type,
            model=request.model,
            output_json={
                "validation_state": "valid",
                "repair_attempted": False,
                "provider_invoked": True,
                "provider_id": request.provider_id,
                "model": request.model,
                "attack_flow": {
                    "id": "attack-flow--fake",
                    "name": "Fake extraction",
                    "scope": "incident",
                    "orchestration_mode": "ai_enrichment",
                    "source_classification": "document_extracted_text",
                    "authors": [],
                    "external_references": [],
                    "provenance": {},
                },
                "attack_actions": [],
                "attack_conditions": [],
                "attack_operators": [],
                "attack_assets": [],
                "deterministic_attack_refs": [],
                "deterministic_entities": [],
                "deterministic_relationships": [],
            },
            output_text=None,
        )


def _build_client(monkeypatch, tmp_path: Path) -> TestClient:
    data_dir = tmp_path / "data"
    providers_path = tmp_path / "providers.yml"
    providers_path.write_text(
        """
providers:
  - provider_id: default-openai
    provider_type: openai
    enabled: true
    base_url: https://api.openai.com/v1
    api_key_env: OPENAI_API_KEY
    default_model: gpt-4.1-mini
    allowed_models:
      - gpt-4.1-mini
""".strip()
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("APP_NAME", "attack-flow-api")
    monkeypatch.setenv("API_PREFIX", "/api/v1")
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("SQLITE_PATH", str(data_dir / "attack-flow.db"))
    monkeypatch.setenv("UPLOAD_DIR", str(data_dir / "uploads"))
    monkeypatch.setenv("ARTIFACT_DIR", str(data_dir / "artifacts"))
    monkeypatch.setenv("PROVIDERS_CONFIG_PATH", str(providers_path))
    if os.environ.get("UPLOAD_MAX_BYTES") is None:
        monkeypatch.setenv("UPLOAD_MAX_BYTES", "1000000")
    if os.environ.get("UPLOAD_ALLOWED_FILE_CLASSES") is None:
        monkeypatch.setenv("UPLOAD_ALLOWED_FILE_CLASSES", "pdf,plaintext,stix_json")
    if os.environ.get("UPLOAD_ALLOWED_MIME_TYPES") is None:
        monkeypatch.setenv("UPLOAD_ALLOWED_MIME_TYPES", "application/pdf,text/plain,application/json")

    original_build_adapter = ProviderRegistry._build_adapter

    def _build_adapter(self, provider: ProviderConfig):
        if provider.provider_type == "openai":
            return _FakeOpenAIAdapter(provider.provider_id, provider.provider_type)
        return original_build_adapter(self, provider)

    monkeypatch.setattr(ProviderRegistry, "_build_adapter", _build_adapter)

    return TestClient(create_app())


def _assert_common_accepted_response(payload: dict[str, str]) -> None:
    assert payload["job_id"]
    assert payload["status"] == "queued"
    assert payload["poll_url"] == f"/api/v1/jobs/{payload['job_id']}"
    assert payload["request_id"]


def test_submit_job_text_returns_202_and_persists_records(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={
                "input_type": "text",
                "text": "investigation content",
                "metadata": {"source": "unit-test"},
                "options": {"priority": "normal"},
            },
        )

        payload = response.json()
        assert response.status_code == 202
        _assert_common_accepted_response(payload)
        assert payload["submitted_at"]

        sqlite_path = client.app.state.sqlite_path

    with sqlite3.connect(sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (payload["job_id"],)).fetchone()
        assert job_row is not None
        assert job_row["status"] == "queued"

        input_row = connection.execute(
            "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
        ).fetchone()
        assert input_row is not None
        assert input_row["type"] == "text"
        assert input_row["content_text"] == "investigation content"
        assert input_row["raw_text"] == "investigation content"
        assert input_row["normalized_text"] == "investigation content"
        assert input_row["normalized_char_count"] == len("investigation content")
        assert input_row["normalization_version"] == "v1"
        assert input_row["source_url"] is None
        assert input_row["metadata_json"] == '{"source": "unit-test"}'
        assert input_row["options_json"] == '{"priority": "normal"}'

        audit_rows = connection.execute(
            "SELECT event_type, status, stage, request_id, message, details_json FROM audit_events WHERE job_id = ? ORDER BY sequence ASC",
            (payload["job_id"],),
        ).fetchall()
        assert [row["event_type"] for row in audit_rows] == ["job_submitted", "job_queued", "text_normalized"]
        assert audit_rows[0]["status"] == "queued"
        assert audit_rows[0]["stage"] == "queued"
        assert audit_rows[0]["request_id"] == payload["request_id"]
        assert audit_rows[0]["message"] == "job submitted"
        assert json.loads(audit_rows[0]["details_json"])["source_type"] == "text"
        assert json.loads(audit_rows[1]["details_json"])["job_id"] == payload["job_id"]
        assert json.loads(audit_rows[2]["details_json"])["normalized_char_count"] == len("investigation content")


def test_submit_job_options_provider_override_persists_safe_metadata(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={
                "input_type": "text",
                "text": "investigation content",
                "options": {
                    "provider_override": {
                        "provider_type": "openai_compatible",
                        "endpoint": "https://compatible.example/v1",
                        "api_key": "runtime-secret",
                        "model": "model-a",
                        "extra_headers": {"X-Test": "header-secret"},
                    }
                },
            },
        )

        payload = response.json()
        assert response.status_code == 202
        sqlite_path = client.app.state.sqlite_path

    with sqlite3.connect(sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (payload["job_id"],)).fetchone()
        assert job_row is not None
        assert job_row["provider_id"] == "runtime-openai_compatible"
        assert job_row["model"] == "model-a"

        input_row = connection.execute(
            "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
        ).fetchone()
        assert input_row is not None
        options = json.loads(input_row["options_json"])
        provider_override = options["provider_override"]
        assert provider_override == {
            "provider_source": "runtime_override",
            "provider_type": "openai_compatible",
            "endpoint_redacted": "https://compatible.example",
            "model": "model-a",
            "api_version": None,
            "deployment": None,
            "extra_header_names": ["X-Test"],
        }
        assert "runtime-secret" not in input_row["options_json"]
        assert "header-secret" not in input_row["options_json"]
        assert "api_key" not in input_row["options_json"]
        assert "extra_headers" not in input_row["options_json"]

        audit_rows = connection.execute(
            "SELECT event_type, details_json FROM audit_events WHERE job_id = ? ORDER BY sequence ASC",
            (payload["job_id"],),
        ).fetchall()
        runtime_event = next(
            row for row in audit_rows if row["event_type"] == "runtime_provider_override_received"
        )
        runtime_details = json.loads(runtime_event["details_json"])
        assert runtime_details["provider_source"] == "runtime_override"
        assert runtime_details["provider_type"] == "openai_compatible"
        assert runtime_details["endpoint_redacted"] == "https://compatible.example"
        assert runtime_details["model"] == "model-a"
        assert "runtime-secret" not in runtime_event["details_json"]
        assert "header-secret" not in runtime_event["details_json"]


def test_submit_job_options_anthropic_provider_override_persists_safe_metadata(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={
                "input_type": "text",
                "text": "investigation content",
                "options": {
                    "provider_override": {
                        "provider_type": "anthropic",
                        "endpoint": "https://api.anthropic.com/v1",
                        "api_key": "runtime-secret",
                        "model": "claude-3-5-haiku-latest",
                    }
                },
            },
        )

        payload = response.json()
        assert response.status_code == 202
        sqlite_path = client.app.state.sqlite_path

    with sqlite3.connect(sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (payload["job_id"],)).fetchone()
        assert job_row is not None
        assert job_row["provider_id"] == "runtime-anthropic"
        assert job_row["model"] == "claude-3-5-haiku-latest"

        input_row = connection.execute(
            "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
        ).fetchone()
        assert input_row is not None
        provider_override = json.loads(input_row["options_json"])["provider_override"]
        assert provider_override == {
            "provider_source": "runtime_override",
            "provider_type": "anthropic",
            "endpoint_redacted": "https://api.anthropic.com",
            "model": "claude-3-5-haiku-latest",
            "api_version": None,
            "deployment": None,
            "extra_header_names": [],
        }
        assert "runtime-secret" not in input_row["options_json"]
        assert "api_key" not in input_row["options_json"]

        runtime_event = connection.execute(
            "SELECT details_json FROM audit_events WHERE job_id = ? AND event_type = ?",
            (payload["job_id"], "runtime_provider_override_received"),
        ).fetchone()
        assert runtime_event is not None
        assert "runtime-secret" not in runtime_event["details_json"]
        assert json.loads(runtime_event["details_json"])["provider_type"] == "anthropic"


def test_submit_job_options_gemini_provider_override_persists_safe_metadata(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={
                "input_type": "text",
                "text": "investigation content",
                "options": {
                    "provider_override": {
                        "provider_type": "gemini",
                        "endpoint": "https://generativelanguage.googleapis.com/v1beta",
                        "api_key": "runtime-secret",
                        "model": "gemini-1.5-flash",
                    }
                },
            },
        )

        payload = response.json()
        assert response.status_code == 202
        sqlite_path = client.app.state.sqlite_path

    with sqlite3.connect(sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (payload["job_id"],)).fetchone()
        assert job_row is not None
        assert job_row["provider_id"] == "runtime-gemini"
        assert job_row["model"] == "gemini-1.5-flash"

        input_row = connection.execute(
            "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
        ).fetchone()
        assert input_row is not None
        provider_override = json.loads(input_row["options_json"])["provider_override"]
        assert provider_override == {
            "provider_source": "runtime_override",
            "provider_type": "gemini",
            "endpoint_redacted": "https://generativelanguage.googleapis.com",
            "model": "gemini-1.5-flash",
            "api_version": None,
            "deployment": None,
            "extra_header_names": [],
        }
        assert "runtime-secret" not in input_row["options_json"]
        assert "api_key" not in input_row["options_json"]

        runtime_event = connection.execute(
            "SELECT details_json FROM audit_events WHERE job_id = ? AND event_type = ?",
            (payload["job_id"], "runtime_provider_override_received"),
        ).fetchone()
        assert runtime_event is not None
        assert "runtime-secret" not in runtime_event["details_json"]
        assert json.loads(runtime_event["details_json"])["provider_type"] == "gemini"


def test_submit_job_options_rejects_provider_id_and_override(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={
                "input_type": "text",
                "text": "investigation content",
                "options": {
                    "provider_id": "default-openai",
                    "provider_override": {
                        "provider_type": "openai",
                        "api_key": "runtime-secret",
                        "model": "gpt-4.1-mini",
                    },
                },
            },
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "invalid_provider_selection"
    assert "runtime-secret" not in response.text


def test_submit_job_text_persists_normalized_text(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={
                "input_type": "text",
                "text": "\r\nalpha  \r\n\r\n\r\nbeta\t\n",
            },
        )

        payload = response.json()
        assert response.status_code == 202
        sqlite_path = client.app.state.sqlite_path

    with sqlite3.connect(sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (payload["job_id"],)).fetchone()
        assert job_row is not None

        input_row = connection.execute(
            "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
        ).fetchone()
        assert input_row is not None
        assert input_row["raw_text"] == "\r\nalpha  \r\n\r\n\r\nbeta\t\n"
        assert input_row["normalized_text"] == "alpha\n\nbeta"
        assert input_row["content_text"] == "alpha\n\nbeta"
        assert input_row["normalized_char_count"] == len("alpha\n\nbeta")
        assert input_row["normalization_version"] == "v1"


def test_submit_job_url_returns_202_and_persists_url(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={"input_type": "url", "url": "https://example.com/report"},
        )

        payload = response.json()
        assert response.status_code == 202
        _assert_common_accepted_response(payload)

        sqlite_path = client.app.state.sqlite_path

    with sqlite3.connect(sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (payload["job_id"],)).fetchone()
        assert job_row is not None
        assert job_row["status"] == "queued"

        input_row = connection.execute(
            "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
        ).fetchone()
        assert input_row is not None
        assert input_row["type"] == "url"
        assert input_row["source_url"] == "https://example.com/report"
        assert input_row["content_text"] is None


def test_submit_job_conflicting_shape_returns_structured_400(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "hello", "url": "https://example.com"},
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "conflicting_input_fields"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_submit_job_unsupported_input_type_returns_structured_400(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={"input_type": "file", "url": "https://example.com"},
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "invalid_input_type"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_submit_job_url_with_non_http_scheme_returns_structured_400(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={"input_type": "url", "url": "ftp://example.com/report"},
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "invalid_url_scheme"
    assert payload["error"]["message"] == "url scheme must be http or https"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_submit_job_missing_supported_input_returns_structured_400(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "   "},
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "invalid_text_input"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_submit_job_text_over_limit_returns_structured_413(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("RAW_TEXT_MAX_CHARS", "5")
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "abcdef"},
        )

    payload = response.json()
    assert response.status_code == 413
    assert payload["error"]["code"] == "text_too_large"
    assert "maximum size of 5 characters" in payload["error"]["message"]
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_submit_job_text_preserves_source_metadata_fields(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={
                "input_type": "text",
                "text": "metadata check",
                "metadata": {
                    "title": "Case report 42",
                    "case_id": "CASE-42",
                    "source_name": "analyst-notes",
                },
            },
        )

        payload = response.json()
        assert response.status_code == 202
        sqlite_path = client.app.state.sqlite_path

    with sqlite3.connect(sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (payload["job_id"],)).fetchone()
        assert job_row is not None

        input_row = connection.execute(
            "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
        ).fetchone()
        assert input_row is not None
        assert (
            input_row["metadata_json"]
            == '{"title": "Case report 42", "case_id": "CASE-42", "source_name": "analyst-notes"}'
        )
        assert input_row["title"] == "Case report 42"
        assert input_row["case_id"] == "CASE-42"
        assert input_row["source_name"] == "analyst-notes"


def test_get_job_status_includes_title_when_present_in_metadata(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={
                "input_type": "text",
                "text": "status title",
                "metadata": {"title": "Incident 9001"},
            },
        )
        job_id = create_response.json()["job_id"]

        response = client.get(f"/api/v1/jobs/{job_id}")

    payload = response.json()
    assert response.status_code == 200
    assert payload["input"]["title"] == "Incident 9001"


def test_submit_job_invalid_json_shape_stays_422(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post("/api/v1/jobs", json={"input_type": "text", "text": 123})

    assert response.status_code == 422


def test_submit_job_multipart_file_returns_202_and_persists_file_metadata(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            files={"file": ("evidence.txt", b"hello", "text/plain")},
            data={"metadata": '{"source":"upload"}', "options": '{"priority":"high"}'},
        )

        payload = response.json()
        assert response.status_code == 202
        _assert_common_accepted_response(payload)

        sqlite_path = client.app.state.sqlite_path
        data_dir = client.app.state.settings.data_dir

    with sqlite3.connect(sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (payload["job_id"],)).fetchone()
        assert job_row is not None

        input_row = connection.execute(
            "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
        ).fetchone()
        assert input_row is not None
        assert input_row["type"] == "file"
        assert input_row["original_name"] == "evidence.txt"
        assert input_row["mime_type"] == "text/plain"
        assert input_row["size_bytes"] == 5
        assert input_row["storage_path"].startswith("uploads/")
        assert input_row["metadata_json"] == '{"source": "upload"}'
        assert input_row["options_json"] == '{"priority": "high"}'
        assert input_row["stored_filename"]
        assert input_row["stored_filename"] != "evidence.txt"
        assert input_row["detected_mime_type"] == "text/plain"
        assert input_row["file_class"] == "plaintext"
        assert input_row["sha256"]

    stored_path = data_dir / input_row["storage_path"]
    assert stored_path.exists()
    assert stored_path.read_bytes() == b"hello"
    assert re.fullmatch(r"[0-9a-f]{32}\.txt", stored_path.name) is not None


def test_submit_job_multipart_missing_file_returns_400(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            files={"metadata": (None, '{"source":"upload"}')},
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "missing_file"


def test_submit_job_multipart_rejects_unsupported_file_type(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            files={"file": ("payload.bin", b"\x00\x01\x02\x03", "application/octet-stream")},
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] in {"unsupported_file_mime_type", "unsupported_file_type"}


def test_submit_job_multipart_rejects_mismatched_file_type_signals(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            files={"file": ("report.txt", b"%PDF-1.7\nexample", "text/plain")},
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "conflicting_file_type_signals"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_submit_job_multipart_sanitizes_original_filename(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            files={"file": ("../../incident notes.txt", b"hello", "text/plain")},
        )

        payload = response.json()
        assert response.status_code == 202
        sqlite_path = client.app.state.sqlite_path

    with sqlite3.connect(sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (payload["job_id"],)).fetchone()
        assert job_row is not None
        input_row = connection.execute(
            "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
        ).fetchone()
        assert input_row is not None
        assert input_row["original_name"] == "incident notes.txt"
        assert input_row["stored_filename"] != "../../incident notes.txt"
        assert input_row["storage_path"].startswith("uploads/")


def test_submit_job_multipart_rejects_file_too_large(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("UPLOAD_MAX_BYTES", "4")
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            files={"file": ("evidence.txt", b"12345", "text/plain")},
        )

    payload = response.json()
    assert response.status_code == 413
    assert payload["error"]["code"] == "file_too_large"


def test_submit_job_multipart_stix_json_persists_routing_markers(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            files={
                "file": (
                    "bundle.json",
                    b'{"type":"bundle","id":"bundle--12345678-1234-1234-1234-123456789012","objects":[]}',
                    "application/json",
                )
            },
        )

        payload = response.json()
        assert response.status_code == 202
        sqlite_path = client.app.state.sqlite_path

    with sqlite3.connect(sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (payload["job_id"],)).fetchone()
        assert job_row is not None

        input_row = connection.execute(
            "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
        ).fetchone()
        assert input_row is not None
        assert input_row["file_class"] == "stix_json"
        assert input_row["stix_json_kind"] == "bundle"
        assert input_row["stix_json_valid"] == 1


def test_submit_job_multipart_stix_json_accepts_bundle_with_custom_properties(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            files={
                "file": (
                    "bundle-custom.json",
                    (
                        b'{"type":"bundle","id":"bundle--12345678-1234-1234-1234-123456789012",'
                        b'"objects":[],"x_opencti_custom":true}'
                    ),
                    "application/json",
                )
            },
        )

        payload = response.json()
        assert response.status_code == 202
        sqlite_path = client.app.state.sqlite_path

    with sqlite3.connect(sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (payload["job_id"],)).fetchone()
        assert job_row is not None

        input_row = connection.execute(
            "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
        ).fetchone()
        assert input_row is not None
        assert input_row["file_class"] == "stix_json"
        assert input_row["stix_json_kind"] == "bundle"
        assert input_row["stix_json_valid"] == 1


def test_submit_job_multipart_stix_json_rejects_non_bundle_shape(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            files={"file": ("report.json", b'{"type":"report","objects":[]}', "application/json")},
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "stix_json_not_bundle"


def test_submit_job_multipart_invalid_metadata_returns_400(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            files={"file": ("evidence.txt", b"hello", "text/plain")},
            data={"metadata": "not-json"},
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "invalid_json_field"


def test_submit_job_multipart_rejects_non_file_input_fields(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            files={"file": ("evidence.txt", b"hello", "text/plain")},
            data={"input_type": "text", "text": "hello"},
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "conflicting_input_fields"


def test_get_job_status_returns_200_with_job_state(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={
                "input_type": "text",
                "text": "investigation content",
                "metadata": {"source": "manual"},
            },
        )
        job_id = create_response.json()["job_id"]

        response = client.get(f"/api/v1/jobs/{job_id}")

    payload = response.json()
    assert response.status_code == 200
    assert payload["job_id"] == job_id
    assert payload["status"] == "queued"
    assert payload["stage"] == "queued"
    assert payload["created_at"]
    assert payload["updated_at"]
    assert payload["completed_at"] is None
    assert payload["input"]["input_type"] == "text"
    assert payload["input"]["original_filename"] is None
    assert payload["request_id"]


def test_get_job_status_includes_export_outcome_when_artifact_exists(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "investigation content"},
        )
        job_id = create_response.json()["job_id"]

        artifact_file = client.app.state.file_storage.write_artifact(
            b'{"type":"bundle","id":"bundle--status"}',
            extension="json",
        )
        client.app.state.persistence_service.create_artifact(
            payload=ArtifactCreate(
                id=str(uuid4()),
                job_id=job_id,
                type="stix",
                path=artifact_file.relative_path,
                size_bytes=artifact_file.size_bytes,
                metadata_json=StixExportArtifactMetadata(
                    validation_state="valid",
                    bundle_id="bundle--status",
                    object_count=1,
                    exported_at="2026-01-01T00:00:00Z",
                    export_status="completed",
                    validation_errors=[],
                ).model_dump_json(),
                validation_state="valid",
                export_status="completed",
                sha256="abc123",
            )
        )

        response = client.get(f"/api/v1/jobs/{job_id}")

    payload = response.json()
    assert response.status_code == 200
    assert payload["artifacts"]["has_stix"] is True
    assert payload["artifacts"]["stix_outcome"]["valid"] is True
    assert payload["artifacts"]["stix_outcome"]["export_status"] == "completed"
    assert payload["artifacts"]["stix_outcome"]["checksum"] == "abc123"


def test_get_job_status_returns_structured_404_when_missing(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.get("/api/v1/jobs/missing-job")

    payload = response.json()
    assert response.status_code == 404
    assert payload["error"]["code"] == "job_not_found"
    assert payload["error"]["message"] == "Job not found"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_delete_job_returns_200_and_removes_related_records_and_files(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            files={"file": ("evidence.txt", b"hello", "text/plain")},
        )
        job_id = create_response.json()["job_id"]

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            assert job_row is not None
            input_row = connection.execute(
                "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
            ).fetchone()
            assert input_row is not None

        artifact_file = client.app.state.file_storage.write_artifact(b"{}", extension="json")
        client.app.state.persistence_service.create_artifact(
            payload=ArtifactCreate(
                id=str(uuid4()),
                job_id=job_id,
                type="stix",
                path=artifact_file.relative_path,
                size_bytes=artifact_file.size_bytes,
                metadata_json=StixExportArtifactMetadata(
                    validation_state="valid",
                    bundle_id="bundle--stix",
                    object_count=1,
                    exported_at="2026-01-01T00:00:00Z",
                    export_status="completed",
                    validation_errors=[],
                ).model_dump_json(),
                validation_state="valid",
                export_status="completed",
            )
        )

        upload_path = client.app.state.settings.data_dir / input_row["storage_path"]
        assert upload_path.exists()
        assert artifact_file.absolute_path.exists()

        response = client.delete(f"/api/v1/jobs/{job_id}")

    payload = response.json()
    assert response.status_code == 200
    assert payload == {"job_id": job_id, "deleted": True, "request_id": payload["request_id"]}
    assert payload["request_id"]

    with sqlite3.connect(client.app.state.sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        assert connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone() is None
        assert (
            connection.execute("SELECT * FROM input_sources WHERE id = ?", (input_row["id"],)).fetchone()
            is None
        )
        assert connection.execute("SELECT * FROM artifacts WHERE job_id = ?", (job_id,)).fetchone() is None

    assert not upload_path.exists()
    assert not artifact_file.absolute_path.exists()


def test_delete_job_returns_structured_404_when_missing(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.delete("/api/v1/jobs/missing-job")

    payload = response.json()
    assert response.status_code == 404
    assert payload["error"]["code"] == "job_not_found"
    assert payload["error"]["message"] == "Job not found"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_download_job_stix_artifact_returns_json_file(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "investigation content"},
        )
        job_id = create_response.json()["job_id"]

        artifact_file = client.app.state.file_storage.write_artifact(
            b'{"type":"bundle","id":"bundle--stix"}',
            extension="json",
        )
        client.app.state.persistence_service.create_artifact(
            payload=ArtifactCreate(
                id=str(uuid4()),
                job_id=job_id,
                type="stix",
                path=artifact_file.relative_path,
                size_bytes=artifact_file.size_bytes,
                metadata_json=StixExportArtifactMetadata(
                    validation_state="valid",
                    bundle_id="bundle--stix",
                    object_count=1,
                    exported_at="2026-01-01T00:00:00Z",
                    export_status="completed",
                    validation_errors=[],
                ).model_dump_json(),
                validation_state="valid",
                export_status="completed",
            )
        )

        response = client.get(f"/api/v1/jobs/{job_id}/artifacts/stix")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["content-disposition"].endswith(f'filename="{job_id}-stix.json"')
    assert response.headers.get("x-request-id")
    assert response.json()["id"] == "bundle--stix"


def test_download_job_afb_artifact_returns_json_file(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "url", "url": "https://example.com/report"},
        )
        job_id = create_response.json()["job_id"]

        artifact_file = client.app.state.file_storage.write_artifact(
            b'{"format":"afb","version":"1"}',
            extension="json",
        )
        client.app.state.persistence_service.create_artifact(
            payload=ArtifactCreate(
                id=str(uuid4()),
                job_id=job_id,
                type="afb",
                path=artifact_file.relative_path,
                size_bytes=artifact_file.size_bytes,
                metadata_json=AfbExportArtifactMetadata(
                    validation_state="valid",
                    bundle_id="bundle--afb",
                    object_count=1,
                    exported_at="2026-01-01T00:00:00Z",
                    export_status="completed",
                    validation_errors=[],
                ).model_dump_json(),
                validation_state="valid",
                export_status="completed",
            )
        )

        response = client.get(f"/api/v1/jobs/{job_id}/artifacts/afb")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["content-disposition"].endswith(f'filename="{job_id}-afb.afb"')
    assert response.headers.get("x-request-id")
    assert response.json()["format"] == "afb"


def test_download_job_ai_trace_artifact_returns_json_file(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "investigation content"},
        )
        job_id = create_response.json()["job_id"]

        initial_file = client.app.state.file_storage.write_artifact(
            b'{"label":"initial","prompt":"SYSTEM_INSTRUCTION...","output_text":"{}"}',
            extension="json",
        )
        client.app.state.persistence_service.create_artifact(
            payload=ArtifactCreate(
                id=str(uuid4()),
                job_id=job_id,
                type="ai_trace",
                path=initial_file.relative_path,
                size_bytes=initial_file.size_bytes,
                metadata_json=json.dumps({"kind": "ai_trace", "label": "initial"}),
            )
        )

        retry_file = client.app.state.file_storage.write_artifact(
            json.dumps({"label": "retry", "prompt": "SYSTEM_INSTRUCTION...", "output_text": {"attack_actions": []}}).encode("utf-8"),
            extension="json",
        )
        client.app.state.persistence_service.create_artifact(
            payload=ArtifactCreate(
                id=str(uuid4()),
                job_id=job_id,
                type="ai_trace",
                path=retry_file.relative_path,
                size_bytes=retry_file.size_bytes,
                metadata_json=json.dumps({"kind": "ai_trace", "label": "retry"}),
            )
        )

        response = client.get(f"/api/v1/jobs/{job_id}/artifacts/ai-trace")
        label_response = client.get(f"/api/v1/jobs/{job_id}/artifacts/ai-trace?label=initial")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["content-disposition"].endswith(f'filename="{job_id}-ai-trace.json"')
    assert response.headers.get("x-request-id")
    assert response.json()["label"] == "retry"

    assert label_response.status_code == 200
    assert label_response.headers["content-disposition"].endswith(f'filename="{job_id}-ai-trace-initial.json"')
    assert label_response.json()["label"] == "initial"


def test_download_job_artifact_returns_404_for_invalid_artifact(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "investigation content"},
        )
        job_id = create_response.json()["job_id"]

        artifact_file = client.app.state.file_storage.write_artifact(
            b'{"type":"bundle","id":"bundle--invalid"}',
            extension="json",
        )
        client.app.state.persistence_service.create_artifact(
            payload=ArtifactCreate(
                id=str(uuid4()),
                job_id=job_id,
                type="stix",
                path=artifact_file.relative_path,
                size_bytes=artifact_file.size_bytes,
                metadata_json=StixExportArtifactMetadata(
                    validation_state="invalid",
                    bundle_id="bundle--invalid",
                    object_count=1,
                    exported_at="2026-01-01T00:00:00Z",
                    export_status="failed",
                    error_code="validation_failed",
                    error_message="export validation failed",
                    validation_errors=[{"code": "invalid"}],
                ).model_dump_json(),
                validation_state="invalid",
                export_status="failed",
                error_code="validation_failed",
                error_message="export validation failed",
            )
        )

        response = client.get(f"/api/v1/jobs/{job_id}/artifacts/stix")

    payload = response.json()
    assert response.status_code == 404
    assert payload["error"]["code"] == "artifact_not_found"
    assert payload["error"]["message"] == "stix artifact not found"


def test_download_job_artifact_returns_structured_404_for_missing_job(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.get("/api/v1/jobs/missing-job/artifacts/stix")

    payload = response.json()
    assert response.status_code == 404
    assert payload["error"]["code"] == "job_not_found"
    assert payload["error"]["message"] == "Job not found"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_download_job_artifact_returns_structured_404_for_missing_artifact(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "investigation content"},
        )
        job_id = create_response.json()["job_id"]

        response = client.get(f"/api/v1/jobs/{job_id}/artifacts/stix")

    payload = response.json()
    assert response.status_code == 404
    assert payload["error"]["code"] == "artifact_not_found"
    assert payload["error"]["message"] == "stix artifact not found"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_get_job_result_returns_structured_404_when_job_missing(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.get("/api/v1/jobs/missing-job/result")

    payload = response.json()
    assert response.status_code == 404
    assert payload["error"]["code"] == "job_not_found"
    assert payload["error"]["message"] == "Job not found"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_get_job_result_returns_structured_409_when_not_ready(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "investigation content"},
        )
        job_id = create_response.json()["job_id"]

        response = client.get(f"/api/v1/jobs/{job_id}/result")

    payload = response.json()
    assert response.status_code == 409
    assert payload["error"]["code"] == "result_not_ready"
    assert payload["error"]["message"] == "Result is not ready"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_get_job_result_returns_200_when_structured_result_exists(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "url", "url": "https://example.com/report"},
        )
        job_id = create_response.json()["job_id"]

        client.app.state.persistence_service.update_job(
            job_id,
            JobUpdate(
                result_json=(
                    '{"summary":"ready","techniques":["T1059"],'
                    '"artifacts":{"stix":true,"afb":false}}'
                )
            ),
        )

        artifact_file = client.app.state.file_storage.write_artifact(
            b'{"type":"bundle","id":"bundle--result"}',
            extension="json",
        )
        client.app.state.persistence_service.create_artifact(
            payload=ArtifactCreate(
                id=str(uuid4()),
                job_id=job_id,
                type="stix",
                path=artifact_file.relative_path,
                size_bytes=artifact_file.size_bytes,
                metadata_json=StixExportArtifactMetadata(
                    validation_state="valid",
                    bundle_id="bundle--result",
                    object_count=1,
                    exported_at="2026-01-01T00:00:00Z",
                    export_status="completed",
                    validation_errors=[],
                ).model_dump_json(),
                validation_state="valid",
                export_status="completed",
            )
        )

        response = client.get(f"/api/v1/jobs/{job_id}/result")

    payload = response.json()
    assert response.status_code == 200
    assert payload["job_id"] == job_id
    assert payload["status"] == "queued"
    assert payload["result"]["summary"] == "ready"
    assert payload["result"]["techniques"] == ["T1059"]
    assert payload["result"]["artifacts"] == {"stix": True, "afb": False}
    assert payload["artifacts"]["has_stix"] is True
    assert payload["artifacts"]["stix_outcome"]["export_status"] == "completed"
    assert payload["request_id"]


def test_get_job_result_returns_structured_409_for_malformed_result_json(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "investigation content"},
        )
        job_id = create_response.json()["job_id"]

        client.app.state.persistence_service.update_job(
            job_id,
            JobUpdate(result_json="{not valid json"),
        )

        response = client.get(f"/api/v1/jobs/{job_id}/result")

    payload = response.json()
    assert response.status_code == 409
    assert payload["error"]["code"] == "result_not_ready"
    assert payload["error"]["message"] == "Result is not ready"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_get_job_result_returns_structured_409_for_non_object_result_json(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "investigation content"},
        )
        job_id = create_response.json()["job_id"]

        client.app.state.persistence_service.update_job(
            job_id,
            JobUpdate(result_json='["not", "an", "object"]'),
        )

        response = client.get(f"/api/v1/jobs/{job_id}/result")

    payload = response.json()
    assert response.status_code == 409
    assert payload["error"]["code"] == "result_not_ready"
    assert payload["error"]["message"] == "Result is not ready"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_get_job_status_prefers_latest_downloadable_stix_artifact(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "investigation content"},
        )
        job_id = create_response.json()["job_id"]

        invalid_artifact = client.app.state.file_storage.write_artifact(b'{"id":"bundle--old"}', extension="json")
        client.app.state.persistence_service.create_artifact(
            payload=ArtifactCreate(
                id=str(uuid4()),
                job_id=job_id,
                type="stix",
                path=invalid_artifact.relative_path,
                size_bytes=invalid_artifact.size_bytes,
                metadata_json=StixExportArtifactMetadata(
                    validation_state="invalid",
                    bundle_id="bundle--old",
                    object_count=1,
                    exported_at="2026-01-01T00:00:00Z",
                    export_status="failed",
                    error_code="validation_failed",
                    error_message="export validation failed",
                    validation_errors=[{"code": "invalid"}],
                ).model_dump_json(),
                validation_state="invalid",
                export_status="failed",
                error_code="validation_failed",
                error_message="export validation failed",
            )
        )

        valid_artifact = client.app.state.file_storage.write_artifact(b'{"id":"bundle--new"}', extension="json")
        client.app.state.persistence_service.create_artifact(
            payload=ArtifactCreate(
                id=str(uuid4()),
                job_id=job_id,
                type="stix",
                path=valid_artifact.relative_path,
                size_bytes=valid_artifact.size_bytes,
                metadata_json=StixExportArtifactMetadata(
                    validation_state="valid",
                    bundle_id="bundle--new",
                    object_count=1,
                    exported_at="2026-01-01T00:00:00Z",
                    export_status="completed",
                    validation_errors=[],
                ).model_dump_json(),
                validation_state="valid",
                export_status="completed",
            )
        )

        status_response = client.get(f"/api/v1/jobs/{job_id}")
        download_response = client.get(f"/api/v1/jobs/{job_id}/artifacts/stix")

    status_payload = status_response.json()
    assert status_response.status_code == 200
    assert status_payload["artifacts"]["has_stix"] is True
    assert status_payload["artifacts"]["stix_url"].endswith(f"/jobs/{job_id}/artifacts/stix")

    assert download_response.status_code == 200
    assert download_response.json()["id"] == "bundle--new"


def test_delete_job_keeps_shared_input_source_until_last_job_is_removed(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        shared_input = client.app.state.persistence_service.create_input_source(
            InputSourceCreate(id="input-shared-1", type="text", content_text="shared content")
        )
        first_job = client.app.state.persistence_service.create_job(
            JobCreate(id="job-shared-1", status="completed", stage="completed", input_source_id=shared_input.id)
        )
        second_job = client.app.state.persistence_service.create_job(
            JobCreate(id="job-shared-2", status="completed", stage="completed", input_source_id=shared_input.id)
        )

        first_response = client.delete(f"/api/v1/jobs/{first_job.id}")
        assert first_response.status_code == 200

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            remaining_input = connection.execute(
                "SELECT * FROM input_sources WHERE id = ?", (shared_input.id,)
            ).fetchone()
            assert remaining_input is not None
            remaining_job = connection.execute(
                "SELECT * FROM jobs WHERE id = ?", (second_job.id,)
            ).fetchone()
            assert remaining_job is not None
            assert remaining_job["input_source_id"] == shared_input.id


def test_worker_advances_claimed_job_through_lifecycle_to_completed(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "lifecycle progression"},
        )
        job_id = create_response.json()["job_id"]

        final_payload = None
        for _ in range(40):
            response = client.get(f"/api/v1/jobs/{job_id}")
            payload = response.json()
            if payload["status"] == "completed":
                final_payload = payload
                break
            time.sleep(0.05)

    assert final_payload is not None
    assert final_payload["job_id"] == job_id
    assert final_payload["status"] == "completed"
    assert final_payload["stage"] == "completed"
    assert final_payload["completed_at"] is not None


def test_worker_marks_failed_job_and_continues_processing_next_job(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        first_create = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "should fail"},
        )
        failed_job_id = first_create.json()["job_id"]
        client.app.state.job_worker.force_failure_for_job(failed_job_id)

        second_create = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "should complete"},
        )
        succeeding_job_id = second_create.json()["job_id"]

        failed_payload = None
        completed_payload = None
        for _ in range(60):
            first_status = client.get(f"/api/v1/jobs/{failed_job_id}").json()
            second_status = client.get(f"/api/v1/jobs/{succeeding_job_id}").json()
            if first_status["status"] == "failed":
                failed_payload = first_status
            if second_status["status"] == "completed":
                completed_payload = second_status
            if failed_payload is not None and completed_payload is not None:
                break
            time.sleep(0.05)

        assert failed_payload is not None
        assert failed_payload["status"] == "failed"
        assert failed_payload["stage"] == "failed"

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            failed_row = connection.execute(
                "SELECT error_code, error_message, updated_at, completed_at FROM jobs WHERE id = ?",
                (failed_job_id,),
            ).fetchone()
            assert failed_row is not None
            assert failed_row["error_code"] == "worker_processing_error"
            assert "Forced worker failure" in failed_row["error_message"]
            assert failed_row["updated_at"] is not None
            assert failed_row["completed_at"] is not None

        assert completed_payload is not None
        assert completed_payload["status"] == "completed"
        assert completed_payload["stage"] == "completed"
