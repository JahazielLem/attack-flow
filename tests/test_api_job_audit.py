import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from attack_flow_api.main import create_app
from attack_flow_api.storage.repositories import AuditEventCreate
from attack_flow_api.storage.repositories import JobCreate


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

    return TestClient(create_app())


def test_get_job_audit_returns_snapshot_and_events(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "audit test"},
        )
        job_id = create_response.json()["job_id"]

        response = client.get(f"/api/v1/jobs/{job_id}/audit")

    payload = response.json()
    assert response.status_code == 200
    assert payload["job_id"] == job_id
    assert payload["job"]["status"] in {"queued", "fetching", "extracting", "normalizing", "ai_extraction", "flow_building", "exporting", "completed"}
    assert payload["job"]["stage"]
    assert payload["timestamps"]["created_at"]
    assert payload["timestamps"]["updated_at"]
    assert "completed_at" in payload["timestamps"]
    assert payload["request_id"]
    assert [event["event_type"] for event in payload["events"][:2]] == ["job_submitted", "job_queued"]
    assert [event["sequence"] for event in payload["events"][:2]] == [1, 2]


def test_get_job_audit_returns_structured_404_when_missing(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.get("/api/v1/jobs/missing-job/audit")

    payload = response.json()
    assert response.status_code == 404
    assert payload["error"]["code"] == "job_not_found"
    assert payload["error"]["message"] == "Job not found"
    assert payload["request_id"]


def test_get_job_audit_redacts_secrets_and_raw_content(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        job = client.app.state.persistence_service.create_job(JobCreate(id="job-secret-1", status="completed", stage="completed"))
        client.app.state.persistence_service.create_audit_event(
            AuditEventCreate(
                id="audit-secret-1",
                job_id=job.id,
                sequence=1,
                event_type="provider_invocation_completed",
                status="completed",
                stage="completed",
                request_id="req-secret",
                source_component="orchestration",
                message="provider invocation completed",
                details_json=(
                    '{"provider_id":"provider-a","model_used":"model-x",'
                    '"raw_text":"full raw incident text","raw_html":"<html>secret</html>",'
                    '"provider_payload":{"api_key":"sk-test-secret"},'
                    '"source_url":"https://example.com/report?token=secret"}'
                ),
                redacted=True,
            )
        )

        response = client.get(f"/api/v1/jobs/{job.id}/audit")

    payload = response.json()
    assert response.status_code == 200
    event = payload["events"][0]
    assert event["redacted"] is True
    assert event["details"]["provider_id"] == "provider-a"
    assert event["details"]["model_used"] == "model-x"
    assert event["details"]["raw_text"] == "[redacted]"
    assert event["details"]["raw_html"] == "[redacted]"
    assert event["details"]["provider_payload"] == "[redacted]"
    assert event["details"]["source_url"] == "[redacted]"
