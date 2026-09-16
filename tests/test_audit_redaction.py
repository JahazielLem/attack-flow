from datetime import UTC, datetime
import json
from pathlib import Path
from types import SimpleNamespace

from attack_flow_api.audit.audit_contracts import job_audit_response
from attack_flow_api.audit.audit_redaction import sanitize_audit_details
from attack_flow_api.services.persistence_service import PersistenceService
from attack_flow_api.storage.database import initialize_database
from attack_flow_api.storage.models import AuditEvent
from attack_flow_api.storage.repositories import JobCreate


def test_audit_event_details_are_sanitized_before_persistence(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    job = service.create_job(JobCreate(id="job-1", status="queued", stage="created"))

    created = service.record_job_event(
        job=job,
        event_type="provider_invocation_completed",
        source_component="orchestration",
        message="provider invocation completed",
        details={
            "provider_id": "provider-a",
            "model_used": "model-x",
            "error_code": "provider_failed",
            "raw_text": "classified incident text should not persist",
            "raw_html": "<html><body>secret</body></html>",
            "provider_payload": {"api_key": "sk-test-secret", "output": "full provider payload"},
            "source_url": "https://example.com/report?token=secret",
        },
    )

    assert created is not None
    assert created.redacted is True

    events = service.list_audit_events(job.id)
    assert len(events) == 1
    details = json.loads(events[0].details_json or "{}")
    assert details["provider_id"] == "provider-a"
    assert details["provider_payload"] == "[redacted]"
    assert details["raw_text"] == "[redacted]"
    assert details["raw_html"] == "[redacted]"
    assert details["source_url"] == "[redacted]"
    assert details["model_used"] == "model-x"


def test_audit_response_sanitizes_unsafe_persisted_details():
    job = SimpleNamespace(
        id="job-1",
        status="completed",
        stage="completed",
        progress_percent=100,
        started_at=datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
        last_heartbeat_at=datetime(2026, 1, 1, 12, 1, tzinfo=UTC),
        worker_id="worker-1",
        attempt_count=1,
        provider_id="provider-a",
        model="model-x",
        input_source_id="input-1",
        error_code=None,
        error_message=None,
        request_id="req-1",
        created_at=datetime(2026, 1, 1, 11, 59, tzinfo=UTC),
        updated_at=datetime(2026, 1, 1, 12, 2, tzinfo=UTC),
        completed_at=datetime(2026, 1, 1, 12, 3, tzinfo=UTC),
    )
    event = AuditEvent(
        id="audit-1",
        job_id="job-1",
        sequence=1,
        request_id="req-1",
        event_type="provider_invocation_completed",
        timestamp=datetime(2026, 1, 1, 12, 1, tzinfo=UTC),
        status="completed",
        stage="completed",
        source_component="orchestration",
        message="provider invocation completed",
        details_json='{"provider_id":"provider-a","raw_text":"super secret","provider_payload":{"api_key":"sk-test-secret"}}',
        redacted=True,
    )

    response = job_audit_response(job, [event])
    payload = response.model_dump(mode="json")

    assert payload["events"][0]["details"]["provider_id"] == "provider-a"
    assert payload["events"][0]["details"]["raw_text"] == "[redacted]"
    assert payload["events"][0]["details"]["provider_payload"] == "[redacted]"


def test_runtime_provider_override_audit_metadata_is_safe_and_deterministic():
    sanitized, redacted = sanitize_audit_details(
        {
            "provider_source": "runtime_override",
            "provider_type": "openai_compatible",
            "endpoint_redacted": "https://compatible.example",
            "model": "model-a",
            "api_key": "runtime-secret",
            "extra_headers": {"X-Test": "header-secret"},
        }
    )

    assert sanitized == {
        "provider_source": "runtime_override",
        "provider_type": "openai_compatible",
        "endpoint_redacted": "https://compatible.example",
        "model": "model-a",
        "api_key": "[redacted]",
        "extra_headers": "[redacted]",
    }
    assert redacted is True
    assert "runtime-secret" not in json.dumps(sanitized)
    assert "header-secret" not in json.dumps(sanitized)
