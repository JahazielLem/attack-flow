from datetime import UTC, datetime
from types import SimpleNamespace

from attack_flow_api.audit.audit_contracts import job_audit_response
from attack_flow_api.storage.models import AuditEvent


def test_job_audit_response_has_explicit_shapes_and_sorted_events():
    job = SimpleNamespace(
        id="job-1",
        status="running",
        stage="processing",
        progress_percent=50,
        started_at=datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
        last_heartbeat_at=datetime(2026, 1, 1, 12, 5, tzinfo=UTC),
        worker_id="worker-1",
        attempt_count=2,
        provider_id="provider-a",
        model="model-x",
        input_source_id="input-1",
        error_code=None,
        error_message=None,
        request_id="req-job",
        created_at=datetime(2026, 1, 1, 11, 55, tzinfo=UTC),
        updated_at=datetime(2026, 1, 1, 12, 6, tzinfo=UTC),
        completed_at=None,
    )
    events = [
        AuditEvent(
            id="audit-2",
            job_id="job-1",
            sequence=2,
            request_id="req-2",
            event_type="job.started",
            timestamp=datetime(2026, 1, 1, 12, 1, tzinfo=UTC),
            status="running",
            stage="processing",
            source_component="worker",
            message="started",
            details_json='{"step":"start"}',
            redacted=False,
        ),
        AuditEvent(
            id="audit-1",
            job_id="job-1",
            sequence=1,
            request_id="req-1",
            event_type="job.created",
            timestamp=datetime(2026, 1, 1, 11, 56, tzinfo=UTC),
            status="queued",
            stage="created",
            source_component="api",
            message="created",
            details_json='{"step":"create"}',
            redacted=False,
        ),
    ]

    response = job_audit_response(job, events)
    payload = response.model_dump(mode="json")

    assert payload["job_id"] == "job-1"
    assert payload["request_id"] == "req-job"
    assert payload["timestamps"] == {
        "created_at": "2026-01-01T11:55:00Z",
        "updated_at": "2026-01-01T12:06:00Z",
        "completed_at": None,
    }
    assert payload["job"]["status"] == "running"
    assert payload["job"]["stage"] == "processing"
    assert [event["sequence"] for event in payload["events"]] == [1, 2]
    assert payload["events"][0]["details"] == {"step": "create"}
    assert payload["events"][1]["details"] == {"step": "start"}
