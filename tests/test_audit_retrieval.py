from datetime import UTC, datetime
from pathlib import Path

from attack_flow_api.audit.audit_contracts import JobAuditResponse
from attack_flow_api.services.audit_retrieval_service import AuditRetrievalService
from attack_flow_api.services.persistence_service import PersistenceService
from attack_flow_api.storage.database import initialize_database
from attack_flow_api.storage.repositories import AuditEventCreate, JobCreate


def test_get_job_audit_returns_snapshot_and_ordered_events(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)
    retrieval = AuditRetrievalService(service)

    job = service.create_job(JobCreate(id="job-1", status="queued", stage="created"))
    service.create_audit_event(
        AuditEventCreate(
            id="audit-2",
            job_id=job.id,
            sequence=2,
            event_type="job_queued",
            timestamp=datetime(2026, 1, 1, 12, 1, tzinfo=UTC),
            status="queued",
            stage="queued",
            request_id="req-1",
            source_component="api",
            message="job queued",
            details_json='{"job_id":"job-1"}',
        )
    )
    service.create_audit_event(
        AuditEventCreate(
            id="audit-1",
            job_id=job.id,
            sequence=1,
            event_type="job_submitted",
            timestamp=datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
            status="queued",
            stage="created",
            request_id="req-1",
            source_component="api",
            message="job submitted",
            details_json='{"input_source_id":"input-1"}',
        )
    )

    result = retrieval.get_job_audit(job.id)

    assert result.found is True
    assert isinstance(result.response, JobAuditResponse)
    assert result.response.job_id == job.id
    assert result.response.job.status == "queued"
    assert [event.sequence for event in result.response.events] == [1, 2]
    assert result.response.events[0].event_type == "job_submitted"
    assert result.response.events[1].event_type == "job_queued"


def test_get_job_audit_returns_not_found_result_for_missing_job(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    retrieval = AuditRetrievalService(PersistenceService(db_path))

    result = retrieval.get_job_audit("missing-job")

    assert result.found is False
    assert result.not_found is not None
    assert result.not_found.job_id == "missing-job"
    assert result.not_found.error_code == "job_not_found"
