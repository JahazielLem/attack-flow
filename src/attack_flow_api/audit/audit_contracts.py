from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Sequence

from pydantic import BaseModel, ConfigDict

from attack_flow_api.audit.audit_redaction import sanitize_audit_details
from attack_flow_api.storage.models import AuditEvent, Job


def _isoformat_z(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _event_sort_key(event: AuditEvent) -> tuple[bool, int, datetime, str]:
    sequence = event.sequence if event.sequence is not None else 0
    return (event.sequence is None, sequence, event.timestamp, event.id)


class AuditEventRecord(BaseModel):
    sequence: int
    time: str
    event_type: str
    status: str | None = None
    stage: str | None = None
    request_id: str | None = None
    source_component: str | None = None
    message: str | None = None
    details: dict[str, Any] | None = None
    redacted: bool | None = None

    model_config = ConfigDict(extra="forbid")


class AuditTimestamps(BaseModel):
    created_at: str
    updated_at: str
    completed_at: str | None = None

    model_config = ConfigDict(extra="forbid")


class AuditJobSnapshot(BaseModel):
    status: str
    stage: str
    progress_percent: int | None = None
    started_at: str | None = None
    last_heartbeat_at: str | None = None
    worker_id: str | None = None
    attempt_count: int | None = None
    provider_id: str | None = None
    model: str | None = None
    input_source_id: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    request_id: str | None = None

    model_config = ConfigDict(extra="forbid")


class JobAuditResponse(BaseModel):
    job_id: str
    job: AuditJobSnapshot
    timestamps: AuditTimestamps
    events: list[AuditEventRecord]
    request_id: str | None = None

    model_config = ConfigDict(extra="forbid")


class JobAuditNotFound(BaseModel):
    job_id: str
    found: bool = False
    error_code: str = "job_not_found"
    message: str = "Job not found"
    request_id: str | None = None

    model_config = ConfigDict(extra="forbid")


class JobAuditLookupResult(BaseModel):
    job_id: str
    found: bool
    response: JobAuditResponse | None = None
    not_found: JobAuditNotFound | None = None

    model_config = ConfigDict(extra="forbid")


def audit_event_record(event: AuditEvent) -> AuditEventRecord:
    details = None
    if event.details_json:
        try:
            parsed_details = json.loads(event.details_json)
        except json.JSONDecodeError:
            parsed_details = None
        if isinstance(parsed_details, dict):
            details, _ = sanitize_audit_details(parsed_details)

    return AuditEventRecord(
        sequence=event.sequence if event.sequence is not None else 0,
        time=_isoformat_z(event.timestamp) or "",
        event_type=event.event_type,
        status=event.status,
        stage=event.stage,
        request_id=event.request_id,
        source_component=event.source_component,
        message=event.message,
        details=details,
        redacted=event.redacted,
    )


def audit_events_response(events: Sequence[AuditEvent]) -> list[AuditEventRecord]:
    return [audit_event_record(event) for event in sorted(events, key=_event_sort_key)]


def audit_job_snapshot(job: Job) -> AuditJobSnapshot:
    return AuditJobSnapshot(
        status=job.status,
        stage=job.stage,
        progress_percent=job.progress_percent,
        started_at=_isoformat_z(job.started_at),
        last_heartbeat_at=_isoformat_z(job.last_heartbeat_at),
        worker_id=job.worker_id,
        attempt_count=job.attempt_count,
        provider_id=job.provider_id,
        model=job.model,
        input_source_id=job.input_source_id,
        error_code=job.error_code,
        error_message=job.error_message,
        request_id=job.request_id,
    )


def job_audit_response(job: Job, events: Sequence[AuditEvent], request_id: str | None = None) -> JobAuditResponse:
    return JobAuditResponse(
        job_id=job.id,
        job=audit_job_snapshot(job),
        timestamps=AuditTimestamps(
            created_at=_isoformat_z(job.created_at) or "",
            updated_at=_isoformat_z(job.updated_at) or "",
            completed_at=_isoformat_z(job.completed_at),
        ),
        events=audit_events_response(events),
        request_id=request_id or job.request_id,
    )
