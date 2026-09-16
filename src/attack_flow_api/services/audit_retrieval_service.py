from __future__ import annotations

from attack_flow_api.audit.audit_contracts import (
    JobAuditNotFound,
    JobAuditLookupResult,
    job_audit_response,
)
from attack_flow_api.services.persistence_service import PersistenceService


class AuditRetrievalService:
    def __init__(self, persistence_service: PersistenceService):
        self.persistence_service = persistence_service

    def get_job_audit(self, job_id: str, request_id: str | None = None) -> JobAuditLookupResult:
        job = self.persistence_service.get_job(job_id)
        if job is None:
            return JobAuditLookupResult(
                job_id=job_id,
                found=False,
                not_found=JobAuditNotFound(job_id=job_id, request_id=request_id),
            )

        events = self.persistence_service.list_audit_events(job_id)
        return JobAuditLookupResult(
            job_id=job_id,
            found=True,
            response=job_audit_response(job, events, request_id=request_id),
        )
