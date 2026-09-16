from pathlib import Path

from attack_flow_api.services.persistence_service import PersistenceService


class StatusService:
    def __init__(self, persistence_service: PersistenceService):
        self.persistence_service = persistence_service

    def database_status(self) -> str:
        return "ok" if self.persistence_service.is_database_ready() else "error"

    def storage_status(self, paths: dict[str, Path]) -> str:
        required_paths = (
            paths["data_dir"],
            paths["upload_dir"],
            paths["artifact_dir"],
            paths["sqlite_path"].parent,
        )
        for required_path in required_paths:
            if not required_path.exists() or not required_path.is_dir():
                return "error"
        return "ok"

    def queue_counts(self) -> dict[str, int]:
        status_counts = self.persistence_service.get_job_status_counts()
        return {
            "active_jobs": status_counts.get("running", 0),
            "pending_jobs": status_counts.get("queued", 0),
        }
