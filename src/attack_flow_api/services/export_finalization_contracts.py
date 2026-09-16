from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


ExportArtifactType = Literal["stix", "afb"]
ExportStatus = Literal["pending", "validating", "validated", "finalizing", "completed", "failed"]


class ExportValidationError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    object_ref: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ExportFinalizationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_type: ExportArtifactType
    valid: bool
    validation_errors: list[ExportValidationError] = Field(default_factory=list)
    checksum: str | None = None
    size_bytes: int | None = Field(default=None, ge=0)
    created_at: datetime | None = None
    export_status: ExportStatus = "pending"
    error_code: str | None = None
    error_message: str | None = None
