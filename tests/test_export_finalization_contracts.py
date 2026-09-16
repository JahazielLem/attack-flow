from datetime import datetime, UTC

from attack_flow_api.services.export_finalization_contracts import (
    ExportFinalizationResult,
    ExportValidationError,
)


def test_export_finalization_result_shape():
    result = ExportFinalizationResult(
        artifact_type="stix",
        valid=False,
        validation_errors=[
            ExportValidationError(code="missing_required_field", message="missing id")
        ],
        checksum="abc123",
        size_bytes=42,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        export_status="failed",
        error_code="validation_failed",
        error_message="export validation failed",
    )

    assert result.artifact_type == "stix"
    assert result.valid is False
    assert result.validation_errors[0].code == "missing_required_field"
    assert result.checksum == "abc123"
    assert result.size_bytes == 42
    assert result.export_status == "failed"
