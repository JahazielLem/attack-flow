import pytest

from attack_flow_api.services.stix_json_validation import (
    StixJsonValidationError,
    validate_stix_json_bundle_shape,
)


def test_validate_stix_json_bundle_shape_accepts_bundle_with_custom_properties():
    payload = (
        b'{"type":"bundle","id":"bundle--12345678-1234-1234-1234-123456789012",'
        b'"objects":[],"x_opencti_custom":true}'
    )

    result = validate_stix_json_bundle_shape(payload)

    assert result.stix_json_kind == "bundle"
    assert result.stix_json_valid is True
    assert result.bundle_id == "bundle--12345678-1234-1234-1234-123456789012"
    assert result.spec_version is None
    assert result.object_count == 0


def test_validate_stix_json_bundle_shape_extracts_spec_version_metadata():
    payload = (
        b'{"type":"bundle","id":"bundle--12345678-1234-1234-1234-123456789012",'
        b'"spec_version":"2.1","objects":[]}'
    )

    result = validate_stix_json_bundle_shape(payload)

    assert result.bundle_id == "bundle--12345678-1234-1234-1234-123456789012"
    assert result.spec_version == "2.1"


def test_validate_stix_json_bundle_shape_rejects_non_object_entries():
    with pytest.raises(StixJsonValidationError) as exc:
        validate_stix_json_bundle_shape(
            b'{"type":"bundle","objects":["not-an-object"]}'
        )

    assert exc.value.code == "stix_json_invalid_object_entry"


def test_validate_stix_json_bundle_shape_rejects_object_without_type():
    with pytest.raises(StixJsonValidationError) as exc:
        validate_stix_json_bundle_shape(
            b'{"type":"bundle","objects":[{"id":"indicator--123"}]}'
        )

    assert exc.value.code == "stix_json_invalid_object_type"


def test_validate_stix_json_bundle_shape_rejects_malformed_json():
    with pytest.raises(StixJsonValidationError) as exc:
        validate_stix_json_bundle_shape(b'{"type":"bundle"')

    assert exc.value.code == "stix_json_malformed"


def test_validate_stix_json_bundle_shape_rejects_non_bundle_type():
    with pytest.raises(StixJsonValidationError) as exc:
        validate_stix_json_bundle_shape(b'{"type":"report","objects":[]}')

    assert exc.value.code == "stix_json_not_bundle"
