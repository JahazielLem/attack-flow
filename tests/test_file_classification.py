from attack_flow_api.services.file_classification import classify_file_for_routing


def test_classify_file_for_routing_identifies_plaintext():
    result = classify_file_for_routing(
        original_filename="notes.txt",
        declared_mime_type="text/plain",
        detected_mime_type="text/plain",
        file_bytes=b"alpha\nbeta\n",
    )
    assert result.file_class == "plaintext"
    assert result.is_supported is True
    assert result.stix_json_kind is None


def test_classify_file_for_routing_identifies_pdf():
    result = classify_file_for_routing(
        original_filename="report.pdf",
        declared_mime_type="application/pdf",
        detected_mime_type="application/pdf",
        file_bytes=b"%PDF-1.7\n...",
    )
    assert result.file_class == "pdf"
    assert result.is_supported is True


def test_classify_file_for_routing_identifies_stix_json_bundle_candidate():
    result = classify_file_for_routing(
        original_filename="bundle.json",
        declared_mime_type="application/json",
        detected_mime_type="application/json",
        file_bytes=(
            b'{"type":"bundle","id":"bundle--1234","objects":[]}'
        ),
    )
    assert result.file_class == "stix_json"
    assert result.is_supported is True
    assert result.stix_json_kind == "bundle_candidate"


def test_classify_file_for_routing_rejects_non_stix_json_shape():
    result = classify_file_for_routing(
        original_filename="payload.json",
        declared_mime_type="application/json",
        detected_mime_type="application/json",
        file_bytes=b'{"hello":"world"}',
    )
    assert result.file_class == "unsupported"
    assert result.is_supported is False
    assert result.unsupported_reason == "json_not_stix_bundle_shape"


def test_classify_file_for_routing_marks_unknown_binary_unsupported():
    result = classify_file_for_routing(
        original_filename="blob.bin",
        declared_mime_type="application/octet-stream",
        detected_mime_type="application/octet-stream",
        file_bytes=b"\x00\x01\x02\x03",
    )
    assert result.file_class == "unsupported"
    assert result.is_supported is False
    assert result.unsupported_reason == "unrecognized_file_type"
