from attack_flow_api.services.afb_extraction_models import build_empty_afb_extraction_intermediate


def test_build_empty_afb_extraction_intermediate_defaults() -> None:
    payload = build_empty_afb_extraction_intermediate(
        orchestration_mode="ai_enrichment",
        provider_invoked=False,
        provider_id=None,
        model=None,
        source_classification="stix_structured",
        authors=["analyst-a"],
        external_references=["https://example.com/report"],
    )

    json_ready = payload.to_json_ready()
    assert json_ready["schema_version"] == "afb-v2-intermediate"
    assert json_ready["orchestration_mode"] == "ai_enrichment"
    assert json_ready["provider_invoked"] is False
    assert json_ready["flow_metadata"]["authors"] == ["analyst-a"]
    assert json_ready["flow_metadata"]["external_references"] == ["https://example.com/report"]
