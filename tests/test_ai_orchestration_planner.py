from attack_flow_api.services.ai_orchestration_planner import (
    OrchestrationMode,
    build_provider_orchestration_input,
    select_orchestration_mode,
)


def test_select_mode_full_extraction_for_narrative_input() -> None:
    normalized_package = {
        "source_type": "narrative_text",
        "normalized_text": "Observed execution details...",
        "structured_summary": {"bundle_metadata": {}, "inventory": {}, "narrative": {}},
        "attack_refs": [],
        "entities": [],
        "relationships": [],
    }

    mode = select_orchestration_mode(normalized_package)

    assert mode == OrchestrationMode.FULL_EXTRACTION


def test_select_mode_enrichment_for_stix_structured_input() -> None:
    normalized_package = {
        "source_type": "stix_structured",
        "normalized_text": "",
        "structured_summary": {"bundle_metadata": {"id": "bundle--1"}},
        "attack_refs": [{"technique_id": "T1059"}],
    }

    mode = select_orchestration_mode(normalized_package)

    assert mode == OrchestrationMode.ENRICHMENT


def test_build_provider_input_preserves_deterministic_findings() -> None:
    normalized_package = {
        "source_type": "stix_structured",
        "normalized_text": "narrative text",
        "metadata": {"case_id": "CASE-1"},
        "structured_summary": {"bundle_metadata": {"id": "bundle--1"}},
        "attack_refs": [{"technique_id": "T1059", "source_object_id": "attack-pattern--1"}],
        "entities": [{"object_id": "malware--1", "object_type": "malware"}],
        "relationships": [
            {
                "relationship_id": "relationship--1",
                "relationship_type": "uses",
                "source_ref": "threat-actor--1",
                "target_ref": "malware--1",
            }
        ],
        "provenance": {"narrative_source_object_ids": ["report--1"]},
    }

    packaged = build_provider_orchestration_input(normalized_package)

    assert packaged.mode == OrchestrationMode.ENRICHMENT
    assert packaged.deterministic_input_sufficient is True
    assert packaged.structured_summary == {"bundle_metadata": {"id": "bundle--1"}}
    assert packaged.deterministic_attack_refs == [
        {"technique_id": "T1059", "source_object_id": "attack-pattern--1"}
    ]
    assert packaged.deterministic_entities == [{"object_id": "malware--1", "object_type": "malware"}]
    assert packaged.deterministic_relationships[0]["relationship_type"] == "uses"


def test_build_provider_input_uses_full_extraction_for_document_input() -> None:
    packaged = build_provider_orchestration_input(
        {
            "source_type": "document_extracted_text",
            "normalized_text": "Observed artifact without deterministic refs",
            "structured_summary": {"bundle_metadata": {"id": "bundle--1"}},
            "entities": [{"object_id": "malware--1", "object_type": "malware"}],
            "relationships": [{"relationship_id": "relationship--1"}],
        }
    )

    assert packaged.mode == OrchestrationMode.FULL_EXTRACTION
    assert packaged.deterministic_input_sufficient is False


def test_build_provider_input_includes_explicit_constraints() -> None:
    packaged = build_provider_orchestration_input(
        {
            "source_type": "narrative_text",
            "normalized_text": "Observed command: whoami",
        }
    )

    assert packaged.constraints.explicit_attack_refs_only is False
    assert packaged.constraints.no_missing_technique_inference is False
    assert packaged.constraints.descriptions_must_be_verbatim_excerpts is True
    assert packaged.constraints.conditions_must_be_source_grounded is True
    assert packaged.constraints.operators_must_be_source_grounded is True
    assert packaged.constraints.allowed_operator_values == ("AND", "OR")
    assert packaged.constraints.allowed_condition_values == ("true", "false")
