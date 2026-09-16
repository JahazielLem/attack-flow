from attack_flow_api.services.afb_extraction_contracts import ExtractionValidationState
from attack_flow_api.services.ai_orchestration_planner import build_provider_orchestration_input
from attack_flow_api.services.ai_output_validation_service import parse_validate_and_repair_extraction_output
from attack_flow_api.services.ai_provider_invocation_service import ProviderInvocationResult


def _packaged_input():
    return build_provider_orchestration_input(
        {
            "source_type": "stix_structured",
            "normalized_text": "",
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
        }
    )


def test_parse_validate_success_with_structured_json() -> None:
    packaged = _packaged_input()
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "provider_id": "default-openai",
        "model": "gpt-4.1-mini",
        "attack_flow": {
            "id": "attack-flow--1",
            "name": "Example flow",
            "scope": "incident",
            "start_refs": ["attack-action--1"],
            "orchestration_mode": "ai_enrichment",
            "source_classification": "stix_structured",
        },
        "attack_actions": [
            {
                "id": "attack-action--1",
                "name": "Credential Access",
                "description": "Observed command exactly as reported.",
                "confidence": 0.8,
                "technique": {
                    "technique_id": "T1059",
                    "confidence": 1.0,
                    "grounded_by": "explicit_attack_id_in_source",
                },
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                    }
                ],
                "object_refs": ["malware--1", "malware--unknown"],
            }
        ],
        "attack_assets": [
            {
                "id": "attack-asset--1",
                "name": "Asset",
                "confidence": 0.9,
                "object_ref": "malware--unknown",
            }
        ],
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.deterministic_attack_refs[0]["technique_id"] == "T1059"
    assert result.extraction_result.deterministic_attack_refs[0]["confidence"] == 1.0
    assert result.extraction_result.deterministic_attack_refs[0]["fact_origin"] == "deterministic_source"
    assert result.extraction_result.attack_actions[0].fact_origin.value == "ai_generated"
    assert result.extraction_result.attack_actions[0].object_refs == ["malware--1"]
    assert result.extraction_result.attack_assets[0].object_ref is None


def test_normalizes_missing_evidence_source_without_losing_provider_excerpt() -> None:
    packaged = _packaged_input()
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "attack_flow": {
            "id": "attack-flow--1",
            "name": "Example flow",
            "scope": "incident",
            "start_refs": ["attack-action--1"],
            "orchestration_mode": "ai_enrichment",
            "source_classification": "stix_structured",
        },
        "attack_actions": [
            {
                "id": "attack-action--1",
                "name": "Use encrypted channel",
                "description": "The malware communicates over an encrypted channel.",
                "confidence": 0.8,
                "evidence": [
                    {
                        "source": "report",
                        "excerpt": "The malware communicates over an encrypted channel.",
                    }
                ],
            }
        ],
        "attack_operators": [
            {
                "id": "attack-operator--1",
                "operator": "AND",
                "confidence": 0.8,
                "effect_refs": ["attack-action--1"],
                "evidence": [
                    {"excerpt": "It also supports encrypted directories."}
                ],
            }
        ],
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-5.4",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    evidence = result.extraction_result.attack_operators[0].evidence[0]
    assert evidence.source == "source_document"
    assert evidence.excerpt == "It also supports encrypted directories."


def test_normalizes_deterministic_entity_ids_for_attachments() -> None:
    packaged = _packaged_input()
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "attack_flow": {
            "id": "attack-flow--1",
            "name": "Example flow",
            "scope": "incident",
            "start_refs": ["attack-action--1"],
            "orchestration_mode": "ai_enrichment",
            "source_classification": "stix_structured",
        },
        "attack_actions": [
            {
                "id": "attack-action--1",
                "name": "Use tool",
                "description": "Observed command exactly as reported.",
                "confidence": 0.8,
                "technique": {
                    "technique_id": "T1059",
                    "confidence": 1.0,
                    "grounded_by": "explicit_attack_id_in_source",
                    "description": "Command and scripting interpreter",
                    "aliases": ["PowerShell"],
                    "kill_chain_phases": ["execution"],
                    "tags": ["att&ck"],
                },
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                    }
                ],
                "object_refs": ["entity--1"],
            }
        ],
        "deterministic_entities": [
            {
                "entity_id": "entity--1",
                "entity_type": "tool",
                "name": "Mimikatz",
                "tags": ["credential-access"],
            }
        ],
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.deterministic_entities[0]["object_id"] == "entity--1"
    assert result.extraction_result.deterministic_entities[0]["object_type"] == "tool"
    assert result.extraction_result.attack_actions[0].object_refs == ["entity--1"]
    assert result.extraction_result.attack_actions[0].technique is not None
    assert result.extraction_result.attack_actions[0].technique.description == "Command and scripting interpreter"
    assert result.extraction_result.attack_actions[0].technique.aliases == ["PowerShell"]


def test_parse_validate_accepts_technique_name_only() -> None:
    packaged = _packaged_input()
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "attack_flow": {
            "id": "attack-flow--1",
            "name": "Example flow",
            "scope": "incident",
            "start_refs": ["attack-action--1"],
            "orchestration_mode": "ai_enrichment",
            "source_classification": "stix_structured",
        },
        "attack_actions": [
            {
                "id": "attack-action--1",
                "name": "Command execution",
                "description": "Observed command exactly as reported.",
                "confidence": 0.8,
                "technique": {
                    "technique_name": "Command and Scripting Interpreter",
                    "confidence": 0.75,
                    "grounded_by": "legacy_attack_term_mapped_to_v19_1",
                },
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                    }
                ],
            }
        ],
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.attack_actions[0].technique is not None
    assert result.extraction_result.attack_actions[0].technique.technique_name == "Command and Scripting Interpreter"


def test_parse_validate_promotes_highest_confidence_technique_from_plural_field() -> None:
    packaged = _packaged_input()
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "attack_flow": {
            "id": "attack-flow--1",
            "name": "Example flow",
            "scope": "incident",
            "start_refs": ["attack-action--1"],
            "orchestration_mode": "ai_enrichment",
            "source_classification": "stix_structured",
        },
        "attack_actions": [
            {
                "id": "attack-action--1",
                "name": "Command execution",
                "description": "Observed command exactly as reported.",
                "confidence": 0.8,
                "techniques": [
                    {
                        "attack_object": {"id": "T1059.001", "name": "PowerShell"},
                        "confidence": 0.75,
                        "grounded_by": "PowerShell command",
                    },
                    {
                        "attack_object": {"id": "T1105", "name": "Ingress Tool Transfer"},
                        "confidence": 0.91,
                        "grounded_by": "downloadstring from a remote URL",
                    },
                ],
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                    }
                ],
            }
        ],
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.attack_actions[0].technique is not None
    assert result.extraction_result.attack_actions[0].technique.technique_id == "T1105"
    assert result.extraction_result.attack_actions[0].technique.technique_name == "Ingress Tool Transfer"


def test_repair_attempt_parses_json_from_fenced_block() -> None:
    packaged = _packaged_input()
    output_text = """```json
{
  "validation_state": "valid",
  "provider_invoked": true,
  "provider_id": "default-openai",
  "model": "gpt-4.1-mini",
  "attack_flow": {
    "id": "attack-flow--1",
    "name": "Example flow",
    "scope": "incident",
    "start_refs": ["attack-action--1"],
    "orchestration_mode": "ai_enrichment",
    "source_classification": "stix_structured"
  },
  "attack_actions": [
    {
      "id": "attack-action--1",
      "name": "Credential Access",
      "description": "Observed command exactly as reported.",
      "confidence": 0.8,
      "evidence": [{"source": "narrative", "excerpt": "Observed command exactly as reported."}]
    }
  ]
}
```"""
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=None,
        output_text=output_text,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.repair_attempted is True
    assert result.extraction_result is not None
    assert result.extraction_result.repair_attempted is True


def test_preserves_authors_and_external_references_lists() -> None:
    packaged = build_provider_orchestration_input(
        {
            "source_type": "stix_structured",
            "normalized_text": "",
            "metadata": {
                "authors": ["analyst-a", "analyst-b"],
                "external_references": ["https://example.com/a", "https://example.com/b"],
            },
            "structured_summary": {"bundle_metadata": {"id": "bundle--1"}},
        }
    )
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "attack_flow": {
            "id": "attack-flow--1",
            "name": "Example flow",
            "scope": "incident",
            "start_refs": ["attack-action--1"],
            "orchestration_mode": "ai_enrichment",
            "source_classification": "stix_structured",
            "authors": ["analyst-a"],
            "external_references": ["https://example.com/a"],
        },
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.attack_flow.authors == ["analyst-a", "analyst-b"]
    assert result.extraction_result.attack_flow.external_references == [
        "https://example.com/a",
        "https://example.com/b",
    ]


def test_promotes_top_level_external_references_into_attack_flow_metadata() -> None:
    packaged = _packaged_input()
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "authors": ["analyst-a"],
        "external_references": ["https://example.com/report"],
        "attack_flow": {
            "id": "attack-flow--1",
            "name": "Example flow",
            "scope": "incident",
            "start_refs": ["attack-action--1"],
            "orchestration_mode": "ai_enrichment",
            "source_classification": "stix_structured",
        },
        "attack_actions": [],
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.attack_flow.authors == ["analyst-a"]
    assert result.extraction_result.attack_flow.external_references == ["https://example.com/report"]


def test_parse_validate_accepts_legacy_attack_flow_objects_envelope() -> None:
    packaged = _packaged_input()
    output_json = {
        "type": "afb-extraction",
        "source_name": "Example report",
        "source_type": "document_extracted_text",
        "attack_version": "19.1",
        "authors": ["analyst-a"],
        "external_references": ["https://example.com/report"],
        "metadata": {
            "mode": "full_extraction",
            "title": "Example report",
        },
        "attack_flow": {
            "type": "attack-flow",
            "name": "Example report",
            "description": "Legacy envelope shape",
            "scope": "incident",
            "start_refs": ["attack-action--1"],
            "objects": [
                {
                    "type": "attack-action",
                    "id": "attack-action--1",
                    "name": "Phishing link",
                    "description": "Clicked a phishing link.",
                    "confidence": 0.9,
                    "evidence": [{"source": "report", "excerpt": "Clicked a phishing link."}],
                }
            ],
        },
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.attack_flow.name == "Example report"
    assert result.extraction_result.attack_flow.provenance["source_name"] == "Example report"
    assert result.extraction_result.attack_actions[0].name == "Phishing link"


def test_parse_validate_unwraps_nested_output_json_wrapper() -> None:
    packaged = _packaged_input()
    output_json = {
        "job_id": "job--1",
        "label": "retry",
        "mode": "full_extraction",
        "source_type": "document_extracted_text",
        "provider_id": "default-openai",
        "model_used": "gpt-5.4",
        "output_json": {
            "validation_state": "valid",
            "provider_invoked": True,
            "attack_flow": {
                "id": "attack-flow--1",
                "name": "Wrapped example",
                "scope": "incident",
                "start_refs": ["attack-action--1"],
                "orchestration_mode": "full_extraction",
                "source_classification": "document_extracted_text",
            },
            "attack_actions": [
                {
                    "id": "attack-action--1",
                    "name": "Phishing link",
                    "description": "Clicked a phishing link.",
                    "confidence": 0.9,
                    "evidence": [{"source": "report", "excerpt": "Clicked a phishing link."}],
                }
            ],
        },
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-5.4",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.attack_flow.name == "Wrapped example"
    assert result.extraction_result.attack_actions[0].id == "attack-action--1"


def test_validation_repairs_descriptions_from_longest_verbatim_evidence() -> None:
    packaged = _packaged_input()
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "attack_flow": {
            "id": "attack-flow--1",
            "name": "Example flow",
            "scope": "incident",
            "start_refs": ["attack-action--1"],
            "orchestration_mode": "ai_enrichment",
            "source_classification": "stix_structured",
        },
        "attack_actions": [
            {
                "id": "attack-action--1",
                "name": "Credential Access",
                "description": "Paraphrased summary",
                "confidence": 0.8,
                "evidence": [
                    {"source": "narrative", "excerpt": "Observed command."},
                    {"source": "narrative", "excerpt": "Observed command exactly as reported."},
                ],
            }
        ],
        "attack_conditions": [
            {
                "id": "attack-condition--1",
                "description": "After access was obtained",
                "value": "true",
                "confidence": 0.8,
                "evidence": [
                    {"source": "narrative", "excerpt": "Once the actor obtained access"}
                ],
            }
        ],
        "attack_assets": [
            {
                "id": "attack-asset--1",
                "name": "Target host",
                "description": "The compromised machine",
                "confidence": 0.8,
                "evidence": [
                    {"source": "narrative", "excerpt": "the targeted Windows host"}
                ],
            }
        ],
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.repair_attempted is True
    assert result.extraction_result is not None
    assert result.extraction_result.validation_state == ExtractionValidationState.REPAIRED
    assert result.extraction_result.repair_attempted is True
    assert (
        result.extraction_result.attack_actions[0].description
        == "Observed command exactly as reported."
    )
    assert (
        result.extraction_result.attack_conditions[0].description
        == "Once the actor obtained access"
    )
    assert (
        result.extraction_result.attack_assets[0].description
        == "the targeted Windows host"
    )


def test_provider_error_is_returned_cleanly() -> None:
    packaged = _packaged_input()
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        error_code="provider_rate_limited",
        error_category="rate_limit",
        error_message="provider rate limit exceeded",
        retryable=True,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is False
    assert result.error_code == "provider_rate_limited"


def test_unrecoverable_malformed_output_fails_cleanly() -> None:
    packaged = _packaged_input()
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=None,
        output_text="not-json-and-no-object-braces",
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is False
    assert result.repair_attempted is True
    assert result.error_code == "extraction_output_malformed"


def test_steps_without_techniques_are_preserved() -> None:
    packaged = _packaged_input()
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "attack_flow": {
            "id": "attack-flow--1",
            "name": "Example flow",
            "scope": "incident",
            "start_refs": ["attack-action--1"],
            "orchestration_mode": "ai_enrichment",
            "source_classification": "stix_structured",
        },
        "attack_actions": [
            {
                "id": "attack-action--1",
                "name": "Unmapped step",
                "description": "Observed command exactly as reported.",
                "confidence": 0.6,
                "evidence": [{"source": "narrative", "excerpt": "Observed command exactly as reported."}],
            }
        ],
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.attack_actions[0].technique is None


def test_invalid_groundings_are_dropped_before_validation() -> None:
    packaged = _packaged_input()
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "attack_flow": {
            "id": "attack-flow--1",
            "name": "Example flow",
            "scope": "incident",
            "start_refs": ["attack-action--1"],
            "orchestration_mode": "ai_enrichment",
            "source_classification": "stix_structured",
        },
        "attack_actions": [
            {
                "id": "attack-action--1",
                "name": "Credential Access",
                "description": "Observed command exactly as reported.",
                "confidence": 0.8,
                "technique": {
                    "technique_id": None,
                    "technique_ref": None,
                    "confidence": 0.9,
                    "grounded_by": "strongly implied",
                },
                "tactic": {
                    "tactic_id": None,
                    "tactic_ref": None,
                    "confidence": 0.8,
                    "grounded_by": "strongly implied",
                },
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                    }
                ],
            }
        ],
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.attack_actions[0].technique is None
    assert result.extraction_result.attack_actions[0].tactic is None


def test_legacy_afb_extraction_envelope_is_coerced() -> None:
    packaged = build_provider_orchestration_input(
        {
            "source_type": "narrative_text",
            "normalized_text": "Observed command: whoami",
            "metadata": {"title": "Legacy example", "authors": ["analyst-a"]},
        }
    )
    output_json = {
        "type": "afb-extraction",
        "version": "1.0",
        "source": {
            "source_type": "document_extracted_text",
            "file_class": "pdf",
            "mime_type": "application/pdf",
            "original_name": "example.pdf",
        },
        "metadata": {"title": "Legacy example", "authors": ["analyst-a"], "mode": "enrichment"},
        "deterministic_findings": {
            "attack_refs": [{"technique_id": "T1059", "source_object_id": "attack-pattern--1"}],
            "entities": [],
            "relationships": [],
        },
        "external_references": ["https://example.com/ref"],
        "attack_flow": {
            "attack_operator": "AND",
            "attack_condition": "true",
            "steps": [
                {
                    "step_id": "step-1",
                    "description": "Observed command: whoami",
                    "confidence": 0.9,
                    "evidence": [{"source": "report", "excerpt": "Observed command: whoami"}],
                }
            ],
        },
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-5.4",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.provider_invoked is True
    assert result.extraction_result.attack_flow.name == "Legacy example"
    assert result.extraction_result.attack_actions[0].id == "step-1"
    assert result.extraction_result.attack_actions[0].description == "Observed command: whoami"
    assert result.extraction_result.attack_operators[0].operator.value == "AND"


def test_legacy_attack_flow_objects_shape_is_coerced() -> None:
    packaged = build_provider_orchestration_input(
        {
            "source_type": "narrative_text",
            "normalized_text": "Observed command: whoami",
            "metadata": {"title": "Legacy objects example"},
        }
    )
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "source_name": "Cybereason Labs Analysis Operation Cobalt Kitty-Part1.pdf",
        "source_type": "document_extracted_text",
        "attack_version": "19.1",
        "authors": ["Assaf Dahan"],
        "external_references": ["https://example.com/ref"],
        "attack_flow": {
            "type": "attack-flow",
            "name": "Legacy objects example",
            "objects": [
                {
                    "id": "action-1",
                    "type": "attack-action",
                    "name": "step-01",
                    "description": "Observed command: whoami",
                    "confidence": 0.95,
                    "evidence": [{"source": "report", "excerpt": "Observed command: whoami"}],
                },
                {
                    "id": "operator-1",
                    "type": "attack-operator",
                    "operator": "OR",
                    "confidence": 0.9,
                    "effect_refs": ["action-1"],
                    "evidence": "The source explicitly shows an OR branch.",
                },
            ],
        },
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-5.4",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.attack_flow.name == "Legacy objects example"
    assert result.extraction_result.attack_flow.authors == ["Assaf Dahan"]
    assert result.extraction_result.attack_actions[0].id == "action-1"
    assert result.extraction_result.attack_operators[0].id == "operator-1"
    assert result.extraction_result.attack_operators[0].evidence[0].excerpt == "The source explicitly shows an OR branch."


def test_legacy_attack_operator_children_shape_is_coerced() -> None:
    packaged = build_provider_orchestration_input(
        {
            "source_type": "narrative_text",
            "normalized_text": "The source describes an OR branch.",
            "metadata": {"title": "Legacy operator children example"},
        }
    )
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "attack_flow": {
            "type": "attack-flow",
            "name": "Legacy operator children example",
            "objects": [
                {
                    "id": "action-1",
                    "type": "attack-action",
                    "name": "Initial step",
                    "description": "Observed command: whoami",
                    "confidence": 0.95,
                    "evidence": [{"source": "report", "excerpt": "Observed command: whoami"}],
                },
                {
                    "id": "operator-1",
                    "type": "attack-operator",
                    "operator": "OR",
                    "confidence": 0.9,
                    "children": ["action-2", "action-3"],
                    "evidence": "The source explicitly shows an OR branch.",
                },
                {
                    "id": "action-2",
                    "type": "attack-action",
                    "name": "Branch A",
                    "description": "Observed command: whoami",
                    "confidence": 0.88,
                    "evidence": [{"source": "report", "excerpt": "Observed command: whoami"}],
                },
                {
                    "id": "action-3",
                    "type": "attack-action",
                    "name": "Branch B",
                    "description": "Observed command: whoami",
                    "confidence": 0.88,
                    "evidence": [{"source": "report", "excerpt": "Observed command: whoami"}],
                },
            ],
        },
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-5.4",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    operator = result.extraction_result.attack_operators[0]
    assert operator.id == "operator-1"
    assert operator.effect_refs == ["action-2", "action-3"]


def test_legacy_bundle_shape_is_coerced() -> None:
    packaged = build_provider_orchestration_input(
        {
            "source_type": "narrative_text",
            "normalized_text": "PowerShell download then regsvr32 execution",
            "metadata": {"title": "Bundle example"},
        }
    )
    output_json = {
        "type": "bundle",
        "id": "bundle--1",
        "spec_version": "2.1",
        "provider_invoked": "api",
        "objects": [
            {
                "type": "attack-action",
                "attack_id": "action-1",
                "name": "Download payload with PowerShell",
                "description": "used PowerShell to download a payload from a remote URL",
                "confidence": 0.58,
                "technique": {"attack_id": "T1059.001", "name": "PowerShell", "confidence": 0.58},
                "object_refs": ["software-1"],
                "next_refs": ["action-2"],
            },
            {
                "type": "attack-action",
                "attack_id": "action-2",
                "name": "Execute scriptlet with regsvr32",
                "description": "used regsvr32 to execute a scriptlet",
                "confidence": 0.93,
                "technique": {"attack_id": "T1218.010", "name": "Regsvr32", "confidence": 0.93},
                "object_refs": ["software-2"],
            },
        ],
        "deterministic_entities": [
            {"entity_ref": "software-1", "type": "software", "name": "PowerShell"},
            {"entity_ref": "software-2", "type": "software", "name": "regsvr32"},
        ],
        "attack_flow": {"start_refs": ["action-1", "action-2"]},
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-5.4",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.provider_invoked is True
    assert result.extraction_result.attack_actions[0].id == "action-1"
    assert result.extraction_result.attack_actions[0].technique is not None
    assert result.extraction_result.attack_actions[0].object_refs == ["software-1"]
    assert result.extraction_result.attack_actions[0].effect_refs == ["action-2"]
    assert result.extraction_result.attack_actions[1].id == "action-2"
    assert result.extraction_result.attack_actions[1].object_refs == ["software-2"]


def test_legacy_attack_action_refs_shape_is_coerced() -> None:
    packaged = build_provider_orchestration_input(
        {
            "source_type": "narrative_text",
            "normalized_text": "Observed PowerShell download and regsvr32 execution",
            "metadata": {"title": "Legacy refs example"},
            "entities": [
                {"object_id": "tool--powershell", "object_type": "tool"},
                {"object_id": "url--remote-url", "object_type": "url"},
                {"object_id": "tool--regsvr32", "object_type": "tool"},
            ],
        }
    )
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "attack_flow": {
            "version": "2.0",
            "scope": "incident",
            "start_refs": ["action-1", "action-2"],
        },
        "attack_actions": [
            {
                "id": "action-1",
                "name": "Download payload with PowerShell",
                "description": "used PowerShell to download a payload from a remote URL",
                "technique_refs": [
                    {
                        "attack_id": "T1059.001",
                        "name": "PowerShell",
                        "confidence": 0.63,
                        "grounded_by": "The source explicitly states the PowerShell download.",
                    }
                ],
                "deterministic_entity_refs": ["tool--powershell", "url--remote-url"],
            },
            {
                "id": "action-2",
                "name": "Execute scriptlet with regsvr32",
                "description": "used regsvr32 to execute a scriptlet",
                "technique_refs": [
                    {
                        "attack_id": "T1218.010",
                        "name": "Regsvr32",
                        "confidence": 0.95,
                        "grounded_by": "The source explicitly states the regsvr32 scriptlet execution.",
                    }
                ],
                "deterministic_entity_refs": ["tool--regsvr32"],
            },
        ],
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-5.4",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.attack_actions[0].technique is not None
    assert result.extraction_result.attack_actions[0].technique.technique_id == "T1059.001"
    assert result.extraction_result.attack_actions[0].object_refs == ["tool--powershell", "url--remote-url"]
    assert result.extraction_result.attack_actions[1].technique is not None
    assert result.extraction_result.attack_actions[1].technique.technique_id == "T1218.010"
    assert result.extraction_result.attack_actions[1].object_refs == ["tool--regsvr32"]
