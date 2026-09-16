import pytest
from pydantic import ValidationError

from attack_flow_api.services.afb_extraction_contracts import (
    AfbExtractionResult,
    AttackConditionNode,
    AttackOperatorNode,
    AttackOperatorType,
    ConditionValue,
    ExtractionValidationState,
    OrchestrationMode,
    SourceClassification,
    TechniqueGrounding,
)


def _base_payload() -> dict[str, object]:
    return {
        "validation_state": ExtractionValidationState.VALID,
        "provider_invoked": False,
        "attack_flow": {
            "id": "attack-flow--1",
            "name": "Example flow",
            "scope": "incident",
            "start_refs": ["attack-action--1"],
            "orchestration_mode": OrchestrationMode.FULL_EXTRACTION,
            "source_classification": SourceClassification.NARRATIVE_TEXT,
            "authors": ["author-1"],
            "external_references": ["https://example.com/ref"],
        },
        "attack_actions": [
            {
                "id": "attack-action--1",
                "name": "Credential Access",
                "description": "Observed command exactly as reported.",
                "confidence": 0.8,
                "evidence": [{"source": "narrative", "excerpt": "Observed command exactly as reported."}],
                "citations": ["line-42"],
            }
        ],
        "attack_conditions": [
            {
                "id": "attack-condition--1",
                "description": "Execution succeeded",
                "value": ConditionValue.TRUE,
                "confidence": 0.9,
                "on_true_refs": ["attack-action--2"],
            }
        ],
        "attack_operators": [
            {
                "id": "attack-operator--1",
                "operator": AttackOperatorType.AND,
                "confidence": 0.7,
                "effect_refs": ["attack-action--3"],
            }
        ],
        "attack_assets": [
            {
                "id": "attack-asset--1",
                "name": "Domain Controller",
                "confidence": 1.0,
                "object_ref": "identity--1",
            }
        ],
    }


def test_afb_extraction_contract_accepts_action_without_technique() -> None:
    payload = _base_payload()
    result = AfbExtractionResult.model_validate(payload)
    assert result.attack_actions[0].technique is None


def test_afb_extraction_contract_accepts_grounded_technique() -> None:
    payload = _base_payload()
    payload["attack_actions"][0]["technique"] = {
        "technique_id": "T1059",
        "confidence": 1.0,
        "grounded_by": "explicit_attack_id_in_source",
    }
    result = AfbExtractionResult.model_validate(payload)
    assert result.attack_actions[0].technique is not None
    assert result.attack_actions[0].technique.technique_id == "T1059"


def test_afb_extraction_contract_accepts_grounded_technique_name_only() -> None:
    payload = _base_payload()
    payload["attack_actions"][0]["technique"] = {
        "technique_name": "Command and Scripting Interpreter",
        "confidence": 0.9,
        "grounded_by": "legacy_attack_term_mapped_to_v19_1",
    }
    result = AfbExtractionResult.model_validate(payload)
    assert result.attack_actions[0].technique is not None
    assert result.attack_actions[0].technique.technique_name == "Command and Scripting Interpreter"


def test_technique_grounding_requires_identifier_or_name() -> None:
    with pytest.raises(ValidationError):
        TechniqueGrounding.model_validate({"confidence": 1.0, "grounded_by": "source"})


def test_operator_only_allows_and_or() -> None:
    valid = AttackOperatorNode.model_validate(
        {
            "id": "attack-operator--1",
            "operator": "AND",
            "confidence": 0.5,
        }
    )
    assert valid.operator.value == "AND"

    with pytest.raises(ValidationError):
        AttackOperatorNode.model_validate(
            {
                "id": "attack-operator--1",
                "operator": "XOR",
                "confidence": 0.5,
            }
        )


def test_condition_only_allows_true_false() -> None:
    valid = AttackConditionNode.model_validate(
        {
            "id": "attack-condition--1",
            "description": "grounded condition",
            "value": "true",
            "confidence": 0.5,
        }
    )
    assert valid.value.value == "true"

    with pytest.raises(ValidationError):
        AttackConditionNode.model_validate(
            {
                "id": "attack-condition--1",
                "description": "something",
                "value": "maybe",
                "confidence": 0.5,
            }
        )


def test_confidence_score_bounds_are_enforced() -> None:
    payload = _base_payload()
    payload["attack_actions"][0]["confidence"] = -0.1
    with pytest.raises(ValidationError):
        AfbExtractionResult.model_validate(payload)

    payload = _base_payload()
    payload["attack_actions"][0]["confidence"] = 1.1
    with pytest.raises(ValidationError):
        AfbExtractionResult.model_validate(payload)
