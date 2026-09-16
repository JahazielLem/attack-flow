import json
import re
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from attack_flow_api.services.afb_extraction_contracts import (
    AfbExtractionResult,
    ExtractionValidationState,
    OrchestrationMode,
    SourceClassification,
)
from attack_flow_api.services.ai_orchestration_planner import ProviderOrchestrationInput
from attack_flow_api.services.ai_provider_invocation_service import ProviderInvocationResult


_VERBATIM_DESCRIPTION_ERRORS = {
    "action_description_not_verbatim_excerpt",
    "condition_description_not_verbatim_excerpt",
    "asset_description_not_verbatim_excerpt",
}


@dataclass(frozen=True, slots=True)
class ExtractionOutputValidationResult:
    valid: bool
    extraction_result: AfbExtractionResult | None
    repair_attempted: bool
    error_code: str | None = None
    error_message: str | None = None


def parse_validate_and_repair_extraction_output(
    *,
    invocation_result: ProviderInvocationResult,
    packaged_input: ProviderOrchestrationInput,
) -> ExtractionOutputValidationResult:
    if invocation_result.error_code:
        return ExtractionOutputValidationResult(
            valid=False,
            extraction_result=None,
            repair_attempted=False,
            error_code=invocation_result.error_code,
            error_message=invocation_result.error_message,
        )

    if not invocation_result.provider_invoked and invocation_result.output_json is None and invocation_result.output_text is None:
        fallback = _build_deterministic_only_result(packaged_input)
        return ExtractionOutputValidationResult(
            valid=True,
            extraction_result=fallback,
            repair_attempted=False,
        )

    candidate = invocation_result.output_json
    repair_attempted = False

    if candidate is None:
        parsed = _try_parse_json(invocation_result.output_text)
        if parsed is None:
            repair_attempted = True
            repaired_text = _attempt_single_repair(invocation_result.output_text)
            parsed = _try_parse_json(repaired_text)
        candidate = parsed

    if not isinstance(candidate, dict):
        return ExtractionOutputValidationResult(
            valid=False,
            extraction_result=None,
            repair_attempted=repair_attempted,
            error_code="extraction_output_malformed",
            error_message="provider output is not valid JSON object",
        )

    candidate = _unwrap_nested_output_json(candidate)
    candidate = _coerce_legacy_afb_extraction_output(candidate, packaged_input)

    merged = _merge_deterministic_findings(candidate, packaged_input)
    if repair_attempted:
        merged["repair_attempted"] = True
        if merged.get("validation_state") == "valid":
            merged["validation_state"] = "repaired"

    try:
        extracted = AfbExtractionResult.model_validate(merged)
    except ValidationError as exc:
        return ExtractionOutputValidationResult(
            valid=False,
            extraction_result=None,
            repair_attempted=repair_attempted,
            error_code="extraction_output_schema_invalid",
            error_message=str(exc),
        )

    hard_constraint_errors = _validate_hard_constraints(extracted)
    if hard_constraint_errors and all(
        error in _VERBATIM_DESCRIPTION_ERRORS for error in hard_constraint_errors
    ):
        if _attempt_verbatim_description_repair(extracted):
            repair_attempted = True
            extracted.repair_attempted = True
            extracted.validation_state = ExtractionValidationState.REPAIRED
            hard_constraint_errors = _validate_hard_constraints(extracted)

    if hard_constraint_errors:
        return ExtractionOutputValidationResult(
            valid=False,
            extraction_result=None,
            repair_attempted=repair_attempted,
            error_code=hard_constraint_errors[0],
            error_message="extraction output violates hard constraints",
        )

    return ExtractionOutputValidationResult(
        valid=True,
        extraction_result=extracted,
        repair_attempted=repair_attempted,
    )


def _merge_deterministic_findings(
    candidate: dict[str, Any],
    packaged_input: ProviderOrchestrationInput,
) -> dict[str, Any]:
    merged = dict(candidate)
    merged = _promote_top_level_flow_metadata(merged)
    merged["deterministic_attack_refs"] = [
        _normalize_deterministic_attack_ref(item) for item in packaged_input.deterministic_attack_refs
    ]
    merged["deterministic_entities"] = _merge_dict_lists(
        [_normalize_deterministic_entity(item) for item in candidate.get("deterministic_entities") if isinstance(item, dict)]
        if isinstance(candidate.get("deterministic_entities"), list)
        else [],
        [_normalize_deterministic_entity(item) for item in packaged_input.deterministic_entities if isinstance(item, dict)],
    )
    merged["deterministic_relationships"] = _merge_dict_lists(
        list(candidate.get("deterministic_relationships") if isinstance(candidate.get("deterministic_relationships"), list) else []),
        list(packaged_input.deterministic_relationships),
    )
    merged = _preserve_authors_and_external_references(merged, packaged_input)
    merged = _normalize_evidence_citations(merged)
    merged = _tag_ai_generated_additions(merged)
    merged = _drop_invalid_groundings(merged)
    merged = _filter_explicit_object_relationship_attachments(merged)
    return merged


def _normalize_evidence_citations(merged: dict[str, Any]) -> dict[str, Any]:
    """Supply a neutral source label when a provider returns an otherwise valid excerpt."""
    for key in ("attack_actions", "attack_conditions", "attack_operators", "attack_assets"):
        values = merged.get(key)
        if not isinstance(values, list):
            continue
        normalized_items: list[dict[str, Any]] = []
        for item in values:
            if not isinstance(item, dict):
                continue
            out = dict(item)
            evidence = out.get("evidence")
            if isinstance(evidence, list):
                normalized_evidence: list[object] = []
                for citation in evidence:
                    if not isinstance(citation, dict):
                        normalized_evidence.append(citation)
                        continue
                    normalized_citation = dict(citation)
                    if not _as_str(normalized_citation.get("source")) and _as_str(normalized_citation.get("excerpt")):
                        normalized_citation["source"] = "source_document"
                    normalized_evidence.append(normalized_citation)
                out["evidence"] = normalized_evidence
            normalized_items.append(out)
        merged[key] = normalized_items
    return merged


def _promote_top_level_flow_metadata(candidate: dict[str, Any]) -> dict[str, Any]:
    merged = dict(candidate)
    flow = merged.get("attack_flow") if isinstance(merged.get("attack_flow"), dict) else {}
    if not flow:
        flow = {}

    top_level_authors = _as_str_list(merged.get("authors"))
    top_level_external_references = _as_str_list(merged.get("external_references"))
    if top_level_authors or top_level_external_references:
        flow_authors = _as_str_list(flow.get("authors"))
        flow_refs = _as_str_list(flow.get("external_references"))
        if top_level_authors:
            flow["authors"] = _dedupe_preserve_order(flow_authors + top_level_authors)
        if top_level_external_references:
            flow["external_references"] = _dedupe_preserve_order(flow_refs + top_level_external_references)

    if flow:
        merged["attack_flow"] = flow
    return merged


def _coerce_legacy_afb_extraction_output(
    candidate: dict[str, Any],
    packaged_input: ProviderOrchestrationInput,
) -> dict[str, Any]:
    if not _looks_like_legacy_afb_extraction(candidate):
        return candidate

    legacy_flow = candidate.get("attack_flow") if isinstance(candidate.get("attack_flow"), dict) else {}
    metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
    source = candidate.get("source") if isinstance(candidate.get("source"), dict) else {}
    source_name = _as_str(candidate.get("source_name")) or _as_str(source.get("original_name"))
    source_type = _as_str(candidate.get("source_type")) or _as_str(source.get("source_type"))
    attack_version = _as_str(candidate.get("attack_version"))
    top_level_authors = _as_str_list(candidate.get("authors"))
    top_level_external_references = _as_str_list(candidate.get("external_references"))
    deterministic_findings = (
        candidate.get("deterministic_findings")
        if isinstance(candidate.get("deterministic_findings"), dict)
        else {}
    )
    top_level_entities = candidate.get("deterministic_entities") if isinstance(candidate.get("deterministic_entities"), list) else []
    top_level_relationships = candidate.get("deterministic_relationships") if isinstance(candidate.get("deterministic_relationships"), list) else []

    attack_actions_input = candidate.get("attack_actions") if isinstance(candidate.get("attack_actions"), list) else []
    attack_conditions_input = candidate.get("attack_conditions") if isinstance(candidate.get("attack_conditions"), list) else []
    attack_operators_input = candidate.get("attack_operators") if isinstance(candidate.get("attack_operators"), list) else []
    attack_assets_input = candidate.get("attack_assets") if isinstance(candidate.get("attack_assets"), list) else []
    steps = legacy_flow.get("steps") if isinstance(legacy_flow.get("steps"), list) else []
    objects = (
        candidate.get("objects")
        if isinstance(candidate.get("objects"), list)
        else legacy_flow.get("objects")
        if isinstance(legacy_flow.get("objects"), list)
        else []
    )
    attack_actions: list[dict[str, Any]] = []
    attack_conditions: list[dict[str, Any]] = []
    attack_operators: list[dict[str, Any]] = []
    attack_assets: list[dict[str, Any]] = []
    action_ids: list[str] = []
    for index, step in enumerate(attack_actions_input, start=1):
        if not isinstance(step, dict):
            continue
        action = _coerce_legacy_step_to_action(step, index)
        attack_actions.append(action)
        action_ids.append(action["id"])

    for index, item in enumerate(attack_conditions_input, start=1):
        if not isinstance(item, dict):
            continue
        attack_conditions.append(_coerce_legacy_object_to_condition(item, index))

    for index, item in enumerate(attack_operators_input, start=1):
        if not isinstance(item, dict):
            continue
        attack_operators.append(_coerce_legacy_object_to_operator(item, index))

    for index, item in enumerate(attack_assets_input, start=1):
        if not isinstance(item, dict):
            continue
        attack_assets.append(_coerce_legacy_object_to_asset(item, index))

    offset = len(attack_actions)
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            continue
        action = _coerce_legacy_step_to_action(step, offset + index)
        attack_actions.append(action)
        action_ids.append(action["id"])

    offset = len(attack_actions)
    for index, item in enumerate(objects, start=1):
        if not isinstance(item, dict):
            continue
        legacy_type = _as_str(item.get("type"))
        if legacy_type == "attack-action":
            action = _coerce_legacy_object_to_action(item, offset + index)
            attack_actions.append(action)
            action_ids.append(action["id"])
        elif legacy_type == "attack-condition":
            attack_conditions.append(_coerce_legacy_object_to_condition(item, len(attack_conditions) + 1))
        elif legacy_type == "attack-operator":
            attack_operators.append(_coerce_legacy_object_to_operator(item, len(attack_operators) + 1))
        elif legacy_type == "attack-asset":
            attack_assets.append(_coerce_legacy_object_to_asset(item, len(attack_assets) + 1))

    operator_value = legacy_flow.get("attack_operator")
    if isinstance(operator_value, str) and operator_value.strip():
        attack_operators.append(
            {
                "id": str(legacy_flow.get("attack_operator_id") or "attack-operator--1"),
                "operator": operator_value.strip(),
                "confidence": _coerce_float(legacy_flow.get("attack_operator_confidence"), default=1.0),
                "effect_refs": action_ids,
            }
        )

    condition_value = legacy_flow.get("attack_condition")
    if isinstance(condition_value, str) and condition_value.strip():
        condition_description = str(
            legacy_flow.get("attack_condition_description")
            or metadata.get("attack_condition_description")
            or "Legacy attack condition"
        )
        attack_conditions.append(
            {
                "id": str(legacy_flow.get("attack_condition_id") or "attack-condition--1"),
                "description": condition_description,
                "value": condition_value.strip(),
                "confidence": _coerce_float(legacy_flow.get("attack_condition_confidence"), default=1.0),
                "on_true_refs": [],
                "on_false_refs": [],
                "evidence": [{"source": "legacy_output", "excerpt": condition_description}],
            }
        )

    source_classification = _coerce_source_classification(
        _as_str(source.get("source_type"))
        or _as_str(legacy_flow.get("source_classification"))
        or packaged_input.source_type
    )
    orchestration_mode = _coerce_orchestration_mode(
        _as_str(metadata.get("mode"))
        or _as_str(legacy_flow.get("orchestration_mode"))
        or packaged_input.mode.value
    )

    attack_flow = {
        "id": _as_str(legacy_flow.get("id")) or "attack-flow--intermediate",
        "name": _first_non_empty_string(
            _as_str(metadata.get("title")),
            _as_str(legacy_flow.get("name")),
            source_name,
            "AFB Intermediate Extraction",
        ),
        "description": _as_str(legacy_flow.get("description")) or None,
        "scope": _as_str(legacy_flow.get("scope")) or "incident",
        "start_refs": _coerce_legacy_start_refs(legacy_flow, attack_actions, attack_conditions),
        "orchestration_mode": orchestration_mode,
        "source_classification": source_classification,
        "authors": _dedupe_preserve_order(
            _as_str_list(metadata.get("authors"))
            or _as_str_list(legacy_flow.get("authors"))
            or top_level_authors
        ),
        "external_references": _as_str_list(metadata.get("external_references"))
        or top_level_external_references
        or _as_str_list(legacy_flow.get("external_references")),
        "provenance": {
            **packaged_input.provenance,
            "source_name": source_name or None,
            "source_type": source_type or None,
            "attack_version": attack_version or None,
        },
    }

    return {
        "validation_state": candidate.get("validation_state") or "valid",
        "repair_attempted": bool(candidate.get("repair_attempted", False)),
        "provider_invoked": bool(candidate.get("provider_invoked", True)),
        "provider_id": candidate.get("provider_id"),
        "model": candidate.get("model"),
        "attack_flow": attack_flow,
        "attack_actions": attack_actions,
        "attack_conditions": attack_conditions,
        "attack_operators": attack_operators,
        "attack_assets": attack_assets,
        "deterministic_attack_refs": list(deterministic_findings.get("attack_refs", [])),
        "deterministic_entities": list(deterministic_findings.get("entities", [])) or list(top_level_entities),
        "deterministic_relationships": list(deterministic_findings.get("relationships", [])) or list(top_level_relationships),
    }


def _looks_like_legacy_afb_extraction(candidate: dict[str, Any]) -> bool:
    if candidate.get("type") == "afb-extraction":
        return True
    if candidate.get("type") == "bundle":
        return True
    attack_flow = candidate.get("attack_flow")
    if isinstance(attack_flow, dict) and ("steps" in attack_flow or "objects" in attack_flow):
        return True
    if isinstance(attack_flow, dict) and isinstance(candidate.get("attack_actions"), list):
        return True
    attack_actions = candidate.get("attack_actions")
    if isinstance(attack_actions, list):
        for item in attack_actions:
            if isinstance(item, dict) and (
                "techniques" in item
                or "technique_refs" in item
                or "deterministic_entity_refs" in item
                or "attack_object" in item
            ):
                return True
    return any(key in candidate for key in ("source", "metadata", "deterministic_findings", "source_name", "source_type", "attack_version", "authors", "external_references"))


def _unwrap_nested_output_json(candidate: dict[str, Any]) -> dict[str, Any]:
    nested = candidate.get("output_json")
    if isinstance(nested, dict) and not any(key in candidate for key in ("attack_flow", "attack_actions", "attack_conditions", "attack_operators", "attack_assets")):
        return nested
    return candidate


def _coerce_legacy_step_to_action(step: dict[str, Any], index: int) -> dict[str, Any]:
    description = _first_non_empty_string(
        step.get("description"),
        step.get("description_excerpt"),
        step.get("text"),
        step.get("summary"),
        step.get("name"),
        step.get("step_id"),
        f"Legacy attack step {index}",
    )
    evidence = step.get("evidence") if isinstance(step.get("evidence"), list) else []
    normalized_evidence = [item for item in evidence if isinstance(item, dict)]
    if not normalized_evidence:
        normalized_evidence = [{"source": "legacy_output", "excerpt": description}]
    else:
        first_excerpt = _first_non_empty_string(
            *(str(item.get("excerpt")).strip() for item in normalized_evidence if isinstance(item, dict)),
            description,
        )
        normalized_evidence[0] = {
            **normalized_evidence[0],
            "excerpt": first_excerpt,
            "source": str(normalized_evidence[0].get("source") or "legacy_output"),
        }

    action = {
        "id": _first_non_empty_string(
            _as_str(step.get("id")),
            _as_str(step.get("attack_id")),
            _as_str(step.get("step_id")),
            _as_str(step.get("action_ref")),
            f"attack-action--{index}",
        ),
        "name": _first_non_empty_string(_as_str(step.get("name")), description, f"Attack action {index}"),
        "description": description,
        "confidence": _coerce_float(step.get("confidence"), default=0.5),
        "evidence": normalized_evidence,
        "citations": _as_str_list(step.get("citations")),
        "asset_refs": _as_str_list(step.get("asset_refs")),
        "object_refs": _dedupe_preserve_order(
            _as_str_list(step.get("object_refs")) + _as_str_list(step.get("deterministic_entity_refs"))
        ),
        "effect_refs": _dedupe_preserve_order(_as_str_list(step.get("effect_refs")) + _as_str_list(step.get("next_refs"))),
        "fact_origin": _as_str(step.get("fact_origin")) or "ai_generated",
    }

    technique = _coerce_legacy_technique(step.get("technique"))
    techniques = (
        step.get("techniques")
        if isinstance(step.get("techniques"), list)
        else step.get("technique_refs")
        if isinstance(step.get("technique_refs"), list)
        else []
    )
    best_technique = technique
    for item in techniques:
        candidate = _coerce_legacy_technique(item)
        if candidate is None:
            continue
        if best_technique is None or candidate["confidence"] > best_technique["confidence"]:
            best_technique = candidate

    if best_technique is not None:
        action["technique"] = best_technique

    tactic = step.get("tactic")
    if isinstance(tactic, dict):
        action["tactic"] = {
            "tactic_id": _as_str(tactic.get("tactic_id")) or None,
            "tactic_ref": _as_str(tactic.get("tactic_ref")) or None,
            "tactic_name": _as_str(tactic.get("tactic_name")) or None,
            "confidence": _coerce_float(tactic.get("confidence"), default=0.5),
            "grounded_by": _first_non_empty_string(_as_str(tactic.get("grounded_by")), "legacy_output"),
        }

    return action


def _coerce_legacy_object_to_action(item: dict[str, Any], index: int) -> dict[str, Any]:
    action = _coerce_legacy_step_to_action(item, index)
    action["asset_refs"] = _as_str_list(item.get("asset_refs"))
    action["object_refs"] = _as_str_list(item.get("object_refs"))
    action["effect_refs"] = _dedupe_preserve_order(_as_str_list(item.get("effect_refs")) + _as_str_list(item.get("next_refs")))
    return action


def _coerce_legacy_technique(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None

    attack_object = value.get("attack_object") if isinstance(value.get("attack_object"), dict) else {}
    technique_id = _first_non_empty_string(
        _as_str(value.get("technique_id")),
        _as_str(value.get("attack_id")),
        _as_str(value.get("technique_ref")),
        _as_str(attack_object.get("id")),
    )
    technique_name = _first_non_empty_string(
        _as_str(value.get("technique_name")),
        _as_str(value.get("name")),
        _as_str(attack_object.get("name")),
    )
    technique_ref = _first_non_empty_string(_as_str(value.get("technique_ref")))
    grounded_by_value = value.get("grounded_by")
    if isinstance(grounded_by_value, list):
        grounded_by = _first_non_empty_string(*(str(item).strip() for item in grounded_by_value))
    else:
        grounded_by = _first_non_empty_string(_as_str(grounded_by_value), "legacy_output")

    if not (technique_id or technique_ref or technique_name):
        return None

    return {
        "technique_id": technique_id or None,
        "technique_ref": technique_ref or None,
        "technique_name": technique_name or None,
        "description": _as_str(value.get("description")) or None,
        "aliases": _as_str_list(value.get("aliases")),
        "kill_chain_phases": _as_str_list(value.get("kill_chain_phases")),
        "tags": _as_str_list(value.get("tags")),
        "confidence": _coerce_float(value.get("confidence"), default=0.5),
        "grounded_by": grounded_by,
    }


def _coerce_legacy_object_to_condition(item: dict[str, Any], index: int) -> dict[str, Any]:
    value = _first_non_empty_string(_as_str(item.get("value")), _as_str(item.get("condition_value")), "true")
    description = _first_non_empty_string(_as_str(item.get("description")), _as_str(item.get("name")), f"Legacy attack condition {index}")
    evidence = [entry for entry in item.get("evidence", []) if isinstance(entry, dict)] if isinstance(item.get("evidence"), list) else []
    if not evidence and description:
        evidence = [{"source": "legacy_output", "excerpt": description}]
    return {
        "id": _first_non_empty_string(_as_str(item.get("id")), _as_str(item.get("condition_id")), f"attack-condition--{index}"),
        "description": description,
        "value": value,
        "confidence": _coerce_float(item.get("confidence"), default=0.5),
        "on_true_refs": _as_str_list(item.get("on_true_refs")),
        "on_false_refs": _as_str_list(item.get("on_false_refs")),
        "evidence": evidence,
        "citations": _as_str_list(item.get("citations")),
        "fact_origin": _as_str(item.get("fact_origin")) or "ai_generated",
    }


def _coerce_legacy_object_to_operator(item: dict[str, Any], index: int) -> dict[str, Any]:
    evidence = item.get("evidence")
    if isinstance(evidence, list):
        normalized_evidence = [entry for entry in evidence if isinstance(entry, dict)]
    elif isinstance(evidence, str) and evidence.strip():
        normalized_evidence = [{"source": "legacy_output", "excerpt": evidence.strip()}]
    else:
        description = _first_non_empty_string(_as_str(item.get("description")), _as_str(item.get("name")), f"Legacy attack operator {index}")
        normalized_evidence = [{"source": "legacy_output", "excerpt": description}] if description else []
    return {
        "id": _first_non_empty_string(_as_str(item.get("id")), _as_str(item.get("operator_id")), f"attack-operator--{index}"),
        "operator": _first_non_empty_string(_as_str(item.get("operator")), "OR"),
        "confidence": _coerce_float(item.get("confidence"), default=0.5),
        "effect_refs": _dedupe_preserve_order(
            _as_str_list(item.get("effect_refs"))
            + _as_str_list(item.get("action_refs"))
            + _as_str_list(item.get("children"))
        ),
        "evidence": normalized_evidence,
        "citations": _as_str_list(item.get("citations")),
        "fact_origin": _as_str(item.get("fact_origin")) or "ai_generated",
    }


def _coerce_legacy_object_to_asset(item: dict[str, Any], index: int) -> dict[str, Any]:
    return {
        "id": _first_non_empty_string(_as_str(item.get("id")), _as_str(item.get("asset_id")), f"attack-asset--{index}"),
        "name": _first_non_empty_string(_as_str(item.get("name")), _as_str(item.get("display_name")), f"Legacy attack asset {index}"),
        "description": _as_str(item.get("description")) or None,
        "tags": _as_str_list(item.get("tags")),
        "object_ref": _as_str(item.get("object_ref")) or None,
        "evidence": [entry for entry in item.get("evidence", []) if isinstance(entry, dict)] if isinstance(item.get("evidence"), list) else [],
        "confidence": _coerce_float(item.get("confidence"), default=0.5),
        "fact_origin": _as_str(item.get("fact_origin")) or "ai_generated",
    }


def _coerce_legacy_start_refs(
    legacy_flow: dict[str, Any],
    attack_actions: list[dict[str, Any]],
    attack_conditions: list[dict[str, Any]],
) -> list[str]:
    start_refs = legacy_flow.get("start_refs")
    if isinstance(start_refs, list):
        return _as_str_list(start_refs)

    candidate_ids = [
        item["id"]
        for item in [*attack_actions, *attack_conditions]
        if isinstance(item, dict) and _as_str(item.get("id"))
    ]
    inbound_refs: set[str] = set()
    for item in [*attack_actions, *attack_conditions]:
        if not isinstance(item, dict):
            continue
        for field_name in ("effect_refs", "on_true_refs", "on_false_refs"):
            for ref in _as_str_list(item.get(field_name)):
                inbound_refs.add(ref)

    derived = [ref for ref in candidate_ids if ref not in inbound_refs]
    if derived:
        return derived
    return candidate_ids[:1]
def _coerce_source_classification(value: str) -> str:
    normalized = value.strip()
    allowed = {"narrative_text", "url_extracted_text", "document_extracted_text", "stix_structured", "mixed"}
    return normalized if normalized in allowed else "mixed"


def _coerce_orchestration_mode(value: str) -> str:
    normalized = value.strip()
    if normalized in {"enrichment", "ai_enrichment"}:
        return "ai_enrichment"
    return "full_extraction"


def _coerce_float(value: Any, *, default: float) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    return default


def _first_non_empty_string(*values: object) -> str:
    for value in values:
        if isinstance(value, str):
            candidate = value.strip()
            if candidate:
                return candidate
    return ""


def _as_str(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _normalize_deterministic_attack_ref(item: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(item)
    normalized.setdefault("confidence", 1.0)
    normalized["fact_origin"] = "deterministic_source"
    return normalized


def _normalize_deterministic_entity(item: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(item)
    object_id = _first_non_empty_string(
        _as_str(normalized.get("object_id")),
        _as_str(normalized.get("entity_id")),
        _as_str(normalized.get("entity_ref")),
        _as_str(normalized.get("id")),
    )
    object_type = _first_non_empty_string(
        _as_str(normalized.get("object_type")),
        _as_str(normalized.get("entity_type")),
        _as_str(normalized.get("kind")),
        _as_str(normalized.get("type")),
    )
    if object_id:
        normalized["object_id"] = object_id
    if object_type:
        normalized["object_type"] = object_type
    display_name = _preferred_entity_display_name(normalized, object_id=object_id, object_type=object_type)
    if display_name:
        normalized["display_name"] = display_name
    if "tags" in normalized and not isinstance(normalized.get("tags"), list):
        normalized.pop("tags", None)
    return normalized


def _preferred_entity_display_name(
    normalized: dict[str, Any],
    *,
    object_id: str,
    object_type: str,
) -> str:
    display_name = _as_str(normalized.get("display_name"))
    if display_name and not _looks_like_placeholder_name(display_name, object_id=object_id, object_type=object_type):
        return display_name

    for field_name in (
        "name",
        "value",
        "path",
        "command_line",
        "display_name",
        "pattern",
        "subject",
        "number",
        "rir",
    ):
        candidate = _as_str(normalized.get(field_name))
        if candidate:
            return candidate

    return display_name


def _looks_like_placeholder_name(value: str, *, object_id: str, object_type: str) -> bool:
    candidate = value.strip().lower()
    if not candidate:
        return True
    if object_id and candidate == object_id.strip().lower():
        return True
    if object_type and candidate == object_type.strip().lower():
        return True
    return bool(re.fullmatch(r"[a-z0-9_-]+-\d+", candidate))


def _preserve_authors_and_external_references(
    merged: dict[str, Any],
    packaged_input: ProviderOrchestrationInput,
) -> dict[str, Any]:
    flow = merged.get("attack_flow")
    if not isinstance(flow, dict):
        return merged

    metadata = packaged_input.metadata
    authors = _as_str_list(metadata.get("authors"))
    external_references = _as_str_list(metadata.get("external_references"))

    flow_authors = _as_str_list(flow.get("authors"))
    flow_refs = _as_str_list(flow.get("external_references"))
    flow["authors"] = _dedupe_preserve_order(flow_authors + authors)
    flow["external_references"] = _dedupe_preserve_order(flow_refs + external_references)
    merged["attack_flow"] = flow
    return merged


def _merge_dict_lists(*lists: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for items in lists:
        for item in items:
            if not isinstance(item, dict):
                continue
            key = json.dumps(item, sort_keys=True, default=str)
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
    return merged


def _tag_ai_generated_additions(merged: dict[str, Any]) -> dict[str, Any]:
    for key in ("attack_actions", "attack_conditions", "attack_operators", "attack_assets"):
        values = merged.get(key)
        if not isinstance(values, list):
            continue
        tagged: list[dict[str, Any]] = []
        for item in values:
            if not isinstance(item, dict):
                continue
            out = dict(item)
            out.setdefault("fact_origin", "ai_generated")
            tagged.append(out)
        merged[key] = tagged
    return merged


def _drop_invalid_groundings(merged: dict[str, Any]) -> dict[str, Any]:
    actions = merged.get("attack_actions")
    if not isinstance(actions, list):
        return merged

    sanitized_actions: list[dict[str, Any]] = []
    for item in actions:
        if not isinstance(item, dict):
            continue
        out = dict(item)

        technique = out.get("technique")
        if isinstance(technique, dict):
            if not (_as_str(technique.get("technique_id")) or _as_str(technique.get("technique_ref")) or _as_str(technique.get("technique_name"))):
                out.pop("technique", None)

        tactic = out.get("tactic")
        if isinstance(tactic, dict):
            if not (_as_str(tactic.get("tactic_id")) or _as_str(tactic.get("tactic_ref")) or _as_str(tactic.get("tactic_name"))):
                out.pop("tactic", None)

        sanitized_actions.append(out)

    merged["attack_actions"] = sanitized_actions
    return merged


def _filter_explicit_object_relationship_attachments(merged: dict[str, Any]) -> dict[str, Any]:
    deterministic_entities = merged.get("deterministic_entities")
    deterministic_relationships = merged.get("deterministic_relationships")

    allowed_refs: set[str] = set()
    if isinstance(deterministic_entities, list):
        for item in deterministic_entities:
            if isinstance(item, dict):
                object_id = item.get("object_id") or item.get("entity_id") or item.get("entity_ref") or item.get("id")
                if isinstance(object_id, str) and object_id:
                    allowed_refs.add(object_id)
    if isinstance(deterministic_relationships, list):
        for item in deterministic_relationships:
            if not isinstance(item, dict):
                continue
            for field in ("source_ref", "target_ref"):
                ref = item.get(field)
                if isinstance(ref, str) and ref:
                    allowed_refs.add(ref)

    filtered_action_refs = 0
    filtered_asset_refs = 0

    actions = merged.get("attack_actions")
    if isinstance(actions, list):
        filtered_actions: list[dict[str, Any]] = []
        for action in actions:
            if not isinstance(action, dict):
                continue
            out = dict(action)
            object_refs = _as_str_list(out.get("object_refs"))
            if object_refs:
                filtered = [ref for ref in object_refs if ref in allowed_refs]
                filtered_action_refs += max(0, len(object_refs) - len(filtered))
                out["object_refs"] = filtered
            filtered_actions.append(out)
        merged["attack_actions"] = filtered_actions

    assets = merged.get("attack_assets")
    if isinstance(assets, list):
        filtered_assets: list[dict[str, Any]] = []
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            out = dict(asset)
            object_ref = out.get("object_ref")
            if isinstance(object_ref, str) and object_ref and object_ref not in allowed_refs:
                out["object_ref"] = None
                filtered_asset_refs += 1
            filtered_assets.append(out)
        merged["attack_assets"] = filtered_assets

    return merged


def _try_parse_json(text: str | None) -> dict[str, Any] | None:
    if text is None:
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _attempt_single_repair(text: str | None) -> str | None:
    if text is None:
        return None
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\\s*```$", "", stripped)

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start >= 0 and end > start:
        stripped = stripped[start : end + 1]
    return stripped


def _validate_hard_constraints(extracted: AfbExtractionResult) -> list[str]:
    errors: list[str] = []
    for action in extracted.attack_actions:
        if action.technique is not None and not action.technique.grounded_by.strip():
            errors.append("technique_not_explicitly_grounded")

        if action.description.strip():
            evidence_excerpts = {item.excerpt for item in action.evidence}
            if action.description not in evidence_excerpts:
                errors.append("action_description_not_verbatim_excerpt")

    for condition in extracted.attack_conditions:
        if condition.description.strip():
            evidence_excerpts = {item.excerpt for item in condition.evidence}
            if condition.description not in evidence_excerpts:
                errors.append("condition_description_not_verbatim_excerpt")

    for asset in extracted.attack_assets:
        if asset.description and asset.description.strip():
            evidence_excerpts = {item.excerpt for item in asset.evidence}
            if asset.description not in evidence_excerpts:
                errors.append("asset_description_not_verbatim_excerpt")

    return errors


def _attempt_verbatim_description_repair(extracted: AfbExtractionResult) -> bool:
    changed = False
    nodes = [
        *extracted.attack_actions,
        *extracted.attack_conditions,
        *extracted.attack_assets,
    ]
    for node in nodes:
        description = node.description
        if not description:
            continue
        excerpts = [item.excerpt for item in node.evidence if item.excerpt]
        if not excerpts or description in excerpts:
            continue
        node.description = max(excerpts, key=len)
        changed = True

    return changed


def _build_deterministic_only_result(packaged_input: ProviderOrchestrationInput) -> AfbExtractionResult:
    source_classification_map = {
        "narrative_text": SourceClassification.NARRATIVE_TEXT,
        "url_extracted_text": SourceClassification.URL_EXTRACTED_TEXT,
        "document_extracted_text": SourceClassification.DOCUMENT_EXTRACTED_TEXT,
        "stix_structured": SourceClassification.STIX_STRUCTURED,
    }
    source_classification = source_classification_map.get(packaged_input.source_type, SourceClassification.MIXED)
    orchestration_mode = (
        OrchestrationMode.AI_ENRICHMENT
        if packaged_input.mode.value == "enrichment"
        else OrchestrationMode.FULL_EXTRACTION
    )

    metadata = packaged_input.metadata
    return AfbExtractionResult.model_validate(
        {
            "validation_state": ExtractionValidationState.VALID,
            "repair_attempted": False,
            "provider_invoked": False,
            "provider_id": None,
            "model": None,
            "attack_flow": {
                "id": "attack-flow--intermediate",
                "name": str(metadata.get("title") or "AFB Intermediate Extraction"),
                "scope": "incident",
                "start_refs": [],
                "orchestration_mode": orchestration_mode,
                "source_classification": source_classification,
                "authors": _as_str_list(metadata.get("authors")),
                "external_references": _as_str_list(metadata.get("external_references")),
                "provenance": packaged_input.provenance,
            },
            "attack_actions": [],
            "attack_conditions": [],
            "attack_operators": [],
            "attack_assets": [],
            "deterministic_attack_refs": [
                _normalize_deterministic_attack_ref(item)
                for item in packaged_input.deterministic_attack_refs
            ],
            "deterministic_entities": [
                _normalize_deterministic_entity(item)
                for item in packaged_input.deterministic_entities
                if isinstance(item, dict)
            ],
            "deterministic_relationships": list(packaged_input.deterministic_relationships),
        }
    )


def _as_str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        candidate = item.strip()
        if candidate:
            out.append(candidate)
    return out


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out
