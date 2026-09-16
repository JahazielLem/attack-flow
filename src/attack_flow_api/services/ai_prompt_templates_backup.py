import json
from dataclasses import dataclass
from typing import Any

from attack_flow_api.services.afb_extraction_contracts import AfbExtractionResult
from attack_flow_api.services.ai_orchestration_planner import OrchestrationMode, ProviderOrchestrationInput


ATTACK_VERSION = "19.1"

SUPPORTED_STIX_OBJECT_TYPES = [
    "attack_pattern",
    "campaign",
    "course_of_action",
    "grouping",
    "identity",
    "indicator",
    "infrastructure",
    "intrusion_set",
    "location",
    "malware",
    "malware_analysis",
    "note",
    "observed_data",
    "opinion",
    "report",
    "threat_actor",
    "tool",
    "vulnerability",
    "marking_definition",
]

SUPPORTED_STIX_OBSERVABLE_TYPES = [
    "artifact",
    "autonomous_system",
    "directory",
    "domain_name",
    "email_address",
    "email_message",
    "file",
    "ipv4_addr",
    "ipv6_addr",
    "mac_addr",
    "mutex",
    "network_traffic",
    "process",
    "software",
    "url",
    "user_account",
    "windows_registry_key",
    "x509_certificate",
]


@dataclass(frozen=True, slots=True)
class PromptTemplateBundle:
    mode: OrchestrationMode
    system_instruction: str
    user_prompt: str
    output_schema: dict[str, Any]


EMPTY_EXTRACTION_REPROMPT_PREFIX = (
    "The previous extraction returned no attack_actions, but this source likely contains attacker behavior that should be captured. "
    "Re-read the full normalized text and extract every clearly supported attack action, even if the ATT&CK mapping is coarse or uncertain. "
    "Do not return an empty attack_actions array when the report describes execution, persistence, credential access, reconnaissance, lateral movement, C2, or other attacker activity.\n\n"
)


def build_prompt_template_bundle(packaged_input: ProviderOrchestrationInput) -> PromptTemplateBundle:
    if packaged_input.mode == OrchestrationMode.ENRICHMENT:
        user_prompt = _build_enrichment_prompt(packaged_input)
    else:
        user_prompt = _build_full_extraction_prompt(packaged_input)

    return PromptTemplateBundle(
        mode=packaged_input.mode,
        system_instruction=_build_system_instruction(),
        user_prompt=user_prompt,
        output_schema=AfbExtractionResult.model_json_schema(),
    )


def build_empty_extraction_reprompt_bundle(
    packaged_input: ProviderOrchestrationInput,
    *,
    source_cues: list[str] | None = None,
) -> PromptTemplateBundle:
    base_bundle = build_prompt_template_bundle(packaged_input)
    cue_text = ""
    if source_cues:
        cue_text = "Strong source cues to focus on:\n" + "\n".join(f"- {cue}" for cue in source_cues) + "\n\n"

    return PromptTemplateBundle(
        mode=base_bundle.mode,
        system_instruction=base_bundle.system_instruction,
        user_prompt=EMPTY_EXTRACTION_REPROMPT_PREFIX + cue_text + base_bundle.user_prompt,
        output_schema=base_bundle.output_schema,
    )


def _build_system_instruction() -> str:
    return (
        "You are an extraction engine that returns JSON only.\n"
        "Follow these hard constraints exactly:\n"
        f"1) If the source explicitly references an ATT&CK tactic or technique, always preserve it as an ATT&CK object.\n"
        "2) Treat ATT&CK IDs in source text, exact or legacy ATT&CK technique/tactic names in source text, STIX attack-pattern objects with ATT&CK external references, and ATT&CK external references on related source objects as explicit ATT&CK evidence.\n"
        f"3) Normalize ATT&CK objects to ATT&CK v{ATTACK_VERSION} when possible.\n"
        "4) If an explicit ATT&CK object cannot be fully normalized with high confidence, preserve the best source-grounded identifier or name available instead of omitting it.\n"
        "5) Never let normalization uncertainty suppress or replace an explicit ATT&CK object.\n"
        "6) If you infer a tactic or technique, only do so when no explicit ATT&CK evidence is present, and keep inferred confidence lower than explicit confidence.\n"
        "7) Create attack-action steps even when no technique mapping is available.\n"
        "8) attack-action descriptions must be verbatim source excerpts only; names should be concise summaries.\n"
        "9) attack-operator values may only be AND or OR, and attack-condition values may only be true or false.\n"
        "10) Create attack-operator and attack-condition only when the source explicitly expresses branching or sibling-step logic. Prefer no branching over guessed branching; do not invent branching from unrelated text. When multiple strong cues point to a branch, you may infer it at low confidence and explain the cues. If the source clearly shows a decision point, emit attack-condition and attack-operator nodes rather than flattening the branch into linear actions. If you create an attack-condition or attack-operator, keep its description and evidence verbatim and source-grounded.\n"
        "11) If one step names or uses a tool and another step shows the concrete runtime command, merge them into one action and link the tool as a deterministic_entity.\n"
        "12) Use the supported STIX catalog as linked deterministic_entities and deterministic_relationships. Only procedural attacker steps should become attack-action nodes. Asset-like or support objects should usually be linked entities instead of standalone attack_assets unless they must be preserved as explicit assets.\n"
        "13) When the source mentions a tool, software, file, URL, IP, process, user, registry key, domain, observable, or artifact, emit the matching STIX catalog object or observable as a deterministic_entity attached to the relevant action when possible. Prefer attack_actions[*].object_refs for these linked catalog objects, prefer attached STIX catalog objects over standalone attack_assets, and prefer concrete source-grounded identifiers and values over generic placeholders. Use object_id and object_type keys in deterministic_entities, not entity_id/entity_type.\n"
        "14) When you emit attack_assets, include a concise name, a source-grounded description when available, and tags when the source provides useful categorization.\n"
        "15) When you emit ATT&CK technique support data on attack_actions, preserve technique_id or technique_ref and also include description, aliases, kill_chain_phases, and tags when supported by the source.\n"
        "16) For deterministic_entities, preserve the type-specific STIX fields supported by the UI catalog instead of collapsing the entity to a name alone. If the source provides evidence for a supported field, populate it and prefer that field as the display label instead of a synthetic placeholder. Examples include value, path, command_line, hashes, display_name, cpe, vendor, version, aliases, kill_chain_phases, first_seen, last_seen, pattern, pattern_type, subject, subject_public_key_info, number, rir, and tags depending on the object or observable type.\n"
        "17) Preserve authors and external references from source metadata.\n"
        "18) Technique confidence must be in [0.0, 1.0].\n"
        "19) Return a single top-level JSON object with the AFB extraction fields validation_state, provider_invoked, attack_flow, attack_actions, attack_conditions, attack_operators, attack_assets, deterministic_attack_refs, deterministic_entities, and deterministic_relationships.\n"
        "20) Do not wrap the result in bundle/object envelopes or emit legacy fields like type, id, spec_version, objects, technique_refs, or deterministic_entity_refs."
    )


def _build_full_extraction_prompt(packaged_input: ProviderOrchestrationInput) -> str:
    payload = {
        "mode": "full_extraction",
        "source_type": packaged_input.source_type,
        "attack_version": ATTACK_VERSION,
        "normalized_text": packaged_input.normalized_text,
        "metadata": packaged_input.metadata,
        "structured_summary": packaged_input.structured_summary,
        "stix_context": {
            "deterministic_entities": packaged_input.deterministic_entities,
            "deterministic_relationships": packaged_input.deterministic_relationships,
            "ui_supported_object_types": SUPPORTED_STIX_OBJECT_TYPES,
            "ui_supported_observable_types": SUPPORTED_STIX_OBSERVABLE_TYPES,
        },
        "constraints": _constraints_payload(packaged_input),
        "required_output_behavior": {
            "preserve_explicit_attack_evidence": True,
            "normalize_to_attack_version": ATTACK_VERSION,
            "preserve_unresolved_explicit_mappings": True,
            "allow_inference_only_when_no_explicit_evidence_exists": True,
            "allow_actions_without_techniques": True,
            "description_must_be_verbatim": True,
            "action_name_should_be_concise_summary": True,
            "merge_tool_setup_with_runtime_action": True,
            "prefer_linked_objects_over_actions": True,
            "prefer_attached_stix_catalog_objects": True,
            "preserve_authors": True,
            "preserve_external_references": True,
            "preserve_explicit_stix_objects": True,
            "preserve_explicit_stix_relationships": True,
            "preserve_explicit_branching_logic": True,
            "allow_inferred_branching_when_supported": True,
            "emit_attack_conditions_for_decisions": True,
            "use_and_operator_for_multi_step_sets": True,
        },
        "output_shape_reminder": {
            "top_level_fields": [
                "validation_state",
                "provider_invoked",
                "attack_flow",
                "attack_actions",
                "attack_conditions",
                "attack_operators",
                "attack_assets",
                "deterministic_attack_refs",
                "deterministic_entities",
                "deterministic_relationships",
            ],
            "attack_action_technique_field": "attack_actions[*].technique",
            "attack_action_linked_objects_field": "attack_actions[*].object_refs",
            "linked_entities_field": "deterministic_entities",
            "linked_relationships_field": "deterministic_relationships",
            "legacy_fields_forbidden": ["type", "id", "spec_version", "objects", "technique_refs", "deterministic_entity_refs"],
        },
    }
    return _render_user_prompt(payload)


def _build_enrichment_prompt(packaged_input: ProviderOrchestrationInput) -> str:
    payload = {
        "mode": "enrichment",
        "source_type": packaged_input.source_type,
        "attack_version": ATTACK_VERSION,
        "normalized_text": packaged_input.normalized_text,
        "metadata": packaged_input.metadata,
        "structured_summary": packaged_input.structured_summary,
        "deterministic_findings": {
            "attack_refs": packaged_input.deterministic_attack_refs,
            "entities": packaged_input.deterministic_entities,
            "relationships": packaged_input.deterministic_relationships,
            "provenance": packaged_input.provenance,
            "ui_supported_object_types": SUPPORTED_STIX_OBJECT_TYPES,
            "ui_supported_observable_types": SUPPORTED_STIX_OBSERVABLE_TYPES,
        },
        "constraints": _constraints_payload(packaged_input),
        "required_output_behavior": {
            "preserve_deterministic_findings": True,
            "do_not_drop_or_rewrite_deterministic_attack_refs": True,
            "preserve_explicit_attack_evidence": True,
            "normalize_to_attack_version": ATTACK_VERSION,
            "preserve_unresolved_explicit_mappings": True,
            "allow_inference_only_when_no_explicit_evidence_exists": True,
            "allow_actions_without_techniques": True,
            "description_must_be_verbatim": True,
            "action_name_should_be_concise_summary": True,
            "merge_tool_setup_with_runtime_action": True,
            "prefer_linked_objects_over_actions": True,
            "preserve_authors": True,
            "preserve_external_references": True,
            "preserve_explicit_stix_objects": True,
            "preserve_explicit_stix_relationships": True,
            "preserve_explicit_branching_logic": True,
            "allow_inferred_branching_when_supported": True,
            "emit_attack_conditions_for_decisions": True,
            "use_and_operator_for_multi_step_sets": True,
        },
        "output_shape_reminder": {
            "top_level_fields": [
                "validation_state",
                "provider_invoked",
                "attack_flow",
                "attack_actions",
                "attack_conditions",
                "attack_operators",
                "attack_assets",
                "deterministic_attack_refs",
                "deterministic_entities",
                "deterministic_relationships",
            ],
            "attack_action_technique_field": "attack_actions[*].technique",
            "attack_action_linked_objects_field": "attack_actions[*].object_refs",
            "linked_entities_field": "deterministic_entities",
            "linked_relationships_field": "deterministic_relationships",
            "legacy_fields_forbidden": ["type", "id", "spec_version", "objects", "technique_refs", "deterministic_entity_refs"],
        },
    }
    return _render_user_prompt(payload)


def _constraints_payload(packaged_input: ProviderOrchestrationInput) -> dict[str, Any]:
    constraints = packaged_input.constraints
    return {
        "explicit_attack_refs_only": constraints.explicit_attack_refs_only,
        "no_missing_technique_inference": False,
        "descriptions_must_be_verbatim_excerpts": constraints.descriptions_must_be_verbatim_excerpts,
        "conditions_must_be_source_grounded": constraints.conditions_must_be_source_grounded,
        "operators_must_be_source_grounded": constraints.operators_must_be_source_grounded,
        "allowed_operator_values": list(constraints.allowed_operator_values),
        "allowed_condition_values": list(constraints.allowed_condition_values),
    }


def _render_user_prompt(payload: dict[str, Any]) -> str:
    return (
        "Build an AFB-compatible extraction JSON output from the following packaged source input. "
        "Output must be valid JSON and conform to the provided schema.\n\n"
        f"PACKAGED_INPUT:\n{json.dumps(payload, indent=2, sort_keys=True)}"
    )
