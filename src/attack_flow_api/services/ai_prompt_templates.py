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
        "Follow these requirements exactly:\n"
        f"1) Map every attack-action to one best-fit technique from an Attack Flow-supported framework only: MITRE ATT&CK Enterprise, Mobile, or ICS; MITRE ATLAS; MITRE D3FEND; or MITRE F3. Do not emit techniques from any other framework or invent custom techniques. Preserve and normalize explicit ATT&CK evidence to ATT&CK v{ATTACK_VERSION} when possible. An ATT&CK ID, a technique or tactic name, or an ATT&CK external reference is explicit evidence. When the source describes attacker behavior without an explicit ATT&CK reference, infer the closest supported technique from that procedure, set grounded_by to inferred_from_procedure, and use lower confidence than for explicit evidence. Do not omit technique for an attack-action. For every ATT&CK technique, also emit its corresponding ATT&CK tactic in the action's tactic field.\n"
        "2) Create an attack-action for every source-grounded procedural attacker step, including when the report does not name an ATT&CK technique. Use a concise action name and make its description the most complete contiguous verbatim source excerpt available for that step. Do not shorten or summarize away material details such as tools, file types, commands, targets, conditions, parameters, or outcomes.\n"
        "3) Order attack_actions chronologically. For every non-terminal action, use effect_refs to point to the next source-supported action, condition, or operator. A terminal action has an empty effect_refs list. Merge contiguous substeps only when they describe the same technique and operational outcome. Treat tool setup as part of its runtime action unless the setup itself maps to a distinct ATT&CK technique; create a separate setup action only in that case. Do not merge source-distinct steps when they have different techniques, create an explicit prerequisite or state change, occur concurrently, or have different documented follow-on outcomes. Retain all source-specific detail in each action's description and linked objects.\n"
        "4) Treat action links as part of the output: do not leave otherwise sequential source-grounded actions disconnected. When the source order is the only sequencing evidence, connect each action to the next action in that order.\n"
        "5) Create attack-condition and attack-operator only for source-grounded flow logic. Create an attack-condition when the source explicitly describes a state or prerequisite that gates a later action, including cues such as upon execution, after, before, when, once, with those credentials, or a documented outcome such as a file being opened or a host being compromised. When an action's effect_refs points to a condition, that condition's on_true_refs must point to the next source-supported action, condition, or operator using its exact emitted ID. Leave on_false_refs empty unless the source documents a false or alternative path. A condition may be terminal only when the source contains no supported next step. Use AND only for documented concurrent activity, parallel requirements, or multiple independent outcomes that all occur after the same source-supported step. Use OR only for documented alternatives. Model a documented split by connecting the predecessor to an operator and the operator to each outcome; model a documented join by connecting each supported predecessor to the shared next action or condition. Do not force supported splits or joins into a sequential chain, and never guess branching.\n"
        "6) Every evidence record for an action, condition, operator, or asset must include a nonempty source and an excerpt. For every action, the evidence must contain the verbatim excerpt used for its description.\n"
        "7) When an action uses or targets a concrete tool, software, file, URL, IP address, process, user, registry key, domain, or observable, emit a matching deterministic_entity and include its object_id in that action's object_refs. Default to the most specific supported STIX object or observable type (for example software, process, file, user_account, or windows_registry_key), not attack_asset. Do not create a linked entity for a generic category without source-specific identifying data.\n"
        "8) Preserve type-specific entity fields from the source, such as value, path, command_line, hashes, display_name, cpe, vendor, version, pattern, subject, number, or rir. Preserve defanged observables exactly as written in the source: never refang indicators such as [.] or [:] in URL, domain, IP, email, or other observable values. Use the most specific source-grounded field as the entity display label.\n"
        "9) Prefer linked deterministic_entities over standalone attack_assets. Emit an attack_asset only when it has a specific name or source-grounded description; never use an internal identifier such as software-1 or tool-1 as its name.\n"
        "10) Do not create standalone attack-pattern nodes. Record ATT&CK techniques only on attack_actions.\n"
        "11) When the source includes an ATT&CK technique table, appendix, or matrix, use it as supplementary authoritative evidence for coverage and mapping. Create an action from a table entry only when its Use text or a referenced source passage describes concrete behavior; do not invent behavior solely from a technique name. Reports without an ATT&CK table must be extracted from their narrative and other source-grounded evidence.\n"
        "12) Preserve authors, external references, explicit STIX objects, and explicit STIX relationships. Carry source dates into relevant action metadata, include a source URL in attack_flow.external_references, preserve source-grounded threat-actor, group, or campaign attribution, and capture every lifecycle phase supported by the source.\n"
        "13) Technique confidence must be in [0.0, 1.0]. Return one top-level AFB extraction JSON object and no prose, bundle envelope, or legacy fields.\n"
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
            "allow_actions_without_techniques": False,
            "require_tactic_for_attack_technique": True,
            "description_must_be_verbatim": True,
            "action_name_should_be_concise_summary": True,
            "separate_tool_setup_action_only_when_distinct_technique": True,
            "consolidate_contiguous_same_technique_substeps": True,
            "prefer_linked_objects_over_actions": True,
            "default_entities_to_supported_stix_types": True,
            "preserve_defanged_observable_values": True,
            "use_attack_technique_table_when_present": True,
            "prefer_attached_stix_catalog_objects": True,
            "preserve_authors": True,
            "preserve_external_references": True,
            "preserve_explicit_stix_objects": True,
            "preserve_explicit_stix_relationships": True,
            "preserve_explicit_branching_logic": True,
            "allow_inferred_branching_when_supported": False,
            "emit_attack_conditions_for_decisions": True,
            "emit_attack_conditions_for_explicit_prerequisites_and_state_changes": True,
            "connect_condition_true_paths_to_next_supported_step": True,
            "condition_references_must_use_exact_emitted_ids": True,
            "use_and_operator_for_explicit_parallel_steps": True,
            "use_or_operator_for_documented_alternatives": True,
            "use_operators_for_multiple_documented_outcomes": True,
            "preserve_documented_flow_joins": True,
        },
        "flow_modeling_requirements": _flow_modeling_requirements(),
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
            "allow_actions_without_techniques": False,
            "require_tactic_for_attack_technique": True,
            "description_must_be_verbatim": True,
            "action_name_should_be_concise_summary": True,
            "separate_tool_setup_action_only_when_distinct_technique": True,
            "consolidate_contiguous_same_technique_substeps": True,
            "prefer_linked_objects_over_actions": True,
            "default_entities_to_supported_stix_types": True,
            "preserve_defanged_observable_values": True,
            "use_attack_technique_table_when_present": True,
            "preserve_authors": True,
            "preserve_external_references": True,
            "preserve_explicit_stix_objects": True,
            "preserve_explicit_stix_relationships": True,
            "preserve_explicit_branching_logic": True,
            "allow_inferred_branching_when_supported": False,
            "emit_attack_conditions_for_decisions": True,
            "emit_attack_conditions_for_explicit_prerequisites_and_state_changes": True,
            "connect_condition_true_paths_to_next_supported_step": True,
            "condition_references_must_use_exact_emitted_ids": True,
            "use_and_operator_for_explicit_parallel_steps": True,
            "use_or_operator_for_documented_alternatives": True,
            "use_operators_for_multiple_documented_outcomes": True,
            "preserve_documented_flow_joins": True,
        },
        "flow_modeling_requirements": _flow_modeling_requirements(),
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
        "no_missing_technique_inference": constraints.no_missing_technique_inference,
        "descriptions_must_be_verbatim_excerpts": constraints.descriptions_must_be_verbatim_excerpts,
        "conditions_must_be_source_grounded": constraints.conditions_must_be_source_grounded,
        "operators_must_be_source_grounded": constraints.operators_must_be_source_grounded,
        "allowed_operator_values": list(constraints.allowed_operator_values),
        "allowed_condition_values": list(constraints.allowed_condition_values),
    }


def _flow_modeling_requirements() -> dict[str, Any]:
    return {
        "action_order": "chronological_source_order",
        "next_step_field": "attack_actions[*].effect_refs",
        "connect_nonterminal_actions": True,
        "action_evidence_must_match_description": True,
        "link_concrete_entities_to_actions": True,
        "generic_entity_placeholders_forbidden": True,
        "require_tactic_for_attack_technique": True,
        "consolidate_contiguous_same_technique_substeps": True,
        "keep_source_distinct_actions_separate": True,
        "default_entities_to_supported_stix_types": True,
        "preserve_defanged_observable_values": True,
        "model_multiple_documented_outcomes_with_operators": True,
        "model_explicit_prerequisites_and_state_changes_as_conditions": True,
        "connect_condition_true_paths": True,
        "condition_references_use_exact_emitted_ids": True,
        "preserve_documented_splits_and_joins": True,
        "infer_branching": False,
    }


def _render_user_prompt(payload: dict[str, Any]) -> str:
    return (
        "Build an AFB-compatible extraction JSON output from the following packaged source input. "
        "Output must be valid JSON and conform to the provided schema.\n\n"
        f"PACKAGED_INPUT:\n{json.dumps(payload, indent=2, sort_keys=True)}"
    )
