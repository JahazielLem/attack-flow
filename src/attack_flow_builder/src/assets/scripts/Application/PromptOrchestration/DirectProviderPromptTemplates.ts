export const DIRECT_PROVIDER_ATTACK_VERSION = "19.1" as const;

export const DIRECT_PROVIDER_SUPPORTED_STIX_OBJECT_TYPES = [
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
    "marking_definition"
] as const;

export const DIRECT_PROVIDER_SUPPORTED_STIX_OBSERVABLE_TYPES = [
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
    "x509_certificate"
] as const;

export const DIRECT_PROVIDER_EMPTY_EXTRACTION_REPROMPT_PREFIX =
    "The previous extraction returned no attack_actions, but this source likely contains attacker behavior that should be captured. " +
    "Re-read the full normalized text and extract every clearly supported attack action, even if the ATT&CK mapping is coarse or uncertain. " +
    "Do not return an empty attack_actions array when the report describes execution, persistence, credential access, reconnaissance, lateral movement, C2, or other attacker activity.\n\n";

export const DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT =
    "You are an extraction engine that returns JSON only.\n" +
    "Follow these requirements exactly:\n" +
    `1) Map every attack-action to one best-fit technique from an Attack Flow-supported framework only: MITRE ATT&CK Enterprise, Mobile, or ICS; MITRE ATLAS; MITRE D3FEND; or MITRE F3. Do not emit techniques from any other framework or invent custom techniques. Preserve and normalize explicit ATT&CK evidence to ATT&CK v${DIRECT_PROVIDER_ATTACK_VERSION} when possible. An ATT&CK ID, a technique or tactic name, or an ATT&CK external reference is explicit evidence. When the source describes attacker behavior without an explicit ATT&CK reference, infer the closest supported technique from that procedure, set grounded_by to inferred_from_procedure, and use lower confidence than for explicit evidence. Do not omit technique for an attack-action. For every ATT&CK technique, also emit its corresponding ATT&CK tactic in the action's tactic field.\n` +
    "2) Create an attack-action for every source-grounded procedural attacker step, including when the report does not name an ATT&CK technique. Use a concise action name and make its description the most complete contiguous verbatim source excerpt available for that step. Do not shorten or summarize away material details such as tools, file types, commands, targets, conditions, parameters, or outcomes.\n" +
    "3) Order attack_actions chronologically. For every non-terminal action, use effect_refs to point to the next source-supported action, condition, or operator. A terminal action has an empty effect_refs list. Merge contiguous substeps only when they describe the same technique and operational outcome. Treat tool setup as part of its runtime action unless the setup itself maps to a distinct ATT&CK technique; create a separate setup action only in that case. Do not merge source-distinct steps when they have different techniques, create an explicit prerequisite or state change, occur concurrently, or have different documented follow-on outcomes. Retain all source-specific detail in each action's description and linked objects.\n" +
    "4) Treat action links as part of the output: do not leave otherwise sequential source-grounded actions disconnected. When the source order is the only sequencing evidence, connect each action to the next action in that order.\n" +
    "5) Create attack-condition and attack-operator only for source-grounded flow logic. Create an attack-condition when the source explicitly describes a state or prerequisite that gates a later action, including cues such as upon execution, after, before, when, once, with those credentials, or a documented outcome such as a file being opened or a host being compromised. When an action's effect_refs points to a condition, that condition's on_true_refs must point to the next source-supported action, condition, or operator using its exact emitted ID. Leave on_false_refs empty unless the source documents a false or alternative path. A condition may be terminal only when the source contains no supported next step. Use AND only for documented concurrent activity, parallel requirements, or multiple independent outcomes that all occur after the same source-supported step. Use OR only for documented alternatives. Model a documented split by connecting the predecessor to an operator and the operator to each outcome; model a documented join by connecting each supported predecessor to the shared next action or condition. Do not force supported splits or joins into a sequential chain, and never guess branching.\n" +
    "6) Every evidence record for an action, condition, operator, or asset must include a nonempty source and an excerpt. For every action, the evidence must contain the verbatim excerpt used for its description.\n" +
    "7) When an action uses or targets a concrete tool, software, file, URL, IP address, process, user, registry key, domain, or observable, emit a matching deterministic_entity and include its object_id in that action's object_refs. Default to the most specific supported STIX object or observable type (for example software, process, file, user_account, or windows_registry_key), not attack_asset. Do not create a linked entity for a generic category without source-specific identifying data.\n" +
    "8) Preserve type-specific entity fields from the source, such as value, path, command_line, hashes, display_name, cpe, vendor, version, pattern, subject, number, or rir. Preserve defanged observables exactly as written in the source: never refang indicators such as [.] or [:] in URL, domain, IP, email, or other observable values. Use the most specific source-grounded field as the entity display label.\n" +
    "9) Prefer linked deterministic_entities over standalone attack_assets. Emit an attack_asset only when it has a specific name or source-grounded description; never use an internal identifier such as software-1 or tool-1 as its name.\n" +
    "10) Do not create standalone attack-pattern nodes. Record ATT&CK techniques only on attack_actions.\n" +
    "11) When the source includes an ATT&CK technique table, appendix, or matrix, use it as supplementary authoritative evidence for coverage and mapping. Create an action from a table entry only when its Use text or a referenced source passage describes concrete behavior; do not invent behavior solely from a technique name. Reports without an ATT&CK table must be extracted from their narrative and other source-grounded evidence.\n" +
    "12) Preserve authors, external references, explicit STIX objects, and explicit STIX relationships. Carry source dates into relevant action metadata, include a source URL in attack_flow.external_references, preserve source-grounded threat-actor, group, or campaign attribution, and capture every lifecycle phase supported by the source.\n" +
    "13) Technique confidence must be in [0.0, 1.0]. Return one top-level AFB extraction JSON object and no prose, bundle envelope, or legacy fields.\n";

export type DirectProviderPromptMode = "full_extraction" | "enrichment";

export interface DirectProviderPromptInput {
    mode: DirectProviderPromptMode;
    sourceType: string;
    normalizedText: string;
    metadata?: Record<string, unknown>;
    structuredSummary?: Record<string, unknown>;
    deterministicAttackRefs?: Record<string, unknown>[];
    deterministicEntities?: Record<string, unknown>[];
    deterministicRelationships?: Record<string, unknown>[];
    provenance?: Record<string, unknown>;
}

export interface DirectProviderPromptTemplateBundle {
    mode: DirectProviderPromptMode;
    systemInstruction: string;
    userPrompt: string;
    outputSchema: Record<string, unknown>;
}

const outputShapeReminder = {
    top_level_fields: [
        "validation_state",
        "provider_invoked",
        "attack_flow",
        "attack_actions",
        "attack_conditions",
        "attack_operators",
        "attack_assets",
        "deterministic_attack_refs",
        "deterministic_entities",
        "deterministic_relationships"
    ],
    attack_action_technique_field: "attack_actions[*].technique",
    attack_action_linked_objects_field: "attack_actions[*].object_refs",
    linked_entities_field: "deterministic_entities",
    linked_relationships_field: "deterministic_relationships",
    legacy_fields_forbidden: ["type", "id", "spec_version", "objects", "technique_refs", "deterministic_entity_refs"]
};

function buildConstraintsPayload(): Record<string, unknown> {
    return {
        explicit_attack_refs_only: false,
        no_missing_technique_inference: false,
        descriptions_must_be_verbatim_excerpts: true,
        conditions_must_be_source_grounded: true,
        operators_must_be_source_grounded: true,
        allowed_operator_values: ["AND", "OR"],
        allowed_condition_values: ["true", "false"]
    };
}

function buildFlowModelingRequirements(): Record<string, unknown> {
    return {
        action_order: "chronological_source_order",
        next_step_field: "attack_actions[*].effect_refs",
        connect_nonterminal_actions: true,
        action_evidence_must_match_description: true,
        link_concrete_entities_to_actions: true,
        generic_entity_placeholders_forbidden: true,
        require_tactic_for_attack_technique: true,
        consolidate_contiguous_same_technique_substeps: true,
        keep_source_distinct_actions_separate: true,
        default_entities_to_supported_stix_types: true,
        preserve_defanged_observable_values: true,
        model_multiple_documented_outcomes_with_operators: true,
        model_explicit_prerequisites_and_state_changes_as_conditions: true,
        connect_condition_true_paths: true,
        condition_references_use_exact_emitted_ids: true,
        preserve_documented_splits_and_joins: true,
        infer_branching: false
    };
}

function buildRequiredOutputBehavior(mode: DirectProviderPromptMode): Record<string, unknown> {
    return {
        ...(mode === "enrichment" ? {
            preserve_deterministic_findings: true,
            do_not_drop_or_rewrite_deterministic_attack_refs: true
        } : {}),
        preserve_explicit_attack_evidence: true,
        normalize_to_attack_version: DIRECT_PROVIDER_ATTACK_VERSION,
        preserve_unresolved_explicit_mappings: true,
        allow_inference_only_when_no_explicit_evidence_exists: true,
        allow_actions_without_techniques: false,
        require_tactic_for_attack_technique: true,
        description_must_be_verbatim: true,
        action_name_should_be_concise_summary: true,
        separate_tool_setup_action_only_when_distinct_technique: true,
        consolidate_contiguous_same_technique_substeps: true,
        prefer_linked_objects_over_actions: true,
        default_entities_to_supported_stix_types: true,
        preserve_defanged_observable_values: true,
        use_attack_technique_table_when_present: true,
        ...(mode === "full_extraction" ? { prefer_attached_stix_catalog_objects: true } : {}),
        preserve_authors: true,
        preserve_external_references: true,
        preserve_explicit_stix_objects: true,
        preserve_explicit_stix_relationships: true,
        preserve_explicit_branching_logic: true,
        allow_inferred_branching_when_supported: false,
        emit_attack_conditions_for_decisions: true,
        emit_attack_conditions_for_explicit_prerequisites_and_state_changes: true,
        connect_condition_true_paths_to_next_supported_step: true,
        condition_references_must_use_exact_emitted_ids: true,
        use_and_operator_for_explicit_parallel_steps: true,
        use_or_operator_for_documented_alternatives: true,
        use_operators_for_multiple_documented_outcomes: true,
        preserve_documented_flow_joins: true
    };
}

function buildPromptPayload(input: DirectProviderPromptInput): Record<string, unknown> {
    const shared = {
        mode: input.mode,
        source_type: input.sourceType,
        attack_version: DIRECT_PROVIDER_ATTACK_VERSION,
        normalized_text: input.normalizedText,
        metadata: input.metadata ?? {},
        structured_summary: input.structuredSummary ?? {}
    };
    const supportedTypes = {
        ui_supported_object_types: [...DIRECT_PROVIDER_SUPPORTED_STIX_OBJECT_TYPES],
        ui_supported_observable_types: [...DIRECT_PROVIDER_SUPPORTED_STIX_OBSERVABLE_TYPES]
    };

    return {
        ...shared,
        ...(input.mode === "enrichment" ? {
            deterministic_findings: {
                attack_refs: input.deterministicAttackRefs ?? [],
                entities: input.deterministicEntities ?? [],
                relationships: input.deterministicRelationships ?? [],
                provenance: input.provenance ?? {},
                ...supportedTypes
            }
        } : {
            stix_context: {
                deterministic_entities: input.deterministicEntities ?? [],
                deterministic_relationships: input.deterministicRelationships ?? [],
                ...supportedTypes
            }
        }),
        constraints: buildConstraintsPayload(),
        required_output_behavior: buildRequiredOutputBehavior(input.mode),
        flow_modeling_requirements: buildFlowModelingRequirements(),
        output_shape_reminder: outputShapeReminder
    };
}

function renderUserPrompt(input: DirectProviderPromptInput): string {
    return "Build an AFB-compatible extraction JSON output from the following packaged source input. " +
        "Output must be valid JSON and conform to the provided schema.\n\n" +
        `PACKAGED_INPUT:\n${pythonCompatibleJsonStringify(buildPromptPayload(input))}`;
}

export function buildDirectProviderPromptTemplateBundle(
    input: DirectProviderPromptInput,
    outputSchema: Record<string, unknown>
): DirectProviderPromptTemplateBundle {
    return {
        mode: input.mode,
        systemInstruction: DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT,
        userPrompt: renderUserPrompt(input),
        outputSchema
    };
}

export function buildDirectProviderEmptyExtractionRepromptBundle(
    input: DirectProviderPromptInput,
    outputSchema: Record<string, unknown>,
    sourceCues?: string[]
): DirectProviderPromptTemplateBundle {
    const base = buildDirectProviderPromptTemplateBundle(input, outputSchema);
    const cueText = sourceCues?.length
        ? `Strong source cues to focus on:\n${sourceCues.map((cue) => `- ${cue}`).join("\n")}\n\n`
        : "";
    return {
        ...base,
        userPrompt: DIRECT_PROVIDER_EMPTY_EXTRACTION_REPROMPT_PREFIX + cueText + base.userPrompt
    };
}

export function composeDirectProviderPrompt(bundle: DirectProviderPromptTemplateBundle): string {
    return "SYSTEM_INSTRUCTION:\n" + bundle.systemInstruction +
        "\n\nUSER_PROMPT:\n" + bundle.userPrompt +
        "\n\nOUTPUT_SCHEMA:\n" + pythonCompatibleJsonStringify(bundle.outputSchema) + "\n";
}

export function pythonCompatibleJsonStringify(value: unknown): string {
    const seen = new WeakSet<object>();
    const normalize = (item: unknown): unknown => {
        if (Array.isArray(item)) {
            return item.map(normalize);
        }
        if (item && typeof item === "object") {
            if (seen.has(item)) {
                throw new TypeError("Cannot stringify circular prompt data.");
            }
            seen.add(item);
            const result: Record<string, unknown> = {};
            for (const key of Object.keys(item).sort()) {
                const normalized = normalize((item as Record<string, unknown>)[key]);
                if (normalized !== undefined) {
                    result[key] = normalized;
                }
            }
            seen.delete(item);
            return result;
        }
        return item;
    };
    return JSON.stringify(normalize(value), null, 2).replace(/[\u007f-\uffff]/g, (character) =>
        `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`
    );
}
