import type { StructuredJsonValue } from "../Providers";
import type { StructuredExtractionResult } from "./StructuredExtractionContracts";
import {
    STRUCTURED_EXTRACTION_RESULT_CONDITION_VALUES,
    STRUCTURED_EXTRACTION_RESULT_OPERATOR_VALUES,
    STRUCTURED_EXTRACTION_RESULT_SCHEMA_VERSION,
    STRUCTURED_EXTRACTION_RESULT_VALIDATION_STATES,
    type StructuredExtractionAttackActionNode,
    type StructuredExtractionAttackAssetNode,
    type StructuredExtractionAttackConditionNode,
    type StructuredExtractionAttackFlowMetadata,
    type StructuredExtractionAttackOperatorNode,
    type StructuredExtractionEvidenceCitation,
    type StructuredExtractionTechniqueGrounding
} from "./StructuredExtractionContracts";
import type {
    StructuredExtractionValidationFailure,
    StructuredExtractionValidationResult,
    StructuredExtractionValidationStatus
} from "./StructuredExtractionValidationContracts";

export interface StructuredExtractionValidatorInput {
    outputJson?: StructuredJsonValue;
    outputText?: string;
    providerId?: string;
    model?: string;
}

interface ValidationContext {
    failures: StructuredExtractionValidationFailure[];
}

/**
 * Validates provider output client-side against the pinned structured
 * extraction schema and hard extraction constraints.
 */
export function validateStructuredExtractionOutput(
    output: StructuredExtractionValidatorInput
): StructuredExtractionValidationResult {
    const parseOutcome = parseStructuredExtractionCandidate(output);
    if (!parseOutcome.ok) {
        return buildValidationResult(parseOutcome.status, parseOutcome.failures);
    }

    const candidate = parseOutcome.value;
    const context: ValidationContext = { failures: [] };

    const result = validateStructuredExtractionResult(candidate, context);
    const status = classifyValidationStatus(context.failures);

    if (status === "valid" && result !== null) {
        return {
            status,
            repairAttempted: Boolean(result.repair_attempted),
            failures: [],
            result,
            message: undefined
        };
    }

    return buildValidationResult(status, context.failures, result ?? undefined, Boolean(result?.repair_attempted));
}

function parseStructuredExtractionCandidate(
    output: StructuredExtractionValidatorInput
):
    | { ok: true, value: Record<string, unknown> }
    | { ok: false, status: StructuredExtractionValidationStatus, failures: StructuredExtractionValidationFailure[] } {
    if (output.outputJson !== undefined && output.outputJson !== null) {
        if (isPlainObject(output.outputJson)) {
            return { ok: true, value: output.outputJson };
        }

        return {
            ok: false,
            status: "unrecoverable",
            failures: [buildFailure({
                code: "structured_extraction_output_not_object",
                category: "schema",
                message: "provider output must be a JSON object",
                path: "$"
            })]
        };
    }

    if (typeof output.outputText === "string") {
        const trimmed = output.outputText.trim();
        if (!trimmed) {
            return {
                ok: false,
                status: "repairable",
                failures: [buildFailure({
                    code: "structured_extraction_output_not_json",
                    category: "parse",
                    message: "provider output was empty",
                    path: "$",
                    field: "outputText"
                })]
            };
        }

        try {
            const parsed = JSON.parse(trimmed) as unknown;
            if (isPlainObject(parsed)) {
                return { ok: true, value: parsed };
            }

            return {
                ok: false,
                status: "unrecoverable",
                failures: [buildFailure({
                    code: "structured_extraction_output_not_object",
                    category: "schema",
                    message: "provider output must be a JSON object",
                    path: "$",
                    field: "outputText"
                })]
            };
        } catch {
            return {
                ok: false,
                status: "repairable",
                failures: [buildFailure({
                    code: "structured_extraction_output_not_json",
                    category: "parse",
                    message: "provider output could not be parsed as JSON",
                    path: "$",
                    field: "outputText"
                })]
            };
        }
    }

    return {
        ok: false,
        status: "repairable",
        failures: [buildFailure({
            code: "structured_extraction_output_not_json",
            category: "parse",
            message: "provider output did not include JSON content",
            path: "$"
        })]
    };
}

function validateStructuredExtractionResult(
    candidate: Record<string, unknown>,
    context: ValidationContext
): StructuredExtractionResult | null {
    const schemaVersion = candidate.schema_version;
    if (schemaVersion !== STRUCTURED_EXTRACTION_RESULT_SCHEMA_VERSION) {
        context.failures.push(buildFailure({
            code: "structured_extraction_schema_version_invalid",
            category: "schema",
            message: `expected schema_version ${STRUCTURED_EXTRACTION_RESULT_SCHEMA_VERSION}`,
            path: "schema_version",
            field: "schema_version"
        }));
    }

    if (!STRUCTURED_EXTRACTION_RESULT_VALIDATION_STATES.includes(candidate.validation_state as never)) {
        context.failures.push(buildFailure({
            code: "structured_extraction_validation_state_invalid",
            category: "schema",
            message: "validation_state must be valid, invalid, or repaired",
            path: "validation_state",
            field: "validation_state"
        }));
    }

    if (typeof candidate.repair_attempted !== "boolean") {
        context.failures.push(buildFailure({
            code: "structured_extraction_repair_attempted_invalid",
            category: "schema",
            message: "repair_attempted must be a boolean",
            path: "repair_attempted",
            field: "repair_attempted"
        }));
    }

    if (typeof candidate.provider_invoked !== "boolean") {
        context.failures.push(buildFailure({
            code: "structured_extraction_provider_invoked_invalid",
            category: "schema",
            message: "provider_invoked must be a boolean",
            path: "provider_invoked",
            field: "provider_invoked"
        }));
    }

    if (candidate.provider_id !== undefined && candidate.provider_id !== null && typeof candidate.provider_id !== "string") {
        context.failures.push(buildFailure({
            code: "structured_extraction_provider_id_invalid",
            category: "schema",
            message: "provider_id must be a string or null",
            path: "provider_id",
            field: "provider_id"
        }));
    }

    if (candidate.model !== undefined && candidate.model !== null && typeof candidate.model !== "string") {
        context.failures.push(buildFailure({
            code: "structured_extraction_model_invalid",
            category: "schema",
            message: "model must be a string or null",
            path: "model",
            field: "model"
        }));
    }

    const attackFlow = candidate.attack_flow;
    if (!isPlainObject(attackFlow)) {
        context.failures.push(buildFailure({
            code: "structured_extraction_attack_flow_invalid",
            category: "schema",
            message: "attack_flow must be an object",
            path: "attack_flow",
            field: "attack_flow"
        }));
        return null;
    }

    const normalizedAttackFlow = validateAttackFlow(attackFlow, context);
    const attackActions = validateAttackActions(candidate.attack_actions, context);
    const attackConditions = validateAttackConditions(candidate.attack_conditions, context);
    const attackOperators = validateAttackOperators(candidate.attack_operators, context);
    const attackAssets = validateAttackAssets(candidate.attack_assets, context);

    validateStructuredJsonArray(candidate.deterministic_attack_refs, "deterministic_attack_refs", context);
    const entityIds = validateDeterministicEntities(candidate.deterministic_entities, context);
    validateDeterministicRelationships(candidate.deterministic_relationships, entityIds, context);
    validateExtractionReferences(attackActions ?? [], attackAssets ?? [], entityIds, context);

    if (context.failures.length > 0) {
        return null;
    }

    return {
        schema_version: STRUCTURED_EXTRACTION_RESULT_SCHEMA_VERSION,
        validation_state: candidate.validation_state as StructuredExtractionResult["validation_state"],
        repair_attempted: Boolean(candidate.repair_attempted),
        provider_invoked: Boolean(candidate.provider_invoked),
        provider_id: toOptionalString(candidate.provider_id),
        model: toOptionalString(candidate.model),
        attack_flow: normalizedAttackFlow,
        attack_actions: attackActions,
        attack_conditions: attackConditions,
        attack_operators: attackOperators,
        attack_assets: attackAssets,
        deterministic_attack_refs: normalizeStructuredJsonArray(candidate.deterministic_attack_refs),
        deterministic_entities: normalizeStructuredJsonArray(candidate.deterministic_entities),
        deterministic_relationships: normalizeStructuredJsonArray(candidate.deterministic_relationships)
    };
}

function validateAttackFlow(
    attackFlow: Record<string, unknown>,
    context: ValidationContext
): StructuredExtractionAttackFlowMetadata {
    const id = requireString(attackFlow.id, "attack_flow.id", "structured_extraction_attack_flow_id_invalid", context);
    const type = requireLiteral(attackFlow.type, "attack_flow.type", "attack-flow", "structured_extraction_attack_flow_type_invalid", context);
    const specVersion = requireLiteral(attackFlow.spec_version, "attack_flow.spec_version", "2.1", "structured_extraction_attack_flow_spec_version_invalid", context);
    const name = requireString(attackFlow.name, "attack_flow.name", "structured_extraction_attack_flow_name_invalid", context);
    const scope = requireString(attackFlow.scope, "attack_flow.scope", "structured_extraction_attack_flow_scope_invalid", context);
    const orchestrationMode = requireString(attackFlow.orchestration_mode, "attack_flow.orchestration_mode", "structured_extraction_attack_flow_orchestration_mode_invalid", context);
    const sourceClassification = requireString(attackFlow.source_classification, "attack_flow.source_classification", "structured_extraction_attack_flow_source_classification_invalid", context);

    const startRefs = normalizeStringArray(attackFlow.start_refs, "attack_flow.start_refs", context, false);
    const authors = normalizeStringArray(attackFlow.authors, "attack_flow.authors", context, false);
    const externalReferences = normalizeStringArray(attackFlow.external_references, "attack_flow.external_references", context, false);
    const provenance = isPlainObject(attackFlow.provenance) ? attackFlow.provenance : undefined;

    return {
        id,
        type,
        spec_version: specVersion,
        name,
        scope,
        start_refs: startRefs.length ? startRefs : undefined,
        description: toOptionalString(attackFlow.description),
        orchestration_mode: orchestrationMode,
        source_classification: sourceClassification,
        authors: authors.length ? authors : undefined,
        external_references: externalReferences.length ? externalReferences : undefined,
        provenance
    };
}

function validateAttackActions(
    value: unknown,
    context: ValidationContext
): StructuredExtractionAttackActionNode[] | undefined {
    if (value === undefined) {
        return undefined;
    }
    if (!Array.isArray(value)) {
        context.failures.push(buildFailure({
            code: "structured_extraction_attack_actions_invalid",
            category: "schema",
            message: "attack_actions must be an array when present",
            path: "attack_actions",
            field: "attack_actions"
        }));
        return undefined;
    }

    return value.map((item, index) => validateAttackAction(item, index, context)).filter(Boolean) as StructuredExtractionAttackActionNode[];
}

function validateAttackAction(
    item: unknown,
    index: number,
    context: ValidationContext
): StructuredExtractionAttackActionNode | null {
    if (!isPlainObject(item)) {
        context.failures.push(buildFailure({
            code: "structured_extraction_attack_action_invalid",
            category: "schema",
            message: "attack_actions items must be objects",
            path: `attack_actions[${index}]`
        }));
        return null;
    }

    const path = `attack_actions[${index}]`;
    const id = requireString(item.id, `${path}.id`, "structured_extraction_attack_action_id_invalid", context);
    const type = requireLiteral(item.type, `${path}.type`, "attack-action", "structured_extraction_attack_action_type_invalid", context);
    const specVersion = requireLiteral(item.spec_version, `${path}.spec_version`, "2.1", "structured_extraction_attack_action_spec_version_invalid", context);
    const name = requireString(item.name, `${path}.name`, "structured_extraction_attack_action_name_invalid", context);
    const description = requireString(item.description, `${path}.description`, "structured_extraction_attack_action_description_invalid", context);
    const confidence = requireProbability(item.confidence, `${path}.confidence`, "structured_extraction_attack_action_confidence_invalid", context);

    const evidence = validateEvidence(item.evidence, `${path}.evidence`, context, true);
    validateCitations(item.citations, `${path}.citations`, context);
    const assetRefs = normalizeStringArray(item.asset_refs, `${path}.asset_refs`, context, false);
    const objectRefs = normalizeStringArray(item.object_refs, `${path}.object_refs`, context, false);
    const effectRefs = normalizeStringArray(item.effect_refs, `${path}.effect_refs`, context, false);
    const factOrigin = requireFactOrigin(item.fact_origin, `${path}.fact_origin`, context);

    validateEvidenceRequired(description, evidence, `${path}.description`, "structured_extraction_attack_action_description_not_verbatim", context);

    const technique = item.technique === undefined || item.technique === null
        ? undefined
        : validateTechnique(item.technique, `${path}.technique`, context);
    const tactic = item.tactic === undefined || item.tactic === null
        ? undefined
        : validateTactic(item.tactic, `${path}.tactic`, context);

    return {
        id,
        type,
        spec_version: specVersion,
        name,
        description,
        confidence,
        technique: technique ?? undefined,
        tactic: tactic ?? undefined,
        asset_refs: assetRefs.length ? assetRefs : undefined,
        object_refs: objectRefs.length ? objectRefs : undefined,
        effect_refs: effectRefs.length ? effectRefs : undefined,
        evidence,
        citations: citationsToStrings(item.citations),
        fact_origin: factOrigin
    };
}

function validateTechnique(
    value: unknown,
    path: string,
    context: ValidationContext
): StructuredExtractionTechniqueGrounding | null {
    if (!isPlainObject(value)) {
        context.failures.push(buildFailure({
            code: "structured_extraction_technique_invalid",
            category: "schema",
            message: "technique must be an object when present",
            path
        }));
        return null;
    }

    const technique_id = toOptionalString(value.technique_id);
    const technique_ref = toOptionalString(value.technique_ref);
    const technique_name = toOptionalString(value.technique_name);
    const grounded_by = requireString(value.grounded_by, `${path}.grounded_by`, "structured_extraction_technique_grounded_by_invalid", context);
    const confidence = requireProbability(value.confidence, `${path}.confidence`, "structured_extraction_technique_confidence_invalid", context);

    if (!technique_id && !technique_ref && !technique_name) {
        context.failures.push(buildFailure({
            code: "structured_extraction_technique_ungrounded",
            category: "constraint",
            message: "technique requires an explicit identifier, reference, or name",
            path,
            field: "technique"
        }));
    }

    if (!grounded_by.trim()) {
        context.failures.push(buildFailure({
            code: "structured_extraction_technique_grounded_by_empty",
            category: "constraint",
            message: "technique grounded_by must be source-grounded",
            path: `${path}.grounded_by`,
            field: "grounded_by"
        }));
    }

    return {
        technique_id,
        technique_ref,
        technique_name,
        description: toOptionalString(value.description),
        aliases: normalizeStringArray(value.aliases, `${path}.aliases`, context, false),
        kill_chain_phases: normalizeStringArray(value.kill_chain_phases, `${path}.kill_chain_phases`, context, false),
        tags: normalizeStringArray(value.tags, `${path}.tags`, context, false),
        confidence,
        grounded_by
    };
}

function validateTactic(
    value: unknown,
    path: string,
    context: ValidationContext
): { tactic_id?: string, tactic_ref?: string, tactic_name?: string, confidence: number, grounded_by: string } | null {
    if (!isPlainObject(value)) {
        context.failures.push(buildFailure({
            code: "structured_extraction_tactic_invalid",
            category: "schema",
            message: "tactic must be an object when present",
            path
        }));
        return null;
    }

    const tactic_id = toOptionalString(value.tactic_id);
    const tactic_ref = toOptionalString(value.tactic_ref);
    const tactic_name = toOptionalString(value.tactic_name);
    const grounded_by = requireString(value.grounded_by, `${path}.grounded_by`, "structured_extraction_tactic_grounded_by_invalid", context);
    const confidence = requireProbability(value.confidence, `${path}.confidence`, "structured_extraction_tactic_confidence_invalid", context);

    if (!tactic_id && !tactic_ref && !tactic_name) {
        context.failures.push(buildFailure({
            code: "structured_extraction_tactic_ungrounded",
            category: "constraint",
            message: "tactic requires an explicit identifier, reference, or name",
            path,
            field: "tactic"
        }));
    }

    return {
        tactic_id,
        tactic_ref,
        tactic_name,
        confidence,
        grounded_by
    };
}

function validateAttackConditions(
    value: unknown,
    context: ValidationContext
): StructuredExtractionAttackConditionNode[] | undefined {
    if (value === undefined) {
        return undefined;
    }
    if (!Array.isArray(value)) {
        context.failures.push(buildFailure({
            code: "structured_extraction_attack_conditions_invalid",
            category: "schema",
            message: "attack_conditions must be an array when present",
            path: "attack_conditions",
            field: "attack_conditions"
        }));
        return undefined;
    }

    return value.map((item, index) => validateAttackCondition(item, index, context)).filter(Boolean) as StructuredExtractionAttackConditionNode[];
}

function validateAttackCondition(
    item: unknown,
    index: number,
    context: ValidationContext
): StructuredExtractionAttackConditionNode | null {
    if (!isPlainObject(item)) {
        context.failures.push(buildFailure({
            code: "structured_extraction_attack_condition_invalid",
            category: "schema",
            message: "attack_conditions items must be objects",
            path: `attack_conditions[${index}]`
        }));
        return null;
    }

    const path = `attack_conditions[${index}]`;
    const id = requireString(item.id, `${path}.id`, "structured_extraction_attack_condition_id_invalid", context);
    const type = requireLiteral(item.type, `${path}.type`, "attack-condition", "structured_extraction_attack_condition_type_invalid", context);
    const specVersion = requireLiteral(item.spec_version, `${path}.spec_version`, "2.1", "structured_extraction_attack_condition_spec_version_invalid", context);
    const description = requireString(item.description, `${path}.description`, "structured_extraction_attack_condition_description_invalid", context);
    const value = requireLiteral(item.value, `${path}.value`, STRUCTURED_EXTRACTION_RESULT_CONDITION_VALUES, "structured_extraction_attack_condition_value_invalid", context);
    const confidence = requireProbability(item.confidence, `${path}.confidence`, "structured_extraction_attack_condition_confidence_invalid", context);

    const evidence = validateEvidence(item.evidence, `${path}.evidence`, context, true);
    validateCitations(item.citations, `${path}.citations`, context);
    const onTrueRefs = normalizeStringArray(item.on_true_refs, `${path}.on_true_refs`, context, false);
    const onFalseRefs = normalizeStringArray(item.on_false_refs, `${path}.on_false_refs`, context, false);
    const factOrigin = requireFactOrigin(item.fact_origin, `${path}.fact_origin`, context);

    validateEvidenceRequired(description, evidence, `${path}.description`, "structured_extraction_attack_condition_description_not_verbatim", context);

    if (onTrueRefs.length === 0 && onFalseRefs.length === 0) {
        context.failures.push(buildFailure({
            code: "structured_extraction_attack_condition_missing_branch_refs",
            category: "constraint",
            message: "attack-condition must reference at least one branch",
            path,
            field: "on_true_refs"
        }));
    }

    return {
        id,
        type,
        spec_version: specVersion,
        description,
        value,
        confidence,
        on_true_refs: onTrueRefs.length ? onTrueRefs : undefined,
        on_false_refs: onFalseRefs.length ? onFalseRefs : undefined,
        evidence,
        citations: citationsToStrings(item.citations),
        fact_origin: factOrigin
    };
}

function validateAttackOperators(
    value: unknown,
    context: ValidationContext
): StructuredExtractionAttackOperatorNode[] | undefined {
    if (value === undefined) {
        return undefined;
    }
    if (!Array.isArray(value)) {
        context.failures.push(buildFailure({
            code: "structured_extraction_attack_operators_invalid",
            category: "schema",
            message: "attack_operators must be an array when present",
            path: "attack_operators",
            field: "attack_operators"
        }));
        return undefined;
    }

    return value.map((item, index) => validateAttackOperator(item, index, context)).filter(Boolean) as StructuredExtractionAttackOperatorNode[];
}

function validateAttackOperator(
    item: unknown,
    index: number,
    context: ValidationContext
): StructuredExtractionAttackOperatorNode | null {
    if (!isPlainObject(item)) {
        context.failures.push(buildFailure({
            code: "structured_extraction_attack_operator_invalid",
            category: "schema",
            message: "attack_operators items must be objects",
            path: `attack_operators[${index}]`
        }));
        return null;
    }

    const path = `attack_operators[${index}]`;
    const id = requireString(item.id, `${path}.id`, "structured_extraction_attack_operator_id_invalid", context);
    const type = requireLiteral(item.type, `${path}.type`, "attack-operator", "structured_extraction_attack_operator_type_invalid", context);
    const specVersion = requireLiteral(item.spec_version, `${path}.spec_version`, "2.1", "structured_extraction_attack_operator_spec_version_invalid", context);
    const operator = requireLiteral(item.operator, `${path}.operator`, STRUCTURED_EXTRACTION_RESULT_OPERATOR_VALUES, "structured_extraction_attack_operator_value_invalid", context);
    const confidence = requireProbability(item.confidence, `${path}.confidence`, "structured_extraction_attack_operator_confidence_invalid", context);
    const evidence = validateEvidence(item.evidence, `${path}.evidence`, context, true);
    validateCitations(item.citations, `${path}.citations`, context);
    const effectRefs = normalizeStringArray(item.effect_refs, `${path}.effect_refs`, context, false);
    const factOrigin = requireFactOrigin(item.fact_origin, `${path}.fact_origin`, context);

    if (effectRefs.length === 0) {
        context.failures.push(buildFailure({
            code: "structured_extraction_attack_operator_missing_effect_refs",
            category: "constraint",
            message: "attack-operator must reference at least one effect",
            path,
            field: "effect_refs"
        }));
    }

    return {
        id,
        type,
        spec_version: specVersion,
        operator,
        confidence,
        effect_refs: effectRefs.length ? effectRefs : undefined,
        evidence,
        citations: citationsToStrings(item.citations),
        fact_origin: factOrigin
    };
}

function validateAttackAssets(
    value: unknown,
    context: ValidationContext
): StructuredExtractionAttackAssetNode[] | undefined {
    if (value === undefined) {
        return undefined;
    }
    if (!Array.isArray(value)) {
        context.failures.push(buildFailure({
            code: "structured_extraction_attack_assets_invalid",
            category: "schema",
            message: "attack_assets must be an array when present",
            path: "attack_assets",
            field: "attack_assets"
        }));
        return undefined;
    }

    return value.map((item, index) => validateAttackAsset(item, index, context)).filter(Boolean) as StructuredExtractionAttackAssetNode[];
}

function validateAttackAsset(
    item: unknown,
    index: number,
    context: ValidationContext
): StructuredExtractionAttackAssetNode | null {
    if (!isPlainObject(item)) {
        context.failures.push(buildFailure({
            code: "structured_extraction_attack_asset_invalid",
            category: "schema",
            message: "attack_assets items must be objects",
            path: `attack_assets[${index}]`
        }));
        return null;
    }

    const path = `attack_assets[${index}]`;
    const id = requireString(item.id, `${path}.id`, "structured_extraction_attack_asset_id_invalid", context);
    const type = requireLiteral(item.type, `${path}.type`, "attack-asset", "structured_extraction_attack_asset_type_invalid", context);
    const specVersion = requireLiteral(item.spec_version, `${path}.spec_version`, "2.1", "structured_extraction_attack_asset_spec_version_invalid", context);
    const name = requireString(item.name, `${path}.name`, "structured_extraction_attack_asset_name_invalid", context);
    const confidence = requireProbability(item.confidence, `${path}.confidence`, "structured_extraction_attack_asset_confidence_invalid", context);
    const evidence = validateEvidence(item.evidence, `${path}.evidence`, context, false);
    const factOrigin = requireFactOrigin(item.fact_origin, `${path}.fact_origin`, context);

    const description = toOptionalString(item.description);
    if (description) {
        if (evidence.length === 0) {
            context.failures.push(buildFailure({
                code: "structured_extraction_attack_asset_description_not_verbatim",
                category: "constraint",
                message: "attack-asset description must be grounded by evidence",
                path: `${path}.description`,
                field: "description"
            }));
        } else if (!evidence.some(entry => entry.excerpt === description)) {
            context.failures.push(buildFailure({
                code: "structured_extraction_attack_asset_description_not_verbatim",
                category: "constraint",
                message: "attack-asset description must be a verbatim source excerpt",
                path: `${path}.description`,
                field: "description"
            }));
        }
    }

    const object_ref = item.object_ref === null
        ? null
        : item.object_ref === undefined
            ? undefined
            : requireString(item.object_ref, `${path}.object_ref`, "structured_extraction_attack_asset_object_ref_invalid", context);
    const tags = normalizeAttackAssetTags(item.tags, `${path}.tags`, context);

    return {
        id,
        type,
        spec_version: specVersion,
        name,
        description,
        tags,
        object_ref,
        evidence,
        confidence,
        fact_origin: factOrigin
    };
}

function normalizeAttackAssetTags(
    value: unknown,
    path: string,
    context: ValidationContext
): Record<string, boolean> | undefined {
    if (isPlainObject(value)) {
        return value as Record<string, boolean>;
    }
    if (Array.isArray(value) && value.every(tag => typeof tag === "string")) {
        return Object.fromEntries(value.map(tag => [tag, true]));
    }
    if (value !== null && value !== undefined) {
        context.failures.push(buildFailure({
            code: "structured_extraction_attack_asset_tags_invalid",
            category: "schema",
            message: "attack_asset tags must be an array, object, or null",
            path,
            field: "tags"
        }));
    }
    return undefined;
}

function validateEvidence(
    value: unknown,
    path: string,
    context: ValidationContext,
    requireAtLeastOne: boolean
): StructuredExtractionEvidenceCitation[] {
    if (value === undefined) {
        if (requireAtLeastOne) {
            context.failures.push(buildFailure({
                code: "structured_extraction_evidence_missing",
                category: "constraint",
                message: "evidence is required",
                path,
                field: path.split(".").pop()
            }));
        }
        return [];
    }

    if (!Array.isArray(value)) {
        context.failures.push(buildFailure({
            code: "structured_extraction_evidence_invalid",
            category: "schema",
            message: "evidence must be an array when present",
            path,
            field: path.split(".").pop()
        }));
        return [];
    }

    const evidence: StructuredExtractionEvidenceCitation[] = [];
    for (const [index, item] of value.entries()) {
        if (!isPlainObject(item)) {
            context.failures.push(buildFailure({
                code: "structured_extraction_evidence_item_invalid",
                category: "schema",
                message: "evidence items must be objects",
                path: `${path}[${index}]`
            }));
            continue;
        }

        const source = requireString(item.source, `${path}[${index}].source`, "structured_extraction_evidence_source_invalid", context);
        const excerpt = requireString(item.excerpt, `${path}[${index}].excerpt`, "structured_extraction_evidence_excerpt_invalid", context);
        const citation = item.citation === undefined || item.citation === null ? undefined : requireString(item.citation, `${path}[${index}].citation`, "structured_extraction_evidence_citation_invalid", context);
        const source_object_id = item.source_object_id === undefined || item.source_object_id === null ? undefined : requireString(item.source_object_id, `${path}[${index}].source_object_id`, "structured_extraction_evidence_source_object_id_invalid", context);
        const source_field = item.source_field === undefined || item.source_field === null ? undefined : requireString(item.source_field, `${path}[${index}].source_field`, "structured_extraction_evidence_source_field_invalid", context);

        if (!source || !excerpt) {
            continue;
        }

        evidence.push({
            source,
            excerpt,
            citation,
            source_object_id,
            source_field
        });
    }

    if (requireAtLeastOne && evidence.length === 0) {
        context.failures.push(buildFailure({
            code: "structured_extraction_evidence_missing",
            category: "constraint",
            message: "evidence is required",
            path,
            field: path.split(".").pop()
        }));
    }

    return evidence;
}

function validateCitations(value: unknown, path: string, context: ValidationContext) {
    if (value === undefined) {
        return;
    }
    if (!Array.isArray(value)) {
        context.failures.push(buildFailure({
            code: "structured_extraction_citations_invalid",
            category: "schema",
            message: "citations must be an array when present",
            path,
            field: path.split(".").pop()
        }));
        return;
    }

    for (const [index, item] of value.entries()) {
        if (typeof item !== "string") {
            context.failures.push(buildFailure({
                code: "structured_extraction_citations_item_invalid",
                category: "schema",
                message: "citations items must be strings",
                path: `${path}[${index}]`
            }));
        }
    }
}

function validateEvidenceRequired(
    description: string | undefined,
    evidence: StructuredExtractionEvidenceCitation[],
    path: string,
    code: string,
    context: ValidationContext
) {
    if (!description) {
        return;
    }
    if (evidence.length === 0) {
        context.failures.push(buildFailure({
            code,
            category: "constraint",
            message: "description must be grounded by evidence",
            path,
            field: path.split(".").pop()
        }));
        return;
    }
    if (!evidence.some(entry => entry.excerpt === description)) {
        context.failures.push(buildFailure({
            code,
            category: "constraint",
            message: "description must exactly match a verbatim source excerpt",
            path,
            field: path.split(".").pop()
        }));
    }
}

function validateStructuredJsonArray(
    value: unknown,
    path: string,
    context: ValidationContext
) {
    if (value === undefined) {
        return;
    }
    if (!Array.isArray(value)) {
        context.failures.push(buildFailure({
            code: `${path}_invalid`,
            category: "schema",
            message: `${path} must be an array when present`,
            path,
            field: path
        }));
        return;
    }
    for (const [index, item] of value.entries()) {
        if (!isPlainObject(item)) {
            context.failures.push(buildFailure({
                code: `${path}_item_invalid`,
                category: "schema",
                message: `${path} items must be objects`,
                path: `${path}[${index}]`
            }));
        }
    }
}

function validateDeterministicEntities(value: unknown, context: ValidationContext): Set<string> {
    validateStructuredJsonArray(value, "deterministic_entities", context);
    const ids = new Set<string>();
    if (!Array.isArray(value)) {
        return ids;
    }
    for (const [index, item] of value.entries()) {
        if (!isPlainObject(item)) {
            continue;
        }
        const path = `deterministic_entities[${index}]`;
        const id = requireString(item.object_id ?? item.id, `${path}.object_id`, "structured_extraction_deterministic_entity_id_invalid", context);
        requireString(item.object_type ?? item.type, `${path}.object_type`, "structured_extraction_deterministic_entity_type_invalid", context);
        if (id && ids.has(id)) {
            context.failures.push(buildFailure({
                code: "structured_extraction_deterministic_entity_id_duplicate",
                category: "constraint",
                message: `duplicate deterministic entity id '${id}'`,
                path: `${path}.object_id`,
                field: "object_id"
            }));
        }
        if (id) {
            ids.add(id);
        }
    }
    return ids;
}

function validateDeterministicRelationships(
    value: unknown,
    entityIds: Set<string>,
    context: ValidationContext
): void {
    validateStructuredJsonArray(value, "deterministic_relationships", context);
    if (!Array.isArray(value)) {
        return;
    }
    for (const [index, item] of value.entries()) {
        if (!isPlainObject(item)) {
            continue;
        }
        const path = `deterministic_relationships[${index}]`;
        requireString(item.relationship_type, `${path}.relationship_type`, "structured_extraction_deterministic_relationship_type_invalid", context);
        const sourceRef = requireString(item.source_ref, `${path}.source_ref`, "structured_extraction_deterministic_relationship_source_invalid", context);
        const targetRef = requireString(item.target_ref, `${path}.target_ref`, "structured_extraction_deterministic_relationship_target_invalid", context);
        validateResolvedReference(sourceRef, entityIds, `${path}.source_ref`, context);
        validateResolvedReference(targetRef, entityIds, `${path}.target_ref`, context);
    }
}

function validateExtractionReferences(
    actions: StructuredExtractionAttackActionNode[],
    assets: StructuredExtractionAttackAssetNode[],
    entityIds: Set<string>,
    context: ValidationContext
): void {
    const assetIds = new Set(assets.map(asset => asset.id));
    for (const [index, action] of actions.entries()) {
        for (const ref of action.asset_refs ?? []) {
            validateResolvedReference(ref, assetIds, `attack_actions[${index}].asset_refs`, context);
        }
        for (const ref of action.object_refs ?? []) {
            validateResolvedReference(ref, entityIds, `attack_actions[${index}].object_refs`, context);
        }
    }
    for (const [index, asset] of assets.entries()) {
        if (asset.object_ref) {
            validateResolvedReference(asset.object_ref, entityIds, `attack_assets[${index}].object_ref`, context);
        }
    }
}

function validateResolvedReference(
    ref: string,
    knownIds: Set<string>,
    path: string,
    context: ValidationContext
): void {
    if (ref && !knownIds.has(ref)) {
        context.failures.push(buildFailure({
            code: "structured_extraction_reference_unresolved",
            category: "constraint",
            message: `reference '${ref}' does not resolve to an emitted object`,
            path,
            field: path.split(".").pop()
        }));
    }
}

function normalizeStructuredJsonArray(value: unknown): StructuredJsonValue[] | undefined {
    if (!Array.isArray(value)) {
        return undefined;
    }
    return value as StructuredJsonValue[];
}

function classifyValidationStatus(
    failures: StructuredExtractionValidationFailure[]
): StructuredExtractionValidationStatus {
    if (failures.length === 0) {
        return "valid";
    }

    const categories = new Set(failures.map(failure => failure.category));
    const hasConstraint = categories.has("constraint");
    const hasSchemaOrParse = categories.has("schema") || categories.has("parse");

    if (hasConstraint && hasSchemaOrParse) {
        return "unrecoverable";
    }

    if (hasConstraint) {
        return "invalid";
    }

    return "repairable";
}

function buildValidationResult(
    status: StructuredExtractionValidationStatus,
    failures: StructuredExtractionValidationFailure[],
    result?: StructuredExtractionResult,
    repairAttempted = false
): StructuredExtractionValidationResult {
    const message = failures.length > 0 ? failures[0].message : undefined;

    if (status === "valid" && result !== undefined) {
        return {
            status,
            repairAttempted,
            failures: [],
            result
        };
    }

    return {
        status,
        repairAttempted,
        failures,
        message,
        result
    } as StructuredExtractionValidationResult;
}

function buildFailure(params: {
    code: string;
    category: StructuredExtractionValidationFailure["category"];
    message: string;
    path?: string;
    field?: string;
    details?: Record<string, string>;
}): StructuredExtractionValidationFailure {
    return {
        code: params.code,
        category: params.category,
        message: params.message,
        path: params.path,
        field: params.field,
        repairAttempted: false,
        details: params.details
    };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireString(
    value: unknown,
    path: string,
    code: string,
    context: ValidationContext
): string {
    if (typeof value === "string" && value.length > 0) {
        return value;
    }

    context.failures.push(buildFailure({
        code,
        category: "schema",
        message: `${path} must be a non-empty string`,
        path,
        field: path.split(".").pop()
    }));
    return "";
}

function requireLiteral<T extends string>(
    value: unknown,
    path: string,
    expected: T,
    code: string,
    context: ValidationContext
): T;
function requireLiteral<T extends readonly string[]>(
    value: unknown,
    path: string,
    expected: T,
    code: string,
    context: ValidationContext
): T[number];
function requireLiteral(
    value: unknown,
    path: string,
    expected: string | readonly string[],
    code: string,
    context: ValidationContext
): string {
    if (typeof value !== "string" || value.length === 0) {
        context.failures.push(buildFailure({
            code,
            category: "schema",
            message: `${path} must be a non-empty string`,
            path,
            field: path.split(".").pop()
        }));
        return "";
    }

    if (Array.isArray(expected)) {
        if (!expected.includes(value as never)) {
            context.failures.push(buildFailure({
                code,
                category: "constraint",
                message: `${path} must be one of ${expected.join(", ")}`,
                path,
                field: path.split(".").pop()
            }));
        }
    } else if (value !== expected) {
        context.failures.push(buildFailure({
            code,
            category: "schema",
            message: `${path} must equal ${expected}`,
            path,
            field: path.split(".").pop()
        }));
    }

    return value;
}

function requireProbability(
    value: unknown,
    path: string,
    code: string,
    context: ValidationContext
): number {
    if (typeof value === "number" && Number.isFinite(value) && 0 <= value && value <= 1) {
        return value;
    }

    context.failures.push(buildFailure({
        code,
        category: "schema",
        message: `${path} must be a number between 0 and 1`,
        path,
        field: path.split(".").pop()
    }));
    return 0;
}

function requireFactOrigin(
    value: unknown,
    path: string,
    context: ValidationContext
): "deterministic_source" | "ai_generated" {
    if (value === undefined || value === null) {
        return "ai_generated";
    }

    if (value === "deterministic_source" || value === "ai_generated") {
        return value;
    }

    context.failures.push(buildFailure({
        code: "structured_extraction_fact_origin_invalid",
        category: "schema",
        message: `${path} must be deterministic_source or ai_generated`,
        path,
        field: path.split(".").pop()
    }));
    return "ai_generated";
}

function normalizeStringArray(
    value: unknown,
    path: string,
    context: ValidationContext,
    allowEmpty = false
): string[] {
    if (value === undefined || value === null) {
        return [];
    }
    if (!Array.isArray(value)) {
        context.failures.push(buildFailure({
            code: `${path}_invalid`,
            category: "schema",
            message: `${path} must be an array of strings`,
            path,
            field: path.split(".").pop()
        }));
        return [];
    }

    const out: string[] = [];
    for (const [index, item] of value.entries()) {
        if (typeof item !== "string") {
            context.failures.push(buildFailure({
                code: `${path}_item_invalid`,
                category: "schema",
                message: `${path}[${index}] must be a string`,
                path: `${path}[${index}]`
            }));
            continue;
        }
        const candidate = item.trim();
        if (candidate || allowEmpty) {
            out.push(candidate);
        }
    }
    return out;
}

function citationsToStrings(value: unknown): string[] {
    if (!Array.isArray(value)) {
        return [];
    }
    return value.filter((item): item is string => typeof item === "string");
}

function toOptionalString(value: unknown): string | undefined {
    return typeof value === "string" && value.length > 0 ? value : undefined;
}
