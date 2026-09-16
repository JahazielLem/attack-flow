import type { StructuredResponseFormat } from "../Providers";
import type {
    InputNormalizedContentStats,
    InputNormalizedMetadata,
    InputNormalizedSourceType,
    InputNormalizedTruncation,
    NormalizedInputPackage
} from "../InputNormalization";

export const DIRECT_PROVIDER_ORCHESTRATION_MODES = ["direct_provider"] as const;

export type DirectProviderOrchestrationMode = typeof DIRECT_PROVIDER_ORCHESTRATION_MODES[number];

export const DIRECT_PROVIDER_ALLOWED_OPERATOR_VALUES = ["AND", "OR"] as const;

export const DIRECT_PROVIDER_ALLOWED_CONDITION_VALUES = ["true", "false"] as const;

export const DIRECT_PROVIDER_REQUEST_MODEL_VERSION = "v1" as const;

/**
 * Deterministic system-instruction payload used by Direct Provider Mode.
 * Prompt text is not rendered here; only the structured instruction contract
 * is defined for later assembly.
 */
export interface DirectProviderSystemInstructionModel {
    version: typeof DIRECT_PROVIDER_REQUEST_MODEL_VERSION;
    constraints: DirectProviderPromptConstraints;
}

/**
 * Constraint flags that will be encoded into the prompt at a later stage.
 */
export interface DirectProviderPromptConstraints {
    allowProcedureInference: true;
    explicitAttackRefsOnly: false;
    requireTechniqueForEveryAction: true;
    requireTacticForAttackTechnique: true;
    supportedFrameworksOnly: true;
    consolidateSameTechniqueSubsteps: true;
    separateToolSetupOnlyForDistinctTechnique: true;
    keepSourceDistinctActionsSeparate: true;
    useSpecificStixEntityTypes: true;
    preserveDefangedObservableValues: true;
    useAttackTechniqueTables: true;
    modelMultipleOutcomesWithOperators: true;
    modelExplicitPrerequisitesAndStateChangesAsConditions: true;
    connectConditionTruePaths: true;
    useExactEmittedIdsForConditionReferences: true;
    preserveDocumentedSplitsAndJoins: true;
    descriptionsMustBeVerbatimExcerpts: true;
    onlyAndOrOperators: true;
    onlyTrueFalseConditions: true;
    noInferredBranching: true;
    outputMustFitPinnedIntermediateShape: true;
}

/**
 * Normalized source payload consumed by the prompt/orchestration builder.
 */
export interface DirectProviderInputPayload {
    sourceType: InputNormalizedSourceType;
    normalizedText: string;
    metadata: InputNormalizedMetadata;
    contentStats?: InputNormalizedContentStats;
    truncation?: InputNormalizedTruncation;
    structuredSummary?: Record<string, unknown>;
    deterministicAttackRefs?: Record<string, unknown>[];
    deterministicEntities?: Record<string, unknown>[];
    deterministicRelationships?: Record<string, unknown>[];
    provenance?: Record<string, unknown>;
}

/**
 * Declarative response-shape expectation for the downstream provider call.
 */
export interface DirectProviderResponseSchemaExpectation {
    format: StructuredResponseFormat;
    schemaName?: string;
}

/**
 * Provider-agnostic structured generation request payload for Direct Provider Mode.
 */
export interface DirectProviderStructuredGenerationRequestModel {
    version: typeof DIRECT_PROVIDER_REQUEST_MODEL_VERSION;
    mode: DirectProviderOrchestrationMode;
    sourceType: InputNormalizedSourceType;
    promptMode?: "full_extraction" | "enrichment";
    promptSourceType?: string;
    systemInstructions: DirectProviderSystemInstructionModel;
    input: DirectProviderInputPayload;
    responseSchema?: DirectProviderResponseSchemaExpectation;
    modelOverride?: string;
    metadata?: Record<string, string>;
}

/**
 * Snapshot of the normalized input package in request-model form.
 */
export type DirectProviderNormalizedInputSnapshot = Pick<
    NormalizedInputPackage,
    "sourceType" | "normalizedText" | "metadata" | "contentStats" | "truncation"
>;
