import {
    DIRECT_PROVIDER_AFB_INTERMEDIATE_SCHEMA_NAME,
    DIRECT_PROVIDER_AFB_INTERMEDIATE_VERSION,
    DIRECT_PROVIDER_AFB_INTERMEDIATE_CONDITION_VALUES,
    DIRECT_PROVIDER_AFB_INTERMEDIATE_OPERATOR_VALUES
} from "./DirectProviderAfbIntermediateShape";
import {
    DIRECT_PROVIDER_REQUEST_MODEL_VERSION,
    type DirectProviderPromptConstraints,
    type DirectProviderSystemInstructionModel
} from "./DirectProviderRequestModels";
import { DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT } from "./DirectProviderPromptTemplates";

export { DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT } from "./DirectProviderPromptTemplates";

export interface DirectProviderSystemInstructionBundle {
    version: typeof DIRECT_PROVIDER_REQUEST_MODEL_VERSION;
    schemaName: typeof DIRECT_PROVIDER_AFB_INTERMEDIATE_SCHEMA_NAME;
    systemInstructions: DirectProviderSystemInstructionModel;
    text: string;
    allowedOperatorValues: readonly typeof DIRECT_PROVIDER_AFB_INTERMEDIATE_OPERATOR_VALUES[number][];
    allowedConditionValues: readonly typeof DIRECT_PROVIDER_AFB_INTERMEDIATE_CONDITION_VALUES[number][];
}

/**
 * Builds the deterministic instruction bundle used to encode the hard
 * extraction constraints for Direct Provider Mode.
 */
export function buildDirectProviderSystemInstructionBundle(): DirectProviderSystemInstructionBundle {
    return {
        version: DIRECT_PROVIDER_AFB_INTERMEDIATE_VERSION,
        schemaName: DIRECT_PROVIDER_AFB_INTERMEDIATE_SCHEMA_NAME,
        systemInstructions: buildDirectProviderSystemInstructionModel(),
        text: DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT,
        allowedOperatorValues: DIRECT_PROVIDER_AFB_INTERMEDIATE_OPERATOR_VALUES,
        allowedConditionValues: DIRECT_PROVIDER_AFB_INTERMEDIATE_CONDITION_VALUES
    };
}

/**
 * Returns the stable system instruction text for the AFA-95 request path.
 */
export function buildDirectProviderSystemInstructionModel(): DirectProviderSystemInstructionModel {
    return {
        version: DIRECT_PROVIDER_REQUEST_MODEL_VERSION,
        constraints: buildDirectProviderPromptConstraints()
    };
}

/**
 * Returns the exact system instruction text used by the request builder.
 */
export function buildDirectProviderSystemInstructionText(): string {
    return DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT;
}

/**
 * Returns the hard constraint flags mirrored by the system instructions.
 */
export function buildDirectProviderPromptConstraints(): DirectProviderPromptConstraints {
    return {
        allowProcedureInference: true,
        explicitAttackRefsOnly: false,
        requireTechniqueForEveryAction: true,
        requireTacticForAttackTechnique: true,
        supportedFrameworksOnly: true,
        consolidateSameTechniqueSubsteps: true,
        separateToolSetupOnlyForDistinctTechnique: true,
        keepSourceDistinctActionsSeparate: true,
        useSpecificStixEntityTypes: true,
        preserveDefangedObservableValues: true,
        useAttackTechniqueTables: true,
        modelMultipleOutcomesWithOperators: true,
        modelExplicitPrerequisitesAndStateChangesAsConditions: true,
        connectConditionTruePaths: true,
        useExactEmittedIdsForConditionReferences: true,
        preserveDocumentedSplitsAndJoins: true,
        descriptionsMustBeVerbatimExcerpts: true,
        onlyAndOrOperators: true,
        onlyTrueFalseConditions: true,
        noInferredBranching: true,
        outputMustFitPinnedIntermediateShape: true
    };
}
