import type { StructuredJsonValue } from "../Providers";

export const DIRECT_PROVIDER_AFB_INTERMEDIATE_VERSION = "v1" as const;

export const DIRECT_PROVIDER_AFB_INTERMEDIATE_SCHEMA_NAME = "direct_provider_afb_intermediate" as const;

export const DIRECT_PROVIDER_AFB_INTERMEDIATE_OBJECT_TYPES = [
    "attack-flow",
    "attack-action",
    "attack-condition",
    "attack-operator",
    "attack-asset"
] as const;

export const DIRECT_PROVIDER_AFB_INTERMEDIATE_OPERATOR_VALUES = ["AND", "OR"] as const;

export const DIRECT_PROVIDER_AFB_INTERMEDIATE_CONDITION_VALUES = ["true", "false"] as const;

export const DIRECT_PROVIDER_AFB_INTERMEDIATE_CONFIDENCE_SCALE = [
    "0",
    "10",
    "20",
    "30",
    "40",
    "50",
    "60",
    "70",
    "80",
    "90",
    "100"
] as const;

/**
 * Evidence and citation metadata preserved on intermediate extraction objects.
 */
export interface DirectProviderAfbEvidenceCitation {
    sourceId?: string;
    sourceType?: string;
    page?: number;
    line?: number;
    startOffset?: number;
    endOffset?: number;
    quote?: string;
}

/**
 * External references that remain source-grounded.
 */
export interface DirectProviderAfbExternalReference {
    sourceName?: string;
    externalId?: string;
    url?: string;
}

/**
 * Minimal metadata shape for the intermediate attack-flow object.
 */
export interface DirectProviderAfbAttackFlowMetadata {
    name?: string;
    description?: string;
    authors?: string[];
    externalReferences?: DirectProviderAfbExternalReference[];
    evidence?: DirectProviderAfbEvidenceCitation[];
    confidence?: number;
}

/**
 * Shared intermediate node fields used by all attack-flow objects.
 */
export interface DirectProviderAfbIntermediateNodeBase {
    id?: string;
    type: typeof DIRECT_PROVIDER_AFB_INTERMEDIATE_OBJECT_TYPES[number];
    name?: string;
    description?: string;
    authors?: string[];
    externalReferences?: DirectProviderAfbExternalReference[];
    evidence?: DirectProviderAfbEvidenceCitation[];
    confidence?: number;
}

/**
 * Intermediate attack-action node.
 * Descriptions must remain verbatim source excerpts.
 */
export interface DirectProviderAfbAttackActionNode extends DirectProviderAfbIntermediateNodeBase {
    type: "attack-action";
    techniqueRefs?: string[];
    assetRefs?: string[];
    effectRefs?: string[];
    deterministicEntities?: StructuredJsonValue[];
    deterministicRelationships?: StructuredJsonValue[];
}

/**
 * Intermediate attack-condition node.
 * Conditions are limited to true/false.
 */
export interface DirectProviderAfbAttackConditionNode extends DirectProviderAfbIntermediateNodeBase {
    type: "attack-condition";
    condition?: typeof DIRECT_PROVIDER_AFB_INTERMEDIATE_CONDITION_VALUES[number];
    onTrueRefs?: string[];
    onFalseRefs?: string[];
}

/**
 * Intermediate attack-operator node.
 * Operators are limited to AND/OR.
 */
export interface DirectProviderAfbAttackOperatorNode extends DirectProviderAfbIntermediateNodeBase {
    type: "attack-operator";
    operator?: typeof DIRECT_PROVIDER_AFB_INTERMEDIATE_OPERATOR_VALUES[number];
    effectRefs?: string[];
}

/**
 * Intermediate attack-asset node.
 */
export interface DirectProviderAfbAttackAssetNode extends DirectProviderAfbIntermediateNodeBase {
    type: "attack-asset";
    objectRefs?: string[];
}

export type DirectProviderAfbIntermediateNode =
    | DirectProviderAfbAttackActionNode
    | DirectProviderAfbAttackConditionNode
    | DirectProviderAfbAttackOperatorNode
    | DirectProviderAfbAttackAssetNode;

/**
 * Target intermediate extraction shape for Direct Provider Mode.
 */
export interface DirectProviderAfbIntermediateOutputShape {
    version: typeof DIRECT_PROVIDER_AFB_INTERMEDIATE_VERSION;
    attackFlow?: DirectProviderAfbAttackFlowMetadata;
    attackActions?: DirectProviderAfbAttackActionNode[];
    attackConditions?: DirectProviderAfbAttackConditionNode[];
    attackOperators?: DirectProviderAfbAttackOperatorNode[];
    attackAssets?: DirectProviderAfbAttackAssetNode[];
    authors?: string[];
    externalReferences?: DirectProviderAfbExternalReference[];
    evidence?: DirectProviderAfbEvidenceCitation[];
    confidence?: number;
}
