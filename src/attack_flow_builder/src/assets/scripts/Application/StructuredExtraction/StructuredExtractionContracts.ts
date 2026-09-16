import type { StructuredJsonValue } from "../Providers";

export const STRUCTURED_EXTRACTION_RESULT_SCHEMA_VERSION = "afb-v2-intermediate" as const;

export const STRUCTURED_EXTRACTION_RESULT_OBJECT_TYPES = [
    "attack-flow",
    "attack-action",
    "attack-condition",
    "attack-operator",
    "attack-asset"
] as const;

export const STRUCTURED_EXTRACTION_RESULT_OPERATOR_VALUES = ["AND", "OR"] as const;

export const STRUCTURED_EXTRACTION_RESULT_CONDITION_VALUES = ["true", "false"] as const;

export const STRUCTURED_EXTRACTION_RESULT_VALIDATION_STATES = [
    "valid",
    "invalid",
    "repaired"
] as const;

/**
 * Evidence and citation metadata preserved in the structured extraction result.
 */
export interface StructuredExtractionEvidenceCitation {
    source: string;
    excerpt: string;
    citation?: string;
    source_object_id?: string;
    source_field?: string;
}

/**
 * Technique grounding is intentionally explicit and source-grounded only.
 */
export interface StructuredExtractionTechniqueGrounding {
    technique_id?: string;
    technique_ref?: string;
    technique_name?: string;
    description?: string;
    aliases?: string[];
    kill_chain_phases?: string[];
    tags?: string[];
    confidence: number;
    grounded_by: string;
}

/**
 * Attack flow metadata included in the intermediate extraction result.
 */
export interface StructuredExtractionAttackFlowMetadata {
    id: string;
    type: "attack-flow";
    spec_version: "2.1";
    name: string;
    scope: string;
    start_refs?: string[];
    description?: string;
    orchestration_mode: string;
    source_classification: string;
    authors?: string[];
    external_references?: string[];
    provenance?: Record<string, unknown>;
}

/**
 * Intermediate attack-action node returned by the model.
 */
export interface StructuredExtractionAttackActionNode {
    id: string;
    type: "attack-action";
    spec_version: "2.1";
    name: string;
    description: string;
    confidence: number;
    technique?: StructuredExtractionTechniqueGrounding | null;
    tactic?: {
        tactic_id?: string;
        tactic_ref?: string;
        tactic_name?: string;
        confidence: number;
        grounded_by: string;
    } | null;
    asset_refs?: string[];
    object_refs?: string[];
    effect_refs?: string[];
    evidence?: StructuredExtractionEvidenceCitation[];
    citations?: string[];
    fact_origin?: "deterministic_source" | "ai_generated";
}

/**
 * Intermediate attack-condition node returned by the model.
 */
export interface StructuredExtractionAttackConditionNode {
    id: string;
    type: "attack-condition";
    spec_version: "2.1";
    description: string;
    value: typeof STRUCTURED_EXTRACTION_RESULT_CONDITION_VALUES[number];
    confidence: number;
    on_true_refs?: string[];
    on_false_refs?: string[];
    evidence?: StructuredExtractionEvidenceCitation[];
    citations?: string[];
    fact_origin?: "deterministic_source" | "ai_generated";
}

/**
 * Intermediate attack-operator node returned by the model.
 */
export interface StructuredExtractionAttackOperatorNode {
    id: string;
    type: "attack-operator";
    spec_version: "2.1";
    operator: typeof STRUCTURED_EXTRACTION_RESULT_OPERATOR_VALUES[number];
    confidence: number;
    effect_refs?: string[];
    evidence?: StructuredExtractionEvidenceCitation[];
    citations?: string[];
    fact_origin?: "deterministic_source" | "ai_generated";
}

/**
 * Intermediate attack-asset node returned by the model.
 */
export interface StructuredExtractionAttackAssetNode {
    id: string;
    type: "attack-asset";
    spec_version: "2.1";
    name: string;
    description?: string;
    tags?: Record<string, boolean> | null;
    object_ref?: string | null;
    evidence?: StructuredExtractionEvidenceCitation[];
    confidence: number;
    fact_origin?: "deterministic_source" | "ai_generated";
}

export type StructuredExtractionIntermediateNode =
    | StructuredExtractionAttackActionNode
    | StructuredExtractionAttackConditionNode
    | StructuredExtractionAttackOperatorNode
    | StructuredExtractionAttackAssetNode;

/**
 * Structured extraction result shape validated client-side before any later
 * mapping/export step.
 */
export interface StructuredExtractionResult {
    schema_version: typeof STRUCTURED_EXTRACTION_RESULT_SCHEMA_VERSION;
    validation_state: typeof STRUCTURED_EXTRACTION_RESULT_VALIDATION_STATES[number];
    repair_attempted: boolean;
    provider_invoked: boolean;
    provider_id?: string | null;
    model?: string | null;
    attack_flow: StructuredExtractionAttackFlowMetadata;
    attack_actions?: StructuredExtractionAttackActionNode[];
    attack_conditions?: StructuredExtractionAttackConditionNode[];
    attack_operators?: StructuredExtractionAttackOperatorNode[];
    attack_assets?: StructuredExtractionAttackAssetNode[];
    deterministic_attack_refs?: StructuredJsonValue[];
    deterministic_entities?: StructuredJsonValue[];
    deterministic_relationships?: StructuredJsonValue[];
}
