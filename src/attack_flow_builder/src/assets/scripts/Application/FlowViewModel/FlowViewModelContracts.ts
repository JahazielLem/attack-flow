export const FLOW_VIEW_MODEL_VERSION = "v1" as const;

export const FLOW_VIEW_MODEL_NODE_TYPES = [
    "attack-flow",
    "attack-action",
    "attack-condition",
    "attack-operator",
    "attack-asset"
] as const;

export const FLOW_VIEW_MODEL_EDGE_RELATIONS = [
    "start",
    "effect",
    "true",
    "false",
    "attachment"
] as const;

export type FlowViewModelNodeType = typeof FLOW_VIEW_MODEL_NODE_TYPES[number];

export type FlowViewModelEdgeRelation = typeof FLOW_VIEW_MODEL_EDGE_RELATIONS[number];

export interface FlowViewModelRoot {
    id: string;
    type: "attack-flow";
    spec_version: "2.1";
    name: string;
    description?: string;
    scope: string;
    start_refs?: string[];
    orchestration_mode: string;
    source_classification: string;
    authors?: string[];
    external_references?: string[];
}

export interface FlowViewModelNodeBase {
    id: string;
    type: FlowViewModelNodeType;
    spec_version: "2.1";
}

export interface FlowViewModelAttackAction extends FlowViewModelNodeBase {
    type: "attack-action";
    name: string;
    description: string;
    confidence: number;
    technique_id?: string;
    technique_ref?: string;
    tactic_id?: string;
    tactic_ref?: string;
    asset_refs?: string[];
    effect_refs?: string[];
    fact_origin?: "deterministic_source" | "ai_generated";
}

export interface FlowViewModelAttackCondition extends FlowViewModelNodeBase {
    type: "attack-condition";
    description: string;
    value: "true" | "false";
    confidence: number;
    on_true_refs?: string[];
    on_false_refs?: string[];
    fact_origin?: "deterministic_source" | "ai_generated";
}

export interface FlowViewModelAttackOperator extends FlowViewModelNodeBase {
    type: "attack-operator";
    operator: "AND" | "OR";
    confidence: number;
    effect_refs?: string[];
    fact_origin?: "deterministic_source" | "ai_generated";
}

export interface FlowViewModelAttackAsset extends FlowViewModelNodeBase {
    type: "attack-asset";
    name: string;
    description?: string;
    tags?: Record<string, boolean> | null;
    object_ref?: string | null;
    confidence: number;
    fact_origin?: "deterministic_source" | "ai_generated";
}

export type FlowViewModelNode =
    | FlowViewModelAttackAction
    | FlowViewModelAttackCondition
    | FlowViewModelAttackOperator
    | FlowViewModelAttackAsset;

export interface FlowViewModelEdge {
    id: string;
    source: string;
    target: string;
    relation: FlowViewModelEdgeRelation;
}

export interface FlowViewModel {
    version: typeof FLOW_VIEW_MODEL_VERSION;
    flow: FlowViewModelRoot;
    nodes: FlowViewModelNode[];
    edges: FlowViewModelEdge[];
}
