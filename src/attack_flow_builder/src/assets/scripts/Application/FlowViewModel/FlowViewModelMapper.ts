import type {
    StructuredExtractionAttackActionNode,
    StructuredExtractionAttackAssetNode,
    StructuredExtractionAttackConditionNode,
    StructuredExtractionAttackFlowMetadata,
    StructuredExtractionAttackOperatorNode,
    StructuredExtractionResult
} from "../StructuredExtraction";
import {
    FLOW_VIEW_MODEL_VERSION,
    type FlowViewModel,
    type FlowViewModelAttackAction,
    type FlowViewModelAttackAsset,
    type FlowViewModelAttackCondition,
    type FlowViewModelAttackOperator,
    type FlowViewModelEdge,
    type FlowViewModelNode
} from "./FlowViewModelContracts";

function toTrimmedString(value: string): string {
    return value.trim();
}

function toOptionalVerbatimString(value: string | undefined): string | undefined {
    if (value === undefined) {
        return undefined;
    }

    return value.trim() ? value : undefined;
}

function toOptionalTrimmedString(value: string | undefined): string | undefined {
    const trimmed = value?.trim();
    return trimmed ? trimmed : undefined;
}

function toNormalizedStringList(values: string[] | undefined): string[] | undefined {
    const refs = (values ?? [])
        .map((value) => value.trim())
        .filter(Boolean);

    return refs.length > 0 ? refs : undefined;
}

function filterKnownRefs(values: string[] | undefined, knownIds: Set<string>): string[] | undefined {
    const refs = toNormalizedStringList(values);
    if (!refs) {
        return undefined;
    }

    const filtered = refs.filter((ref) => knownIds.has(ref));
    return filtered.length > 0 ? filtered : undefined;
}

function createEdge(source: string, relation: FlowViewModelEdge["relation"], target: string): FlowViewModelEdge {
    return {
        id: `${source}--${relation}--${target}`,
        source,
        target,
        relation
    };
}

function pushEdgesFromRefs(
    edges: Map<string, FlowViewModelEdge>,
    source: string,
    relation: FlowViewModelEdge["relation"],
    refs: string[] | undefined
): void {
    for (const target of refs ?? []) {
        const edge = createEdge(source, relation, target);
        if (!edges.has(edge.id)) {
            edges.set(edge.id, edge);
        }
    }
}

function mapAttackFlow(
    attackFlow: StructuredExtractionAttackFlowMetadata,
    startRefs: string[] | undefined
): FlowViewModel["flow"] {
    return {
        id: toTrimmedString(attackFlow.id),
        type: "attack-flow",
        spec_version: "2.1",
        name: toTrimmedString(attackFlow.name),
        scope: toTrimmedString(attackFlow.scope),
        orchestration_mode: toTrimmedString(attackFlow.orchestration_mode),
        source_classification: toTrimmedString(attackFlow.source_classification),
        ...(toOptionalVerbatimString(attackFlow.description) ? { description: toOptionalVerbatimString(attackFlow.description) } : {}),
        ...(startRefs ? { start_refs: startRefs } : {}),
        ...(toNormalizedStringList(attackFlow.authors) ? { authors: toNormalizedStringList(attackFlow.authors) } : {}),
        ...(toNormalizedStringList(attackFlow.external_references)
            ? { external_references: toNormalizedStringList(attackFlow.external_references) }
            : {})
    };
}

function mapAttackAction(action: StructuredExtractionAttackActionNode): FlowViewModelAttackAction {
    const techniqueId = toOptionalTrimmedString(action.technique?.technique_id);
    const techniqueRef = toOptionalTrimmedString(action.technique?.technique_ref);
    const tacticId = toOptionalTrimmedString(action.tactic?.tactic_id);
    const tacticRef = toOptionalTrimmedString(action.tactic?.tactic_ref);
    const assetRefs = toNormalizedStringList(action.asset_refs);
    const effectRefs = toNormalizedStringList(action.effect_refs);

    return {
        id: toTrimmedString(action.id),
        type: "attack-action",
        spec_version: "2.1",
        name: toTrimmedString(action.name),
        description: action.description,
        confidence: action.confidence,
        ...(techniqueId ? { technique_id: techniqueId } : {}),
        ...(techniqueRef ? { technique_ref: techniqueRef } : {}),
        ...(tacticId ? { tactic_id: tacticId } : {}),
        ...(tacticRef ? { tactic_ref: tacticRef } : {}),
        ...(assetRefs ? { asset_refs: assetRefs } : {}),
        ...(effectRefs ? { effect_refs: effectRefs } : {}),
        ...(action.fact_origin ? { fact_origin: action.fact_origin } : {})
    };
}

function mapAttackCondition(condition: StructuredExtractionAttackConditionNode): FlowViewModelAttackCondition {
    const trueRefs = toNormalizedStringList(condition.on_true_refs);
    const falseRefs = toNormalizedStringList(condition.on_false_refs);

    return {
        id: toTrimmedString(condition.id),
        type: "attack-condition",
        spec_version: "2.1",
        description: condition.description,
        value: condition.value,
        confidence: condition.confidence,
        ...(trueRefs ? { on_true_refs: trueRefs } : {}),
        ...(falseRefs ? { on_false_refs: falseRefs } : {}),
        ...(condition.fact_origin ? { fact_origin: condition.fact_origin } : {})
    };
}

function mapAttackOperator(operator: StructuredExtractionAttackOperatorNode): FlowViewModelAttackOperator {
    const effectRefs = toNormalizedStringList(operator.effect_refs);

    return {
        id: toTrimmedString(operator.id),
        type: "attack-operator",
        spec_version: "2.1",
        operator: operator.operator,
        confidence: operator.confidence,
        ...(effectRefs ? { effect_refs: effectRefs } : {}),
        ...(operator.fact_origin ? { fact_origin: operator.fact_origin } : {})
    };
}

function mapAttackAsset(asset: StructuredExtractionAttackAssetNode): FlowViewModelAttackAsset {
    const objectRef = asset.object_ref === undefined ? undefined : asset.object_ref === null ? null : toTrimmedString(asset.object_ref);

    return {
        id: toTrimmedString(asset.id),
        type: "attack-asset",
        spec_version: "2.1",
        name: toTrimmedString(asset.name),
        confidence: asset.confidence,
        ...(toOptionalVerbatimString(asset.description) ? { description: toOptionalVerbatimString(asset.description) } : {}),
        ...(asset.tags !== undefined ? { tags: asset.tags } : {}),
        ...(objectRef === undefined ? {} : { object_ref: objectRef }),
        ...(asset.fact_origin ? { fact_origin: asset.fact_origin } : {})
    };
}

/**
 * Maps validated structured extraction into the browser-side flow view model
 * without introducing new semantics or inference.
 */
export function mapValidatedStructuredExtractionToFlowViewModel(
    extraction: StructuredExtractionResult
): FlowViewModel {
    const knownNodeIds = new Set([
        ...(extraction.attack_actions ?? []).map((node) => node.id.trim()),
        ...(extraction.attack_conditions ?? []).map((node) => node.id.trim()),
        ...(extraction.attack_operators ?? []).map((node) => node.id.trim()),
        ...(extraction.attack_assets ?? []).map((node) => node.id.trim())
    ]);

    const nodes: FlowViewModelNode[] = [
        ...(extraction.attack_actions ?? []).map((action) => ({
            ...mapAttackAction(action),
            ...(filterKnownRefs(action.asset_refs, knownNodeIds) ? { asset_refs: filterKnownRefs(action.asset_refs, knownNodeIds) } : {}),
            ...(filterKnownRefs(action.effect_refs, knownNodeIds) ? { effect_refs: filterKnownRefs(action.effect_refs, knownNodeIds) } : {})
        })),
        ...(extraction.attack_conditions ?? []).map((condition) => ({
            ...mapAttackCondition(condition),
            ...(filterKnownRefs(condition.on_true_refs, knownNodeIds) ? { on_true_refs: filterKnownRefs(condition.on_true_refs, knownNodeIds) } : {}),
            ...(filterKnownRefs(condition.on_false_refs, knownNodeIds) ? { on_false_refs: filterKnownRefs(condition.on_false_refs, knownNodeIds) } : {})
        })),
        ...(extraction.attack_operators ?? []).map((operator) => ({
            ...mapAttackOperator(operator),
            ...(filterKnownRefs(operator.effect_refs, knownNodeIds) ? { effect_refs: filterKnownRefs(operator.effect_refs, knownNodeIds) } : {})
        })),
        ...(extraction.attack_assets ?? []).map((asset) => mapAttackAsset(asset))
    ];
    const flowStartRefs = filterKnownRefs(extraction.attack_flow.start_refs, knownNodeIds);
    const edges = new Map<string, FlowViewModelEdge>();

    pushEdgesFromRefs(edges, extraction.attack_flow.id.trim(), "start", flowStartRefs);

    for (const action of extraction.attack_actions ?? []) {
        const sourceId = action.id.trim();
        pushEdgesFromRefs(edges, sourceId, "effect", filterKnownRefs(action.effect_refs, knownNodeIds));
        pushEdgesFromRefs(edges, sourceId, "attachment", filterKnownRefs(action.asset_refs, knownNodeIds));
    }

    for (const condition of extraction.attack_conditions ?? []) {
        const sourceId = condition.id.trim();
        pushEdgesFromRefs(edges, sourceId, "true", filterKnownRefs(condition.on_true_refs, knownNodeIds));
        pushEdgesFromRefs(edges, sourceId, "false", filterKnownRefs(condition.on_false_refs, knownNodeIds));
    }

    for (const operator of extraction.attack_operators ?? []) {
        pushEdgesFromRefs(edges, operator.id.trim(), "effect", filterKnownRefs(operator.effect_refs, knownNodeIds));
    }

    return {
        version: FLOW_VIEW_MODEL_VERSION,
        flow: mapAttackFlow(extraction.attack_flow, flowStartRefs),
        nodes,
        edges: [...edges.values()]
    };
}
