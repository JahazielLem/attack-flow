import { describe, expect, it } from "vitest";
import type { StructuredExtractionResult } from "../StructuredExtraction";
import { mapValidatedStructuredExtractionToFlowViewModel } from "./FlowViewModelMapper";

const extraction: StructuredExtractionResult = {
    schema_version: "afb-v2-intermediate",
    validation_state: "valid",
    repair_attempted: false,
    provider_invoked: true,
    attack_flow: {
        id: "attack-flow--1",
        type: "attack-flow",
        spec_version: "2.1",
        name: " Incident Flow ",
        description: "  Flow description  ",
        scope: " incident ",
        start_refs: ["attack-action--1", " attack-asset--1 ", "missing"],
        orchestration_mode: " direct_provider ",
        source_classification: " narrative_text ",
        authors: [" Analyst "],
        external_references: [" https://example.com/report "]
    },
    attack_actions: [
        {
            id: "attack-action--1",
            type: "attack-action",
            spec_version: "2.1",
            name: " Deploy Payload ",
            description: "  Action description  ",
            confidence: 0.9,
            technique: {
                technique_id: "T1059",
                technique_ref: " attack-pattern--1 ",
                confidence: 0.8,
                grounded_by: "source"
            },
            tactic: {
                tactic_id: "TA0002",
                tactic_ref: " x-mitre-tactic--1 ",
                confidence: 0.7,
                grounded_by: "source"
            },
            asset_refs: ["attack-asset--1", "missing"],
            effect_refs: ["attack-condition--1"],
            fact_origin: "deterministic_source"
        },
        {
            id: "attack-action--2",
            type: "attack-action",
            spec_version: "2.1",
            name: " Follow Up ",
            description: "Follow up",
            confidence: 0.7
        }
    ],
    attack_conditions: [
        {
            id: "attack-condition--1",
            type: "attack-condition",
            spec_version: "2.1",
            description: " Is admin? ",
            value: "true",
            confidence: 0.8,
            on_true_refs: ["attack-operator--1"],
            on_false_refs: ["attack-action--2"],
            fact_origin: "ai_generated"
        }
    ],
    attack_operators: [
        {
            id: "attack-operator--1",
            type: "attack-operator",
            spec_version: "2.1",
            operator: "AND",
            confidence: 0.6,
            effect_refs: ["attack-action--2"]
        }
    ],
    attack_assets: [
        {
            id: "attack-asset--1",
            type: "attack-asset",
            spec_version: "2.1",
            name: " Host ",
            description: "  Server  ",
            tags: { critical: true },
            object_ref: " attack-asset--ref ",
            confidence: 0.5,
            fact_origin: "deterministic_source"
        }
    ],
    deterministic_attack_refs: [],
    deterministic_entities: [],
    deterministic_relationships: []
};

describe("FlowViewModelMapper", () => {
    it("maps validated attack-flow metadata into the root flow", () => {
        const model = mapValidatedStructuredExtractionToFlowViewModel(extraction);

        expect(model.version).toBe("v1");
        expect(model.flow).toMatchObject({
            id: "attack-flow--1",
            type: "attack-flow",
            spec_version: "2.1",
            name: "Incident Flow",
            description: "  Flow description  ",
            scope: "incident",
            start_refs: ["attack-action--1", "attack-asset--1"],
            orchestration_mode: "direct_provider",
            source_classification: "narrative_text",
            authors: ["Analyst"],
            external_references: ["https://example.com/report"]
        });
    });

    it("maps nodes without inference and preserves source-grounded fields", () => {
        const model = mapValidatedStructuredExtractionToFlowViewModel(extraction);

        expect(model.nodes).toEqual([
            {
                id: "attack-action--1",
                type: "attack-action",
                spec_version: "2.1",
                name: "Deploy Payload",
                description: "  Action description  ",
                confidence: 0.9,
                technique_id: "T1059",
                technique_ref: "attack-pattern--1",
                tactic_id: "TA0002",
                tactic_ref: "x-mitre-tactic--1",
                asset_refs: ["attack-asset--1"],
                effect_refs: ["attack-condition--1"],
                fact_origin: "deterministic_source"
            },
            {
                id: "attack-action--2",
                type: "attack-action",
                spec_version: "2.1",
                name: "Follow Up",
                description: "Follow up",
                confidence: 0.7
            },
            {
                id: "attack-condition--1",
                type: "attack-condition",
                spec_version: "2.1",
                description: " Is admin? ",
                value: "true",
                confidence: 0.8,
                on_true_refs: ["attack-operator--1"],
                on_false_refs: ["attack-action--2"],
                fact_origin: "ai_generated"
            },
            {
                id: "attack-operator--1",
                type: "attack-operator",
                spec_version: "2.1",
                operator: "AND",
                confidence: 0.6,
                effect_refs: ["attack-action--2"]
            },
            {
                id: "attack-asset--1",
                type: "attack-asset",
                spec_version: "2.1",
                name: "Host",
                description: "  Server  ",
                tags: { critical: true },
                object_ref: "attack-asset--ref",
                confidence: 0.5,
                fact_origin: "deterministic_source"
            }
        ]);
    });

    it("derives deterministic edges from explicit references", () => {
        const model = mapValidatedStructuredExtractionToFlowViewModel(extraction);

        expect(model.edges).toEqual([
            {
                id: "attack-flow--1--start--attack-action--1",
                source: "attack-flow--1",
                target: "attack-action--1",
                relation: "start"
            },
            {
                id: "attack-flow--1--start--attack-asset--1",
                source: "attack-flow--1",
                target: "attack-asset--1",
                relation: "start"
            },
            {
                id: "attack-action--1--effect--attack-condition--1",
                source: "attack-action--1",
                target: "attack-condition--1",
                relation: "effect"
            },
            {
                id: "attack-action--1--attachment--attack-asset--1",
                source: "attack-action--1",
                target: "attack-asset--1",
                relation: "attachment"
            },
            {
                id: "attack-condition--1--true--attack-operator--1",
                source: "attack-condition--1",
                target: "attack-operator--1",
                relation: "true"
            },
            {
                id: "attack-condition--1--false--attack-action--2",
                source: "attack-condition--1",
                target: "attack-action--2",
                relation: "false"
            },
            {
                id: "attack-operator--1--effect--attack-action--2",
                source: "attack-operator--1",
                target: "attack-action--2",
                relation: "effect"
            }
        ]);
    });

    it("returns the same model for repeated inputs", () => {
        const first = mapValidatedStructuredExtractionToFlowViewModel(extraction);
        const second = mapValidatedStructuredExtractionToFlowViewModel(extraction);

        expect(second).toEqual(first);
    });
});
