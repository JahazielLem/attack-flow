import { describe, expect, it } from "vitest";
import { validateStructuredExtractionOutput } from "./StructuredExtractionValidator";

const validOutput = {
    schema_version: "afb-v2-intermediate",
    validation_state: "valid",
    repair_attempted: false,
    provider_invoked: true,
    provider_id: "runtime-openai_compatible",
    model: "gpt-4o-mini",
    attack_flow: {
        id: "attack-flow--1",
        type: "attack-flow",
        spec_version: "2.1",
        name: "Incident Flow",
        scope: "incident",
        orchestration_mode: "direct_provider",
        source_classification: "narrative_text",
        authors: ["Analyst"],
        external_references: ["https://example.com"],
        provenance: { source_name: "Report" }
    },
    attack_actions: [
        {
            id: "attack-action--1",
            type: "attack-action",
            spec_version: "2.1",
            name: "Run command",
            description: "Run the command",
            confidence: 0.9,
            evidence: [{ source: "report", excerpt: "Run the command" }],
            effect_refs: ["attack-condition--1"]
        }
    ],
    attack_conditions: [
        {
            id: "attack-condition--1",
            type: "attack-condition",
            spec_version: "2.1",
            description: "If successful",
            value: "true",
            confidence: 0.8,
            evidence: [{ source: "report", excerpt: "If successful" }],
            on_true_refs: ["attack-action--1"]
        }
    ],
    attack_operators: [
        {
            id: "attack-operator--1",
            type: "attack-operator",
            spec_version: "2.1",
            operator: "AND",
            confidence: 0.8,
            evidence: [{ source: "report", excerpt: "and" }],
            effect_refs: ["attack-action--1"]
        }
    ],
    attack_assets: [
        {
            id: "attack-asset--1",
            type: "attack-asset",
            spec_version: "2.1",
            name: "Host",
            confidence: 0.7,
            evidence: [{ source: "report", excerpt: "Host" }]
        }
    ],
    deterministic_attack_refs: [],
    deterministic_entities: [],
    deterministic_relationships: []
};

describe("StructuredExtractionValidator", () => {
    it("accepts valid structured extraction output from outputJson", () => {
        const result = validateStructuredExtractionOutput({ outputJson: validOutput });

        expect(result.status).toBe("valid");
        expect(result.failures).toEqual([]);
        expect(result.result?.attack_flow.id).toBe("attack-flow--1");
        expect(result.result?.attack_actions?.[0].description).toBe("Run the command");
    });

    it("rejects invalid output shapes clearly", () => {
        const result = validateStructuredExtractionOutput({ outputJson: [] });

        expect(result.status).toBe("unrecoverable");
        expect(result.failures[0]).toMatchObject({
            category: "schema",
            path: "$"
        });
    });

    it("rejects inferred ATT&CK mapping without an explicit grounded technique reference", () => {
        const result = validateStructuredExtractionOutput({
            outputJson: {
                ...validOutput,
                attack_actions: [
                    {
                        ...validOutput.attack_actions[0],
                        technique: {
                            grounded_by: "inferred",
                            confidence: 0.5
                        }
                    }
                ]
            }
        });

        expect(result.status).toBe("invalid");
        expect(result.failures.some(failure => failure.code === "structured_extraction_technique_ungrounded")).toBe(true);
    });

    it("allows steps without techniques", () => {
        const result = validateStructuredExtractionOutput({
            outputJson: {
                ...validOutput,
                attack_actions: [
                    {
                        ...validOutput.attack_actions[0],
                        technique: null
                    }
                ]
            }
        });

        expect(result.status).toBe("valid");
        expect(result.result?.attack_actions?.[0].technique).toBeUndefined();
    });

    it("parses valid structured extraction output from outputText", () => {
        const result = validateStructuredExtractionOutput({ outputText: JSON.stringify(validOutput) });

        expect(result.status).toBe("valid");
        expect(result.result?.attack_conditions?.[0].value).toBe("true");
    });

    it("marks schema-only failures as repairable", () => {
        const result = validateStructuredExtractionOutput({
            outputJson: {
                ...validOutput,
                schema_version: "wrong-version"
            }
        });

        expect(result.status).toBe("repairable");
        expect(result.failures[0]).toMatchObject({
            category: "schema",
            path: "schema_version"
        });
    });

    it("marks hard constraint failures as invalid", () => {
        const result = validateStructuredExtractionOutput({
            outputJson: {
                ...validOutput,
                attack_actions: [
                    {
                        ...validOutput.attack_actions[0],
                        description: "Inserted text",
                        evidence: [{ source: "report", excerpt: "Run the command" }]
                    }
                ]
            }
        });

        expect(result.status).toBe("invalid");
        expect(result.failures.some(failure => failure.code === "structured_extraction_attack_action_description_not_verbatim")).toBe(true);
    });

    it("preserves resolved deterministic entities and object references", () => {
        const result = validateStructuredExtractionOutput({
            outputJson: {
                ...validOutput,
                attack_actions: [{
                    ...validOutput.attack_actions[0],
                    object_refs: ["url--1"]
                }],
                deterministic_entities: [{
                    object_id: "url--1",
                    object_type: "url",
                    value: "hxxps://evil[.]example"
                }]
            }
        });

        expect(result.status).toBe("valid");
        expect(result.result?.attack_actions?.[0].object_refs).toEqual(["url--1"]);
        expect(result.result?.deterministic_entities?.[0]).toMatchObject({
            object_id: "url--1",
            value: "hxxps://evil[.]example"
        });
    });

    it("rejects unresolved object references instead of dropping them", () => {
        const result = validateStructuredExtractionOutput({
            outputJson: {
                ...validOutput,
                attack_actions: [{
                    ...validOutput.attack_actions[0],
                    object_refs: ["url--missing"]
                }]
            }
        });

        expect(result.status).toBe("invalid");
        expect(result.failures).toContainEqual(expect.objectContaining({
            code: "structured_extraction_reference_unresolved",
            path: "attack_actions[0].object_refs"
        }));
    });

    it("rejects unsupported operator values", () => {
        const result = validateStructuredExtractionOutput({
            outputJson: {
                ...validOutput,
                attack_operators: [
                    {
                        ...validOutput.attack_operators[0],
                        operator: "XOR"
                    }
                ]
            }
        });

        expect(result.status).toBe("invalid");
        expect(result.failures.some(failure => failure.code === "structured_extraction_attack_operator_value_invalid")).toBe(true);
    });

    it("rejects unsupported condition values", () => {
        const result = validateStructuredExtractionOutput({
            outputJson: {
                ...validOutput,
                attack_conditions: [
                    {
                        ...validOutput.attack_conditions[0],
                        value: "maybe"
                    }
                ]
            }
        });

        expect(result.status).toBe("invalid");
        expect(result.failures.some(failure => failure.code === "structured_extraction_attack_condition_value_invalid")).toBe(true);
    });

    it("rejects malformed JSON text as repairable parse failure", () => {
        const result = validateStructuredExtractionOutput({ outputText: "not json" });

        expect(result.status).toBe("repairable");
        expect(result.failures[0]).toMatchObject({ category: "parse" });
    });

    it("rejects non-object JSON output as unrecoverable", () => {
        const result = validateStructuredExtractionOutput({ outputText: "[1,2,3]" });

        expect(result.status).toBe("unrecoverable");
        expect(result.failures[0]).toMatchObject({
            category: "schema",
            path: "$"
        });
    });
});
