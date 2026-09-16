import { describe, expect, it } from "vitest";
import { validateAndRepairStructuredExtractionOutput } from "./StructuredExtractionRepairService";

const validOutput = {
    schema_version: "afb-v2-intermediate",
    validation_state: "valid",
    repair_attempted: false,
    provider_invoked: true,
    attack_flow: {
        id: "attack-flow--1",
        type: "attack-flow",
        spec_version: "2.1",
        name: "Incident Flow",
        scope: "incident",
        orchestration_mode: "direct_provider",
        source_classification: "narrative_text"
    },
    attack_actions: [],
    attack_conditions: [],
    attack_operators: [],
    attack_assets: [],
    deterministic_attack_refs: [],
    deterministic_entities: [],
    deterministic_relationships: []
};

describe("StructuredExtractionRepairService", () => {
    it("repairs fenced json output with one bounded pass", () => {
        const result = validateAndRepairStructuredExtractionOutput({
            outputText: [
                "Here is the result:",
                "",
                "```json",
                JSON.stringify(validOutput),
                "```"
            ].join("\n")
        });

        expect(result.validation.status).toBe("valid");
        expect(result.validation.repairAttempted).toBe(true);
        expect(result.validation.result?.attack_flow.id).toBe("attack-flow--1");
    });

    it("repairs descriptions that do not exactly match their evidence", () => {
        const evidenceExcerpt = "The actor executed PowerShell to download and run the payload.";
        const result = validateAndRepairStructuredExtractionOutput({
            outputJson: {
                ...validOutput,
                attack_actions: [{
                    id: "attack-action--1",
                    type: "attack-action",
                    spec_version: "2.1",
                    name: "Execute PowerShell",
                    description: "The actor downloaded a payload with PowerShell.",
                    confidence: 0.9,
                    evidence: [{ source: "report", excerpt: evidenceExcerpt }]
                }]
            }
        });

        expect(result.validation.status).toBe("valid");
        expect(result.validation.repairAttempted).toBe(true);
        expect(result.validation.result?.validation_state).toBe("repaired");
        expect(result.validation.result?.attack_actions?.[0].description).toBe(evidenceExcerpt);
    });

    it("returns unrecoverable when one repair pass cannot fix the output", () => {
        const result = validateAndRepairStructuredExtractionOutput({
            outputText: "not json"
        });

        expect(result.validation.status).toBe("unrecoverable");
        expect(result.validation.repairAttempted).toBe(true);
        expect(result.validation.failures.some(failure => failure.category === "repair")).toBe(true);
    });
});
