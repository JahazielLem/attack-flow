import { describe, expect, it } from "vitest";
import { buildStructuredExtractionFailureDisplayState } from "./StructuredExtractionFailureDisplayState";

describe("StructuredExtractionFailureDisplayState", () => {
    it("returns a compact failure display state for unrecoverable validation results", () => {
        const displayState = buildStructuredExtractionFailureDisplayState({
            status: "unrecoverable",
            repairAttempted: true,
            message: "provider output could not be parsed as JSON",
            failures: [
                {
                    code: "structured_extraction_output_not_json",
                    category: "parse",
                    message: "provider output could not be parsed as JSON",
                    repairAttempted: true,
                    path: "$",
                    field: "outputText"
                },
                {
                    code: "structured_extraction_repair_failed",
                    category: "repair",
                    message: "single structural repair pass did not produce valid structured extraction output",
                    repairAttempted: true
                }
            ]
        });

        expect(displayState).toEqual({
            status: "unrecoverable",
            message: "provider output could not be parsed as JSON",
            code: "structured_extraction_output_not_json",
            category: "parse",
            repairAttempted: true,
            failures: [
                {
                    code: "structured_extraction_output_not_json",
                    category: "parse",
                    message: "provider output could not be parsed as JSON",
                    repairAttempted: true,
                    path: "$",
                    field: "outputText"
                },
                {
                    code: "structured_extraction_repair_failed",
                    category: "repair",
                    message: "single structural repair pass did not produce valid structured extraction output",
                    repairAttempted: true
                }
            ]
        });
    });

    it("returns null for valid structured extraction results", () => {
        expect(buildStructuredExtractionFailureDisplayState({
            status: "valid",
            repairAttempted: false,
            failures: [],
            result: {
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
                }
            }
        })).toBeNull();
    });
});
