import { describe, expect, it } from "vitest";
import {
    STRUCTURED_EXTRACTION_RESULT_CONDITION_VALUES,
    STRUCTURED_EXTRACTION_RESULT_OBJECT_TYPES,
    STRUCTURED_EXTRACTION_RESULT_OPERATOR_VALUES,
    STRUCTURED_EXTRACTION_RESULT_SCHEMA_VERSION,
    STRUCTURED_EXTRACTION_RESULT_VALIDATION_STATES
} from "./StructuredExtractionContracts";

describe("StructuredExtractionContracts", () => {
    it("pins the structured extraction result contract constants", () => {
        expect(STRUCTURED_EXTRACTION_RESULT_SCHEMA_VERSION).toBe("afb-v2-intermediate");
        expect(STRUCTURED_EXTRACTION_RESULT_OBJECT_TYPES).toEqual([
            "attack-flow",
            "attack-action",
            "attack-condition",
            "attack-operator",
            "attack-asset"
        ]);
        expect(STRUCTURED_EXTRACTION_RESULT_OPERATOR_VALUES).toEqual(["AND", "OR"]);
        expect(STRUCTURED_EXTRACTION_RESULT_CONDITION_VALUES).toEqual(["true", "false"]);
        expect(STRUCTURED_EXTRACTION_RESULT_VALIDATION_STATES).toEqual([
            "valid",
            "invalid",
            "repaired"
        ]);
    });
});
