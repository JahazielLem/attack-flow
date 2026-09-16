import { describe, expect, it } from "vitest";
import {
    STRUCTURED_EXTRACTION_VALIDATION_FAILURE_CATEGORIES,
    STRUCTURED_EXTRACTION_VALIDATION_STATUSES
} from "./StructuredExtractionValidationContracts";

describe("StructuredExtractionValidationContracts", () => {
    it("pins validation status and failure categories", () => {
        expect(STRUCTURED_EXTRACTION_VALIDATION_STATUSES).toEqual([
            "valid",
            "invalid",
            "repairable",
            "unrecoverable"
        ]);
        expect(STRUCTURED_EXTRACTION_VALIDATION_FAILURE_CATEGORIES).toEqual([
            "schema",
            "constraint",
            "parse",
            "repair"
        ]);
    });
});
