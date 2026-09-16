import { describe, expect, it } from "vitest";
import {
    PDF_EXTRACTION_ERROR_CODES,
    PDF_EXTRACTION_SOURCE_TYPE,
    type PdfExtractionErrorState,
    type PdfExtractionResult,
    type PdfExtractionState
} from "./PdfExtractionContracts";

describe("PdfExtractionContracts", () => {
    it("defines a browser-side PDF extraction result", () => {
        const result: PdfExtractionResult = {
            sourceType: PDF_EXTRACTION_SOURCE_TYPE,
            filename: "report.pdf",
            pageCount: 12,
            extractedText: "example text"
        };

        expect(result.sourceType).toBe("pdf");
        expect(result.filename).toBe("report.pdf");
    });

    it("defines a browser-side PDF extraction error state", () => {
        const errorState: PdfExtractionErrorState = {
            status: "error",
            error: {
                sourceType: PDF_EXTRACTION_SOURCE_TYPE,
                category: "no_extractable_text",
                code: "no_extractable_text",
                message: "No extractable text was found.",
                filename: "scan.pdf",
                pageCount: 1,
                details: { reason: "empty_text_layer" }
            }
        };

        const state: PdfExtractionState = errorState;

        expect(state.status).toBe("error");
        expect(errorState.error.code).toBe("no_extractable_text");
    });

    it("exposes stable pdf extraction error codes", () => {
        expect(PDF_EXTRACTION_ERROR_CODES).toContain("invalid_file");
        expect(PDF_EXTRACTION_ERROR_CODES).toContain("parse_failure");
    });
});
