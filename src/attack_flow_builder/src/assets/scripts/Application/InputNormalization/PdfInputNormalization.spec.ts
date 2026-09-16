import { describe, expect, it } from "vitest";
import { normalizePdfExtractionInput } from "./PdfInputNormalization";

describe("PdfInputNormalization", () => {
    it("normalizes extracted PDF text into the shared input package", () => {
        const result = normalizePdfExtractionInput({
            sourceType: "pdf",
            filename: "report.pdf",
            pageCount: 4,
            extractedText: "  Alpha\r\n\r\n\r\nBeta  "
        });

        expect(result).toEqual({
            sourceType: "pdf",
            normalizedText: "Alpha\n\nBeta",
            metadata: {
                filename: "report.pdf",
                sourceName: "PDF Upload",
                pageCount: 4
            },
            contentStats: {
                characterCount: 11,
                wordCount: 2,
                lineCount: 3,
                paragraphCount: 2
            }
        });
    });

    it("preserves a caller-provided title", () => {
        const result = normalizePdfExtractionInput({
            sourceType: "pdf",
            filename: "scan.pdf",
            pageCount: 1,
            extractedText: "Example"
        }, {
            title: "  Incident Report  "
        });

        expect(result.metadata).toMatchObject({
            title: "Incident Report",
            filename: "scan.pdf",
            sourceName: "PDF Upload",
            pageCount: 1
        });
    });

    it("preserves pdf metadata and calculates lightweight stats", () => {
        const result = normalizePdfExtractionInput({
            sourceType: "pdf",
            filename: "memo.pdf",
            pageCount: 3,
            extractedText: "One\n\nTwo"
        }, {
            sourceName: "Evidence PDF"
        });

        expect(result.metadata).toEqual({
            filename: "memo.pdf",
            sourceName: "Evidence PDF",
            pageCount: 3
        });
        expect(result.contentStats).toEqual({
            characterCount: 8,
            wordCount: 2,
            lineCount: 3,
            paragraphCount: 2
        });
    });
});
