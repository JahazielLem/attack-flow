import { describe, expect, it } from "vitest";
import { normalizeUrlExtractionInput } from "./UrlInputNormalization";

describe("UrlInputNormalization", () => {
    it("normalizes URL extraction text and preserves provenance", () => {
        const normalized = normalizeUrlExtractionInput({
            sourceType: "url",
            requestedUrl: "https://reports.example/start",
            finalUrl: "https://reports.example/final",
            canonicalUrl: "https://reports.example/article",
            statusCode: 200,
            contentType: "text/html",
            responseSizeBytes: 100,
            title: "Threat Report",
            extractedText: " First paragraph.\r\n\r\n\r\nSecond paragraph. "
        });

        expect(normalized).toMatchObject({
            sourceType: "url",
            normalizedText: "First paragraph.\n\nSecond paragraph.",
            metadata: {
                title: "Threat Report",
                sourceName: "URL Fetch",
                sourceUrl: "https://reports.example/start",
                finalUrl: "https://reports.example/final",
                canonicalUrl: "https://reports.example/article",
                contentType: "text/html",
                responseSizeBytes: 100
            },
            contentStats: {
                paragraphCount: 2
            },
            truncation: {
                wasTruncated: false,
                originalCharacterCount: 35
            }
        });
    });

    it("applies a deterministic budget without splitting surrogate pairs", () => {
        const normalized = normalizeUrlExtractionInput({
            sourceType: "url",
            requestedUrl: "https://reports.example/article",
            finalUrl: "https://reports.example/article",
            statusCode: 200,
            contentType: "text/html",
            responseSizeBytes: 20,
            extractedText: "1234😀more"
        }, { contentBudgetCharacters: 5 });

        expect(normalized.normalizedText).toBe("1234");
        expect(normalized.truncation).toEqual({
            wasTruncated: true,
            budgetCharacters: 5,
            originalCharacterCount: 10
        });
    });
});
