import { describe, expect, it } from "vitest";
import { buildDirectProviderInputPayload } from "./DirectProviderInputPackager";

describe("DirectProviderInputPackager", () => {
    it("packages normalized text and safe metadata deterministically", () => {
        const normalizedInput = {
            sourceType: "pdf" as const,
            normalizedText: "Alpha\n\nBeta",
            metadata: {
                title: "Incident Report",
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
        };

        const result = buildDirectProviderInputPayload(normalizedInput);

        expect(result).toEqual({
            sourceType: "pdf",
            normalizedText: "Alpha\n\nBeta",
            metadata: {
                title: "Incident Report",
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

    it("preserves text source payloads without adding interpretation", () => {
        const result = buildDirectProviderInputPayload({
            sourceType: "text",
            normalizedText: "Keep these words exactly.",
            metadata: {
                sourceName: "Pasted Text"
            }
        });

        expect(result).toEqual({
            sourceType: "text",
            normalizedText: "Keep these words exactly.",
            metadata: {
                sourceName: "Pasted Text"
            },
            contentStats: undefined
        });
    });
});
