import { describe, expect, it } from "vitest";
import { normalizeRawTextInput } from "./RawTextInputNormalization";

describe("RawTextInputNormalization", () => {
    it("normalizes raw text into the shared input package", () => {
        const result = normalizeRawTextInput("  First line\r\n\r\n\r\nSecond line  ");

        expect(result).toEqual({
            sourceType: "text",
            normalizedText: "First line\n\nSecond line",
            metadata: {
                sourceName: "Pasted Text"
            },
            contentStats: {
                characterCount: 23,
                wordCount: 4,
                lineCount: 3,
                paragraphCount: 2
            }
        });
    });

    it("preserves a caller-provided title", () => {
        const result = normalizeRawTextInput("Example", { title: "  Incident Note  " });

        expect(result.metadata).toMatchObject({
            title: "Incident Note",
            sourceName: "Pasted Text"
        });
    });

    it("preserves source metadata and calculates lightweight stats", () => {
        const result = normalizeRawTextInput("One\n\nTwo", {
            title: "  Short Note  ",
            sourceName: "  Manual Paste  "
        });

        expect(result.metadata).toEqual({
            title: "Short Note",
            sourceName: "Manual Paste"
        });
        expect(result.contentStats).toEqual({
            characterCount: 8,
            wordCount: 2,
            lineCount: 3,
            paragraphCount: 2
        });
    });
});
