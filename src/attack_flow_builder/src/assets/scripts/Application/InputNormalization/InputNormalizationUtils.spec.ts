import { describe, expect, it } from "vitest";
import {
    applyInputContentBudget,
    countNormalizedLines,
    normalizeInputText
} from "./InputNormalizationUtils";

describe("InputNormalizationUtils", () => {
    it("normalizes line endings and trims outer whitespace", () => {
        expect(normalizeInputText("\r\n  Hello\r\nWorld  \n")).toBe("Hello\nWorld");
    });

    it("collapses repeated blank lines while preserving paragraphs", () => {
        expect(normalizeInputText("Line 1\n\n\nLine 2\n\n\n\nLine 3")).toBe("Line 1\n\nLine 2\n\nLine 3");
    });

    it("preserves paragraph boundaries as intended", () => {
        expect(normalizeInputText("Paragraph one\n\nParagraph two\n\nParagraph three")).toBe("Paragraph one\n\nParagraph two\n\nParagraph three");
    });

    it("does not paraphrase or rewrite content", () => {
        expect(normalizeInputText("Keep these words exactly.")).toBe("Keep these words exactly.");
    });

    it("counts normalized lines deterministically", () => {
        expect(countNormalizedLines("A\r\n\r\nB\n\nC")).toBe(5);
        expect(countNormalizedLines("   \n\n   ")).toBe(0);
    });

    it("applies deterministic content budgets", () => {
        expect(applyInputContentBudget("abcdef", 4)).toEqual({
            text: "abcd",
            truncation: {
                wasTruncated: true,
                budgetCharacters: 4,
                originalCharacterCount: 6
            }
        });
    });
});
