import {
    URL_NORMALIZED_CONTENT_MAX_CHARACTERS,
    type UrlExtractionResult
} from "../UrlExtraction/UrlExtractionContracts";
import type { NormalizedInputPackage } from "./InputNormalizationContracts";
import {
    applyInputContentBudget,
    buildNormalizedContentStats,
    normalizeInputText
} from "./InputNormalizationUtils";

export interface UrlInputNormalizationOptions {
    title?: string;
    sourceName?: string;
    contentBudgetCharacters?: number;
}

/** Converts extracted article text into the shared direct-provider input. */
export function normalizeUrlExtractionInput(
    extraction: UrlExtractionResult,
    options: UrlInputNormalizationOptions = {}
): NormalizedInputPackage {
    const normalizedText = normalizeInputText(extraction.extractedText);
    const { text, truncation } = applyInputContentBudget(
        normalizedText,
        options.contentBudgetCharacters ?? URL_NORMALIZED_CONTENT_MAX_CHARACTERS
    );
    return {
        sourceType: "url",
        normalizedText: text,
        metadata: {
            title: options.title?.trim() || extraction.title,
            sourceName: options.sourceName?.trim() || "URL Fetch",
            sourceUrl: extraction.requestedUrl,
            finalUrl: extraction.finalUrl,
            canonicalUrl: extraction.canonicalUrl,
            contentType: extraction.contentType,
            responseSizeBytes: extraction.responseSizeBytes
        },
        contentStats: buildNormalizedContentStats(text),
        truncation
    };
}
