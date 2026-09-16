import type { PdfExtractionResult } from "../PdfExtraction";
import type { InputNormalizedMetadata, NormalizedInputPackage } from "./InputNormalizationContracts";
import { buildNormalizedContentStats, normalizeInputText } from "./InputNormalizationUtils";

export interface PdfInputNormalizationOptions {
    title?: string;
    sourceName?: string;
}

/**
 * Normalizes extracted PDF text into the shared normalized package without
 * paraphrasing or semantic rewriting.
 */
export function normalizePdfExtractionInput(
    extraction: PdfExtractionResult,
    options: PdfInputNormalizationOptions = {}
): NormalizedInputPackage {
    const normalizedText = normalizeInputText(extraction.extractedText);

    return {
        sourceType: "pdf",
        normalizedText,
        metadata: buildPdfMetadata(extraction, options),
        contentStats: buildNormalizedContentStats(normalizedText)
    };
}

function buildPdfMetadata(
    extraction: PdfExtractionResult,
    options: PdfInputNormalizationOptions
): InputNormalizedMetadata {
    return {
        title: trimOrUndefined(options.title),
        filename: extraction.filename,
        sourceName: trimOrDefault(options.sourceName, "PDF Upload"),
        pageCount: extraction.pageCount
    };
}

function trimOrUndefined(value: string | undefined): string | undefined {
    const trimmed = value?.trim();
    return trimmed ? trimmed : undefined;
}

function trimOrDefault(value: string | undefined, fallback: string): string {
    const trimmed = value?.trim();
    return trimmed ? trimmed : fallback;
}
