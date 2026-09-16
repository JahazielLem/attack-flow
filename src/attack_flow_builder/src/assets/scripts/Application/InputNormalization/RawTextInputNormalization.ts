import type { InputNormalizedMetadata, NormalizedInputPackage } from "./InputNormalizationContracts";
import { buildNormalizedContentStats, normalizeInputText } from "./InputNormalizationUtils";

export interface RawTextNormalizationOptions {
    title?: string;
    sourceName?: string;
}

/**
 * Normalizes raw pasted text into the shared normalized package without
 * paraphrasing or semantic rewriting.
 */
export function normalizeRawTextInput(
    text: string,
    options: RawTextNormalizationOptions = {}
): NormalizedInputPackage {
    const normalizedText = normalizeInputText(text);

    return {
        sourceType: "text",
        normalizedText,
        metadata: buildRawTextMetadata(options),
        contentStats: buildNormalizedContentStats(normalizedText)
    };
}

function buildRawTextMetadata(options: RawTextNormalizationOptions): InputNormalizedMetadata {
    return {
        title: trimOrUndefined(options.title),
        sourceName: trimOrDefault(options.sourceName, "Pasted Text")
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
