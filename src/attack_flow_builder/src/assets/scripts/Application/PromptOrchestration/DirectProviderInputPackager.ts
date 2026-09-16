import type {
    InputNormalizedContentStats,
    InputNormalizedMetadata,
    InputNormalizedTruncation,
    NormalizedInputPackage
} from "../InputNormalization";
import type { DirectProviderInputPayload } from "./DirectProviderRequestModels";

/**
 * Builds the provider-facing input payload from the normalized browser-side
 * package without adding ATT&CK semantics or other interpretation.
 */
export function buildDirectProviderInputPayload(
    normalizedInput: NormalizedInputPackage
): DirectProviderInputPayload {
    return {
        sourceType: normalizedInput.sourceType,
        normalizedText: normalizedInput.normalizedText,
        metadata: cloneMetadata(normalizedInput.metadata),
        contentStats: cloneContentStats(normalizedInput.contentStats),
        truncation: cloneTruncation(normalizedInput.truncation)
    };
}

function cloneMetadata(metadata: InputNormalizedMetadata): InputNormalizedMetadata {
    return {
        title: metadata.title,
        filename: metadata.filename,
        sourceName: metadata.sourceName,
        pageCount: metadata.pageCount,
        sourceUrl: metadata.sourceUrl,
        finalUrl: metadata.finalUrl,
        canonicalUrl: metadata.canonicalUrl,
        contentType: metadata.contentType,
        responseSizeBytes: metadata.responseSizeBytes
    };
}

function cloneTruncation(
    truncation: InputNormalizedTruncation | undefined
): InputNormalizedTruncation | undefined {
    return truncation ? { ...truncation } : undefined;
}

function cloneContentStats(
    contentStats: InputNormalizedContentStats | undefined
): InputNormalizedContentStats | undefined {
    if (!contentStats) {
        return undefined;
    }

    return {
        characterCount: contentStats.characterCount,
        wordCount: contentStats.wordCount,
        lineCount: contentStats.lineCount,
        paragraphCount: contentStats.paragraphCount
    };
}
