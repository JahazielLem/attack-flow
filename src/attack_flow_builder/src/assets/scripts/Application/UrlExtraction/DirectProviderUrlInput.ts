import {
    normalizeUrlExtractionInput,
    type UrlInputNormalizationOptions
} from "../InputNormalization/UrlInputNormalization";
import type { NormalizedInputPackage } from "../InputNormalization/InputNormalizationContracts";
import { BrowserUrlExtractionService } from "./BrowserUrlExtractionService";
import type {
    UrlExtractionDependencies,
    UrlExtractionOptions
} from "./UrlExtractionContracts";

export interface DirectProviderUrlInputOptions extends UrlExtractionOptions, UrlInputNormalizationOptions {}

/**
 * Fetches, extracts, and normalizes a public article for direct-provider use.
 */
export async function prepareDirectProviderUrlInput(
    rawUrl: string,
    options: DirectProviderUrlInputOptions = {},
    dependencies: UrlExtractionDependencies = {}
): Promise<NormalizedInputPackage> {
    const extraction = await new BrowserUrlExtractionService(dependencies).extract(rawUrl, options);
    return normalizeUrlExtractionInput(extraction, options);
}
