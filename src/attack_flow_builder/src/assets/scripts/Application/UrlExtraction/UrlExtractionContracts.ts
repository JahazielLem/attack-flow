export const URL_EXTRACTION_SOURCE_TYPE = "url" as const;
export const URL_FETCH_TIMEOUT_MS = 10_000;
export const URL_FETCH_MAX_RESPONSE_BYTES = 2_000_000;
export const URL_NORMALIZED_CONTENT_MAX_CHARACTERS = 100_000;

export const URL_EXTRACTION_SUPPORTED_CONTENT_TYPES = [
    "text/html",
    "application/xhtml+xml"
] as const;

export type UrlExtractionErrorCode =
    | "invalid_url"
    | "fetch_timeout"
    | "network_or_cors"
    | "http_error"
    | "unsupported_content_type"
    | "unsupported_charset"
    | "response_too_large"
    | "html_parse_failure"
    | "no_extractable_text"
    | "aborted";

export interface UrlExtractionError {
    sourceType: typeof URL_EXTRACTION_SOURCE_TYPE;
    code: UrlExtractionErrorCode;
    message: string;
    requestedUrl?: string;
    finalUrl?: string;
    statusCode?: number;
    contentType?: string;
    retryable: boolean;
    details?: Record<string, string>;
}

export interface UrlExtractionResult {
    sourceType: typeof URL_EXTRACTION_SOURCE_TYPE;
    requestedUrl: string;
    finalUrl: string;
    canonicalUrl?: string;
    statusCode: number;
    contentType: string;
    responseSizeBytes: number;
    title?: string;
    extractedText: string;
}

export interface UrlExtractionOptions {
    timeoutMs?: number;
    maxResponseBytes?: number;
    signal?: AbortSignal;
}

export interface UrlExtractionDependencies {
    fetch?: typeof globalThis.fetch;
    createDomParser?: () => DOMParser;
}

export interface HtmlTextExtractionResult {
    title?: string;
    canonicalUrl?: string;
    extractedText: string;
}

export class UrlExtractionServiceError extends Error {
    public readonly error: UrlExtractionError;

    constructor(error: UrlExtractionError) {
        super(error.message);
        this.name = "UrlExtractionServiceError";
        this.error = error;
    }
}
