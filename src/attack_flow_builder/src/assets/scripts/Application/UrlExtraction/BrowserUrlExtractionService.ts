import { extractReadableTextFromHtml } from "./HtmlTextExtraction";
import {
    URL_EXTRACTION_SOURCE_TYPE,
    URL_EXTRACTION_SUPPORTED_CONTENT_TYPES,
    URL_FETCH_MAX_RESPONSE_BYTES,
    URL_FETCH_TIMEOUT_MS,
    UrlExtractionServiceError,
    type UrlExtractionDependencies,
    type UrlExtractionError,
    type UrlExtractionOptions,
    type UrlExtractionResult
} from "./UrlExtractionContracts";

interface ExtractionContext {
    requestedUrl?: string;
    finalUrl?: string;
    statusCode?: number;
    contentType?: string;
}

/**
 * Best-effort browser fetch and extraction for public HTTPS articles.
 * CORS and browser network policy still determine whether a response is readable.
 */
export class BrowserUrlExtractionService {
    private readonly fetchImpl: typeof globalThis.fetch;
    private readonly createDomParser: () => DOMParser;

    constructor(dependencies: UrlExtractionDependencies = {}) {
        this.fetchImpl = dependencies.fetch ?? globalThis.fetch.bind(globalThis);
        this.createDomParser = dependencies.createDomParser ?? (() => new DOMParser());
    }

    async extract(rawUrl: string, options: UrlExtractionOptions = {}): Promise<UrlExtractionResult> {
        const requestedUrl = validatePublicHttpsUrl(rawUrl).toString();
        const timeoutMs = normalizePositiveLimit(options.timeoutMs, URL_FETCH_TIMEOUT_MS);
        const maxResponseBytes = normalizePositiveLimit(
            options.maxResponseBytes,
            URL_FETCH_MAX_RESPONSE_BYTES
        );
        const controller = new AbortController();
        let timedOut = false;
        let callerAborted = options.signal?.aborted ?? false;
        const abortFromCaller = () => {
            callerAborted = true;
            controller.abort();
        };
        options.signal?.addEventListener("abort", abortFromCaller, { once: true });
        if (callerAborted) {
            controller.abort();
        }
        const timeout = globalThis.setTimeout(() => {
            timedOut = true;
            controller.abort();
        }, timeoutMs);

        const context: ExtractionContext = { requestedUrl };
        try {
            const response = await this.fetchImpl(requestedUrl, {
                method: "GET",
                mode: "cors",
                credentials: "omit",
                redirect: "follow",
                cache: "no-store",
                referrerPolicy: "no-referrer",
                headers: {
                    Accept: "text/html,application/xhtml+xml"
                },
                signal: controller.signal
            });
            const finalUrl = validatePublicHttpsUrl(response.url || requestedUrl).toString();
            context.finalUrl = finalUrl;
            context.statusCode = response.status;
            context.contentType = response.headers.get("content-type")?.trim() || undefined;

            if (!response.ok) {
                throw createServiceError({
                    code: "http_error",
                    message: `The report returned HTTP ${response.status}.`,
                    retryable: response.status === 408 || response.status === 429 || response.status >= 500,
                    ...context
                });
            }

            const mediaType = parseSupportedContentType(context.contentType, context);
            const { body, sizeBytes } = await readBoundedResponseBody(
                response,
                maxResponseBytes,
                context
            );
            const decoder = createTextDecoder(
                detectBomCharset(body) ?? mediaType.charset ?? detectHtmlMetaCharset(body),
                context
            );
            const html = decoder.decode(body);

            let extracted;
            try {
                extracted = extractReadableTextFromHtml(html, this.createDomParser());
            } catch (error) {
                throw createServiceError({
                    code: "html_parse_failure",
                    message: "The article HTML could not be parsed.",
                    retryable: false,
                    details: { cause: toCauseString(error) },
                    ...context
                });
            }
            if (!extracted.extractedText.trim()) {
                throw createServiceError({
                    code: "no_extractable_text",
                    message: "The page does not contain readable article text.",
                    retryable: false,
                    ...context
                });
            }

            return {
                sourceType: URL_EXTRACTION_SOURCE_TYPE,
                requestedUrl,
                finalUrl,
                canonicalUrl: normalizeCanonicalUrl(extracted.canonicalUrl, finalUrl),
                statusCode: response.status,
                contentType: mediaType.value,
                responseSizeBytes: sizeBytes,
                title: extracted.title,
                extractedText: extracted.extractedText
            };
        } catch (error) {
            if (error instanceof UrlExtractionServiceError) {
                throw error;
            }
            if (timedOut) {
                throw createServiceError({
                    code: "fetch_timeout",
                    message: "The report fetch timed out.",
                    retryable: true,
                    ...context
                });
            }
            if (callerAborted) {
                throw createServiceError({
                    code: "aborted",
                    message: "The report fetch was cancelled.",
                    retryable: true,
                    ...context
                });
            }
            throw createServiceError({
                code: "network_or_cors",
                message: "The report could not be fetched. The site may be unavailable or may not allow browser cross-origin access.",
                retryable: true,
                details: { cause: toCauseString(error) },
                ...context
            });
        } finally {
            globalThis.clearTimeout(timeout);
            options.signal?.removeEventListener("abort", abortFromCaller);
        }
    }
}

export function normalizeUrlExtractionFailure(
    error: unknown,
    context: ExtractionContext = {}
): UrlExtractionError {
    if (error instanceof UrlExtractionServiceError) {
        return error.error;
    }
    return {
        sourceType: URL_EXTRACTION_SOURCE_TYPE,
        code: "network_or_cors",
        message: "The report could not be fetched. The site may be unavailable or may not allow browser cross-origin access.",
        retryable: true,
        details: { cause: toCauseString(error) },
        ...context
    };
}

function validatePublicHttpsUrl(rawUrl: string): URL {
    let url: URL;
    try {
        url = new URL(rawUrl.trim());
    } catch {
        throw createServiceError({
            code: "invalid_url",
            message: "Enter a valid HTTPS report URL.",
            retryable: false
        });
    }
    url.hash = "";
    if (url.protocol !== "https:" || !url.hostname || url.username || url.password) {
        throw createServiceError({
            code: "invalid_url",
            message: "Enter a public HTTPS URL without embedded credentials.",
            retryable: false,
            requestedUrl: url.toString()
        });
    }
    if (isObviouslyLocalDestination(url.hostname)) {
        throw createServiceError({
            code: "invalid_url",
            message: "Local and private-network URLs are not supported.",
            retryable: false,
            requestedUrl: url.toString()
        });
    }
    return url;
}

function isObviouslyLocalDestination(rawHostname: string): boolean {
    const hostname = rawHostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
    if (
        hostname === "localhost"
        || hostname.endsWith(".localhost")
        || hostname.endsWith(".local")
        || hostname === "metadata.google.internal"
        || hostname === "::"
        || hostname === "::1"
        || hostname.startsWith("fe80:")
        || (hostname.includes(":") && (hostname.startsWith("fc") || hostname.startsWith("fd")))
    ) {
        return true;
    }

    const octets = hostname.split(".").map(Number);
    if (octets.length !== 4 || octets.some(value => !Number.isInteger(value) || value < 0 || value > 255)) {
        return false;
    }
    const [first, second] = octets;
    return first === 0
        || first === 10
        || first === 127
        || (first === 100 && second >= 64 && second <= 127)
        || (first === 169 && second === 254)
        || (first === 172 && second >= 16 && second <= 31)
        || (first === 192 && second === 168)
        || first >= 224
        || hostname === "100.100.100.200";
}

function parseSupportedContentType(
    contentType: string | undefined,
    context: ExtractionContext
): { value: string, charset?: string } {
    if (!contentType) {
        throw createServiceError({
            code: "unsupported_content_type",
            message: "The report response did not identify HTML content.",
            retryable: false,
            ...context
        });
    }
    const [rawMediaType, ...parameters] = contentType.split(";");
    const mediaType = rawMediaType.trim().toLowerCase();
    if (!(URL_EXTRACTION_SUPPORTED_CONTENT_TYPES as readonly string[]).includes(mediaType)) {
        throw createServiceError({
            code: "unsupported_content_type",
            message: `The URL returned unsupported content type '${mediaType || "unknown"}'.`,
            retryable: false,
            contentType,
            ...context
        });
    }
    const charsetParameter = parameters
        .map(parameter => parameter.trim())
        .find(parameter => parameter.toLowerCase().startsWith("charset="));
    const charset = charsetParameter?.slice(charsetParameter.indexOf("=") + 1).trim().replace(/^['"]|['"]$/g, "");
    return { value: mediaType, ...(charset ? { charset } : {}) };
}

function createTextDecoder(charset: string | undefined, context: ExtractionContext): TextDecoder {
    try {
        return new TextDecoder(charset || "utf-8", { fatal: false });
    } catch (error) {
        throw createServiceError({
            code: "unsupported_charset",
            message: `The report uses unsupported character encoding '${charset}'.`,
            retryable: false,
            details: { cause: toCauseString(error) },
            ...context
        });
    }
}

async function readBoundedResponseBody(
    response: Response,
    maxResponseBytes: number,
    context: ExtractionContext
): Promise<{ body: Uint8Array, sizeBytes: number }> {
    const declaredLength = Number(response.headers.get("content-length"));
    if (Number.isFinite(declaredLength) && declaredLength > maxResponseBytes) {
        void response.body?.cancel().catch(() => undefined);
        throw responseTooLarge(maxResponseBytes, context);
    }
    if (!response.body) {
        throw createServiceError({
            code: "no_extractable_text",
            message: "The report response did not contain a readable body.",
            retryable: false,
            ...context
        });
    }

    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let sizeBytes = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) {
                break;
            }
            sizeBytes += value.byteLength;
            if (sizeBytes > maxResponseBytes) {
                void reader.cancel().catch(() => undefined);
                throw responseTooLarge(maxResponseBytes, context);
            }
            chunks.push(value);
        }
        const body = new Uint8Array(sizeBytes);
        let offset = 0;
        for (const chunk of chunks) {
            body.set(chunk, offset);
            offset += chunk.byteLength;
        }
        return { body, sizeBytes };
    } finally {
        reader.releaseLock();
    }
}

function detectBomCharset(body: Uint8Array): string | undefined {
    if (body[0] === 0xEF && body[1] === 0xBB && body[2] === 0xBF) {
        return "utf-8";
    }
    if (body[0] === 0xFF && body[1] === 0xFE) {
        return "utf-16le";
    }
    if (body[0] === 0xFE && body[1] === 0xFF) {
        return "utf-16be";
    }
    return undefined;
}

function detectHtmlMetaCharset(body: Uint8Array): string | undefined {
    const prefix = new TextDecoder("windows-1252").decode(body.slice(0, 4096));
    for (const match of prefix.matchAll(/<meta\b[^>]*>/gi)) {
        const attributes = parseHtmlTagAttributes(match[0]);
        if (attributes.charset) {
            return attributes.charset;
        }
        if (attributes["http-equiv"]?.toLowerCase() === "content-type" && attributes.content) {
            const charset = attributes.content.match(/(?:^|;)\s*charset\s*=\s*([^\s;]+)/i)?.[1];
            if (charset) {
                return charset;
            }
        }
    }
    return undefined;
}

function parseHtmlTagAttributes(tag: string): Record<string, string> {
    const attributes: Record<string, string> = {};
    const pattern = /([^\s=/>]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/g;
    for (const match of tag.matchAll(pattern)) {
        attributes[match[1].toLowerCase()] = match[2] ?? match[3] ?? match[4] ?? "";
    }
    return attributes;
}

function normalizeCanonicalUrl(value: string | undefined, finalUrl: string): string | undefined {
    if (!value) {
        return undefined;
    }
    try {
        return validatePublicHttpsUrl(new URL(value, finalUrl).toString()).toString();
    } catch {
        return undefined;
    }
}

function responseTooLarge(maxResponseBytes: number, context: ExtractionContext): UrlExtractionServiceError {
    return createServiceError({
        code: "response_too_large",
        message: `The report exceeds the ${maxResponseBytes}-byte browser fetch limit.`,
        retryable: false,
        ...context
    });
}

function createServiceError(error: Omit<UrlExtractionError, "sourceType">): UrlExtractionServiceError {
    return new UrlExtractionServiceError({ sourceType: URL_EXTRACTION_SOURCE_TYPE, ...error });
}

function normalizePositiveLimit(value: number | undefined, fallback: number): number {
    return typeof value === "number" && Number.isFinite(value) && value > 0
        ? Math.floor(value)
        : fallback;
}

function toCauseString(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}
