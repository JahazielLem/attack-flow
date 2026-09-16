import type {
    BrowserProviderError,
    ProviderValidationRequest,
    ProviderValidationResult,
    StructuredGenerationRequest,
    StructuredGenerationResult,
    StructuredResponseFormat,
    StructuredFinishReason,
    ProviderTokenUsage,
    StructuredJsonValue
} from "./ProviderContracts";
import type { RuntimeProviderConfig } from "../Configuration";
import { ProviderAdapterInvocationError } from "./ProviderAdapter";
import type { ProviderAdapter } from "./ProviderAdapter";

export { ProviderAdapterInvocationError } from "./ProviderAdapter";

const DEFAULT_TIMEOUT_SECONDS = 10;
const DEFAULT_VALIDATE_PROMPT = "ping";

interface RequestContext {
    providerId: string;
    providerType: RuntimeProviderConfig["providerType"];
    endpoint: string;
    apiKey: string;
    useAzure?: boolean;
    azureApiVersion?: string;
    extraHeaders?: Record<string, string>;
    model: string;
}

/**
 * Browser-side OpenAI-compatible adapter.
 *
 * Supports direct validation and structured generation calls against a user-
 * defined endpoint, while normalizing failures into client-side provider
 * errors. Orchestration and final AFB shaping remain outside this adapter.
 */
export class OpenAICompatibleProviderAdapter implements ProviderAdapter {
    public readonly providerId: string;
    public readonly providerType: RuntimeProviderConfig["providerType"];

    private readonly provider: RuntimeProviderConfig;

    constructor(provider: RuntimeProviderConfig) {
        this.provider = provider;
        this.providerId = this.buildProviderId(provider);
        this.providerType = provider.providerType;
    }

    async validate(request: ProviderValidationRequest): Promise<ProviderValidationResult> {
        const started = Date.now();
        const context = this.resolveRequestContext(request, "validate");
        const response = await this.requestJson({
            operation: "validate",
            path: this.buildRequestPath(context.providerType, context.model),
            timeoutSeconds: request.timeoutSeconds,
            body: this.buildRequestBody({
                providerType: context.providerType,
                model: context.model,
                prompt: DEFAULT_VALIDATE_PROMPT,
                maxOutputTokens: 16
            }),
            apiKey: context.apiKey,
            endpoint: context.endpoint,
            useAzure: context.useAzure,
            azureApiVersion: context.azureApiVersion,
            extraHeaders: context.extraHeaders,
            providerId: context.providerId,
            providerType: context.providerType
        });

        return this.normalizeValidationResult({
            response,
            started,
            model: context.model,
            providerId: context.providerId,
            providerType: context.providerType
        });
    }

    private normalizeValidationResult(params: {
        response: Record<string, unknown>;
        started: number;
        model: string;
        providerId: string;
        providerType: RuntimeProviderConfig["providerType"];
    }): ProviderValidationResult {
        return {
            providerId: params.providerId,
            providerType: params.providerType,
            isValid: true,
            checkedModel: params.model,
            latencyMs: Date.now() - params.started,
            details: this.extractDetails(params.response)
        };
    }

    async generateStructured(
        request: StructuredGenerationRequest
    ): Promise<StructuredGenerationResult> {
        const started = Date.now();
        const context = this.resolveRequestContext(request, "structured_generation");
        const response = await this.requestJson({
            operation: "structured_generation",
            path: this.buildRequestPath(context.providerType, context.model),
            timeoutSeconds: request.timeoutSeconds,
            body: this.buildRequestBody({
                providerType: context.providerType,
                model: context.model,
                prompt: request.prompt,
                responseFormat: request.responseFormat,
                temperature: request.temperature,
                maxOutputTokens: request.maxOutputTokens
            }),
            apiKey: context.apiKey,
            endpoint: context.endpoint,
            useAzure: context.useAzure,
            azureApiVersion: context.azureApiVersion,
            extraHeaders: context.extraHeaders,
            providerId: context.providerId,
            providerType: context.providerType
        });

        const outputText = this.extractOutputText(response);
        const outputJson = this.extractOutputJson(outputText, request.responseFormat, context.providerType);

        return {
            providerId: context.providerId,
            providerType: context.providerType,
            model: context.model,
            finishReason: this.extractFinishReason(response),
            outputText,
            outputJson,
            usage: this.extractUsage(response),
            latencyMs: Date.now() - started,
            metadata: this.extractDetails(response)
        };
    }

    private buildProviderId(provider: RuntimeProviderConfig): string {
        return `runtime-${provider.providerType}`;
    }

    private resolveRequestContext(
        request: ProviderValidationRequest | StructuredGenerationRequest,
        operation: "validate" | "structured_generation"
    ): RequestContext {
        const providerType = request.providerType ?? this.providerType;
        const providerId = request.providerId ?? this.providerId;
        const endpoint = (request.endpoint || this.provider.endpoint).trim();
        const apiKey = (request.apiKey ?? this.provider.apiKey).trim();
        const model = (request.model || this.provider.model || "").trim();
        const useAzure = request.useAzure ?? this.provider.useAzure;
        const azureApiVersion = (request.azureApiVersion ?? this.provider.azureApiVersion ?? "").trim();

        if (!model) {
            throw this.createError({
                operation,
                code: "provider_configuration_error",
                category: "configuration_error",
                message: "provider model is required",
                retryable: false
            });
        }

        return {
            providerId,
            providerType,
            endpoint,
            apiKey,
            useAzure,
            azureApiVersion: azureApiVersion || undefined,
            extraHeaders: request.extraHeaders ?? this.provider.extraHeaders,
            model
        };
    }

    /**
     * Builds the raw structured-generation request body.
     * The prompt is passed through as-is for later orchestration layers.
     */
    private buildRequestBody(params: {
        providerType: RuntimeProviderConfig["providerType"];
        model: string;
        prompt: string;
        responseFormat?: StructuredResponseFormat;
        temperature?: number;
        maxOutputTokens?: number;
    }): Record<string, unknown> {
        if (params.providerType === "gemini") {
            const generationConfig: Record<string, unknown> = {};
            if (typeof params.temperature === "number") {
                generationConfig.temperature = params.temperature;
            }
            if (typeof params.maxOutputTokens === "number") {
                generationConfig.maxOutputTokens = params.maxOutputTokens;
            }
            if (params.responseFormat === "json_object") {
                generationConfig.responseMimeType = "application/json";
            }

            return {
                contents: [
                    {
                        role: "user",
                        parts: [{ text: params.prompt }]
                    }
                ],
                generationConfig
            };
        }

        const body: Record<string, unknown> = { model: params.model, input: params.prompt };

        if (typeof params.maxOutputTokens === "number") {
            body.max_output_tokens = params.maxOutputTokens;
        }
        if (typeof params.temperature === "number") {
            body.temperature = params.temperature;
        }
        if (params.responseFormat === "json_object") {
            body.response_format = { type: "json_object" };
        }

        return body;
    }

    private async requestJson(params: {
        operation: "validate" | "structured_generation";
        path: string;
        timeoutSeconds?: number;
        body: Record<string, unknown>;
        apiKey?: string;
        endpoint: string;
        useAzure?: boolean;
        azureApiVersion?: string;
        extraHeaders?: Record<string, string>;
        providerId: string;
        providerType: RuntimeProviderConfig["providerType"];
    }): Promise<Record<string, unknown>> {
        const endpoint = params.endpoint.trim();
        const apiKey = (params.apiKey || "").trim();
        if (!endpoint) {
            throw this.createError({
                operation: params.operation,
                code: "provider_configuration_error",
                category: "configuration_error",
                message: "provider endpoint is required",
                retryable: false,
                providerId: params.providerId,
                providerType: params.providerType
            });
        }
        if (!apiKey) {
            throw this.createError({
                operation: params.operation,
                code: "provider_configuration_error",
                category: "configuration_error",
                message: "provider api key is required",
                retryable: false,
                providerId: params.providerId,
                providerType: params.providerType
            });
        }

        const controller = new AbortController();
        const timeoutSeconds = params.timeoutSeconds ?? (params.providerType === "gemini" ? 300 : DEFAULT_TIMEOUT_SECONDS);
        const timeoutMs = 1000 * timeoutSeconds;
        const timer = globalThis.setTimeout(() => controller.abort(), timeoutMs);
        const isGemini = params.providerType === "gemini";
        const url = this.buildRequestUrl(endpoint, params.path, params.useAzure ? params.azureApiVersion : undefined, isGemini ? apiKey : undefined);
        const headers = isGemini
            ? {
                "Content-Type": "application/json",
                ...params.extraHeaders
            }
            : params.useAzure
                ? {
                    "api-key": apiKey,
                    "Content-Type": "application/json",
                    ...params.extraHeaders
                }
                : {
                    "Authorization": `Bearer ${apiKey}`,
                    "Content-Type": "application/json",
                    ...params.extraHeaders
                };

        try {
            const response = await fetch(url, {
                method: "POST",
                signal: controller.signal,
                headers,
                body: JSON.stringify(params.body)
            });

            if (!response.ok) {
                throw this.mapHttpError(response.status, params);
            }

            try {
                return await response.json() as Record<string, unknown>;
            } catch {
                throw this.createError({
                    operation: params.operation,
                    code: "provider_invalid_response",
                    category: "invalid_response",
                    message: "provider response was not valid json",
                    retryable: false,
                    statusCode: response.status,
                    providerId: params.providerId,
                    providerType: params.providerType
                });
            }
        } catch (err) {
            if (err instanceof ProviderAdapterInvocationError) {
                throw err;
            }
            if (err instanceof DOMException && err.name === "AbortError") {
                throw this.createError({
                    operation: params.operation,
                    code: "provider_timeout",
                    category: "timeout",
                    message: "provider request timed out",
                    retryable: true,
                    providerId: params.providerId,
                    providerType: params.providerType
                });
            }
            if (err instanceof TypeError) {
                throw this.createError({
                    operation: params.operation,
                    code: "provider_network_error",
                    category: "network_error",
                    message: "provider request failed",
                    retryable: true,
                    providerId: params.providerId,
                    providerType: params.providerType,
                    details: { cause: "network_or_cors" }
                });
            }
            throw err;
        } finally {
            clearTimeout(timer);
        }
    }

    private mapHttpError(
        statusCode: number,
        params: {
            operation: "validate" | "structured_generation";
            providerId: string;
            providerType: RuntimeProviderConfig["providerType"];
        }
    ): ProviderAdapterInvocationError {
        if (statusCode === 401 || statusCode === 403) {
            return this.createError({
                operation: params.operation,
                code: "provider_auth_failure",
                category: "auth_failure",
                message: "provider authentication failed",
                retryable: false,
                statusCode,
                providerId: params.providerId,
                providerType: params.providerType
            });
        }

        if (statusCode === 408 || statusCode === 429 || (500 <= statusCode && statusCode < 600)) {
            return this.createError({
                operation: params.operation,
                code: statusCode === 408 ? "provider_timeout" : "provider_unavailable",
                category: statusCode === 408 ? "timeout" : "unavailable",
                message: statusCode === 408
                    ? "provider request timed out"
                    : "provider is unavailable",
                retryable: true,
                statusCode,
                providerId: params.providerId,
                providerType: params.providerType
            });
        }

        return this.createError({
            operation: params.operation,
            code: "provider_unavailable",
            category: "unavailable",
            message: "provider request failed",
            retryable: true,
            statusCode,
            providerId: params.providerId,
            providerType: params.providerType
        });
    }

    private extractOutputText(response: Record<string, unknown>): string {
        const outputText = response.output_text;
        if (typeof outputText === "string") {
            return outputText;
        }

        const candidates = response.candidates;
        if (Array.isArray(candidates) && candidates.length > 0) {
            const first = candidates[0];
            if (first && typeof first === "object") {
                const content = (first as Record<string, unknown>).content;
                if (content && typeof content === "object") {
                    const parts = (content as Record<string, unknown>).parts;
                    if (Array.isArray(parts)) {
                        return parts
                            .map(part => part && typeof part === "object" ? (part as Record<string, unknown>).text : "")
                            .filter((text): text is string => typeof text === "string" && text.length > 0)
                            .join("");
                    }
                }
            }
        }

        const choices = response.choices;
        if (Array.isArray(choices) && choices.length > 0) {
            const first = choices[0];
            if (first && typeof first === "object") {
                const message = (first as Record<string, unknown>).message;
                if (message && typeof message === "object") {
                    const content = (message as Record<string, unknown>).content;
                    if (typeof content === "string") {
                        return content;
                    }
                }
            }
        }

        return "";
    }

    private extractOutputJson(
        outputText: string,
        responseFormat: StructuredResponseFormat | undefined,
        providerType: RuntimeProviderConfig["providerType"]
    ): StructuredJsonValue | undefined {
        if (responseFormat !== "json_object") {
            return undefined;
        }

        try {
            const parsed = JSON.parse(outputText) as unknown;
            if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
                return providerType === "gemini"
                    ? this.normalizeGeminiStructuredOutput(parsed as Record<string, unknown>)
                    : parsed as StructuredJsonValue;
            }
        } catch {
            // fall through
        }

        throw this.createError({
            operation: "structured_generation",
            code: "provider_invalid_response",
            category: "invalid_response",
            message: "provider output was not valid json",
            retryable: false
        });
    }

    private normalizeGeminiStructuredOutput(value: Record<string, unknown>): StructuredJsonValue {
        return this.normalizeGeminiValue(value, false) as StructuredJsonValue;
    }

    private normalizeGeminiValue(value: unknown, inConfidenceField: boolean): unknown {
        if (Array.isArray(value)) {
            return value.map((item) => this.normalizeGeminiValue(item, false));
        }

        if (!value || typeof value !== "object") {
            return inConfidenceField ? 0 : value;
        }

        const record = value as Record<string, unknown>;
        const normalized: Record<string, unknown> = {};

        for (const [key, child] of Object.entries(record)) {
            normalized[key] = this.normalizeGeminiValue(child, key === "confidence");
        }

        if (typeof normalized.schema_version !== "string" && typeof normalized.version === "string") {
            normalized.schema_version = normalized.version;
        }

        if (this.isGeminiAttackNode(normalized) && typeof normalized.spec_version !== "string") {
            normalized.spec_version = "2.1";
        }
        normalized.confidence = 0;
        normalized.evidence = this.normalizeGeminiEvidence(normalized);

        return normalized;
    }

    private normalizeGeminiConfidence(value: unknown): number | undefined {
        if (typeof value === "number" && Number.isFinite(value)) {
            return value > 1 && value <= 100 ? value / 100 : value;
        }

        if (typeof value === "string") {
            const parsed = Number(value.trim());
            if (Number.isFinite(parsed)) {
                return parsed > 1 && parsed <= 100 ? parsed / 100 : parsed;
            }
        }

        return undefined;
    }

    private normalizeGeminiEvidence(value: Record<string, unknown>): unknown {
        if (Array.isArray(value.evidence) && value.evidence.length > 0) {
            return value.evidence;
        }

        if ((value.type === "attack-action" || value.type === "attack-condition") && typeof value.description === "string" && value.description.trim()) {
            return [{ source: "source", excerpt: value.description.trim() }];
        }

        if (value.type === "attack-operator" && typeof value.operator === "string" && value.operator.trim()) {
            return [{ source: "source", excerpt: value.operator.trim() }];
        }

        if (value.type === "attack-asset") {
            const excerpt = typeof value.description === "string" && value.description.trim()
                ? value.description.trim()
                : typeof value.name === "string" && value.name.trim()
                    ? value.name.trim()
                    : undefined;

            if (excerpt) {
                return [{ source: "source", excerpt }];
            }
        }

        return value.evidence;
    }

    private isGeminiAttackNode(value: Record<string, unknown>): boolean {
        return value.type === "attack-flow"
            || value.type === "attack-action"
            || value.type === "attack-condition"
            || value.type === "attack-operator"
            || value.type === "attack-asset";
    }

    private extractFinishReason(response: Record<string, unknown>): StructuredFinishReason {
        const finishReason = response.finish_reason;
        if (
            finishReason === "stop"
            || finishReason === "length"
            || finishReason === "content_filter"
            || finishReason === "tool_call"
        ) {
            return finishReason;
        }

        const candidates = response.candidates;
        if (Array.isArray(candidates) && candidates.length > 0) {
            const first = candidates[0];
            if (first && typeof first === "object") {
                const geminiFinishReason = (first as Record<string, unknown>).finishReason;
                if (typeof geminiFinishReason === "string") {
                    switch (geminiFinishReason.toUpperCase()) {
                        case "STOP":
                            return "stop";
                        case "MAX_TOKENS":
                            return "length";
                        case "SAFETY":
                        case "BLOCKED":
                        case "PROHIBITED_CONTENT":
                        case "SPII":
                            return "content_filter";
                        case "MALFORMED_FUNCTION_CALL":
                            return "tool_call";
                        default:
                            return "unknown";
                    }
                }
            }
        }
        return "unknown";
    }

    private extractUsage(response: Record<string, unknown>): ProviderTokenUsage | undefined {
        const usage = response.usage;
        if (!usage || typeof usage !== "object") {
            const usageMetadata = response.usageMetadata;
            if (!usageMetadata || typeof usageMetadata !== "object") {
                return undefined;
            }

            const metadata = usageMetadata as Record<string, unknown>;
            const inputTokens = this.toNumber(metadata.promptTokenCount);
            const outputTokens = this.toNumber(metadata.candidatesTokenCount);
            const totalTokens = this.toNumber(metadata.totalTokenCount);

            if (inputTokens === undefined && outputTokens === undefined && totalTokens === undefined) {
                return undefined;
            }

            return {
                inputTokens,
                outputTokens,
                totalTokens
            };
        }

        const record = usage as Record<string, unknown>;
        const inputTokens = this.toNumber(record.input_tokens ?? record.prompt_tokens);
        const outputTokens = this.toNumber(record.output_tokens ?? record.completion_tokens);
        const totalTokens = this.toNumber(record.total_tokens);

        if (
            inputTokens === undefined
            && outputTokens === undefined
            && totalTokens === undefined
        ) {
            return undefined;
        }

        return {
            inputTokens,
            outputTokens,
            totalTokens
        };
    }

    private extractDetails(response: Record<string, unknown>): Record<string, string> {
        const requestId = response.request_id;
        return typeof requestId === "string" && requestId.trim()
            ? { request_id: requestId }
            : {};
    }

    private toNumber(value: unknown): number | undefined {
        return typeof value === "number" && Number.isFinite(value) ? value : undefined;
    }

    private buildRequestUrl(endpoint: string, path: string, apiVersion?: string, apiKey?: string): string {
        try {
            const url = new URL(endpoint.trim());
            url.pathname = `${url.pathname.replace(/\/+$/, "")}${path}`;
            if (apiVersion) {
                url.searchParams.set("api-version", apiVersion);
            }
            if (apiKey) {
                url.searchParams.set("key", apiKey);
            }
            return url.toString();
        } catch {
            const base = endpoint.replace(/\/+$/, "");
            const url = `${base}${path}`;
            let withQuery = apiVersion ? `${url}${url.includes("?") ? "&" : "?"}api-version=${encodeURIComponent(apiVersion)}` : url;
            if (apiKey) {
                withQuery += withQuery.includes("?") ? "&" : "?";
                withQuery += `key=${encodeURIComponent(apiKey)}`;
            }
            return withQuery;
        }
    }

    private buildRequestPath(providerType: RuntimeProviderConfig["providerType"], model: string): string {
        if (providerType === "gemini") {
            return `/models/${encodeURIComponent(model)}:generateContent`;
        }

        return "/responses";
    }

    private createError(params: {
        operation: "validate" | "structured_generation";
        code: BrowserProviderError["code"];
        category: BrowserProviderError["category"];
        message: string;
        retryable: boolean;
        statusCode?: number;
        providerId?: string;
        providerType?: RuntimeProviderConfig["providerType"];
        details?: Record<string, string>;
    }): ProviderAdapterInvocationError {
        return new ProviderAdapterInvocationError({
            category: params.category,
            code: params.code,
            message: params.message,
            retryable: params.retryable,
            operation: params.operation,
            statusCode: params.statusCode,
            providerId: params.providerId ?? this.providerId,
            providerType: params.providerType ?? this.providerType,
            details: params.details
        });
    }
}
