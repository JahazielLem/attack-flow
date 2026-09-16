import { describe, expect, it } from "vitest";
import type {
    BrowserProviderError,
    ProviderValidationRequest,
    ProviderValidationResult,
    StructuredGenerationRequest,
    StructuredGenerationResult
} from "./ProviderContracts";
import {
    PROVIDER_ERROR_CATEGORIES,
    PROVIDER_ERROR_CODES
} from "./ProviderContracts";

describe("ProviderContracts", () => {
    it("defines validation request and result shapes", () => {
        const request: ProviderValidationRequest = {
            providerType: "openai_compatible",
            endpoint: "https://example.com/v1",
            apiKey: "secret",
            model: "gpt-4o-mini",
            timeoutSeconds: 5,
            metadata: { source: "ui" }
        };

        const result: ProviderValidationResult = {
            providerId: "runtime-openai_compatible",
            providerType: "openai_compatible",
            isValid: true,
            checkedModel: "gpt-4o-mini",
            latencyMs: 12,
            details: { request_id: "req_123" }
        };

        expect(request.providerType).toBe("openai_compatible");
        expect(result.isValid).toBe(true);
    });

    it("defines structured generation request and result shapes", () => {
        const request: StructuredGenerationRequest = {
            providerType: "openai_compatible",
            endpoint: "https://example.com/v1",
            apiKey: "secret",
            model: "gpt-4o-mini",
            prompt: "hello",
            responseFormat: "json_object",
            temperature: 0,
            maxOutputTokens: 32,
            metadata: { purpose: "test" }
        };

        const result: StructuredGenerationResult = {
            providerId: "runtime-openai_compatible",
            providerType: "openai_compatible",
            model: "gpt-4o-mini",
            finishReason: "unknown",
            outputText: "{}",
            outputJson: { nested: ["ok", 1, null] },
            usage: { totalTokens: 1 },
            latencyMs: 20,
            metadata: { request_id: "req_123" }
        };

        expect(request.responseFormat).toBe("json_object");
        expect(result.finishReason).toBe("unknown");
        expect(result.outputJson).toEqual({ nested: ["ok", 1, null] });
    });

    it("defines normalized browser provider error shapes", () => {
        const error: BrowserProviderError = {
            category: "network_error",
            code: "provider_network_error",
            message: "request failed",
            retryable: true,
            operation: "validate",
            providerType: "openai_compatible",
            details: { cause: "cors" }
        };

        expect(error.category).toBe("network_error");
        expect(error.retryable).toBe(true);
    });

    it("exposes stable provider error categories and codes", () => {
        expect(PROVIDER_ERROR_CATEGORIES).toContain("timeout");
        expect(PROVIDER_ERROR_CATEGORIES).toContain("network_error");
        expect(PROVIDER_ERROR_CODES).toContain("provider_timeout");
        expect(PROVIDER_ERROR_CODES).toContain("provider_configuration_error");
    });
});
