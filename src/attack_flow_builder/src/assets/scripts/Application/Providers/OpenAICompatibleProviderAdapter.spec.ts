// @vitest-environment jsdom

import { beforeEach, describe, expect, it, vi } from "vitest";
import { OpenAICompatibleProviderAdapter, ProviderAdapterInvocationError } from "./OpenAICompatibleProviderAdapter";

const provider = {
    providerType: "openai_compatible" as const,
    endpoint: "https://provider.example/v1",
    apiKey: "secret-key",
    model: "gpt-4o-mini"
};

describe("OpenAICompatibleProviderAdapter", () => {
    beforeEach(() => {
        vi.unstubAllGlobals();
    });

    it("builds validation requests against the responses endpoint", async () => {
        const fetchMock = vi.fn(async () => new Response(JSON.stringify({ request_id: "req_123" }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
        }));
        vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);

        const adapter = new OpenAICompatibleProviderAdapter(provider);
        const result = await adapter.validate({
            providerType: "openai_compatible",
            endpoint: provider.endpoint,
            apiKey: provider.apiKey,
            model: provider.model,
            timeoutSeconds: 5
        });

        expect(fetchMock).toHaveBeenCalledTimes(1);
        const [url, init] = fetchMock.mock.calls[0] as unknown as [unknown, RequestInit];
        expect(url).toBe("https://provider.example/v1/responses");
        expect(init.method).toBe("POST");
        expect((init.headers as Record<string, string>).Authorization).toBe("Bearer secret-key");
        expect(JSON.parse(String(init.body))).toMatchObject({
            model: "gpt-4o-mini",
            input: "ping",
            max_output_tokens: 16
        });
        expect(result.isValid).toBe(true);
        expect(result.checkedModel).toBe("gpt-4o-mini");
    });

    it("normalizes validation authentication failures", async () => {
        const fetchMock = vi.fn(async () => new Response("", {
            status: 401,
            headers: { "Content-Type": "application/json" }
        }));
        vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);

        const adapter = new OpenAICompatibleProviderAdapter(provider);

        await expect(adapter.validate({
            providerType: "openai_compatible",
            endpoint: provider.endpoint,
            apiKey: provider.apiKey,
            model: provider.model
        })).rejects.toMatchObject({
            error: {
                category: "auth_failure",
                code: "provider_auth_failure",
                retryable: false,
                operation: "validate"
            }
        });
    });

    it("normalizes validation configuration failures", async () => {
        const adapter = new OpenAICompatibleProviderAdapter({
            ...provider,
            model: ""
        });

        await expect(adapter.validate({
            providerType: "openai_compatible",
            endpoint: provider.endpoint,
            apiKey: provider.apiKey
        })).rejects.toMatchObject({
            error: {
                category: "configuration_error",
                code: "provider_configuration_error",
                retryable: false,
                operation: "validate"
            }
        });
    });

    it("normalizes invalid validation responses", async () => {
        const fetchMock = vi.fn(async () => new Response("not-json", {
            status: 200,
            headers: { "Content-Type": "application/json" }
        }));
        vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);

        const adapter = new OpenAICompatibleProviderAdapter(provider);

        await expect(adapter.validate({
            providerType: "openai_compatible",
            endpoint: provider.endpoint,
            apiKey: provider.apiKey,
            model: provider.model
        })).rejects.toMatchObject({
            error: {
                category: "invalid_response",
                code: "provider_invalid_response",
                retryable: false,
                operation: "validate"
            }
        });
    });

    it("normalizes validation timeout failures", async () => {
        vi.stubGlobal("fetch", vi.fn((_url: string, init?: RequestInit) => new Promise((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () => {
                reject(new DOMException("The operation was aborted.", "AbortError"));
            });
        })) as unknown as typeof fetch);

        const adapter = new OpenAICompatibleProviderAdapter(provider);

        await expect(adapter.validate({
            providerType: "openai_compatible",
            endpoint: provider.endpoint,
            apiKey: provider.apiKey,
            model: provider.model,
            timeoutSeconds: 0
        })).rejects.toMatchObject({
            error: {
                category: "timeout",
                code: "provider_timeout",
                retryable: true,
                operation: "validate"
            }
        });
    });

    it("normalizes validation unavailable failures", async () => {
        vi.stubGlobal("fetch", vi.fn(async () => new Response("", {
            status: 503,
            headers: { "Content-Type": "application/json" }
        })) as unknown as typeof fetch);

        const adapter = new OpenAICompatibleProviderAdapter(provider);

        await expect(adapter.validate({
            providerType: "openai_compatible",
            endpoint: provider.endpoint,
            apiKey: provider.apiKey,
            model: provider.model
        })).rejects.toMatchObject({
            error: {
                category: "unavailable",
                code: "provider_unavailable",
                retryable: true,
                operation: "validate"
            }
        });
    });

    it("normalizes validation network and cors failures", async () => {
        vi.stubGlobal("fetch", vi.fn(async () => {
            throw new TypeError("failed to fetch");
        }) as unknown as typeof fetch);

        const adapter = new OpenAICompatibleProviderAdapter(provider);

        await expect(adapter.validate({
            providerType: "openai_compatible",
            endpoint: provider.endpoint,
            apiKey: provider.apiKey,
            model: provider.model
        })).rejects.toMatchObject({
            error: {
                category: "network_error",
                code: "provider_network_error",
                retryable: true,
                operation: "validate"
            }
        });
    });

    it("builds structured generation requests and parses text output", async () => {
        const fetchMock = vi.fn(async () => new Response(JSON.stringify({
            output_text: "{\"ok\":true}",
            finish_reason: "stop",
            usage: { total_tokens: 3 },
            request_id: "req_456"
        }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
        }));
        vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);

        const adapter = new OpenAICompatibleProviderAdapter(provider);
        const result = await adapter.generateStructured({
            providerType: "openai_compatible",
            endpoint: provider.endpoint,
            apiKey: provider.apiKey,
            model: provider.model,
            prompt: "hello",
            responseFormat: "json_object"
        });

        expect(fetchMock).toHaveBeenCalledTimes(1);
        const [, init] = fetchMock.mock.calls[0] as unknown as [unknown, RequestInit];
        expect(JSON.parse(String(init.body))).toMatchObject({
            model: "gpt-4o-mini",
            input: "hello",
            response_format: { type: "json_object" }
        });
        expect(result.outputJson).toEqual({ ok: true });
        expect(result.finishReason).toBe("stop");
    });

    it("uses azure api-key auth and api-version when configured", async () => {
        const fetchMock = vi.fn(async () => new Response(JSON.stringify({ request_id: "req_azure" }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
        }));
        vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);

        const adapter = new OpenAICompatibleProviderAdapter({
            ...provider,
            useAzure: true,
            azureApiVersion: "2025-04-01-preview"
        });

        await adapter.validate({
            providerType: "openai_compatible",
            endpoint: provider.endpoint,
            apiKey: provider.apiKey,
            model: provider.model,
            useAzure: true,
            azureApiVersion: "2025-04-01-preview"
        });

        expect(fetchMock).toHaveBeenCalledTimes(1);
        const [url, init] = fetchMock.mock.calls[0] as unknown as [unknown, RequestInit];
        expect(url).toBe("https://provider.example/v1/responses?api-version=2025-04-01-preview");
        expect((init.headers as Record<string, string>)["api-key"]).toBe("secret-key");
        expect((init.headers as Record<string, string>).Authorization).toBeUndefined();
    });

    it("builds gemini validation and generation requests", async () => {
        const fetchMock = vi.fn(async () => new Response(JSON.stringify({
            candidates: [
                {
                    content: {
                        parts: [{ text: JSON.stringify({
                            version: "afb-v2-intermediate",
                            validation_state: "valid",
                            repair_attempted: false,
                            provider_invoked: true,
                            attack_flow: { id: "attack-flow--1", type: "attack-flow" },
                            attack_actions: [{ id: "attack-action--1", type: "attack-action", confidence: 80, description: "Launch process" }],
                            attack_conditions: [],
                            attack_operators: [],
                            attack_assets: [],
                            deterministic_attack_refs: [],
                            deterministic_entities: [],
                            deterministic_relationships: []
                        }) }]
                    },
                    finishReason: "STOP"
                }
            ],
            usageMetadata: {
                promptTokenCount: 2,
                candidatesTokenCount: 3,
                totalTokenCount: 5
            },
            responseId: "resp_gemini"
        }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
        }));
        vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);

        const adapter = new OpenAICompatibleProviderAdapter({
            ...provider,
            providerType: "gemini",
            endpoint: "https://generativelanguage.googleapis.com/v1beta"
        });

        const validation = await adapter.validate({
            providerType: "gemini",
            endpoint: "https://generativelanguage.googleapis.com/v1beta",
            apiKey: provider.apiKey,
            model: "gemini-2.0-flash"
        });

        expect(fetchMock).toHaveBeenCalledTimes(1);
        const [validationUrl, validationInit] = fetchMock.mock.calls[0] as unknown as [unknown, RequestInit];
        expect(validationUrl).toBe("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=secret-key");
        expect((validationInit.headers as Record<string, string>).Authorization).toBeUndefined();
        expect((validationInit.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
        expect(JSON.parse(String(validationInit.body))).toMatchObject({
            contents: [{ role: "user", parts: [{ text: "ping" }] }],
            generationConfig: { maxOutputTokens: 16 }
        });
        expect(validation).toMatchObject({
            isValid: true,
            checkedModel: "gemini-2.0-flash"
        });

        const generation = await adapter.generateStructured({
            providerType: "gemini",
            endpoint: "https://generativelanguage.googleapis.com/v1beta",
            apiKey: provider.apiKey,
            model: "gemini-2.0-flash",
            prompt: "hello",
            responseFormat: "json_object"
        });

        expect(fetchMock).toHaveBeenCalledTimes(2);
        const [generationUrl, generationInit] = fetchMock.mock.calls[1] as unknown as [unknown, RequestInit];
        expect(generationUrl).toBe("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=secret-key");
        expect(JSON.parse(String(generationInit.body))).toMatchObject({
            contents: [{ role: "user", parts: [{ text: "hello" }] }],
            generationConfig: { responseMimeType: "application/json" }
        });
        expect(generation).toMatchObject({
            providerType: "gemini",
            model: "gemini-2.0-flash",
            finishReason: "stop",
            outputJson: expect.objectContaining({
                schema_version: "afb-v2-intermediate",
                attack_actions: [
                    expect.objectContaining({
                        spec_version: "2.1",
                        confidence: 0,
                        evidence: [
                            expect.objectContaining({
                                source: "source",
                                excerpt: "Launch process"
                            })
                        ]
                    })
                ]
            }),
            usage: {
                inputTokens: 2,
                outputTokens: 3,
                totalTokens: 5
            }
        });
    });

    it("normalizes invalid structured generation responses", async () => {
        const fetchMock = vi.fn(async () => new Response(JSON.stringify({
            output_text: "not-json",
            finish_reason: "stop"
        }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
        }));
        vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);

        const adapter = new OpenAICompatibleProviderAdapter(provider);

        await expect(adapter.generateStructured({
            providerType: "openai_compatible",
            endpoint: provider.endpoint,
            apiKey: provider.apiKey,
            model: provider.model,
            prompt: "hello",
            responseFormat: "json_object"
        })).rejects.toMatchObject({
            error: {
                category: "invalid_response",
                code: "provider_invalid_response",
                retryable: false,
                operation: "structured_generation"
            }
        });
    });

    it("normalizes structured generation network failures", async () => {
        vi.stubGlobal("fetch", vi.fn(async () => {
            throw new TypeError("failed to fetch");
        }) as unknown as typeof fetch);

        const adapter = new OpenAICompatibleProviderAdapter(provider);

        await expect(adapter.generateStructured({
            providerType: "openai_compatible",
            endpoint: provider.endpoint,
            apiKey: provider.apiKey,
            model: provider.model,
            prompt: "hello"
        })).rejects.toBeInstanceOf(ProviderAdapterInvocationError);
    });

    it("normalizes network failures", async () => {
        vi.stubGlobal("fetch", vi.fn(async () => {
            throw new TypeError("failed to fetch");
        }) as typeof fetch);

        const adapter = new OpenAICompatibleProviderAdapter(provider);

        await expect(adapter.validate({
            providerType: "openai_compatible",
            endpoint: provider.endpoint,
            apiKey: provider.apiKey,
            model: provider.model
        })).rejects.toBeInstanceOf(ProviderAdapterInvocationError);
    });
});
