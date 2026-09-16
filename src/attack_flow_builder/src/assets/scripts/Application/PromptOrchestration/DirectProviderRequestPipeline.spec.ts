import { describe, expect, it } from "vitest";
import { buildDirectProviderRequestPipeline } from "./DirectProviderRequestPipeline";

describe("DirectProviderRequestPipeline", () => {
    it("builds a provider-agnostic request from normalized input", () => {
        const request = buildDirectProviderRequestPipeline({
            normalizedInput: {
                sourceType: "text",
                normalizedText: "Alpha",
                metadata: {
                    sourceName: "Pasted Text"
                }
            },
            provider: {
                providerType: "openai_compatible",
                endpoint: "https://example.com/v1",
                apiKey: "secret",
                model: "gpt-4o-mini"
            }
        });

        expect(request).toMatchObject({
            providerType: "openai_compatible",
            endpoint: "https://example.com/v1",
            apiKey: "secret",
            model: "gpt-4o-mini",
            responseFormat: "json_object",
            temperature: 0,
            metadata: {
                request_version: "v1",
                schema_name: "direct_provider_afb_intermediate",
                schema_version: "afb-v2-intermediate",
                mode: "direct_provider",
                prompt_mode: "full_extraction",
                source_type: "text",
                system_instruction_version: "v1"
            }
        });
        expect(request.prompt).toContain("SYSTEM_INSTRUCTION:");
        expect(request.prompt).toContain("PACKAGED_INPUT:");
    });

    it("builds a provider-agnostic request from normalized pdf input", () => {
        const request = buildDirectProviderRequestPipeline({
            normalizedInput: {
                sourceType: "pdf",
                normalizedText: "Alpha\n\nBeta",
                metadata: {
                    filename: "report.pdf",
                    sourceName: "PDF Upload",
                    pageCount: 2
                },
                contentStats: {
                    characterCount: 11,
                    wordCount: 2,
                    lineCount: 3,
                    paragraphCount: 2
                }
            },
            provider: {
                providerType: "openai_compatible",
                endpoint: "https://example.com/v1",
                apiKey: "secret",
                model: "gpt-4o-mini"
            }
        });

        expect(request).toMatchObject({
            providerType: "openai_compatible",
            endpoint: "https://example.com/v1",
            apiKey: "secret",
            responseFormat: "json_object",
            temperature: 0,
            metadata: {
                schema_name: "direct_provider_afb_intermediate",
                mode: "direct_provider",
                prompt_mode: "full_extraction",
                source_type: "pdf",
                schema_version: "afb-v2-intermediate"
            }
        });
        expect(request.prompt).toContain("\"source_type\": \"document_extracted_text\"");
        expect(request.prompt).toContain("\"original_name\": \"report.pdf\"");
        expect(request.prompt).toContain("\"page_count\": 2");
    });

    it("is deterministic for the same input", () => {
        const params = {
            normalizedInput: {
                sourceType: "text" as const,
                normalizedText: "Alpha\n\nBeta",
                metadata: {
                    sourceName: "Pasted Text"
                }
            },
            provider: {
                providerType: "openai_compatible" as const,
                endpoint: "https://example.com/v1",
                apiKey: "secret",
                model: "gpt-4o-mini"
            }
        };

        const first = buildDirectProviderRequestPipeline(params);
        const second = buildDirectProviderRequestPipeline(params);

        expect(first).toEqual(second);
    });

    it("packages URL-derived article text and provenance", () => {
        const request = buildDirectProviderRequestPipeline({
            normalizedInput: {
                sourceType: "url",
                normalizedText: "Actor executed PowerShell.",
                metadata: {
                    title: "Threat Report",
                    sourceName: "URL Fetch",
                    sourceUrl: "https://reports.example/start",
                    finalUrl: "https://reports.example/final",
                    canonicalUrl: "https://reports.example/article",
                    contentType: "text/html",
                    responseSizeBytes: 100
                },
                truncation: {
                    wasTruncated: true,
                    budgetCharacters: 100_000,
                    originalCharacterCount: 120_000
                }
            },
            provider: {
                providerType: "openai_compatible",
                endpoint: "https://provider.example/v1",
                apiKey: "secret",
                model: "gpt-4o-mini"
            }
        });

        expect(request.metadata?.prompt_source_type).toBe("url_extracted_text");
        expect(request.prompt).toContain("\"source_type\": \"url_extracted_text\"");
        expect(request.prompt).toContain("\"requested_url\": \"https://reports.example/start\"");
        expect(request.prompt).toContain("\"source_url\": \"https://reports.example/final\"");
        expect(request.prompt).toContain("\"canonical_url\": \"https://reports.example/article\"");
        expect(request.prompt).toContain("\"was_truncated\": true");
        expect(request.prompt).toContain("Actor executed PowerShell.");
    });

    it("supports the API enrichment prompt shape without changing provider output handling", () => {
        const request = buildDirectProviderRequestPipeline({
            normalizedInput: {
                sourceType: "text",
                normalizedText: "Narrative from report",
                metadata: {}
            },
            provider: {
                providerType: "openai_compatible",
                endpoint: "https://example.com/v1",
                apiKey: "secret",
                model: "gpt-4o-mini"
            },
            promptMode: "enrichment",
            promptSourceType: "stix_structured",
            promptContext: {
                deterministicAttackRefs: [{ technique_id: "T1059" }],
                deterministicEntities: [{ object_id: "malware--1" }],
                deterministicRelationships: [],
                provenance: { source: "bundle--1" }
            }
        });

        expect(request.metadata?.prompt_mode).toBe("enrichment");
        expect(request.prompt).toContain("\"mode\": \"enrichment\"");
        expect(request.prompt).toContain("\"source_type\": \"stix_structured\"");
        expect(request.prompt).toContain("\"deterministic_findings\": {");
        expect(request.prompt).toContain("\"technique_id\": \"T1059\"");
    });
});
