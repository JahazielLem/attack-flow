// @vitest-environment jsdom

import { afterEach, describe, expect, it, vi } from "vitest";
import { BrowserUrlExtractionService } from "./BrowserUrlExtractionService";

describe("BrowserUrlExtractionService", () => {
    afterEach(() => {
        vi.useRealTimers();
    });

    it("fetches bounded public HTML without ambient credentials", async () => {
        const fetchMock = vi.fn(async () => createResponse(
            ["<article><h1>Report</h1><p>Actor executed PowerShell.</p></article>"],
            {
                url: "https://reports.example/final",
                headers: { "content-type": "text/html; charset=utf-8" }
            }
        ));
        const result = await new BrowserUrlExtractionService({
            fetch: fetchMock as unknown as typeof fetch
        }).extract(" https://reports.example/start ");

        expect(fetchMock).toHaveBeenCalledWith("https://reports.example/start", expect.objectContaining({
            method: "GET",
            mode: "cors",
            credentials: "omit",
            redirect: "follow",
            cache: "no-store",
            referrerPolicy: "no-referrer"
        }));
        expect(result).toMatchObject({
            requestedUrl: "https://reports.example/start",
            finalUrl: "https://reports.example/final",
            title: "Report",
            extractedText: "Report\n\nActor executed PowerShell.",
            contentType: "text/html"
        });
    });

    it.each([
        "http://reports.example/article",
        "https://localhost/article",
        "https://127.0.0.1/article",
        "https://192.168.1.10/article",
        "https://user:secret@reports.example/article"
    ])("rejects unsafe URL %s before fetch", async (url) => {
        const fetchMock = vi.fn();
        await expect(new BrowserUrlExtractionService({
            fetch: fetchMock as unknown as typeof fetch
        }).extract(url)).rejects.toMatchObject({
            error: { code: "invalid_url" }
        });
        expect(fetchMock).not.toHaveBeenCalled();
    });

    it("classifies unreadable cross-origin responses as network or CORS failures", async () => {
        const service = new BrowserUrlExtractionService({
            fetch: vi.fn(async () => { throw new TypeError("Failed to fetch"); }) as unknown as typeof fetch
        });
        await expect(service.extract("https://reports.example/article")).rejects.toMatchObject({
            error: {
                code: "network_or_cors",
                retryable: true
            }
        });
    });

    it("rejects unsupported content types and HTTP failures", async () => {
        const pdfService = new BrowserUrlExtractionService({
            fetch: vi.fn(async () => createResponse(["pdf"], {
                url: "https://reports.example/report.pdf",
                headers: { "content-type": "application/pdf" }
            })) as unknown as typeof fetch
        });
        await expect(pdfService.extract("https://reports.example/report.pdf")).rejects.toMatchObject({
            error: { code: "unsupported_content_type" }
        });

        const unavailableService = new BrowserUrlExtractionService({
            fetch: vi.fn(async () => createResponse(["failure"], {
                url: "https://reports.example/article",
                status: 503,
                headers: { "content-type": "text/html" }
            })) as unknown as typeof fetch
        });
        await expect(unavailableService.extract("https://reports.example/article")).rejects.toMatchObject({
            error: { code: "http_error", retryable: true, statusCode: 503 }
        });
    });

    it("cancels a streamed response that exceeds the byte limit", async () => {
        let cancelled = false;
        const body = new ReadableStream<Uint8Array>({
            start(controller) {
                controller.enqueue(new TextEncoder().encode("12345"));
                controller.enqueue(new TextEncoder().encode("67890"));
            },
            cancel() {
                cancelled = true;
            }
        });
        const response = new Response(body, { headers: { "content-type": "text/html" } });
        Object.defineProperty(response, "url", { value: "https://reports.example/article" });
        const service = new BrowserUrlExtractionService({
            fetch: vi.fn(async () => response) as unknown as typeof fetch
        });

        await expect(service.extract("https://reports.example/article", {
            maxResponseBytes: 6
        })).rejects.toMatchObject({ error: { code: "response_too_large" } });
        expect(cancelled).toBe(true);
    });

    it("aborts a fetch after the configured timeout", async () => {
        vi.useFakeTimers();
        const fetchMock = vi.fn((_url: RequestInfo | URL, init?: RequestInit) =>
            new Promise<Response>((_resolve, reject) => {
                init?.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
            })
        );
        const promise = new BrowserUrlExtractionService({
            fetch: fetchMock as unknown as typeof fetch
        }).extract("https://reports.example/article", { timeoutMs: 25 }).catch(error => error);
        await vi.advanceTimersByTimeAsync(25);
        await expect(promise).resolves.toMatchObject({ error: { code: "fetch_timeout" } });
    });

    it("rejects article pages without readable text", async () => {
        const service = new BrowserUrlExtractionService({
            fetch: vi.fn(async () => createResponse(["<nav>Only navigation</nav>"], {
                url: "https://reports.example/article",
                headers: { "content-type": "text/html" }
            })) as unknown as typeof fetch
        });
        await expect(service.extract("https://reports.example/article")).rejects.toMatchObject({
            error: { code: "no_extractable_text" }
        });
    });

    it("uses an HTML meta charset when the response header omits one", async () => {
        const prefix = new TextEncoder().encode("<meta charset='windows-1252'><article><p>caf");
        const suffix = new TextEncoder().encode("</p></article>");
        const body = new Uint8Array(prefix.length + 1 + suffix.length);
        body.set(prefix);
        body[prefix.length] = 0xE9;
        body.set(suffix, prefix.length + 1);
        const response = new Response(body, { headers: { "content-type": "text/html" } });
        Object.defineProperty(response, "url", { value: "https://reports.example/article" });
        const service = new BrowserUrlExtractionService({
            fetch: vi.fn(async () => response) as unknown as typeof fetch
        });

        await expect(service.extract("https://reports.example/article")).resolves.toMatchObject({
            extractedText: "café"
        });
    });

    it("supports content-type meta attributes in either order", async () => {
        const prefix = new TextEncoder().encode(
            "<meta content='text/html; charset=windows-1252' http-equiv='Content-Type'><article><p>caf"
        );
        const suffix = new TextEncoder().encode("</p></article>");
        const body = new Uint8Array(prefix.length + 1 + suffix.length);
        body.set(prefix);
        body[prefix.length] = 0xE9;
        body.set(suffix, prefix.length + 1);
        const response = new Response(body, { headers: { "content-type": "text/html" } });
        Object.defineProperty(response, "url", { value: "https://reports.example/article" });

        await expect(new BrowserUrlExtractionService({
            fetch: vi.fn(async () => response) as unknown as typeof fetch
        }).extract("https://reports.example/article")).resolves.toMatchObject({
            extractedText: "café"
        });
    });
});

function createResponse(
    chunks: string[],
    options: {
        url: string;
        status?: number;
        headers?: HeadersInit;
    }
): Response {
    const encoded = chunks.map(chunk => new TextEncoder().encode(chunk));
    const body = new ReadableStream<Uint8Array>({
        start(controller) {
            encoded.forEach(chunk => controller.enqueue(chunk));
            controller.close();
        }
    });
    const response = new Response(body, {
        status: options.status ?? 200,
        headers: options.headers
    });
    Object.defineProperty(response, "url", { value: options.url });
    return response;
}
