// @vitest-environment jsdom

import { describe, expect, it, vi } from "vitest";
import { prepareDirectProviderUrlInput } from "./DirectProviderUrlInput";

describe("prepareDirectProviderUrlInput", () => {
    it("returns the shared normalized package expected by direct-provider mode", async () => {
        const response = new Response("<article><h1>Report</h1><p>Executed whoami.</p></article>", {
            headers: { "content-type": "text/html" }
        });
        Object.defineProperty(response, "url", { value: "https://reports.example/final" });
        const result = await prepareDirectProviderUrlInput(
            "https://reports.example/start",
            { sourceName: "Link to Report" },
            { fetch: vi.fn(async () => response) as unknown as typeof fetch }
        );

        expect(result).toMatchObject({
            sourceType: "url",
            normalizedText: "Report\n\nExecuted whoami.",
            metadata: {
                sourceName: "Link to Report",
                sourceUrl: "https://reports.example/start",
                finalUrl: "https://reports.example/final"
            }
        });
    });
});
