// @vitest-environment jsdom

import { describe, expect, it } from "vitest";
import { extractReadableTextFromHtml } from "./HtmlTextExtraction";

describe("HtmlTextExtraction", () => {
    it("extracts article text while preserving nested inline content", () => {
        const result = extractReadableTextFromHtml(`
            <html>
                <head><title>Threat Report</title><link rel="canonical" href="/canonical"></head>
                <body>
                    <nav>Navigation</nav>
                    <article>
                        <h1>Campaign</h1>
                        <p>Actor used <strong>PowerShell</strong> through <a href="#">WMI</a>.</p>
                        <script>ignored()</script>
                        <p>Second line<br>after break.</p>
                    </article>
                </body>
            </html>
        `);

        expect(result).toEqual({
            title: "Threat Report",
            canonicalUrl: "/canonical",
            extractedText: "Campaign\n\nActor used PowerShell through WMI.\n\nSecond line\n\nafter break."
        });
        expect(result.extractedText).not.toContain("Navigation");
        expect(result.extractedText).not.toContain("ignored");
    });

    it("falls back to main and then body content", () => {
        expect(extractReadableTextFromHtml("<main><p>Main report</p></main>").extractedText).toBe("Main report");
        expect(extractReadableTextFromHtml("<body><p>Body report</p></body>").extractedText).toBe("Body report");
    });

    it("removes hidden and chrome-only content", () => {
        const result = extractReadableTextFromHtml(`
            <body>
                <header>Header</header>
                <aside>Aside</aside>
                <p hidden>Hidden</p>
                <p aria-hidden="true">Also hidden</p>
                <p>Visible</p>
            </body>
        `);
        expect(result.extractedText).toBe("Visible");
    });

    it("preserves headers that belong to article content", () => {
        const result = extractReadableTextFromHtml(`
            <body>
                <header>Site navigation</header>
                <article>
                    <header><h1>Article title</h1><p>Article summary</p></header>
                    <p>Article body</p>
                </article>
            </body>
        `);
        expect(result.extractedText).toBe("Article title\n\nArticle summary\n\nArticle body");
        expect(result.extractedText).not.toContain("Site navigation");
    });

    it("does not attach parsed content to the live document", () => {
        document.body.innerHTML = "<div id='existing'>Existing</div>";
        extractReadableTextFromHtml("<article><p id='remote'>Remote</p></article>");
        expect(document.querySelector("#existing")).not.toBeNull();
        expect(document.querySelector("#remote")).toBeNull();
    });
});
