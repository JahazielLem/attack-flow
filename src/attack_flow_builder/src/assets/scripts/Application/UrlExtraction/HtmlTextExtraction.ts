import type { HtmlTextExtractionResult } from "./UrlExtractionContracts";

const ignoredSelector = [
    "script",
    "style",
    "noscript",
    "nav",
    "aside",
    "form",
    "svg",
    "canvas",
    "template",
    "[inert]",
    "input[type='hidden']",
    "[hidden]",
    "[aria-hidden='true']"
].join(",");

const blockTags = new Set([
    "ADDRESS",
    "ARTICLE",
    "BLOCKQUOTE",
    "DD",
    "DIV",
    "DL",
    "DT",
    "FIELDSET",
    "FIGCAPTION",
    "FIGURE",
    "H1",
    "H2",
    "H3",
    "H4",
    "H5",
    "H6",
    "HR",
    "LI",
    "MAIN",
    "OL",
    "P",
    "PRE",
    "SECTION",
    "TABLE",
    "TBODY",
    "TD",
    "TFOOT",
    "TH",
    "THEAD",
    "TR",
    "UL"
]);

/**
 * Extracts deterministic plain text and basic metadata from detached HTML.
 */
export function extractReadableTextFromHtml(
    html: string,
    parser: DOMParser = new DOMParser()
): HtmlTextExtractionResult {
    let documentRoot: Document;
    try {
        documentRoot = parser.parseFromString(html, "text/html");
    } catch (error) {
        throw new Error(`HTML parsing failed: ${toCauseString(error)}`);
    }

    const articleText = selectLongestExtractedText(documentRoot.querySelectorAll("article"));
    const mainText = articleText || selectLongestExtractedText(documentRoot.querySelectorAll("main"));
    const extractedText = mainText || (documentRoot.body ? extractTextFromRoot(documentRoot.body) : "");

    return {
        title: firstNonEmptyText(
            documentRoot.querySelector("title")?.textContent,
            documentRoot.querySelector("h1")?.textContent
        ),
        canonicalUrl: toOptionalString(
            documentRoot.querySelector<HTMLLinkElement>("link[rel~='canonical']")?.getAttribute("href")
        ),
        extractedText
    };
}

function selectLongestExtractedText(elements: NodeListOf<Element>): string {
    let selected = "";
    elements.forEach(element => {
        const text = extractTextFromRoot(element);
        if (text.length > selected.length) {
            selected = text;
        }
    });
    return selected;
}

function extractTextFromRoot(sourceRoot: Element): string {
    const root = sourceRoot.cloneNode(true) as Element;
    root.querySelectorAll(ignoredSelector).forEach(element => element.remove());
    root.querySelectorAll("header, footer").forEach(element => {
        if (!element.closest("article")) {
            element.remove();
        }
    });
    root.querySelectorAll<HTMLElement>("[style]").forEach(element => {
        if (
            element.style.display === "none"
            || element.style.visibility === "hidden"
            || element.style.opacity === "0"
        ) {
            element.remove();
        }
    });

    const fragments: string[] = [];
    const visit = (node: Node) => {
        if (node.nodeType === Node.TEXT_NODE) {
            fragments.push(node.textContent ?? "");
            return;
        }
        if (!(node instanceof Element)) {
            return;
        }
        if (node.tagName === "BR" || node.tagName === "HR") {
            fragments.push("\n\n");
            return;
        }

        const isBlock = blockTags.has(node.tagName);
        if (isBlock) {
            fragments.push("\n\n");
        }
        node.childNodes.forEach(visit);
        if (isBlock) {
            fragments.push("\n\n");
        }
    };
    visit(root);
    return fragments
        .join("")
        .replace(/\r\n?/g, "\n")
        .replace(/[\t\f\v ]+/g, " ")
        .replace(/ *\n */g, "\n")
        .replace(/\n{3,}/g, "\n\n")
        .trim();
}

function firstNonEmptyText(...values: Array<string | null | undefined>): string | undefined {
    for (const value of values) {
        const text = value?.replace(/\s+/g, " ").trim();
        if (text) {
            return text;
        }
    }
    return undefined;
}

function toOptionalString(value: string | null | undefined): string | undefined {
    const normalized = value?.trim();
    return normalized || undefined;
}

function toCauseString(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}
