// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BrowserPdfExtractionService } from "./PdfExtractionService";

const getDocumentMock = vi.fn();
const globalWorkerOptions = { workerSrc: "" };

describe("BrowserPdfExtractionService", () => {
    beforeEach(() => {
        getDocumentMock.mockReset();
        globalWorkerOptions.workerSrc = "";
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    function createService() {
        return new BrowserPdfExtractionService({
            getDocument: getDocumentMock,
            globalWorkerOptions
        });
    }

    function createPdfFile(name: string) {
        const file = new File(["%PDF-1.7"], name, { type: "application/pdf" });
        Object.defineProperty(file, "arrayBuffer", {
            value: vi.fn(async () => new ArrayBuffer(8))
        });
        return file;
    }

    it("returns extracted text and metadata for a text-based PDF", async () => {
        getDocumentMock.mockReturnValue({
            promise: Promise.resolve({
                numPages: 2,
                getPage: vi.fn(async (pageNumber: number) => {
                    if (pageNumber === 1) {
                        return {
                            getTextContent: vi.fn(async () => ({
                                items: [{ str: "First" }, { str: "page" }, { str: "text" }]
                            }))
                        };
                    }

                    return {
                        getTextContent: vi.fn(async () => ({
                            items: [{ str: "Second" }, { str: "page" }]
                        }))
                    };
                }),
                destroy: vi.fn(async () => undefined)
            })
        });

        const result = await createService().extract(createPdfFile("report.pdf"));

        expect(result).toEqual({
            sourceType: "pdf",
            filename: "report.pdf",
            pageCount: 2,
            extractedText: "First page text\n\nSecond page"
        });
        expect(getDocumentMock).toHaveBeenCalledTimes(1);
        expect(getDocumentMock).toHaveBeenCalledWith(expect.objectContaining({
            verbosity: 0
        }));
    });

    it("preserves page ordering for representative samples", async () => {
        getDocumentMock.mockReturnValue({
            promise: Promise.resolve({
                numPages: 3,
                getPage: vi.fn(async (pageNumber: number) => ({
                    getTextContent: vi.fn(async () => ({
                        items: [{ str: `Page ${pageNumber}` }]
                    }))
                })),
                destroy: vi.fn(async () => undefined)
            })
        });

        const result = await createService().extract(createPdfFile("ordered.pdf"));

        expect(result.pageCount).toBe(3);
        expect(result.extractedText).toBe("Page 1\n\nPage 2\n\nPage 3");
    });

    it("fails clearly when no extractable text exists", async () => {
        getDocumentMock.mockReturnValue({
            promise: Promise.resolve({
                numPages: 1,
                getPage: vi.fn(async () => ({
                    getTextContent: vi.fn(async () => ({ items: [] }))
                })),
                destroy: vi.fn(async () => undefined)
            })
        });

        await expect(createService().extract(createPdfFile("scan.pdf"))).rejects.toMatchObject({
            error: {
                category: "no_extractable_text",
                code: "no_extractable_text",
                filename: "scan.pdf",
                pageCount: 1
            }
        });
    });

    it("fails clearly for invalid files", async () => {
        const file = new File(["hello"], "notes.txt", { type: "text/plain" });

        await expect(createService().extract(file)).rejects.toMatchObject({
            error: {
                category: "invalid_file",
                code: "invalid_file",
                filename: "notes.txt"
            }
        });
    });

    it("fails clearly for unreadable PDFs", async () => {
        getDocumentMock.mockImplementation(() => {
            throw new Error("PasswordException: Document is password protected");
        });

        await expect(createService().extract(createPdfFile("locked.pdf"))).rejects.toMatchObject({
            error: {
                category: "unreadable_pdf",
                code: "unreadable_pdf",
                filename: "locked.pdf"
            }
        });
    });

    it("fails clearly for parse failures", async () => {
        getDocumentMock.mockImplementation(() => {
            throw new Error("xref parse failure");
        });

        await expect(createService().extract(createPdfFile("broken.pdf"))).rejects.toMatchObject({
            error: {
                category: "parse_failure",
                code: "parse_failure",
                filename: "broken.pdf"
            }
        });
    });
});
