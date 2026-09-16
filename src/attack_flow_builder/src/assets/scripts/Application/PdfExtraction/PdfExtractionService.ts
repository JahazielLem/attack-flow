import { getDocument, PDFWorker, VerbosityLevel } from "pdfjs-dist";
import pdfWorkerUrl from "pdfjs-dist/build/pdf.worker.mjs?url";
import type {
    PdfExtractionError,
    PdfExtractionResult
} from "./PdfExtractionContracts";
import { PDF_EXTRACTION_SOURCE_TYPE } from "./PdfExtractionContracts";

type PdfJsTextItem = {
    str?: string;
};

type PdfJsTextContent = {
    items?: PdfJsTextItem[];
};

type PdfJsPage = {
    getTextContent(): Promise<PdfJsTextContent>;
};

type PdfJsDocument = {
    numPages: number;
    getPage(pageNumber: number): Promise<PdfJsPage>;
    destroy?: () => Promise<void> | void;
};

type PdfJsAdapter = {
    getDocument: typeof getDocument;
    globalWorkerOptions?: {
        workerSrc: string;
    };
};

export class PdfExtractionServiceError extends Error {
    public readonly error: PdfExtractionError;

    constructor(error: PdfExtractionError) {
        super(error.message);
        this.name = "PdfExtractionServiceError";
        this.error = error;
    }
}

/**
 * Normalizes unknown extraction failures into the explicit PDF error model.
 */
export function normalizePdfExtractionFailure(
    error: unknown,
    params: {
        filename: string;
        fallbackCode: PdfExtractionError["code"];
        fallbackMessage: string;
        fallbackDetails?: Record<string, string>;
    }
): PdfExtractionError {
    const cause = toCauseString(error);
    const message = toMessageString(error);
    const normalized = `${cause} ${message}`.toLowerCase();

    if (normalized.includes("password") || normalized.includes("encrypted")) {
        return createPdfExtractionError({
            code: "unreadable_pdf",
            message: "The PDF is encrypted or password protected.",
            filename: params.filename,
            details: { cause }
        });
    }

    if (
        normalized.includes("invalid pdf")
        || normalized.includes("corrupt")
        || normalized.includes("xref")
        || normalized.includes("syntax")
        || normalized.includes("parse")
        || normalized.includes("format")
    ) {
        return createPdfExtractionError({
            code: "parse_failure",
            message: "The PDF could not be parsed.",
            filename: params.filename,
            details: { cause }
        });
    }

    return createPdfExtractionError({
        code: params.fallbackCode,
        message: params.fallbackMessage,
        filename: params.filename,
        details: params.fallbackDetails
    });
}

/**
 * Browser-safe PDF text extraction service for text-based PDFs.
 *
 * Extraction happens client-side, preserves page order best-effort, and
 * returns raw text plus basic metadata. OCR is intentionally out of scope.
 */
export class BrowserPdfExtractionService {
    private readonly pdfJs: PdfJsAdapter;

    constructor(pdfJs: Partial<PdfJsAdapter> = {}) {
        this.pdfJs = {
            getDocument: pdfJs.getDocument ?? getDocument,
            globalWorkerOptions: pdfJs.globalWorkerOptions
        };
    }

    async extract(file: File): Promise<PdfExtractionResult> {
        const filename = this.getFilename(file);
        this.validateInput(file, filename);

        let worker: PDFWorker | undefined;
        let releaseWorker: (() => void) | undefined;
        let document: PdfJsDocument | undefined;
        try {
            ({ worker, releaseWorker } = await this.createWorker());
            const loadingTask = this.pdfJs.getDocument({
                data: await file.arrayBuffer(),
                verbosity: VerbosityLevel.ERRORS,
                ...(worker ? { worker } : {})
            });
            document = await loadingTask.promise as PdfJsDocument;
        } catch (error) {
            throw new PdfExtractionServiceError(normalizePdfExtractionFailure(error, {
                filename,
                fallbackCode: "unreadable_pdf",
                fallbackMessage: "The PDF could not be read.",
                fallbackDetails: { cause: toCauseString(error) }
            }));
        }

        const pdfDocument = document;
        if (!pdfDocument) {
            throw new PdfExtractionServiceError(createPdfExtractionError({
                code: "parse_failure",
                message: "The PDF could not be parsed.",
                filename
            }));
        }

        const pageTexts: string[] = [];
        try {
            for (let pageNumber = 1; pageNumber <= pdfDocument.numPages; pageNumber += 1) {
                const page = await pdfDocument.getPage(pageNumber);
                const content = await page.getTextContent();
                const text = this.extractPageText(content);
                if (text) {
                    pageTexts.push(text);
                }
            }
        } catch (error) {
            throw new PdfExtractionServiceError(createPdfExtractionError({
                code: "parse_failure",
                message: "The PDF could not be parsed for text extraction.",
                filename,
                pageCount: pdfDocument.numPages,
                details: { cause: toCauseString(error) }
            }));
        } finally {
            await this.safeDestroy(pdfDocument);
            await this.safeDestroyWorker(worker);
            releaseWorker?.();
        }

        const extractedText = pageTexts.join("\n\n").trim();
        if (!extractedText) {
            throw new PdfExtractionServiceError(createPdfExtractionError({
                code: "no_extractable_text",
                message: "The PDF does not contain extractable text.",
                filename,
                pageCount: pdfDocument.numPages
            }));
        }

        return {
            sourceType: PDF_EXTRACTION_SOURCE_TYPE,
            filename,
            pageCount: pdfDocument.numPages,
            extractedText
        };
    }

    private async createWorker(): Promise<{ worker?: PDFWorker, releaseWorker: () => void }> {
        try {
            const response = await fetch(pdfWorkerUrl);
            const source = await response.text();
            const workerUrl = URL.createObjectURL(new Blob([source], { type: "text/javascript" }));
            const port = new Worker(workerUrl, {
                type: "module",
                name: "pdfjs-worker"
            });
            type PDFWorkerOptions = ConstructorParameters<typeof PDFWorker>[0];
            return {
                worker: new PDFWorker({ port } as unknown as PDFWorkerOptions),
                releaseWorker: () => URL.revokeObjectURL(workerUrl)
            };
        } catch {
            return {
                worker: undefined,
                releaseWorker: () => undefined
            };
        }
    }

    private validateInput(file: File, filename: string) {
        const isPdfMimeType = file.type === "application/pdf";
        const isPdfFilename = /\.pdf$/i.test(filename);

        if (!filename || file.size === 0 || (!isPdfMimeType && !isPdfFilename)) {
            throw new PdfExtractionServiceError(createPdfExtractionError({
                code: "invalid_file",
                message: "Select a valid PDF file.",
                filename
            }));
        }
    }

    private extractPageText(content: PdfJsTextContent): string {
        const items = Array.isArray(content.items) ? content.items : [];
        const text = items
            .map(item => typeof item?.str === "string" ? item.str : "")
            .filter(value => value.trim().length > 0)
            .join(" ");

        return text.replace(/\s+/g, " ").trim();
    }

    private getFilename(file: File): string {
        return file.name.trim();
    }

    private async safeDestroy(document?: PdfJsDocument) {
        try {
            await document?.destroy?.();
        } catch {
            // best-effort cleanup
        }
    }

    private async safeDestroyWorker(worker?: PDFWorker) {
        try {
            worker?.destroy();
        } catch {
            // best-effort cleanup
        }
    }
}

function createPdfExtractionError(params: {
    code: PdfExtractionError["code"];
    message: string;
    filename?: string;
    pageCount?: number;
    details?: Record<string, string>;
}): PdfExtractionError {
    return {
        sourceType: PDF_EXTRACTION_SOURCE_TYPE,
        category: params.code,
        code: params.code,
        message: params.message,
        filename: params.filename,
        pageCount: params.pageCount,
        details: params.details
    };
}

function toCauseString(error: unknown): string {
    if (error instanceof Error && error.name.trim()) {
        return error.name;
    }

    return typeof error === "string" ? error : "unknown";
}

function toMessageString(error: unknown): string {
    if (error instanceof Error && error.message.trim()) {
        return error.message;
    }

    return typeof error === "string" ? error : "";
}
