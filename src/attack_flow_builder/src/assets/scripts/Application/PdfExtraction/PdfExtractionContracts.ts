export const PDF_EXTRACTION_SOURCE_TYPE = "pdf" as const;

export type PdfExtractionSourceType = typeof PDF_EXTRACTION_SOURCE_TYPE;

export type PdfExtractionErrorCode =
    | "invalid_file"
    | "unreadable_pdf"
    | "no_extractable_text"
    | "parse_failure";

export type PdfExtractionErrorCategory = PdfExtractionErrorCode;

export const PDF_EXTRACTION_ERROR_CODES = [
    "invalid_file",
    "unreadable_pdf",
    "no_extractable_text",
    "parse_failure"
] as const;

/**
 * Browser-side PDF extraction payload for text-based PDFs.
 *
 * Client-side extraction returns the raw text layer plus basic file metadata.
 */
export interface PdfExtractionResult {
    sourceType: PdfExtractionSourceType;
    filename: string;
    pageCount: number;
    extractedText: string;
}

export interface PdfExtractionError {
    sourceType: PdfExtractionSourceType;
    category: PdfExtractionErrorCategory;
    code: PdfExtractionErrorCode;
    message: string;
    filename?: string;
    pageCount?: number;
    details?: Record<string, string>;
}

export interface PdfExtractionIdleState {
    status: "idle";
}

export interface PdfExtractionSelectedState {
    status: "selected";
    sourceType: PdfExtractionSourceType;
    filename: string;
    pageCount?: number;
}

export interface PdfExtractionSuccessState {
    status: "success";
    result: PdfExtractionResult;
}

export interface PdfExtractionErrorState {
    status: "error";
    error: PdfExtractionError;
}

export type PdfExtractionState =
    | PdfExtractionIdleState
    | PdfExtractionSelectedState
    | PdfExtractionSuccessState
    | PdfExtractionErrorState;
