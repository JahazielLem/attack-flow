import type { StructuredExtractionResult } from "./StructuredExtractionContracts";

export const STRUCTURED_EXTRACTION_VALIDATION_STATUSES = [
    "valid",
    "invalid",
    "repairable",
    "unrecoverable"
] as const;

export type StructuredExtractionValidationStatus = typeof STRUCTURED_EXTRACTION_VALIDATION_STATUSES[number];

export const STRUCTURED_EXTRACTION_VALIDATION_FAILURE_CATEGORIES = [
    "schema",
    "constraint",
    "parse",
    "repair"
] as const;

export type StructuredExtractionValidationFailureCategory =
    typeof STRUCTURED_EXTRACTION_VALIDATION_FAILURE_CATEGORIES[number];

/**
 * Practical validation failure information for UI and retry handling.
 */
export interface StructuredExtractionValidationFailure {
    code: string;
    category: StructuredExtractionValidationFailureCategory;
    message: string;
    path?: string;
    field?: string;
    repairAttempted: boolean;
    details?: Record<string, string>;
}

/**
 * Shared validation result state for structured extraction output.
 */
export interface StructuredExtractionValidationResultBase {
    status: StructuredExtractionValidationStatus;
    repairAttempted: boolean;
    failures: StructuredExtractionValidationFailure[];
    message?: string;
    result?: StructuredExtractionResult;
}

export interface StructuredExtractionValidationValidResult extends StructuredExtractionValidationResultBase {
    status: "valid";
    failures: [];
    result: StructuredExtractionResult;
    message?: string;
}

export interface StructuredExtractionValidationInvalidResult extends StructuredExtractionValidationResultBase {
    status: "invalid";
    message: string;
}

export interface StructuredExtractionValidationRepairableResult extends StructuredExtractionValidationResultBase {
    status: "repairable";
    message: string;
}

export interface StructuredExtractionValidationUnrecoverableResult extends StructuredExtractionValidationResultBase {
    status: "unrecoverable";
    message: string;
}

export type StructuredExtractionValidationResult =
    | StructuredExtractionValidationValidResult
    | StructuredExtractionValidationInvalidResult
    | StructuredExtractionValidationRepairableResult
    | StructuredExtractionValidationUnrecoverableResult;
