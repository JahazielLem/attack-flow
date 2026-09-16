import type {
    StructuredExtractionValidationFailure,
    StructuredExtractionValidationResult
} from "./StructuredExtractionValidationContracts";

export type StructuredExtractionFailureDisplayFailure = Pick<
    StructuredExtractionValidationFailure,
    "code" | "category" | "message" | "repairAttempted" | "path" | "field"
>;

export type StructuredExtractionFailureDisplayState = Pick<
    StructuredExtractionValidationResult,
    "status" | "repairAttempted"
> & {
    message: string;
    code: string | null;
    category: StructuredExtractionValidationFailure["category"] | null;
    failures: StructuredExtractionFailureDisplayFailure[];
};

/**
 * Converts client-side validation output into a compact failure state for UI
 * display.
 */
export function buildStructuredExtractionFailureDisplayState(
    validation: StructuredExtractionValidationResult | null
): StructuredExtractionFailureDisplayState | null {
    if (!validation || validation.status === "valid") {
        return null;
    }

    const failures = validation.failures.map((failure) => toDisplayFailure(failure));
    const firstFailure = failures[0] ?? null;

    return {
        status: validation.status,
        message: validation.message ?? firstFailure?.message ?? "Structured extraction failed validation.",
        code: firstFailure?.code ?? null,
        category: firstFailure?.category ?? null,
        repairAttempted: validation.repairAttempted,
        failures
    };
}

function toDisplayFailure(failure: StructuredExtractionValidationFailure): StructuredExtractionFailureDisplayFailure {
    return {
        code: failure.code,
        category: failure.category,
        message: failure.message,
        repairAttempted: failure.repairAttempted,
        path: failure.path,
        field: failure.field
    };
}
