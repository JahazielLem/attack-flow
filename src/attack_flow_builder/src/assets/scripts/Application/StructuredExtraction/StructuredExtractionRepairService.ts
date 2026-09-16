import {
    type StructuredExtractionValidationFailure,
    type StructuredExtractionValidationResult
} from "./StructuredExtractionValidationContracts";
import {
    validateStructuredExtractionOutput,
    type StructuredExtractionValidatorInput
} from "./StructuredExtractionValidator";
import type { StructuredJsonValue } from "../Providers";

const REPAIR_FAILURE_MESSAGES = {
    failed: "single structural repair pass did not produce valid structured extraction output"
} as const;

const VERBATIM_DESCRIPTION_FAILURE_CODES = new Set([
    "structured_extraction_attack_action_description_not_verbatim",
    "structured_extraction_attack_condition_description_not_verbatim",
    "structured_extraction_attack_asset_description_not_verbatim"
]);

export interface StructuredExtractionRepairResult {
    validation: StructuredExtractionValidationResult;
}

/**
 * Runs validation and, when practical, performs one bounded repair
 * pass before re-validating.
 */
export function validateAndRepairStructuredExtractionOutput(
    output: StructuredExtractionValidatorInput
): StructuredExtractionRepairResult {
    const initialValidation = validateStructuredExtractionOutput(output);
    if (
        initialValidation.status === "invalid"
        && initialValidation.failures.length > 0
        && initialValidation.failures.every(failure => VERBATIM_DESCRIPTION_FAILURE_CODES.has(failure.code))
    ) {
        const repairedInput = attemptVerbatimDescriptionRepair(output);
        if (repairedInput !== null) {
            return validateRepairedInput(repairedInput);
        }
    }

    if (initialValidation.status !== "repairable") {
        return { validation: initialValidation };
    }

    const repairedInput = attemptSingleStructuralRepair(output);
    if (repairedInput === null) {
        return {
            validation: markAsUnrecoverable(initialValidation, [buildRepairFailure("structured_extraction_repair_failed", REPAIR_FAILURE_MESSAGES.failed)])
        };
    }

    return validateRepairedInput(repairedInput);
}

function validateRepairedInput(
    repairedInput: StructuredExtractionValidatorInput
): StructuredExtractionRepairResult {
    const repairedValidation = validateStructuredExtractionOutput(repairedInput);
    if (repairedValidation.status === "valid") {
        return {
            validation: {
                ...repairedValidation,
                repairAttempted: true
            }
        };
    }

    return {
        validation: markAsUnrecoverable(repairedValidation, [
            buildRepairFailure(
                "structured_extraction_repair_failed",
                REPAIR_FAILURE_MESSAGES.failed
            )
        ])
    };
}

function attemptVerbatimDescriptionRepair(
    output: StructuredExtractionValidatorInput
): StructuredExtractionValidatorInput | null {
    const candidate = parseCandidateObject(output);
    if (candidate === null) {
        return null;
    }

    const repaired = JSON.parse(JSON.stringify(candidate)) as Record<string, StructuredJsonValue>;
    let changed = false;
    for (const field of ["attack_actions", "attack_conditions", "attack_assets"]) {
        const nodes = repaired[field];
        if (!Array.isArray(nodes)) {
            continue;
        }
        for (const node of nodes) {
            if (!isPlainObject(node) || typeof node.description !== "string" || !Array.isArray(node.evidence)) {
                continue;
            }
            const excerpts = node.evidence.flatMap(entry =>
                isPlainObject(entry) && typeof entry.excerpt === "string" && entry.excerpt.length > 0
                    ? [entry.excerpt]
                    : []
            );
            if (excerpts.length === 0 || excerpts.includes(node.description)) {
                continue;
            }
            node.description = excerpts.reduce((longest, excerpt) => excerpt.length > longest.length ? excerpt : longest);
            changed = true;
        }
    }

    if (!changed) {
        return null;
    }
    repaired.validation_state = "repaired";
    repaired.repair_attempted = true;
    return {
        ...output,
        outputJson: repaired,
        outputText: undefined
    };
}

function parseCandidateObject(output: StructuredExtractionValidatorInput): Record<string, unknown> | null {
    if (isPlainObject(output.outputJson)) {
        return output.outputJson;
    }
    if (typeof output.outputText !== "string") {
        return null;
    }
    try {
        const parsed = JSON.parse(output.outputText);
        return isPlainObject(parsed) ? parsed : null;
    } catch {
        return null;
    }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function attemptSingleStructuralRepair(
    output: StructuredExtractionValidatorInput
): StructuredExtractionValidatorInput | null {
    if (typeof output.outputText !== "string") {
        return null;
    }

    const repairedText = extractLikelyJsonObject(output.outputText);
    if (repairedText === null || repairedText === output.outputText) {
        return null;
    }

    return {
        ...output,
        outputText: repairedText
    };
}

function extractLikelyJsonObject(text: string): string | null {
    const trimmed = text.trim();
    if (!trimmed) {
        return null;
    }

    const withoutFence = stripMarkdownCodeFence(trimmed);
    const firstBrace = withoutFence.indexOf("{");
    const lastBrace = withoutFence.lastIndexOf("}");
    if (firstBrace < 0 || lastBrace <= firstBrace) {
        return null;
    }

    return withoutFence.slice(firstBrace, lastBrace + 1).trim();
}

function stripMarkdownCodeFence(text: string): string {
    if (!text.startsWith("```") && !text.endsWith("```")) {
        return text;
    }

    return text
        .replace(/^```(?:json)?\s*/i, "")
        .replace(/\s*```$/i, "")
        .trim();
}

function markAsUnrecoverable(
    validation: StructuredExtractionValidationResult,
    extraFailures: StructuredExtractionValidationFailure[]
): StructuredExtractionValidationResult {
    const failures = [...validation.failures, ...extraFailures].map((failure) => ({
        ...failure,
        repairAttempted: true
    }));
    return {
        status: "unrecoverable",
        repairAttempted: true,
        failures,
        message: failures[0]?.message ?? "structured extraction output is unrecoverable after one repair pass",
        result: undefined
    };
}

function buildRepairFailure(
    code: string,
    message: string
): StructuredExtractionValidationFailure {
    return {
        code,
        category: "repair",
        message,
        repairAttempted: true
    };
}
