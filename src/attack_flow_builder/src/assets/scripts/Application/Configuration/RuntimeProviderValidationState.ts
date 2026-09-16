import type { SupportedRuntimeProviderType } from "./RuntimeProviderConfig";

export type RuntimeProviderEndpointSummary = string;

/**
 * Frontend-only validation lifecycle for runtime provider settings.
 */
export type RuntimeProviderValidationStatus =
    | "idle"
    | "validating"
    | "valid"
    | "invalid"
    | "error";

/**
 * Shared display fields for runtime provider validation UI.
 */
export interface RuntimeProviderValidationBaseState {
    status: RuntimeProviderValidationStatus;
    providerType?: SupportedRuntimeProviderType;
    endpointSummary?: RuntimeProviderEndpointSummary;
    model?: string;
    message?: string;
}

export interface RuntimeProviderValidationIdleState extends RuntimeProviderValidationBaseState {
    status: "idle";
}

export interface RuntimeProviderValidationValidatingState extends RuntimeProviderValidationBaseState {
    status: "validating";
}

export interface RuntimeProviderValidationValidState extends RuntimeProviderValidationBaseState {
    status: "valid";
    message?: string;
}

export interface RuntimeProviderValidationInvalidState extends RuntimeProviderValidationBaseState {
    status: "invalid";
    message: string;
}

export interface RuntimeProviderValidationErrorState extends RuntimeProviderValidationBaseState {
    status: "error";
    message: string;
}

export type RuntimeProviderValidationState =
    | RuntimeProviderValidationIdleState
    | RuntimeProviderValidationValidatingState
    | RuntimeProviderValidationValidState
    | RuntimeProviderValidationInvalidState
    | RuntimeProviderValidationErrorState;

/**
 * Canonical idle validation state.
 */
export const IDLE_RUNTIME_PROVIDER_VALIDATION_STATE: RuntimeProviderValidationIdleState = {
    status: "idle"
};
