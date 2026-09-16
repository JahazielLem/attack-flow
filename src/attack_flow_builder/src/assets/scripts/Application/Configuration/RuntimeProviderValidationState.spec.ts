import { describe, expect, it } from "vitest";
import {
    IDLE_RUNTIME_PROVIDER_VALIDATION_STATE,
    type RuntimeProviderValidationState
} from "./RuntimeProviderValidationState";

describe("RuntimeProviderValidationState", () => {
    it("supports the expected frontend states", () => {
        const states: RuntimeProviderValidationState[] = [
            IDLE_RUNTIME_PROVIDER_VALIDATION_STATE,
            { status: "validating", providerType: "openai_compatible", endpointSummary: "https://example.com", model: "gpt-4o-mini" },
            { status: "valid", providerType: "openai_compatible", endpointSummary: "https://example.com", model: "gpt-4o-mini" },
            { status: "invalid", message: "invalid config", providerType: "openai_compatible", endpointSummary: "https://example.com", model: "gpt-4o-mini" },
            { status: "error", message: "unexpected error", providerType: "openai_compatible", endpointSummary: "https://example.com", model: "gpt-4o-mini" }
        ];

        expect(states.map(state => state.status)).toEqual([
            "idle",
            "validating",
            "valid",
            "invalid",
            "error"
        ]);
    });
});
