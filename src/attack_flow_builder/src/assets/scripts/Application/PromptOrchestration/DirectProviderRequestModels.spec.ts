import { describe, expect, it } from "vitest";
import {
    DIRECT_PROVIDER_ALLOWED_CONDITION_VALUES,
    DIRECT_PROVIDER_ALLOWED_OPERATOR_VALUES,
    DIRECT_PROVIDER_ORCHESTRATION_MODES,
    DIRECT_PROVIDER_REQUEST_MODEL_VERSION
} from "./DirectProviderRequestModels";

describe("DirectProviderRequestModels", () => {
    it("pins the direct-provider request model constants", () => {
        expect(DIRECT_PROVIDER_REQUEST_MODEL_VERSION).toBe("v1");
        expect(DIRECT_PROVIDER_ORCHESTRATION_MODES).toEqual(["direct_provider"]);
        expect(DIRECT_PROVIDER_ALLOWED_OPERATOR_VALUES).toEqual(["AND", "OR"]);
        expect(DIRECT_PROVIDER_ALLOWED_CONDITION_VALUES).toEqual(["true", "false"]);
    });
});
