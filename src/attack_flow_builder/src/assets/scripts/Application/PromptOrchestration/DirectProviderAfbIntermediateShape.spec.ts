import { describe, expect, it } from "vitest";
import {
    DIRECT_PROVIDER_AFB_INTERMEDIATE_CONDITION_VALUES,
    DIRECT_PROVIDER_AFB_INTERMEDIATE_SCHEMA_NAME,
    DIRECT_PROVIDER_AFB_INTERMEDIATE_OBJECT_TYPES,
    DIRECT_PROVIDER_AFB_INTERMEDIATE_OPERATOR_VALUES,
    DIRECT_PROVIDER_AFB_INTERMEDIATE_VERSION
} from "./DirectProviderAfbIntermediateShape";

describe("DirectProviderAfbIntermediateShape", () => {
    it("pins the intermediate output shape constants", () => {
        expect(DIRECT_PROVIDER_AFB_INTERMEDIATE_VERSION).toBe("v1");
        expect(DIRECT_PROVIDER_AFB_INTERMEDIATE_SCHEMA_NAME).toBe("direct_provider_afb_intermediate");
        expect(DIRECT_PROVIDER_AFB_INTERMEDIATE_OBJECT_TYPES).toEqual([
            "attack-flow",
            "attack-action",
            "attack-condition",
            "attack-operator",
            "attack-asset"
        ]);
        expect(DIRECT_PROVIDER_AFB_INTERMEDIATE_OPERATOR_VALUES).toEqual(["AND", "OR"]);
        expect(DIRECT_PROVIDER_AFB_INTERMEDIATE_CONDITION_VALUES).toEqual(["true", "false"]);
    });
});
