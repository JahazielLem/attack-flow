import { describe, expect, it } from "vitest";
import {
    buildDirectProviderPromptConstraints,
    buildDirectProviderSystemInstructionBundle,
    buildDirectProviderSystemInstructionModel,
    buildDirectProviderSystemInstructionText,
    DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT
} from "./DirectProviderSystemInstructionBuilder";

describe("DirectProviderSystemInstructionBuilder", () => {
    it("builds deterministic system instruction text", () => {
        expect(buildDirectProviderSystemInstructionText()).toBe(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT);
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Map every attack-action to one best-fit technique");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("ATT&CK v19.1");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("MITRE ATLAS; MITRE D3FEND; or MITRE F3");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("grounded_by to inferred_from_procedure");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Do not omit technique for an attack-action");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("corresponding ATT&CK tactic");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("For every non-terminal action, use effect_refs");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Merge contiguous substeps");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("do not leave otherwise sequential source-grounded actions disconnected");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("never guess branching");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("state or prerequisite that gates a later action");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("upon execution, after, before, when, once, with those credentials");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("documented concurrent activity, parallel requirements");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("model a documented join by connecting each supported predecessor");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("include its object_id in that action's object_refs");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("most specific supported STIX object or observable type");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Preserve defanged observables exactly as written in the source");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("never refang indicators such as [.] or [:]");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Do not create standalone attack-pattern nodes");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("ATT&CK technique table, appendix, or matrix");
        expect(DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT).toContain("Return one top-level AFB extraction JSON object");
    });

    it("builds deterministic instruction models and bundle metadata", () => {
        expect(buildDirectProviderPromptConstraints()).toEqual({
            allowProcedureInference: true,
            explicitAttackRefsOnly: false,
            requireTechniqueForEveryAction: true,
            requireTacticForAttackTechnique: true,
            supportedFrameworksOnly: true,
            consolidateSameTechniqueSubsteps: true,
            separateToolSetupOnlyForDistinctTechnique: true,
            keepSourceDistinctActionsSeparate: true,
            useSpecificStixEntityTypes: true,
            preserveDefangedObservableValues: true,
            useAttackTechniqueTables: true,
            modelMultipleOutcomesWithOperators: true,
            modelExplicitPrerequisitesAndStateChangesAsConditions: true,
            connectConditionTruePaths: true,
            useExactEmittedIdsForConditionReferences: true,
            preserveDocumentedSplitsAndJoins: true,
            descriptionsMustBeVerbatimExcerpts: true,
            onlyAndOrOperators: true,
            onlyTrueFalseConditions: true,
            noInferredBranching: true,
            outputMustFitPinnedIntermediateShape: true
        });

        expect(buildDirectProviderSystemInstructionModel()).toEqual({
            version: "v1",
            constraints: {
                allowProcedureInference: true,
                explicitAttackRefsOnly: false,
                requireTechniqueForEveryAction: true,
                requireTacticForAttackTechnique: true,
                supportedFrameworksOnly: true,
                consolidateSameTechniqueSubsteps: true,
                separateToolSetupOnlyForDistinctTechnique: true,
                keepSourceDistinctActionsSeparate: true,
                useSpecificStixEntityTypes: true,
                preserveDefangedObservableValues: true,
                useAttackTechniqueTables: true,
                modelMultipleOutcomesWithOperators: true,
                modelExplicitPrerequisitesAndStateChangesAsConditions: true,
                connectConditionTruePaths: true,
                useExactEmittedIdsForConditionReferences: true,
                preserveDocumentedSplitsAndJoins: true,
                descriptionsMustBeVerbatimExcerpts: true,
                onlyAndOrOperators: true,
                onlyTrueFalseConditions: true,
                noInferredBranching: true,
                outputMustFitPinnedIntermediateShape: true
            }
        });

        expect(buildDirectProviderSystemInstructionBundle()).toMatchObject({
            version: "v1",
            schemaName: "direct_provider_afb_intermediate",
            text: DIRECT_PROVIDER_SYSTEM_INSTRUCTION_TEXT,
            allowedOperatorValues: ["AND", "OR"],
            allowedConditionValues: ["true", "false"]
        });
    });
});
