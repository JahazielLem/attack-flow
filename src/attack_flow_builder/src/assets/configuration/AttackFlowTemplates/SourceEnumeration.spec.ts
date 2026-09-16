import { describe, expect, it } from "vitest";
import Enums, { sourceData } from "./SourceEnumeration";

describe("SourceEnumeration", () => {
    it("keeps object-shaped source data and array-shaped UI enums in sync", () => {
        const sourceObjects = [
            sourceData.tactics,
            sourceData.techniques,
            sourceData.mitigations,
            sourceData.detections
        ];
        const sourceObjectCount = sourceObjects.reduce(
            (sum, objects) => sum + Object.keys(objects).length,
            0
        );
        const relationshipCount = sourceData.relationships.tacticTechniques.length
            + sourceData.relationships.techniqueMitigations.length
            + sourceData.relationships.techniqueDetections.length
            + (sourceData.relationships.techniqueSubtechniques?.length ?? 0)
            + sourceData.relationships.tacticTechniques.filter(
                rel => sourceData.techniques[rel.techniqueId]?.type === "subtechnique"
            ).length;

        expect(Array.isArray(sourceData.tactics)).toBe(false);
        expect(Array.isArray(Enums.tactics)).toBe(true);
        expect(Enums.tactics[0]).toHaveLength(2);
        expect(Enums.relationships[0]).toHaveLength(4);
        expect(Object.keys(Enums.stixIds)).toHaveLength(sourceObjectCount);
        expect(Enums.relationships).toHaveLength(relationshipCount);

        for (const objects of sourceObjects) {
            for (const obj of Object.values(objects)) {
                expect(Enums.stixIds[obj.id]).toBe(obj.stixId);
            }
        }
    });
});
