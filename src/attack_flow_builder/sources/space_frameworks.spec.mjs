import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseSourceObjectsFromManifest } from "./download_stix_source.mjs";
import { generateSourceEnumeration, getBundleMetadata } from "./update_stix_source.mjs";
import { STIX_SOURCES } from "./sources.mjs";

const readBundle = name => JSON.parse(readFileSync(new URL(`../data/${name}.json`, import.meta.url), "utf8"));

describe("official space framework ingestion", () => {
    it("loads SPARTA subtechniques, stable tactics and countermeasures without threat-only entries", () => {
        const bundle = readBundle("sparta-attack");
        const { data, wiki } = generateSourceEnumeration(parseSourceObjectsFromManifest(bundle), "MitreSparta");
        expect(data.tactics.ST0001.name).toBe("Reconnaissance");
        expect(data.subtechniques["REC-0001.01"]).toBeDefined();
        expect(data.relationships.techniqueSubtechniques).toContainEqual({
            techniqueId: "REC-0001", subtechniqueId: "REC-0001.01"
        });
        expect(Object.keys(data.techniques).some(id => id.startsWith("SV-"))).toBe(false);
        expect(data.relationships.techniqueMitigations.length).toBeGreaterThan(0);
        expect(data.mitigations["SPA.D3-ACA"].stixId).toMatch(/^course-of-action--/);
        expect(data.mitigations["D3-ACA"]).toBeUndefined();
        expect(wiki.wiki.find(entry => entry.id === "REC-0001.01").url).toContain("sparta.aerospace.org");
    });

    it("keeps Space Shield native STIX references separate from ATT&CK IDs", () => {
        const bundle = readBundle("space-attack");
        const { data, wiki } = generateSourceEnumeration(parseSourceObjectsFromManifest(bundle), "SpaceShield");
        const original = bundle.objects.find(obj => obj.external_references?.some(ref => ref.external_id === "TA0043"));
        expect(data.tactics["SSH.TA0043"].stixId).toBe(original.id);
        expect(data.tactics.TA0043).toBeUndefined();
        expect(data.tactics.ST0001).toBeUndefined();
        expect(data.relationships.techniqueSubtechniques).toContainEqual({
            techniqueId: "SSH.T2001", subtechniqueId: "SSH.T2001.001"
        });
        expect(data.relationships.tacticTechniques).toContainEqual({
            tacticId: "SSH.TA0043", techniqueId: "SSH.T2001.001"
        });
        expect(data.relationships.techniqueMitigations.length).toBeGreaterThan(0);
        expect(wiki.wiki.find(entry => entry.id === "SSH.T2001.001").model).toBe("SPACE-SHIELD");
        expect(Object.values(data.techniques).every(obj => obj.label.startsWith("[SSH]"))).toBe(true);
    });

    it("uses collection versions rather than the STIX schema version", () => {
        const bundle = readBundle("space-attack");
        const collection = bundle.objects.find(obj => obj.type === "x-mitre-collection");
        expect(getBundleMetadata([bundle], STIX_SOURCES.SpaceShield).version).toBe(collection.x_mitre_version);
        expect(getBundleMetadata([bundle], STIX_SOURCES.SpaceShield).version).not.toBe(collection.x_mitre_attack_spec_version);
    });
});
