import { describe, it, expect } from "vitest";
import { populateProperties } from "./PopulateBlockProperties";
import {
    DictionaryProperty,
    FloatProperty,
    TupleProperty,
    StringProperty
} from "../OpenChart/DiagramModel";
import type { StixObject } from "./StixTypes";

function createRootWithTTPTuple() {
    const root = new DictionaryProperty({ id: "root", editable: true });
    const ttp = new TupleProperty({ id: "ttp", editable: true });
    // Add the expected subfields for the TTP tuple
    ttp.addProperty(new StringProperty({ id: "tactic", editable: true }), "tactic");
    ttp.addProperty(new StringProperty({ id: "technique", editable: true }), "technique");
    ttp.addProperty(new StringProperty({ id: "subtechnique", editable: true }), "subtechnique");
    root.addProperty(ttp, "ttp");
    return { root, ttp };
}

describe("PopulateBlockProperties - handleTTPTuple", () => {
    it("sets tactic when only tactic_id is present", () => {
        const { root, ttp } = createRootWithTTPTuple();
        const stix = { type: "attack-action", tactic_id: "TA0001" } as unknown as StixObject;

        populateProperties(stix, root);

        const tactic = ttp.get("tactic", StringProperty)!.value;
        const technique = ttp.get("technique", StringProperty)!.value;

        expect(tactic).toBe("TA0001");
        expect(technique).toBeNull();
    });

    it("sets technique when only technique_id is present", () => {
        const { root, ttp } = createRootWithTTPTuple();
        const stix = { type: "attack-action", technique_id: "T1059" } as unknown as StixObject;

        populateProperties(stix, root);

        const tactic = ttp.get("tactic", StringProperty)!.value;
        const technique = ttp.get("technique", StringProperty)!.value;

        expect(tactic).toBeNull();
        expect(technique).toBe("T1059");
    });

    it("sets both when tactic_id and technique_id are present", () => {
        const { root, ttp } = createRootWithTTPTuple();
        const stix = {
            type: "attack-action",
            tactic_id: "TA0001",
            technique_id: "T1059"
        } as unknown as StixObject;

        populateProperties(stix, root);

        const tactic = ttp.get("tactic", StringProperty)!.value;
        const technique = ttp.get("technique", StringProperty)!.value;

        expect(tactic).toBe("TA0001");
        expect(technique).toBe("T1059");
    });

    it("does not set values when neither tactic_id nor technique_id are present", () => {
        const { root, ttp } = createRootWithTTPTuple();
        const stix = { type: "attack-action" } as unknown as StixObject;

        populateProperties(stix, root);

        const tactic = ttp.get("tactic", StringProperty)!.value;
        const technique = ttp.get("technique", StringProperty)!.value;

        expect(tactic).toBeNull();
        expect(technique).toBeNull();
    });

    it("imports a subtechnique even when its parent IDs are absent", () => {
        const { root, ttp } = createRootWithTTPTuple();
        const stix = {
            type: "attack-action",
            subtechnique_id: "T1059.001"
        } as unknown as StixObject;

        populateProperties(stix, root);

        expect(ttp.get("subtechnique", StringProperty)!.value).toBe("T1059.001");
    });
});

describe("PopulateBlockProperties - RF captures", () => {
    it("preserves fractional frequencies and sample rates", () => {
        const root = new DictionaryProperty({ id: "root", editable: true });
        for (const id of ["frequency_hz", "sample_rate_hz"]) {
            root.addProperty(new FloatProperty({ id, editable: true, min: 0, max: Infinity }), id);
        }

        populateProperties({
            type: "x-sigmf-capture",
            frequency_hz: 145800000.25,
            sample_rate_hz: "2400000.5"
        } as unknown as StixObject, root);

        expect(root.get("frequency_hz", FloatProperty)!.value).toBe(145800000.25);
        expect(root.get("sample_rate_hz", FloatProperty)!.value).toBe(2400000.5);
    });
});

describe("PopulateBlockProperties - defensive object IDs", () => {
    it("sets mitigation_id on mitigation objects", () => {
        const root = new DictionaryProperty({ id: "root", editable: true });
        const mitigationId = new StringProperty({ id: "mitigation_id", editable: true });
        root.addProperty(mitigationId, "mitigation_id");
        const stix = { type: "mitigation", mitigation_id: "M1021" } as unknown as StixObject;

        populateProperties(stix, root);

        expect(mitigationId.value).toBe("M1021");
    });

    it("sets detection_id on detection objects", () => {
        const root = new DictionaryProperty({ id: "root", editable: true });
        const detectionId = new StringProperty({ id: "detection_id", editable: true });
        root.addProperty(detectionId, "detection_id");
        const stix = { type: "detection", detection_id: "DET0516" } as unknown as StixObject;

        populateProperties(stix, root);

        expect(detectionId.value).toBe("DET0516");
    });
});
