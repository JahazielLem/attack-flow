import { describe, expect, it } from "vitest";
import {
    Block,
    DiagramObjectFactory,
    DiagramObjectType,
    PropertyType,
    StringProperty,
    TupleProperty
} from "@/assets/scripts/OpenChart/DiagramModel";
import { TacticTechniqueProperty } from "./TacticTechniqueProperty";
import type { DiagramSchemaConfiguration } from "@/assets/scripts/OpenChart/DiagramModel";

const schema: DiagramSchemaConfiguration = {
    id: "sparta_tuple_schema",
    canvas: {
        name: "flow",
        type: DiagramObjectType.Canvas,
        properties: {}
    },
    templates: [
        {
            name: "action",
            type: DiagramObjectType.Block,
            anchors: {
                up: "anchor",
                left: "anchor",
                down: "anchor",
                right: "anchor"
            },
            properties: {
                ttp: {
                    ...TacticTechniqueProperty,
                    name: "TTP"
                },
                name: {
                    type: PropertyType.String,
                    is_representative: true
                }
            }
        },
        {
            name: "anchor",
            type: DiagramObjectType.Anchor
        }
    ]
};

const factory = new DiagramObjectFactory(schema);

function createTtp(): TupleProperty {
    const block = factory.createNewDiagramObject("action", Block);
    return block.properties.value.get("ttp") as TupleProperty;
}

function getField(ttp: TupleProperty, key: string): StringProperty {
    return ttp.value.get(key) as StringProperty;
}

describe("TacticTechniqueProperty", () => {
    it("filters SPARTA techniques and subtechniques from the selected tactic", () => {
        const ttp = createTtp();
        getField(ttp, "tactic").setValue("ST0001");

        const validTechniques = ttp.validPropValues?.get("technique");
        const validSubtechniques = ttp.validPropValues?.get("subtechnique");

        expect(validTechniques?.has("REC-0001")).toBe(true);
        expect(validTechniques?.has("EX-0001")).toBe(false);
        expect(validSubtechniques?.has("REC-0001.01")).toBe(true);
        expect(validSubtechniques?.has("EX-0001.01")).toBe(false);
    });

    it("autocompletes tactic and technique from a SPARTA subtechnique", () => {
        const ttp = createTtp();
        getField(ttp, "subtechnique").setValue("REC-0001.01");

        expect(getField(ttp, "tactic").value).toBe("ST0001");
        expect(getField(ttp, "technique").value).toBe("REC-0001");
    });
});
