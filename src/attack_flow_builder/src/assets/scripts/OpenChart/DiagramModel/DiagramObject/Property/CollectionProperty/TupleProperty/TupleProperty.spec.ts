import { describe, expect, it } from "vitest";
import { DiagramObjectFactory, StringProperty, TTPTupleProperty } from "@/assets/scripts/OpenChart/DiagramModel";
import {
    DiagramObjectType,
    PropertyType
} from "@/assets/scripts/OpenChart/DiagramModel/DiagramObjectFactory";
import type {
    DiagramSchemaConfiguration,
    TuplePropertyDescriptor
} from "@/assets/scripts/OpenChart/DiagramModel/DiagramObjectFactory";

const schema: DiagramSchemaConfiguration = {
    id: "tuple_spec_schema",
    canvas: {
        name: "tuple_spec_canvas",
        type: DiagramObjectType.Canvas,
        properties: {}
    },
    templates: []
};

const tupleDescriptor: TuplePropertyDescriptor = {
    type: PropertyType.Tuple,
    form: {
        tactic: {
            type: PropertyType.String,
            options: {
                type: PropertyType.List,
                form: { type: PropertyType.String },
                default: [
                    ["TA1", "TA1"],
                    ["TA2", "TA2"]
                ]
            }
        },
        technique: {
            type: PropertyType.String,
            options: {
                type: PropertyType.List,
                form: { type: PropertyType.String },
                default: [
                    ["T1001", "T1001"],
                    ["T1002", "T1002"]
                ]
            }
        },
        subtechnique: {
            type: PropertyType.String,
            options: {
                type: PropertyType.List,
                form: { type: PropertyType.String },
                default: [
                    ["T1001.001", "T1001.001"]
                ]
            }
        }
    },
    validValueCombinations: [
        ["tactic", "TA1", "technique", "T1001"],
        ["tactic", "TA1", "technique", "T1002"],
        ["tactic", "TA1", "subtechnique", "T1001.001"],
        ["technique", "T1001", "subtechnique", "T1001.001"]
    ]
};

describe("TupleProperty", () => {
    it("preserves the framework-aware TTP type and constraints when cloned", () => {
        const factory = new DiagramObjectFactory(schema);
        const tuple = factory.createTTPTupleProperty("ttp", {
            ...tupleDescriptor,
            type: PropertyType.TTPTuple
        }, [
            ["tactic", "TA1"],
            ["technique", "T1001"],
            ["subtechnique", "T1001.001"]
        ]);

        const clone = tuple.clone();

        expect(clone).toBeInstanceOf(TTPTupleProperty);
        expect(clone.toOrderedJson()).toEqual(tuple.toOrderedJson());
        clone.get("technique", StringProperty)!.setValue("T1002");
        expect(clone.get("subtechnique", StringProperty)!.value).toBeNull();
        expect(tuple.get("subtechnique", StringProperty)!.value).toBe("T1001.001");
    });

    it("aligns singleton valid combinations without recursive updates", () => {
        const factory = new DiagramObjectFactory(schema);
        const tuple = factory.createTupleProperty("ttp", tupleDescriptor, [
            ["tactic", "TA2"],
            ["technique", "T1001"],
            ["subtechnique", "T1001.001"]
        ]);

        expect(tuple.toOrderedJson()).toEqual([
            ["tactic", "TA1"],
            ["technique", "T1001"],
            ["subtechnique", "T1001.001"]
        ]);
    });
});
