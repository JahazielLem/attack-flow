import Enums from "./SourceEnumeration";
import { PropertyType } from "@OpenChart/DiagramModel";
import type { TTPTuplePropertyDescriptor, ValueCombinations } from "@OpenChart/DiagramModel";

export const TacticTechniqueProperty: TTPTuplePropertyDescriptor = {
    type: PropertyType.TTPTuple,
    form: {
        tactic: {
            type: PropertyType.String,
            options: {
                type: PropertyType.List,
                form: { type: PropertyType.String },
                default: Enums.tactics as [string, string][]
            }
        },
        technique: {
            type: PropertyType.String,
            options: {
                type: PropertyType.List,
                form: { type: PropertyType.String },
                default: Enums.techniques as [string, string][]
            },
            is_representative: true
        },
        subtechnique: {
            type: PropertyType.String,
            options: {
                type: PropertyType.List,
                form: { type: PropertyType.String },
                default: Enums.subtechniques as [string, string][]
            },
            is_representative: true
        }
    },
    validValueCombinations: Enums.relationships as ValueCombinations
};
