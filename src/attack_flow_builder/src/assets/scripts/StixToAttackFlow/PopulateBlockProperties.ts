import {
    DateProperty,
    EnumProperty,
    FloatProperty,
    IntProperty,
    StringProperty,
    TupleProperty,
    type DictionaryProperty
} from "../OpenChart/DiagramModel";
import type { StixObject } from "./StixTypes";


export function populateProperties(stix: StixObject, root: DictionaryProperty) {
    // Simple right now
    for (const [id, property] of root.value) {
        if (property instanceof StringProperty) {
            if (id in stix) {
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                property.setValue(`${(stix as any)[id]}`);
            }
        } else if (
            property instanceof DateProperty ||
            property instanceof IntProperty ||
            property instanceof FloatProperty ||
            property instanceof EnumProperty
        ) {
            if (id in stix) {
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                property.setValue((stix as any)[id] ?? null);
            }
        } else if (property instanceof TupleProperty && id === "ttp" && stix.type === "attack-action") {
            property.setValue([
                ["tactic", stix.tactic_id ?? null],
                ["technique", stix.technique_id ?? null],
                ["subtechnique", stix.subtechnique_id ?? null]
            ]);
        }
    }
}
