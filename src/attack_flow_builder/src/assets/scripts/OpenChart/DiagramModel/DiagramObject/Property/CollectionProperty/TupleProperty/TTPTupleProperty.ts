import { TupleProperty } from "./TupleProperty";
import type { TuplePropertyOptions } from "./TuplePropertyOptions";

/**
 * Specialized TupleProperty for TTP mapping and its framework-aware editor.
 */
export class TTPTupleProperty extends TupleProperty {
    constructor(options: TuplePropertyOptions) {
        super(options);
    }

    /**
     * Keep the specialized TTP editor and combinations when copying a block.
     * @param id The cloned property's ID.
     * @returns A clone of the TTP tuple.
     */
    public clone(id: string = this.id): TTPTupleProperty {
        const property = new TTPTupleProperty({
            id,
            name: this.name,
            metadata: this.metadata,
            editable: this.isEditable,
            combinations: this._combinations
        });
        for (const [key, prop] of this.value) {
            property.addProperty(prop.clone(), key);
        }
        property.representativeKey = this.representativeKey;
        return property;
    }
}
