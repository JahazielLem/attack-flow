import type { DictionaryProperty, Property } from "@OpenChart/DiagramModel";



export function isVisibleEditorProperty(property: Property): boolean {

    return property.isEditable ?? true;

}



export function hasVisibleEditorProperties(property: DictionaryProperty): boolean {

    for (const value of property.value.values()) {

        if (isVisibleEditorProperty(value)) {

            return true;

        }

    }

    return false;

}
