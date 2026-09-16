import {
    DictionaryProperty,
    MultiSelectProperty,
    StringProperty
} from "@OpenChart/DiagramModel";
import type { LogSource } from "./SourceEnumeration";
import { getCatalogLogSources } from "./logSourceCatalog";
import { logSourceKey, parseLogSourceKey } from "./logSourceUtils";

/**
 * Populates a log sources multiselect with catalog or provided options.
 */
export function populateLogSourceOptions(
    property: MultiSelectProperty,
    sources: LogSource[]
): void {
    const optionsList = property.options;
    optionsList.value.clear();

    for (const source of sources) {
        const key = logSourceKey(source.name, source.channel);
        if (optionsList.value.has(key)) {
            continue;
        }

        const option = optionsList.createListItem() as StringProperty;
        option.setValue(key, false);
        optionsList.addProperty(option, key, undefined, false);
    }
}

/**
 * Sets the selected log sources on a multiselect property.
 */
export function selectLogSources(
    property: MultiSelectProperty,
    sources: LogSource[],
    update: boolean = true
): void {
    property.setSelections(
        sources.map(source => logSourceKey(source.name, source.channel)),
        update
    );
}

/**
 * Resolves the detection block id from a log sources property.
 */
export function findDetectionId(property: MultiSelectProperty): string | null {
    let current = property.parent;

    while (current) {
        if (current instanceof DictionaryProperty) {
            const id = current.get("detection_id", StringProperty)?.value;
            if (typeof id === "string" && id.startsWith("DET")) {
                return id;
            }
        }
        current = current.parent;
    }

    return null;
}

/**
 * Returns the selectable log source keys for a multiselect (read-only).
 */
export function getLogSourceOptionKeys(property: MultiSelectProperty): string[] {
    const keys = new Set<string>();
    const detectionId = findDetectionId(property);

    for (const source of getCatalogLogSources(detectionId)) {
        keys.add(logSourceKey(source.name, source.channel));
    }

    for (const key of property.values) {
        keys.add(key);
    }

    return [...keys];
}

/**
 * Hydrates log source options from the MITRE catalog and any persisted selections.
 */
export function hydrateLogSourceOptions(property: MultiSelectProperty): void {
    const keys = getLogSourceOptionKeys(property);
    populateLogSourceOptions(
        property,
        keys.map(key => parseLogSourceKey(key))
    );
}
