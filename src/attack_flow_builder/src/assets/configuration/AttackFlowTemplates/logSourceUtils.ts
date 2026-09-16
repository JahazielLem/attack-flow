import type { LogSource } from "./SourceEnumeration";


const LOG_SOURCE_KEY_SEP = "\0";



/**

 * Builds a stable multiselect key for a log source.

 */

export function logSourceKey(name: string, channel: string): string {

    return `${name}${LOG_SOURCE_KEY_SEP}${channel}`;

}



/**

 * Parses a multiselect key back into name and channel.

 */

export function parseLogSourceKey(key: string): LogSource {

    const sep = key.indexOf(LOG_SOURCE_KEY_SEP);

    if (sep === -1) {

        return { name: key, channel: "" };

    }

    return {

        name: key.slice(0, sep),

        channel: key.slice(sep + 1)

    };

}



/**

 * Short label for multiselect option text.

 */

export function formatLogSourceLabel(key: string): string {

    const { name, channel } = parseLogSourceKey(key);

    return channel ? `${name} (${channel})` : name;

}



/**

 * Full property-editor label with name and channel lines.

 */

export function formatLogSourceEntry(key: string): string {

    const { name, channel } = parseLogSourceKey(key);

    return `name: ${name}\nchannel: ${channel}`;

}



/**

 * Compact canvas bullets showing source names only.

 */

export function formatLogSourceBlockLines(values: Iterable<string>): string[] {

    const lines: string[] = [];

    for (const key of values) {

        lines.push(`• ${parseLogSourceKey(key).name}`);

    }

    return lines;

}
