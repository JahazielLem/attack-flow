/**
 * Convert an array of plain row objects into a CSV string.
 *
 * Assumptions:
 * - Each row is a flat object whose values are already suitable for stringification.
 * - Nested objects are serialized with `JSON.stringify()`.
 * - Arrays are joined with `", "` before CSV escaping.
 * - The header row is derived from the first row's keys when `columns` is omitted.
 * - Column order is stable only when `columns` is provided explicitly.
 *
 * @param rows
 *  The row data to serialize.
 * @param columns
 *  Optional ordered list of object keys to include as CSV columns.
 * @returns
 *  A UTF-8 CSV string with CRLF row endings.
 */
export function rowsToCsv(
    rows: Record<string, unknown>[],
    columns?: string[]
): string {
    const resolvedColumns = columns ?? Object.keys(rows[0] ?? {});
    const csvLines = [
        resolvedColumns.map(escapeCsvCell).join(",")
    ];

    for (const row of rows) {
        csvLines.push(
            resolvedColumns.map((column) => {
                return escapeCsvCell(row[column]);
            }).join(",")
        );
    }

    return csvLines.join("\r\n");
}

/**
 * Download a CSV string as a file in the browser.
 * @param fileName
 *  The file name to use for the download. Appends `.csv` if no extension exists.
 * @param csvText
 *  The CSV contents to download.
 */
export function downloadCsv(fileName: string, csvText: string): void {
    const blob = new Blob([csvText], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = withCsvExtension(fileName);
    anchor.click();
    URL.revokeObjectURL(url);
}

/**
 * Convert a single value into a CSV-safe cell string.
 */
function escapeCsvCell(value: unknown): string {
    let stringValue = "";

    if (value == null) {
        stringValue = "";
    } else if (Array.isArray(value)) {
        stringValue = value.map(item => stringifyValue(item)).join(", ");
    } else {
        stringValue = stringifyValue(value);
    }

    const escapedValue = stringValue.replaceAll("\"", "\"\"");
    return `"${escapedValue}"`;
}

/**
 * Convert an unknown value into a string for CSV serialization.
 */
function stringifyValue(value: unknown): string {
    if (value == null) {
        return "";
    }
    if (typeof value === "object") {
        return JSON.stringify(value);
    }
    return String(value);
}

/**
 * Append `.csv` to a file name when it does not already have an extension.
 */
function withCsvExtension(fileName: string): string {
    const trimmedName = fileName.trim();
    const lastSlashIndex = Math.max(
        trimmedName.lastIndexOf("/"),
        trimmedName.lastIndexOf("\\")
    );
    const baseName = lastSlashIndex >= 0
        ? trimmedName.slice(lastSlashIndex + 1)
        : trimmedName;

    return baseName.includes(".") ? trimmedName : `${trimmedName}.csv`;
}
