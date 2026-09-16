
/**
 * A naive approach to wrapping. It assumes that there will be
 * spaces in opportune places and never forces a line break.
 * @param text the text to wrap
 * @param maxCols max characters in a line
 * @param maxRows max rows before text is truncated with ellipsis
 * @returns array of lines of text
 */
export function wrapText(text: string, maxCols: number, maxRows: number): string[] {
    let startIdx = 0;
    let lastSpace = -1;
    let lines = [];

    // Break the string into multiple smaller strings, ideally at natural spaces.
    for (let endIdx = 0; endIdx < text.length; endIdx++) {
        if (/\s/.test(text.charAt(endIdx))) {
            lastSpace = endIdx;
        } else if (endIdx - startIdx >= maxCols) {
            if (lastSpace === -1) {
                lastSpace = endIdx; // Break long strings even if there's no space.
            }
            lines.push(text.substring(startIdx, lastSpace));
            startIdx = lastSpace + 1;
            lastSpace = -1;
        }
    }
    lines.push(text.substring(startIdx));

    // Truncate lines beyond limit and add ellipsis.
    if (lines.length > maxRows) {
        lines = lines.slice(0, maxRows);
        if (lines[maxRows - 1].length > maxCols - 3) {
            lines[maxRows - 1] = lines[maxRows - 1].substring(0, maxCols - 3);
        }
        lines[maxRows - 1] += "…";
    }

    return lines;
}
