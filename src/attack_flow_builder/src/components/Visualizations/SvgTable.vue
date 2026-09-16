<template>
  <component
    :is="asGroup ? 'g' : 'svg'"
    :width="asGroup ? undefined : tableWidth"
    :height="asGroup ? undefined : tableHeight"
    :viewBox="asGroup ? undefined : `0 0 ${tableWidth} ${tableHeight}`"
    :xmlns="asGroup ? undefined : 'http://www.w3.org/2000/svg'"
    :role="asGroup ? undefined : 'img'"
    class="svg-table-root"
  >
    <g v-if="resolvedColumns.length">
      <template
        v-for="(column, columnIndex) in resolvedColumns"
        :key="`header-${column.id}`"
      >
        <rect
          :x="column.x"
          y="0"
          :width="column.width"
          :height="resolvedHeaderHeight"
          :fill="headerBackgroundColor"
          :stroke="borderColor"
          :stroke-width="borderWidth"
        />
        <template v-if="hasSlot(`header-${column.id}`)">
          <slot
            :name="`header-${column.id}`"
            :column="column"
            :x="column.x"
            y="0"
            :width="column.width"
            :height="resolvedHeaderHeight"
            :text-x="getTextX(column.x, column.width, getHeaderAlign(column), cellPaddingX)"
            :text-y="getTextBlockStartY(0, resolvedHeaderHeight, getLineBlockHeight(resolvedHeaderLines[columnIndex].length, resolvedHeaderWraps[columnIndex].lineHeight, headerFontSize), headerFontSize)"
            :lines="resolvedHeaderLines[columnIndex]"
          />
        </template>
        <template v-else-if="hasSlot('header')">
          <slot
            name="header"
            :column="column"
            :x="column.x"
            y="0"
            :width="column.width"
            :height="resolvedHeaderHeight"
            :text-x="getTextX(column.x, column.width, getHeaderAlign(column), cellPaddingX)"
            :text-y="getTextBlockStartY(0, resolvedHeaderHeight, getLineBlockHeight(resolvedHeaderLines[columnIndex].length, resolvedHeaderWraps[columnIndex].lineHeight, headerFontSize), headerFontSize)"
            :lines="resolvedHeaderLines[columnIndex]"
          />
        </template>
        <text
          v-else
          :x="getTextX(column.x, column.width, getHeaderAlign(column), cellPaddingX)"
          :y="getTextBlockStartY(0, resolvedHeaderHeight, getLineBlockHeight(resolvedHeaderLines[columnIndex].length, resolvedHeaderWraps[columnIndex].lineHeight, headerFontSize), headerFontSize)"
          :fill="headerFontColor"
          :font-size="headerFontSize"
          :font-weight="getHeaderFontWeight(column)"
          :text-anchor="getHeaderAlign(column)"
        >
          <tspan
            v-for="(line, lineIndex) in resolvedHeaderLines[columnIndex]"
            :key="`header-line-${column.id}-${lineIndex}`"
            :x="getTextX(column.x, column.width, getHeaderAlign(column), cellPaddingX)"
            :dy="lineIndex === 0 ? 0 : resolvedHeaderWraps[columnIndex].lineHeight"
          >
            {{ line }}
          </tspan>
        </text>
      </template>
    </g>

    <g
      v-for="(row, rowIndex) in rows"
      :key="getRowKey(row, rowIndex)"
    >
      <template
        v-for="(column, columnIndex) in resolvedColumns"
        :key="`${getRowKey(row, rowIndex)}-${column.id}`"
      >
        <rect
          :x="column.x"
          :y="rowOffsets[rowIndex]"
          :width="column.width"
          :height="resolvedRowHeights[rowIndex]"
          :fill="resolveRowBackgroundColor(row, rowIndex)"
          :stroke="borderColor"
          :stroke-width="borderWidth"
        />
        <template v-if="hasSlot(`cell-${column.id}`)">
          <slot
            :name="`cell-${column.id}`"
            :row="row"
            :row-index="rowIndex"
            :column="column"
            :value="getCellValue(row, column)"
            :formatted-value="getFormattedCellValue(row, rowIndex, column)"
            :lines="resolvedBodyLines[rowIndex][columnIndex]"
            :x="column.x"
            :y="rowOffsets[rowIndex]"
            :width="column.width"
            :height="resolvedRowHeights[rowIndex]"
            :text-x="getTextX(column.x, column.width, getColumnAlign(column), cellPaddingX)"
            :text-y="getTextBlockStartY(rowOffsets[rowIndex], resolvedRowHeights[rowIndex], getLineBlockHeight(resolvedBodyLines[rowIndex][columnIndex].length, resolvedBodyWraps[columnIndex].lineHeight, rowFontSize), rowFontSize)"
          />
        </template>
        <template v-else-if="hasSlot('cell')">
          <slot
            name="cell"
            :row="row"
            :row-index="rowIndex"
            :column="column"
            :value="getCellValue(row, column)"
            :formatted-value="getFormattedCellValue(row, rowIndex, column)"
            :lines="resolvedBodyLines[rowIndex][columnIndex]"
            :x="column.x"
            :y="rowOffsets[rowIndex]"
            :width="column.width"
            :height="resolvedRowHeights[rowIndex]"
            :text-x="getTextX(column.x, column.width, getColumnAlign(column), cellPaddingX)"
            :text-y="getTextBlockStartY(rowOffsets[rowIndex], resolvedRowHeights[rowIndex], getLineBlockHeight(resolvedBodyLines[rowIndex][columnIndex].length, resolvedBodyWraps[columnIndex].lineHeight, rowFontSize), rowFontSize)"
          />
        </template>
        <text
          v-else
          :x="getTextX(column.x, column.width, getColumnAlign(column), cellPaddingX)"
          :y="getTextBlockStartY(rowOffsets[rowIndex], resolvedRowHeights[rowIndex], getLineBlockHeight(resolvedBodyLines[rowIndex][columnIndex].length, resolvedBodyWraps[columnIndex].lineHeight, rowFontSize), rowFontSize)"
          :fill="rowFontColor"
          :font-size="rowFontSize"
          :font-weight="getColumnFontWeight(column)"
          :text-anchor="getColumnAlign(column)"
        >
          <tspan
            v-for="(line, lineIndex) in resolvedBodyLines[rowIndex][columnIndex]"
            :key="`body-line-${getRowKey(row, rowIndex)}-${column.id}-${lineIndex}`"
            :x="getTextX(column.x, column.width, getColumnAlign(column), cellPaddingX)"
            :dy="lineIndex === 0 ? 0 : resolvedBodyWraps[columnIndex].lineHeight"
          >
            {{ line }}
          </tspan>
        </text>
      </template>
    </g>

    <g v-if="showRowDividers">
      <line
        v-for="(row, rowIndex) in rows.slice(0, -1)"
        :key="`row-divider-${getRowKey(row, rowIndex)}`"
        x1="0"
        :x2="tableWidth"
        :y1="rowOffsets[rowIndex] + resolvedRowHeights[rowIndex]"
        :y2="rowOffsets[rowIndex] + resolvedRowHeights[rowIndex]"
        :stroke="rowDividerColor"
        :stroke-width="rowDividerWidth"
      />
    </g>
  </component>
</template>

<script lang="ts">
// This module-scope script exists so <script setup> can reference shared
// default objects from withDefaults(), which is hoisted by the SFC compiler.
export const DEFAULT_TEXT_WRAP = {
    maxLines: 1,
    charWidth: 8.5,
    lineHeight: 19,
    autoRowHeight: true
};
</script>

<script setup lang="ts">
import { computed, useSlots, watch } from "vue";
import { wrapText } from "./SvgHelpers";

/**
 * SvgTable renders a configurable SVG-based table from plain row objects and column definitions.
 *
 * Rows should be simple objects whose keys match the configured column ids. By default, each cell
 * renders the value at `row[column.id]`, optionally transformed by `column.valueFormatter`.
 *
 * Custom rendering is provided through scoped slots:
 * - `cell-${column.id}` for a specific body column
 * - `header-${column.id}` for a specific header column
 * - `cell` as a fallback body cell slot
 * - `header` as a fallback header cell slot
 *
 * Automatic header and row height only consider cells that use the built-in text renderer. Slot-
 * rendered content is ignored for sizing and is expected to fit inside the assigned cell bounds.
 *
 * When `asGroup` is true, the component renders as a `<g>` for composition inside an external SVG
 * root and emits `sizeChange` whenever its computed width or height changes.
 */
export type SvgTableRow = Record<string, unknown>;
export type SvgTableTextAlign = "start" | "middle" | "end";
export type SvgTableFontWeight = string | number;
export type SvgTablePercentageWidth = `${number}%`;
export type SvgTableWidth = number | SvgTablePercentageWidth;

export interface SvgTableTextWrapOptions {
    /** Maximum wrapped lines before text is truncated with ellipsis. */
    maxLines?: number;
    /** Approximate character width in pixels used to estimate wrapping. */
    charWidth?: number;
    /** Line height in pixels used for wrapped text. */
    lineHeight?: number;
    /** Grow row height to fit wrapped body text when enabled. */
    autoRowHeight?: boolean;
}

export interface SvgTableColumn {
    /** Stable column id that also maps to the row object key. */
    id: string;
    /** Header text displayed for this column. */
    header: string;
    /** Fixed column width in pixels or percentage of available table width. */
    width?: SvgTableWidth;
    /** Minimum column width in pixels for flexible columns. */
    minWidth?: number;
    /** Default text alignment used for this column's body cells. */
    align?: SvgTableTextAlign;
    /** Optional font weight override for this column's body cells. */
    fontWeight?: SvgTableFontWeight;
    /** Optional header text alignment override for this column. */
    headerAlign?: SvgTableTextAlign;
    /** Optional font weight override for this column's header cell. */
    headerFontWeight?: SvgTableFontWeight;
    /** Optional wrapping overrides for this column's default body text. */
    textWrap?: SvgTableTextWrapOptions;
    /** Optional wrapping overrides for this column's default header text. */
    headerTextWrap?: SvgTableTextWrapOptions;
    /** Optional formatter for the default text rendered from the row value. */
    valueFormatter?: (args: {
        row: SvgTableRow;
        rowIndex: number;
        value: unknown;
        column: SvgTableColumn;
    }) => string;
}

interface ResolvedSvgTableColumn extends SvgTableColumn {
    width: number;
    x: number;
}

interface ResolvedSvgTableTextWrapOptions {
    maxLines: number;
    charWidth: number;
    lineHeight: number;
    autoRowHeight: boolean;
}

const DEFAULT_VERTICAL_PADDING = 8;

interface Props {
    /** Column definitions that control headers, sizing, and cell formatting. */
    columns: SvgTableColumn[];
    /** Plain row objects whose keys should match the configured column ids. */
    rows: SvgTableRow[];
    /** Preferred table width in pixels before column expansion is applied. */
    width: number;
    /** Render the table as a `<g>` instead of a standalone root `<svg>`. */
    asGroup?: boolean;
    /** Optional row key field name or resolver used for stable row identity. */
    rowKey?: string | ((row: SvgTableRow, rowIndex: number) => string);
    /** Header cell fill as any valid CSS color string. */
    headerBackgroundColor?: string;
    /** Font size in pixels used for header text. */
    headerFontSize?: number;
    /** Default font weight used for header text. */
    headerFontWeight?: SvgTableFontWeight;
    /** Header text color as any valid CSS color string. */
    headerFontColor?: string;
    /** Default text alignment used for header labels. */
    headerTextAlign?: SvgTableTextAlign;
    /** Horizontal and vertical gap in pixels inserted between adjacent cells. */
    cellSpacing?: number;
    /** Row fill color as any valid CSS color string, or a per-row resolver. */
    rowBackgroundColor?: string | ((row: SvgTableRow, rowIndex: number) => string);
    /** Font size in pixels used for default row text. */
    rowFontSize?: number;
    /** Default font weight used for body cell text. */
    rowFontWeight?: SvgTableFontWeight;
    /** Row text color as any valid CSS color string. */
    rowFontColor?: string;
    /** Default text alignment used for body cell labels. */
    rowTextAlign?: SvgTableTextAlign;
    /** Height in pixels reserved for the header row. */
    headerHeight?: number;
    /** Height in pixels reserved for each data row. */
    rowHeight?: number;
    /** Horizontal padding in pixels applied to default text inside each cell. */
    cellPaddingX?: number;
    /** Whether to draw horizontal divider lines between body rows. */
    showRowDividers?: boolean;
    /** Divider line color as any valid CSS color string. */
    rowDividerColor?: string;
    /** Divider line width in pixels. */
    rowDividerWidth?: number;
    /** Wrapping behavior applied to default body cell text. */
    textWrap?: SvgTableTextWrapOptions;
    /** Wrapping behavior applied to default header cell text. */
    headerTextWrap?: SvgTableTextWrapOptions;
    /** Cell border color as any valid CSS color string. */
    borderColor?: string;
    /** Stroke width in pixels used for cell borders. */
    borderWidth?: number;
}

const props = withDefaults(defineProps<Props>(), {
    asGroup: false,
    rowKey: undefined,
    headerBackgroundColor: "#005b94",
    headerFontSize: 17,
    headerFontWeight: 700,
    headerFontColor: "#f1f3f4",
    headerTextAlign: "start",
    cellSpacing: 8,
    rowBackgroundColor: "#ffffff",
    rowFontSize: 16,
    rowFontWeight: 400,
    rowFontColor: "#333333",
    rowTextAlign: "start",
    headerHeight: 36,
    rowHeight: 32,
    cellPaddingX: 10,
    showRowDividers: false,
    rowDividerColor: "#eeeeee",
    rowDividerWidth: 1,
    textWrap: () => ({ ...DEFAULT_TEXT_WRAP }),
    headerTextWrap: () => ({ ...DEFAULT_TEXT_WRAP }),
    borderColor: "#d4d4d3",
    borderWidth: 1
});

const emit = defineEmits<{
    sizeChange: [size: { width: number; height: number }];
}>();

const slots = useSlots();

const resolvedColumns = computed<ResolvedSvgTableColumn[]>(() => {
    if (!props.columns.length) {
        return [];
    }

    const gapWidth = props.cellSpacing * Math.max(0, props.columns.length - 1);
    const availableWidth = Math.max(0, props.width - gapWidth);
    const fixedWidthSum = props.columns.reduce((sum, column) => {
        return sum + (typeof column.width === "number" ? column.width : 0);
    }, 0);
    const percentageWidthSum = props.columns.reduce((sum, column) => {
        return sum + resolvePercentageWidth(column.width, availableWidth);
    }, 0);
    const explicitWidthSum = fixedWidthSum + percentageWidthSum;
    const flexibleColumns = props.columns.filter(column => column.width == null);
    const defaultFlexibleWidth = flexibleColumns.length
        ? Math.max(0, availableWidth - explicitWidthSum) / flexibleColumns.length
        : 0;

    const widths = props.columns.map((column) => {
        if (typeof column.width === "number") {
            return column.width;
        }
        if (typeof column.width === "string") {
            return resolvePercentageWidth(column.width, availableWidth);
        }
        return Math.max(column.minWidth ?? 120, defaultFlexibleWidth);
    });

    const widthSum = widths.reduce((sum, width) => sum + width, 0);
    if (!flexibleColumns.length && widths.length && widthSum < availableWidth) {
        widths[widths.length - 1] += availableWidth - widthSum;
    }

    let currentX = 0;
    return props.columns.map((column, index) => {
        const resolvedColumn: ResolvedSvgTableColumn = {
            ...column,
            width: widths[index],
            x: currentX
        };
        currentX += widths[index] + props.cellSpacing;
        return resolvedColumn;
    });
});

const tableWidth = computed(() => {
    if (!resolvedColumns.value.length) {
        return props.width;
    }
    const lastColumn = resolvedColumns.value[resolvedColumns.value.length - 1];
    return Math.max(props.width, lastColumn.x + lastColumn.width);
});

const resolvedBodyWraps = computed<ResolvedSvgTableTextWrapOptions[]>(() => {
    return resolvedColumns.value.map(column => resolveBodyTextWrap(column));
});

const resolvedHeaderWraps = computed<ResolvedSvgTableTextWrapOptions[]>(() => {
    return resolvedColumns.value.map(column => resolveHeaderTextWrap(column));
});

const resolvedHeaderLines = computed<string[][]>(() => {
    return resolvedColumns.value.map((column, columnIndex) => {
        if (!isDefaultHeaderRendered(column)) {
            return [column.header];
        }
        return getWrappedLines(column.header, column.width, resolvedHeaderWraps.value[columnIndex]);
    });
});

const resolvedBodyLines = computed<string[][][]>(() => {
    return props.rows.map((row, rowIndex) => {
        return resolvedColumns.value.map((column, columnIndex) => {
            if (!isDefaultCellRendered(column)) {
                return [getFormattedCellValue(row, rowIndex, column)];
            }
            return getWrappedLines(
                getFormattedCellValue(row, rowIndex, column),
                column.width,
                resolvedBodyWraps.value[columnIndex]
            );
        });
    });
});

const resolvedHeaderHeight = computed(() => {
    let height = props.headerHeight;
    for (let columnIndex = 0; columnIndex < resolvedColumns.value.length; columnIndex++) {
        const column = resolvedColumns.value[columnIndex];
        const wrap = resolvedHeaderWraps.value[columnIndex];
        if (!wrap.autoRowHeight || !isDefaultHeaderRendered(column)) {
            continue;
        }
        const requiredHeight = getLineBlockHeight(
            resolvedHeaderLines.value[columnIndex].length,
            wrap.lineHeight,
            props.headerFontSize
        ) + (DEFAULT_VERTICAL_PADDING * 2);
        height = Math.max(height, requiredHeight);
    }
    return height;
});

const resolvedRowHeights = computed<number[]>(() => {
    return props.rows.map((_, rowIndex) => {
        let height = props.rowHeight;
        for (let columnIndex = 0; columnIndex < resolvedColumns.value.length; columnIndex++) {
            const column = resolvedColumns.value[columnIndex];
            const wrap = resolvedBodyWraps.value[columnIndex];
            if (!wrap.autoRowHeight || !isDefaultCellRendered(column)) {
                continue;
            }
            const requiredHeight = getLineBlockHeight(
                resolvedBodyLines.value[rowIndex][columnIndex].length,
                wrap.lineHeight,
                props.rowFontSize
            ) + (DEFAULT_VERTICAL_PADDING * 2);
            height = Math.max(height, requiredHeight);
        }
        return height;
    });
});

const rowOffsets = computed<number[]>(() => {
    const offsets: number[] = [];
    let currentY = resolvedHeaderHeight.value + (props.rows.length ? props.cellSpacing : 0);
    for (let rowIndex = 0; rowIndex < props.rows.length; rowIndex++) {
        offsets.push(currentY);
        currentY += resolvedRowHeights.value[rowIndex] + props.cellSpacing;
    }
    return offsets;
});

const tableHeight = computed(() => {
    if (!props.rows.length) {
        return resolvedHeaderHeight.value;
    }
    return resolvedHeaderHeight.value
        + props.cellSpacing
        + resolvedRowHeights.value.reduce((sum, height) => sum + height, 0)
        + (props.cellSpacing * Math.max(0, props.rows.length - 1));
});

watch(
    [tableWidth, tableHeight],
    ([width, height], [oldWidth, oldHeight]) => {
        if (width !== oldWidth || height !== oldHeight) {
            emit("sizeChange", { width, height });
        }
    },
    { immediate: true }
);

/**
 * Return whether a named scoped slot is available.
 */
function hasSlot(name: string): boolean {
    const slotMap = slots as Record<string, unknown>;
    return typeof slotMap[name] === "function";
}

/**
 * Return whether the header uses the built-in text renderer.
 */
function isDefaultHeaderRendered(column: SvgTableColumn): boolean {
    return !hasSlot(`header-${column.id}`) && !hasSlot("header");
}

/**
 * Return whether the cell uses the built-in text renderer.
 */
function isDefaultCellRendered(column: SvgTableColumn): boolean {
    return !hasSlot(`cell-${column.id}`) && !hasSlot("cell");
}

/**
 * Resolve body text wrapping options for the given column.
 */
function resolveBodyTextWrap(column: SvgTableColumn): ResolvedSvgTableTextWrapOptions {
    const merged = {
        ...DEFAULT_TEXT_WRAP,
        ...props.textWrap,
        ...column.textWrap
    };
    return {
        maxLines: Math.max(1, merged.maxLines),
        charWidth: Math.max(1, merged.charWidth),
        lineHeight: Math.max(1, merged.lineHeight),
        autoRowHeight: merged.autoRowHeight
    };
}

/**
 * Resolve header text wrapping options for the given column.
 */
function resolveHeaderTextWrap(column: SvgTableColumn): ResolvedSvgTableTextWrapOptions {
    const merged = {
        ...DEFAULT_TEXT_WRAP,
        ...props.headerTextWrap,
        ...column.headerTextWrap
    };
    return {
        maxLines: Math.max(1, merged.maxLines),
        charWidth: Math.max(1, merged.charWidth),
        lineHeight: Math.max(1, merged.lineHeight),
        autoRowHeight: merged.autoRowHeight
    };
}

/**
 * Resolve a percentage width string into pixels using the available table width.
 */
function resolvePercentageWidth(width: SvgTableWidth | undefined, availableWidth: number): number {
    if (typeof width !== "string") {
        return 0;
    }
    const percentage = Number.parseFloat(width.slice(0, -1));
    if (!Number.isFinite(percentage)) {
        return 0;
    }
    return availableWidth * (percentage / 100);
}

/**
 * Wrap a string into one or more lines using the configured helper.
 */
function getWrappedLines(text: string, width: number, wrap: ResolvedSvgTableTextWrapOptions): string[] {
    const usableWidth = Math.max(1, width - (props.cellPaddingX * 2));
    const maxCols = Math.max(1, Math.floor(usableWidth / wrap.charWidth));
    return wrapText(text, maxCols, wrap.maxLines);
}

/**
 * Resolve a stable key for the given row.
 */
function getRowKey(row: SvgTableRow, rowIndex: number): string {
    if (typeof props.rowKey === "function") {
        return props.rowKey(row, rowIndex);
    }
    if (typeof props.rowKey === "string") {
        const value = row[props.rowKey];
        if (value != null) {
            return String(value);
        }
    }
    return `row-${rowIndex}`;
}

/**
 * Compute the rendered text block height for the given line count.
 */
function getLineBlockHeight(lineCount: number, lineHeight: number, fontSize: number): number {
    if (lineCount <= 0) {
        return fontSize;
    }
    return fontSize + ((lineCount - 1) * lineHeight);
}

/**
 * Compute the first-line baseline that vertically centers a text block.
 */
function getTextBlockStartY(y: number, height: number, blockHeight: number, fontSize: number): number {
    return y + Math.max(0, (height - blockHeight) / 2) + fontSize;
}

/**
 * Read the raw cell value from the row using the column id.
 */
function getCellValue(row: SvgTableRow, column: SvgTableColumn): unknown {
    return row[column.id];
}

/**
 * Format the cell value for default text rendering.
 */
function getFormattedCellValue(row: SvgTableRow, rowIndex: number, column: SvgTableColumn): string {
    const value = getCellValue(row, column);
    if (column.valueFormatter) {
        return column.valueFormatter({
            row,
            rowIndex,
            value,
            column
        });
    }
    return stringifyValue(value);
}

/**
 * Convert a raw value into a string suitable for default cell text.
 */
function stringifyValue(value: unknown): string {
    if (value == null) {
        return "";
    }
    if (Array.isArray(value)) {
        return value.map(stringifyValue).join(", ");
    }
    if (typeof value === "object") {
        return JSON.stringify(value);
    }
    return String(value);
}

/**
 * Resolve the background fill for the given data row.
 */
function resolveRowBackgroundColor(row: SvgTableRow, rowIndex: number): string {
    if (typeof props.rowBackgroundColor === "function") {
        return props.rowBackgroundColor(row, rowIndex);
    }
    return props.rowBackgroundColor;
}

/**
 * Resolve the text alignment for a body cell.
 */
function getColumnAlign(column: SvgTableColumn): SvgTableTextAlign {
    return column.align ?? props.rowTextAlign;
}

/**
 * Resolve the font weight for a body cell.
 */
function getColumnFontWeight(column: SvgTableColumn): SvgTableFontWeight {
    return column.fontWeight ?? props.rowFontWeight;
}

/**
 * Resolve the text alignment for a header cell.
 */
function getHeaderAlign(column: SvgTableColumn): SvgTableTextAlign {
    return column.headerAlign ?? props.headerTextAlign;
}

/**
 * Resolve the font weight for a header cell.
 */
function getHeaderFontWeight(column: SvgTableColumn): SvgTableFontWeight {
    return column.headerFontWeight ?? props.headerFontWeight;
}

/**
 * Compute the x-coordinate for default text inside a cell.
 */
function getTextX(x: number, width: number, align: SvgTableTextAlign, paddingX: number): number {
    switch (align) {
        case "middle":
            return x + (width / 2);
        case "end":
            return x + width - paddingX;
        case "start":
        default:
            return x + paddingX;
    }
}
</script>

<style scoped>
.svg-table-root {
    display: block;
}
</style>
