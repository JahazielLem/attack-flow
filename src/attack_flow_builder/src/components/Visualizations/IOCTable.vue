<template>
  <div class="ioc-table-visualization">
    <div class="ioc-table-controls">
      <VisualizationWidthControl
        v-model="tableWidth"
        :min="minTableWidth"
        :max="maxTableWidth"
        :step="tableWidthStep"
      />

      <button
        type="button"
        class="export-to-csv-button"
        @click="exportToCsv"
      >
        Export to CSV
      </button>
    </div>
    <div class="ioc-table-stage">
      <div
        id="ioc-table-vis"
        :style="{ width: `${tableWidth}px` }"
      >
        <SvgTable
          :columns="columnDefinitions"
          :rows="iocTableData"
          :width="tableWidth"
          :cell-spacing="0"
          :text-wrap="{ maxLines: 3 }"
          :border-width="0"
          :show-row-dividers="true"
          :row-divider-width="2"
        />
      </div>
    </div>
  </div>
</template>
<script setup lang="ts">
import { DictionaryProperty, ListProperty, StringProperty } from '@/assets/scripts/OpenChart/DiagramModel';
import { useApplicationStore } from '@/stores/ApplicationStore';
import { computed, ref } from 'vue';
import VisualizationWidthControl from './VisualizationWidthControl.vue';
import SvgTable, { type SvgTableColumn, type SvgTableRow } from './SvgTable.vue';
import { downloadCsv, rowsToCsv } from './CsvHelpers';

const app = useApplicationStore();

const columnDefinitions : SvgTableColumn[] = [
    {
        id: "ioc",
        header: "IOC"
    },
    {
        id: "type",
        header: "Type",
        width: "20%",
        valueFormatter: ({ row }) => {
            const displayName = iocTypesToDisplayNames.get(row.type as string);
            return `${displayName ?? row.type}`;
        }
    },
    {
        id: "label",
        header: "Label"
    }
];

/** A table row detailing an indicator of compromise (IOC). */
interface IocTableRow extends SvgTableRow {
    /** The actual IOC artifact. */
    ioc: string;
    /** The type of IOC, basically the block id. */
    type: string;
    /** Human-readable description of the IOC. */
    label: string;
}

/** This maps serves as a source for allowed IOC types and provides human-readable versions of their ids. */
const iocTypesToDisplayNames = new Map<string, string>([
    ["indicator", "Indicator"],
    ["infrastructure", "Infrastructure"],
    ["malware", "Malware"],
    ["tool", "Tool"],
    ["domain_name", "Domain"],
    ["email_address", "Email"],
    ["file", "File"],
    ["ipv4_addr", "IPv4"],
    ["ipv6_addr", "IPv6"],
    ["mac_address", "MAC Address"],
    ["url", "URL"]
])

const defaultTableWidth = 1200;
const minTableWidth = 800;
const maxTableWidth = 2400;
const tableWidthStep = 200;
const tableWidth = ref(defaultTableWidth);

const iocTableData = computed<IocTableRow[]>(() => {
    const iocBlocks = app.activeEditor.file.canvas.blocks.filter(b => iocTypesToDisplayNames.has(b.id));
    const rows : IocTableRow[] = [];

    for (const block of iocBlocks) {
        switch (block.id) {
            case "indicator":
            case "infrastructure":
            case "malware":
            case "tool": {
                // Simple mapping of "name" to ioc and "description" to label.
                const rowData : IocTableRow = {
                    ioc: "",
                    type: block.id,
                    label: ""
                };
                rowData.ioc = block.properties.get("name", StringProperty)?.value ?? rowData.ioc;
                rowData.label = block.properties.get("description", StringProperty)?.value ?? rowData.label;
                rows.push(rowData);
                break;
            }
            case "domain_name":
            case "email_address":
            case "ipv4_addr":
            case "ipv6_addr":
            case "mac_addr":
            case "url": {
                // Simple mapping of "value" to ioc. Label is left blank because there's no other properties.
                const rowData : IocTableRow = {
                    ioc: "",
                    type: block.id,
                    label: ""
                };
                rowData.ioc = block.properties.get("value", StringProperty)?.value ?? rowData.ioc;
                rows.push(rowData);
                break;
            }
            case "file": {
                // For files, if there is a hash, then the name should be the label, but if there's no hash, the name should be the IOC.
                // Also, if there are multiple hashes, each hash should have it's own row.
                const rowsToAdd : IocTableRow[] = [];

                const hashes = block.properties.get("hashes", ListProperty)?.value;
                const fileName = block.properties.get("name", StringProperty)?.value;

                // If hashes are available, create a row for each hash.
                if (hashes && hashes.size) {
                    for (const val of hashes.values()) {
                        const hashVal = (val as DictionaryProperty).get("hash_value", StringProperty)?.value;

                        if (!hashVal) continue;

                        rowsToAdd.push(
                            {
                                ioc: hashVal ?? "",
                                type: block.id,
                                label: fileName ?? ""
                            }
                        );
                    }
                }

                // If a hash row was not added, add a row with the file name as the IOC. Leave label blank because there
                // is no human readable description property.
                if (!rowsToAdd.length) {
                    rowsToAdd.push(
                        {
                            ioc: fileName ?? "",
                            type: block.id,
                            label: ""
                        }
                    )
                }

                rows.push(...rowsToAdd);
                break;
            }
        }
    }

    return rows;
});

/** Convert row data to csv and download as a csv file. */
function exportToCsv() {
    const exportRows = iocTableData.value.map((row, rowIndex) => {
        return Object.fromEntries(
            columnDefinitions.map((column) => {
                const value = row[column.id];
                const formattedValue = column.valueFormatter
                    ? column.valueFormatter({
                        row,
                        rowIndex,
                        value,
                        column
                    })
                    : String(value ?? "");
                return [column.header, formattedValue];
            })
        );
    });

    const csvText = rowsToCsv(
        exportRows,
        columnDefinitions.map(column => column.header)
    );
    downloadCsv(`${getVisualizationExportName()}.csv`, csvText);
}

/**
 * Resolve the exported file name without an extension.
 */
function getVisualizationExportName(): string {
    const sourceName = app.activeEditor.file.canvas.properties.toString() || "attack-flow";
    return sanitizeFileName(`${sourceName} - IOC Table`);
}

/**
 * Remove characters that are unsafe for downloaded file names.
 */
function sanitizeFileName(value: string): string {
    return value
        .replace(/[\\/:*?"<>|]+/g, "-")
        .replace(/\s+/g, " ")
        .trim();
}

</script>
<style scoped>

.ioc-table-visualization {
    background-color: white;
    height: 100%;
    display: flex;
    flex-direction: column;
}

.ioc-table-controls {
    align-items: center;
    background: #f7f7f7;
    border-bottom: 1px solid #d4d4d3;
    display: flex;
    flex-wrap: wrap;
    gap: 10px 14px;
    padding: 10px;
    justify-content: space-between;
}

.ioc-table-stage {
    overflow: auto;
    flex: 1;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th {
    text-align: left;
}

th {
    padding: 5px;
    color: rgb(241, 243, 244);
}

td {
    padding: 5px;
}

tr:not(:last-child) {
    border-bottom: solid 1px #eee;
}

.export-to-csv-button {
    background-color: white;
    border: 1px solid #bbb;
    padding: 2px 6px;
    height: 24px;
    color: #333;
}

</style>
