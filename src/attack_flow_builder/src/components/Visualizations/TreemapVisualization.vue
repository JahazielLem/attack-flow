<template>
  <div class="treemap-visualization">
    <div class="treemap-controls visualization-export-ignore">
      <label class="checkbox-control">
        <input
          v-model="showTechniqueIds"
          type="checkbox"
        >
        <span>Technique IDs</span>
      </label>
      <label class="checkbox-control">
        <input
          v-model="showTacticIds"
          type="checkbox"
        >
        <span>Tactic IDs</span>
      </label>
      <label>
        <span>Tiling</span>
        <select v-model="tileMethod">
          <option value="binary">
            Binary
          </option>
          <option value="squarify">
            Squarify
          </option>
          <option value="slice-dice">
            Slice-dice
          </option>
        </select>
      </label>
      <VisualizationWidthControl
        v-model="treemapWidth"
        aria-label="Treemap width"
        :min="minTreemapWidth"
        :max="maxTreemapWidth"
        :step="treemapWidthStep"
      />
      <label class="file-control">
        <span>Additional flows</span>
        <input
          ref="uploadInput"
          type="file"
          accept=".json,application/json"
          multiple
          @change="loadUploadedFlows"
        >
      </label>
      <button
        v-if="uploadedFlows.length || uploadError"
        type="button"
        class="clear-button"
        @click="clearUploadedFlows"
      >
        Clear
      </button>
      <span class="flow-summary">
        {{ flowSummary }}
      </span>
      <span
        v-if="uploadError"
        class="upload-error"
      >
        {{ uploadError }}
      </span>
    </div>

    <div class="treemap-stage">
      <div
        id="treemap-vis"
        class="treemap-export-root"
      >
        <svg
          v-if="treemapLayout"
          :width="treemapWidth"
          :height="height"
          :viewBox="treemapViewBox"
          role="img"
        >
          <g class="tactic-labels">
            <text
              v-for="tactic in treemapLayout.tactics"
              :key="tactic.id"
              class="tactic-label"
              :x="tactic.x"
              :y="tactic.y"
            >
              <title>{{ tactic.tooltip }}</title>
              {{ tactic.label }}
            </text>
          </g>

          <g
            v-for="leaf in treemapLayout.leaves"
            :key="leaf.id"
            :transform="`translate(${leaf.x}, ${leaf.y})`"
          >
            <rect
              :width="leaf.width"
              :height="leaf.height"
              :fill="leaf.color"
              fill-opacity="0.72"
            />
            <title>{{ leaf.tooltip }}</title>
            <clipPath :id="leaf.clipId">
              <rect
                :width="leaf.width"
                :height="leaf.height"
              />
            </clipPath>
            <text
              class="technique-label"
              :clip-path="`url(#${leaf.clipId})`"
            >
              <tspan
                v-for="(line, index) in leaf.lines"
                :key="`${leaf.id}-${index}`"
                x="4"
                :y="14 + index * 13"
                :font-weight="line.bold ? 'bold' : 'normal'"
              >
                {{ line.text }}
              </tspan>
            </text>
          </g>
        </svg>
        <div
          v-else
          class="treemap-empty"
        >
          No mapped techniques.
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import * as d3 from "d3";
import { computed, ref } from "vue";
import { StringProperty, TTPTupleProperty } from "@/assets/scripts/OpenChart/DiagramModel";
import {
    getTacticNameFromLabel,
    getTechniqueNameFromLabel
} from "@/assets/configuration/AttackFlowTemplates/TTPFrameworkConstants.ts";
import { useApplicationStore } from "@/stores/ApplicationStore";
import VisualizationWidthControl from "./VisualizationWidthControl.vue";

type TileMethod = "binary" | "squarify" | "slice-dice";

interface TechniqueDatum {
    id: string;
    name: string;
    tacticId: string;
    tacticName: string;
    value: number;
}

interface TechniqueInput {
    techniqueId: string;
    techniqueName: string;
    tacticId: string;
    tacticName: string;
}

interface TacticDatum {
    id: string;
    name: string;
    children: TechniqueDatum[];
}

interface TreemapRootDatum {
    name: string;
    children: TacticDatum[];
}

interface TacticLabel {
    id: string;
    label: string;
    tooltip: string;
    x: number;
    y: number;
}

interface TextLine {
    text: string;
    bold?: boolean;
}

interface TreemapLeaf {
    id: string;
    clipId: string;
    x: number;
    y: number;
    width: number;
    height: number;
    color: string;
    lines: TextLine[];
    tooltip: string;
}

interface TreemapLayout {
    tactics: TacticLabel[];
    leaves: TreemapLeaf[];
}

interface UploadedFlow {
    name: string;
    techniques: TechniqueInput[];
}

type StixObject = Record<string, unknown>;

const app = useApplicationStore();

const showTechniqueIds = ref(false);
const showTacticIds = ref(false);
const tileMethod = ref<TileMethod>("binary");
const uploadedFlows = ref<UploadedFlow[]>([]);
const uploadError = ref("");
const uploadInput = ref<HTMLInputElement | null>(null);

const defaultTreemapWidth = 1200;
const minTreemapWidth = 760;
const maxTreemapWidth = 2400;
const treemapWidthStep = 200;
const height = 700;
const labelLineHeight = 13;
const minLabelWidth = 56;
const minLabelHeight = 30;
const tacticLabelCharWidth = 7;
const techniqueLabelCharWidth = 6;
const labelHorizontalPadding = 8;
const labelVerticalPadding = 8;
const tacticColorScale = d3.scaleOrdinal<string, string>(d3.schemeSet2);
const treemapWidth = ref(defaultTreemapWidth);

const tacticNameById: Record<string, string> = {
    TA0043: "Reconnaissance",
    TA0042: "Resource Development",
    TA0001: "Initial Access",
    TA0002: "Execution",
    TA0003: "Persistence",
    TA0004: "Privilege Escalation",
    TA0005: "Defense Evasion",
    TA0006: "Credential Access",
    TA0007: "Discovery",
    TA0008: "Lateral Movement",
    TA0009: "Collection",
    TA0011: "Command and Control",
    TA0010: "Exfiltration",
    TA0040: "Impact",
    TA0027: "Initial Access",
    TA0041: "Execution",
    TA0028: "Persistence",
    TA0029: "Privilege Escalation",
    TA0030: "Defense Evasion",
    TA0031: "Credential Access",
    TA0032: "Discovery",
    TA0033: "Lateral Movement",
    TA0035: "Collection",
    TA0037: "Command and Control",
    TA0036: "Exfiltration",
    TA0034: "Impact",
    TA0038: "Network Effects",
    TA0039: "Remote Service Effects",
    TA0108: "Initial Access",
    TA0104: "Execution",
    TA0110: "Persistence",
    TA0111: "Privilege Escalation",
    TA0103: "Evasion",
    TA0102: "Discovery",
    TA0109: "Lateral Movement",
    TA0100: "Collection",
    TA0101: "Command and Control",
    TA0107: "Inhibit Response Function",
    TA0106: "Impair Process Control",
    TA0105: "Impact"
};

const activeFlowTechniques = computed<TechniqueInput[]>(() => {
    const techniques: TechniqueInput[] = [];
    const actionBlocks = app.activeEditor.file.canvas.blocks.filter(block => {
        return block.id === "action";
    });

    for (const block of actionBlocks) {
        const ttp = block.properties.get("ttp", TTPTupleProperty);
        const tacticProp = ttp?.value.get("tactic") as StringProperty | undefined;
        const techniqueProp = ttp?.value.get("technique") as StringProperty | undefined;
        const techniqueId = techniqueProp?.value;

        if (!techniqueProp || !techniqueId) {
            continue;
        }

        const tacticId = tacticProp?.value ?? "(NA)";
        const tacticName = tacticProp && tacticProp.value
            ? getTacticNameFromLabel(tacticProp.toString())
            : "(Tactic Not Provided)";
        const techniqueName = getTechniqueNameFromLabel(techniqueProp.toString());
        techniques.push({
            techniqueId,
            techniqueName,
            tacticId,
            tacticName
        });
    }

    return techniques;
});

const flowSummary = computed(() => {
    const flowCount = 1 + uploadedFlows.value.length;
    const suffix = flowCount === 1 ? "flow" : "flows";
    return `${flowCount} ${suffix} included`;
});

const treemapViewBox = computed(() => {
    return `0 0 ${treemapWidth.value} ${height}`;
});

const treemapData = computed<TreemapRootDatum | null>(() => {
    const tactics = new Map<string, TacticDatum>();
    const techniques = [
        ...activeFlowTechniques.value,
        ...uploadedFlows.value.flatMap(flow => flow.techniques)
    ];

    for (const technique of techniques) {
        addTechnique(tactics, technique);
    }

    const children = [...tactics.values()]
        .map(tactic => ({
            ...tactic,
            children: [...tactic.children].sort((a, b) => {
                return b.value - a.value || a.name.localeCompare(b.name);
            })
        }))
        .sort((a, b) => {
            if (a.id === "(NA)") {
                return 1;
            }
            if (b.id === "(NA)") {
                return -1;
            }
            return a.name.localeCompare(b.name);
        });

    if (!children.length) {
        return null;
    }

    return {
        name: "Techniques",
        children
    };
});

const treemapLayout = computed<TreemapLayout | null>(() => {
    const data = treemapData.value;

    if (!data) {
        return null;
    }

    const hierarchy = d3.hierarchy<TreemapRootDatum | TacticDatum | TechniqueDatum>(data)
        .sum(datum => "value" in datum ? datum.value : 0)
        .sort((a, b) => {
            return (b.value ?? 0) - (a.value ?? 0);
        });

    const root = d3.treemap<TreemapRootDatum | TacticDatum | TechniqueDatum>()
        .size([treemapWidth.value, height])
        .padding(2)
        .paddingTop(18)
        .round(false)
        .tile(getTile())
        (hierarchy);

    const tactics = root.children?.map(child => {
        const tactic = child.data as TacticDatum;
        const tacticWidth = Math.max(0, child.x1 - child.x0);
        const fullLabel = showTacticIds.value && tactic.id !== "(NA)"
            ? `${tactic.id}: ${tactic.name}`
            : tactic.name;
        return {
            id: tactic.id,
            label: getSingleLineLabel(fullLabel, tacticWidth, tacticLabelCharWidth),
            tooltip: fullLabel,
            x: child.x0 + 4,
            y: child.y0 + 13
        };
    }).filter(tactic => {
        return tactic.label;
    }) ?? [];

    const leaves = root.leaves().map((leaf, index) => {
        const technique = leaf.data as TechniqueDatum;
        const leafWidth = Math.max(0, leaf.x1 - leaf.x0);
        const leafHeight = Math.max(0, leaf.y1 - leaf.y0);
        const lines = leafWidth >= minLabelWidth && leafHeight >= minLabelHeight
            ? getTechniqueLines(technique, leafWidth, leafHeight)
            : [];
        return {
            id: `${technique.tacticId}-${technique.id}`,
            clipId: `treemap-clip-${index}`,
            x: leaf.x0,
            y: leaf.y0,
            width: leafWidth,
            height: leafHeight,
            color: tacticColorScale(technique.tacticId),
            lines,
            tooltip: getTechniqueTooltip(technique)
        };
    });

    return {
        tactics,
        leaves
    };
});

function getOrCreateTactic(
    tactics: Map<string, TacticDatum>,
    id: string,
    name: string
): TacticDatum {
    let tactic = tactics.get(id);
    if (!tactic) {
        tactic = {
            id,
            name,
            children: []
        };
        tactics.set(id, tactic);
    }
    return tactic;
}

function addTechnique(
    tactics: Map<string, TacticDatum>,
    input: TechniqueInput
) {
    const tactic = getOrCreateTactic(tactics, input.tacticId, input.tacticName);
    const technique = tactic.children.find(child => child.id === input.techniqueId);

    if (technique) {
        technique.value += 1;
    } else {
        tactic.children.push({
            id: input.techniqueId,
            name: input.techniqueName,
            tacticId: input.tacticId,
            tacticName: input.tacticName,
            value: 1
        });
    }
}

function getTile() {
    switch (tileMethod.value) {
        case "squarify":
            return d3.treemapSquarify;
        case "slice-dice":
            return d3.treemapSliceDice;
        case "binary":
        default:
            return d3.treemapBinary;
    }
}

async function loadUploadedFlows(event: Event) {
    const input = event.target as HTMLInputElement;
    const files = input.files ? Array.from(input.files) : [];
    const flows: UploadedFlow[] = [];
    const failedFiles: string[] = [];

    uploadError.value = "";

    for (const file of files) {
        try {
            const data = JSON.parse(await file.text()) as unknown;
            flows.push({
                name: file.name,
                techniques: getStixTechniques(data)
            });
        } catch {
            failedFiles.push(file.name);
        }
    }

    uploadedFlows.value = [
        ...uploadedFlows.value,
        ...flows
    ];
    if (failedFiles.length) {
        uploadError.value = `Could not read ${failedFiles.join(", ")}.`;
    }
    input.value = "";
}

function clearUploadedFlows() {
    uploadedFlows.value = [];
    uploadError.value = "";
    if (uploadInput.value) {
        uploadInput.value.value = "";
    }
}

function getStixTechniques(data: unknown): TechniqueInput[] {
    const objects = getStixObjects(data);
    const techniques: TechniqueInput[] = [];

    for (const object of objects) {
        if (!isRecord(object) || object.type !== "attack-action") {
            continue;
        }

        const techniqueId = getString(object.technique_id);
        if (!techniqueId) {
            continue;
        }

        const tacticId = getString(object.tactic_id) ?? "(NA)";
        techniques.push({
            techniqueId,
            techniqueName: getString(object.name) ?? techniqueId,
            tacticId,
            tacticName: getTacticNameFromId(tacticId)
        });
    }

    return techniques;
}

function getStixObjects(data: unknown): unknown[] {
    if (isRecord(data) && Array.isArray(data.objects)) {
        return data.objects;
    }
    throw new Error("Expected an exported Attack Flow STIX bundle.");
}

function isRecord(value: unknown): value is StixObject {
    return typeof value === "object" && value !== null;
}

function getString(value: unknown): string | undefined {
    return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function getTacticNameFromId(tacticId: string): string {
    if (tacticId === "(NA)") {
        return "(Tactic Not Provided)";
    }
    return tacticNameById[tacticId] ?? tacticId;
}

function getTechniqueLines(
    technique: TechniqueDatum,
    leafWidth: number,
    leafHeight: number
): TextLine[] {
    const label = showTechniqueIds.value
        ? `${technique.id}: ${technique.name}`
        : technique.name;
    const maxCols = getMaxChars(leafWidth, techniqueLabelCharWidth);
    const maxRows = Math.max(1, Math.floor((leafHeight - labelVerticalPadding) / labelLineHeight));
    const nameRows = maxRows > 1 ? maxRows - 1 : maxRows;
    const lines: TextLine[] = wrapText(label, maxCols, nameRows).map(text => {
        return { text };
    });

    if (maxRows > 1) {
        lines.push({
            text: `Count: ${technique.value}`,
            bold: true
        });
    }

    return lines.slice(0, maxRows);
}

function getTechniqueTooltip(technique: TechniqueDatum): string {
    return [
        `${technique.tacticName} - ${technique.name}`,
        `Technique ID: ${technique.id}`,
        `Count: ${technique.value}`
    ].join("\n");
}

function getSingleLineLabel(
    text: string,
    width: number,
    charWidth: number
): string {
    const maxChars = getMaxChars(width, charWidth);

    if (maxChars < 6) {
        return "";
    }

    return truncateText(text, maxChars);
}

function getMaxChars(
    width: number,
    charWidth: number
): number {
    return Math.max(1, Math.floor((width - labelHorizontalPadding) / charWidth));
}

function wrapText(text: string, maxCols: number, maxRows: number): string[] {
    const words = text.split(/\s+/).filter(Boolean);
    let current = "";
    const lines: string[] = [];

    for (const word of words) {
        if (current && `${current} ${word}`.length <= maxCols) {
            current = `${current} ${word}`;
        } else {
            if (current) {
                lines.push(current);
            }
            current = word;
        }

        while (current.length > maxCols) {
            lines.push(current.slice(0, maxCols));
            current = current.slice(maxCols);
        }
    }

    if (current) {
        lines.push(current);
    }

    if (!lines.length) {
        lines.push("");
    }

    if (lines.length <= maxRows) {
        return lines;
    }

    const visibleLines = lines.slice(0, maxRows);
    const lastIndex = visibleLines.length - 1;
    visibleLines[lastIndex] = truncateText(visibleLines[lastIndex], maxCols);
    return visibleLines;
}

function truncateText(text: string, maxChars: number): string {
    if (text.length <= maxChars) {
        return text;
    }

    if (maxChars <= 3) {
        return text.slice(0, maxChars);
    }

    return `${text.slice(0, maxChars - 3)}...`;
}
</script>

<style scoped>
.treemap-visualization {
    background-color: white;
    color: #111;
    min-height: 100%;
}

.treemap-controls {
    align-items: center;
    background: #f7f7f7;
    border-bottom: 1px solid #d4d4d3;
    display: flex;
    flex-wrap: wrap;
    gap: 10px 14px;
    padding: 10px;
}

.treemap-controls label {
    align-items: center;
    color: #333;
    display: flex;
    font-size: 12px;
    gap: 6px;
    white-space: nowrap;
}

.treemap-controls select {
    max-width: 130px;
}

.treemap-controls input[type="file"] {
    max-width: 220px;
}

.checkbox-control {
    gap: 4px;
}

.file-control {
    gap: 8px;
}

.clear-button {
    background: #fff;
    border: 1px solid #bbb;
    color: #333;
    cursor: pointer;
    font-size: 12px;
    padding: 3px 8px;
}

.flow-summary,
.upload-error {
    color: #555;
    font-size: 12px;
}

.upload-error {
    color: #b00020;
}

.treemap-stage {
    background-color: white;
    overflow: auto;
}

.treemap-export-root {
    background-color: white;
    box-sizing: border-box;
    display: inline-block;
    min-height: 480px;
    min-width: 100%;
    padding: 12px;
}

.treemap-export-root svg {
    display: block;
    min-width: 760px;
}

.tactic-label {
    fill: #222;
    font-size: 12px;
    font-weight: 700;
}

.technique-label {
    fill: #111;
    font-family: sans-serif;
    font-size: 10px;
    pointer-events: none;
}

.treemap-empty {
    align-items: center;
    color: #555;
    display: flex;
    font-size: 16px;
    justify-content: center;
    min-height: 320px;
}
</style>
