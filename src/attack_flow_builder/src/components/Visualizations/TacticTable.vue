<template>
  <div class="tactic-table-visualization">
    <div class="tactic-table-controls visualization-export-ignore">
      <VisualizationWidthControl
        v-model="tacticTableWidth"
        aria-label="Tactic table width"
        :min="minTacticTableWidth"
        :max="maxTacticTableWidth"
        :step="tacticTableWidthStep"
      />
      <label class="checkbox-control">
        <input
          v-model="displayCount"
          type="checkbox"
        >
        <span>Display Count</span>
      </label>
      <label class="file-control">
        <span>Additional flows</span>
        <input
          ref="uploadInput"
          type="file"
          accept=".afb,.json,application/json"
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
    <div class="tactic-table-stage">
      <div
        id="tactic-table-vis"
        v-if="groupedTechniques"
        :style="{ width: `${tacticTableWidth}px` }"
      >
        <div
          v-for="(group, index) in groupedTechniques.values()"
          :key="group.tactic.id"
          class="tactic"
          style="margin-bottom: 30px;"
        >
          <h3>
            Table {{ index + 1 }}: {{ group.tactic.id }} - {{ group.tactic.name }}
            <span v-if="group.tactic.domainLong">({{ group.tactic.domainLong }})</span>
          </h3>
          <table>
            <thead>
              <tr style="background-color: rgb(0, 91, 148);">
                <th
                  width="25%"
                  style="padding: 5px; color: rgb(241, 243, 244);"
                >
                  Technique Name
                </th>
                <th
                  width="15%"
                  style="padding: 5px; color: rgb(241, 243, 244);"
                >
                  ATT&amp;CK ID
                </th>
                <th
                  width="50%"
                  style="padding: 5px; color: rgb(241, 243, 244);"
                >
                  Use
                </th>
                <th
                  v-if="displayCount"
                  width="10%"
                  style="padding: 5px; color: rgb(241, 243, 244);"
                >
                  Count
                </th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="(technique, techniqueIndex) in group.techniques"
                :key="`${group.tactic.id}-${technique.id}-${techniqueIndex}`"
              >
                <td style="padding: 5px;">
                  {{ technique.name }}
                </td>
                <td style="padding: 5px;">
                  <a
                    :href="getTechniqueUrl(technique.id, technique.name, group.tactic.domainShort)"
                    target="_blank"
                  >{{
                    technique.id }}</a>
                </td>
                <td style="padding: 5px;">
                  {{ technique.description }}
                </td>
                <td
                  v-if="displayCount"
                  style="padding: 5px;"
                >
                  {{ technique.count }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
      <div
        id="tactic-table-vis"
        v-else
        :style="{ width: `${tacticTableWidth}px` }"
      >
        No data
      </div>
    </div>
  </div>
</template>
<script setup lang="ts">
import { StringProperty, TTPTupleProperty } from '@/assets/scripts/OpenChart/DiagramModel';
import { useApplicationStore } from '@/stores/ApplicationStore';
import { computed, ref } from 'vue';
import {
    getTacticNameFromLabel,
    getTechniqueNameFromLabel,
    getDomainCodeFromLabel
} from '@/assets/configuration/AttackFlowTemplates/TTPFrameworkConstants.ts';
import Enums from '@/assets/configuration/AttackFlowTemplates/SourceEnumeration';
import VisualizationWidthControl from './VisualizationWidthControl.vue';
import { getTacticOrder } from './TacticOrder.ts';

const app = useApplicationStore();

const defaultTacticTableWidth = 1200;
const minTacticTableWidth = 760;
const maxTacticTableWidth = 2400;
const tacticTableWidthStep = 200;
const tacticTableWidth = ref(defaultTacticTableWidth);

interface GroupedTechnique {
    tactic: {
        id: string,
        name: string,
        order: number,
        domainShort: string,
        domainLong: string
    },
    techniques: {
        id: string,
        name: string,
        description: string,
        count: number
    }[]
}

interface TechniqueInput {
    tacticId: string,
    tacticName: string,
    tacticOrder: number,
    domainShort: string,
    domainLong: string,
    techniqueId: string,
    techniqueName: string,
    description: string
}

interface UploadedFlow {
    name: string,
    techniques: TechniqueInput[]
}

type FileObject = Record<string, unknown>;

const domainShortToLong: { [key: string]: string } = {
    "ENT": "Enterprise",
    "ATL": "Atlas",
    "D3F": "D3FEND",
    "ICS": "Industrial Control Systems",
    "MOB": "Mobile",
    "F3": "Fight Fraud Framework"
};

const uploadedFlows = ref<UploadedFlow[]>([]);
const uploadError = ref("");
const uploadInput = ref<HTMLInputElement | null>(null);
const displayCount = ref(false);
const tacticLabelById = createLabelMap(Enums.tactics);
const techniqueLabelById = createLabelMap(Enums.techniques);

const flowSummary = computed(() => {
    const flowCount = 1 + uploadedFlows.value.length;
    const suffix = flowCount === 1 ? "flow" : "flows";
    return `${flowCount} ${suffix} included`;
});

const groupedTechniques = computed<Map<string, GroupedTechnique> | null>(() => {
    const techniques = [
        ...activeFlowTechniques.value,
        ...uploadedFlows.value.flatMap(flow => flow.techniques)
    ];

    if (!techniques.length) {
        return null;
    }

    let result = new Map<string, GroupedTechnique>();

    for (const technique of techniques) {
        addTechnique(result, technique);
    }

    if (result.size) {
        // Sort by the "tactic.order" field.
        result = new Map([...result.entries()].sort((a, b) => {
            return a[1].tactic.order - b[1].tactic.order;
        }));

        return result;
    }

    return null;
});

const activeFlowTechniques = computed<TechniqueInput[]>(() => {
    const blocks = app.activeEditor.file.canvas.blocks;
    const techniques: TechniqueInput[] = [];

    if (!blocks.length) {
        return techniques;
    }

    const actionBlocks = blocks.filter(b => b.id === 'action');

    if (!actionBlocks.length) {
        return techniques;
    }

    for (const block of actionBlocks) {
        const ttp = block.properties.get("ttp", TTPTupleProperty);
        const blockDescription = block.properties.get("description", StringProperty)?.value || "";

        if (ttp) {
            const tacticProp = ttp.value.get("tactic") as StringProperty | undefined;
            const techniqueProp = ttp.value.get("technique") as StringProperty | undefined;

            const tacticId = tacticProp?.value;
            const techniqueId = techniqueProp?.value;

            if (techniqueId) {
                const tacticKey = tacticId || "(NA)";
                const techniqueStr = techniqueProp.toString();
                const tacticStr = tacticProp?.toString() || "";
                const tacticName = tacticStr
                    ? getTacticNameFromLabel(tacticStr)
                    : "(Tactic Not Provided)";
                const domainCode = tacticStr ? getDomainCodeFromLabel(tacticStr) : "";
                techniques.push({
                    tacticId: tacticKey,
                    tacticName,
                    tacticOrder: tacticKey === "(NA)" ? 99 : getTacticOrder(tacticName),
                    domainShort: domainCode,
                    domainLong: domainShortToLong[domainCode] || "",
                    techniqueId,
                    techniqueName: getTechniqueNameFromLabel(techniqueStr),
                    description: blockDescription
                });
            }
        }
    }

    return techniques;
});

function getTechniqueUrl(techniqueId: string, techniqueName: string, domainShort: string) {
    switch (domainShort) {
        case "ENT":
        case "MOB":
        case "ICS":
            return `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`;
        case "ATL":
            return `https://atlas.mitre.org/techniques/${techniqueId}`;
        case "D3F":
            return `https://d3fend.mitre.org/technique/d3f:${techniqueName.replaceAll(' ', '')}/`;
        case "F3":
            return `https://ctid.mitre.org/fraud#/technique/${techniqueId.replace('F3.', '')}`;
    }
    return "";
}

function createLabelMap(entries: string[][]): Map<string, string> {
    const result = new Map<string, string>();
    for (const [id, label] of entries) {
        if (id && label) {
            result.set(id, label);
        }
    }
    return result;
}

function addTechnique(
    result: Map<string, GroupedTechnique>,
    technique: TechniqueInput
) {
    if (!result.has(technique.tacticId)) {
        result.set(technique.tacticId, {
            tactic: {
                id: technique.tacticId,
                name: technique.tacticName,
                order: technique.tacticOrder,
                domainShort: technique.domainShort,
                domainLong: technique.domainLong
            },
            techniques: []
        });
    }

    const group = result.get(technique.tacticId) as GroupedTechnique;
    const existingTechnique = displayCount.value
        ? group.techniques.find(row => row.id === technique.techniqueId)
        : undefined;

    if (existingTechnique) {
        existingTechnique.count += 1;
        return;
    }

    group.techniques.push({
        id: technique.techniqueId,
        name: technique.techniqueName,
        description: technique.description,
        count: 1
    });
}

async function loadUploadedFlows(event: Event) {
    const input = event.target as HTMLInputElement;
    const files = input.files ? Array.from(input.files) : [];
    const flows: UploadedFlow[] = [];
    const failedFiles: string[] = [];
    const emptyFiles: string[] = [];

    uploadError.value = "";

    for (const file of files) {
        try {
            const data = JSON.parse(await file.text()) as unknown;
            const techniques = getUploadedFlowTechniques(data);
            if (techniques.length) {
                flows.push({
                    name: file.name,
                    techniques
                });
            } else {
                emptyFiles.push(file.name);
            }
        } catch {
            failedFiles.push(file.name);
        }
    }

    uploadedFlows.value = [
        ...uploadedFlows.value,
        ...flows
    ];
    const errors: string[] = [];
    if (failedFiles.length) {
        errors.push(`Could not read ${failedFiles.join(", ")}.`);
    }
    if (emptyFiles.length) {
        errors.push(`No mapped techniques found in ${emptyFiles.join(", ")}.`);
    }
    uploadError.value = errors.join(" ");
    input.value = "";
}

function clearUploadedFlows() {
    uploadedFlows.value = [];
    uploadError.value = "";
    if (uploadInput.value) {
        uploadInput.value.value = "";
    }
}

function getUploadedFlowTechniques(data: unknown): TechniqueInput[] {
    const objects = getFileObjects(data);
    const stixTechniques = getStixTechniques(objects);

    if (stixTechniques.length) {
        return stixTechniques;
    }

    return getAttackFlowTechniques(objects);
}

function getAttackFlowTechniques(objects: unknown[]): TechniqueInput[] {
    const techniques: TechniqueInput[] = [];

    for (const object of objects) {
        if (!isRecord(object) || object.id !== "action") {
            continue;
        }

        const properties = entriesToMap(object.properties);
        const ttp = entriesToMap(properties.get("ttp"));
        const techniqueId = getString(ttp.get("technique"));

        if (!techniqueId) {
            continue;
        }

        const tacticId = getString(ttp.get("tactic")) || "(NA)";
        const tacticLabel = tacticLabelById.get(tacticId);
        const techniqueLabel = techniqueLabelById.get(techniqueId);
        const tacticName = tacticLabel
            ? getTacticNameFromLabel(tacticLabel)
            : tacticId === "(NA)" ? "(Tactic Not Provided)" : tacticId;
        const domainCode = tacticLabel ? getDomainCodeFromLabel(tacticLabel) : "";

        techniques.push({
            tacticId,
            tacticName,
            tacticOrder: tacticId === "(NA)" ? 99 : getTacticOrder(tacticName),
            domainShort: domainCode,
            domainLong: domainShortToLong[domainCode] || "",
            techniqueId,
            techniqueName: techniqueLabel ? getTechniqueNameFromLabel(techniqueLabel) : techniqueId,
            description: getString(properties.get("description")) || ""
        });
    }

    return techniques;
}

function getStixTechniques(objects: unknown[]): TechniqueInput[] {
    const techniques: TechniqueInput[] = [];

    for (const object of objects) {
        if (!isRecord(object) || object.type !== "attack-action") {
            continue;
        }

        const techniqueId = getString(object.technique_id);

        if (!techniqueId) {
            continue;
        }

        const tacticId = getString(object.tactic_id) || "(NA)";
        const tacticLabel = tacticLabelById.get(tacticId);
        const techniqueLabel = techniqueLabelById.get(techniqueId);
        const tacticName = tacticLabel
            ? getTacticNameFromLabel(tacticLabel)
            : tacticId === "(NA)" ? "(Tactic Not Provided)" : tacticId;
        const domainCode = tacticLabel ? getDomainCodeFromLabel(tacticLabel) : "";

        techniques.push({
            tacticId,
            tacticName,
            tacticOrder: tacticId === "(NA)" ? 99 : getTacticOrder(tacticName),
            domainShort: domainCode,
            domainLong: domainShortToLong[domainCode] || "",
            techniqueId,
            techniqueName: techniqueLabel
                ? getTechniqueNameFromLabel(techniqueLabel)
                : getString(object.name) || techniqueId,
            description: getString(object.description) || ""
        });
    }

    return techniques;
}

function getFileObjects(data: unknown): unknown[] {
    if (isRecord(data) && Array.isArray(data.objects)) {
        return data.objects;
    }
    throw new Error("Expected an Attack Flow file.");
}

function entriesToMap(value: unknown): Map<string, unknown> {
    if (!Array.isArray(value)) {
        return new Map();
    }
    return new Map(
        value
            .filter((entry): entry is [string, unknown] => {
                return Array.isArray(entry) && typeof entry[0] === "string";
            })
            .map(([key, entryValue]) => [key, entryValue])
    );
}

function isRecord(value: unknown): value is FileObject {
    return typeof value === "object" && value !== null;
}

function getString(value: unknown): string | undefined {
    return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

</script>
<style scoped>
.tactic-table-visualization {
    background-color: white;
    color: #111;
    min-height: 100%;
}

.tactic-table-controls {
    align-items: center;
    background: #f7f7f7;
    border-bottom: 1px solid #d4d4d3;
    display: flex;
    flex-wrap: wrap;
    gap: 10px 14px;
    padding: 10px;
}

.tactic-table-controls label {
    align-items: center;
    color: #333;
    display: flex;
    font-size: 12px;
    gap: 6px;
    white-space: nowrap;
}

.tactic-table-controls input[type="file"] {
    max-width: 220px;
}

.file-control {
    gap: 8px;
}

.checkbox-control {
    gap: 4px;
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

.tactic-table-stage {
    background-color: white;
    overflow: auto;
}

#tactic-table-vis {
    background-color: white;
    padding: 1px;
    /* prevent margin collapse */
}

h3 {
    margin: 0;
    margin-bottom: 5px;
    font-family: "Times New Roman", serif;
}

table {
    width: 100%;
    border-collapse: collapse;
}

a {
    color: rgb(49, 130, 189);
}

a:hover {
    text-decoration: underline;
}

th {
    text-align: left;
}

tr:not(:last-child) {
    border-bottom: solid 1px #eee;
}
</style>
