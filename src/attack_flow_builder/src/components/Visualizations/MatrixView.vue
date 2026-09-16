<template>
  <div id="matrix-vis-root">
    <div class="matrix-toolbar visualization-export-ignore">
      <label>
        <input
          type="checkbox"
          value="show-tactic-ids"
          v-model="showTacticIds"
        >
        Tactic IDs
      </label>
      <label>
        <input
          type="checkbox"
          value="show-technique-ids"
          v-model="showTechniqueIds"
        >
        Technique IDs
      </label>
    </div>

    <div class="svg-container">
      <svg
        :width="svgWidth"
        :height="svgHeight"
        :viewBox="`0 0 ${svgWidth} ${svgHeight}`"
        v-if="groupedTechniques && groupedTechniques.length"
      >
        <g
          v-for="({tactic, techniques}, tacticIndex) in groupedTechniques.values()"
          class="tactic"
          :transform="getTacticTranslation(tacticIndex)"
          :key="tactic.id"
        >
          <g>
            <rect
              :width="columnWidth"
              :height="headerHeight"
              fill="#0B2338"
            />
            <text
              v-for="(line, index) in headerLinesByTactic.get(tactic)"
              x="100"
              :y="getHeaderLineY(tactic, index)"
              fill="#F1F3F4"
              font-weight="bold"
              :font-size="showTacticIds ? '10pt' : '12pt'"
              text-anchor="middle"
              :key="index"
            >{{ line }}</text>
          </g>
          <g
            v-for="(technique, techniqueIndex) in techniques"
            class="technique"
            :transform="getTechniqueTranslation(techniqueIndex)"
            :key="technique.id"
          >
            <rect
              fill="#F1F3F4"
              :width="columnWidth"
              :height="techniqueHeight"
            />
            <text
              v-for="(line, lineIndex) in technique.titleLines"
              x="5"
              :y="(lineIndex + 1) * textHeight"
              font-weight="bold"
              :key="`title${lineIndex}`"
              font-size="10pt"
            >
              {{ line }}
            </text>
            <text
              v-for="(line, lineIndex) in technique.descriptionLines"
              x="5"
              :y="(lineIndex + 1 + technique.titleLines.length) * textHeight"
              font-weight="regular"
              :key="`desc${lineIndex}`"
              font-size="10pt"
            >
              {{ line }}
            </text>
          </g>
        </g>
      </svg>
      <svg v-else>
        <text
          x="5"
          y="20"
        >No techniques detected. Add action nodes with techniques to your flow.</text>
      </svg>
    </div>
  </div>
</template>
<script setup lang="ts">
import { StringProperty, TTPTupleProperty } from '@/assets/scripts/OpenChart/DiagramModel';
import { useApplicationStore } from '@/stores/ApplicationStore';
import { computed, ref } from 'vue';
import {
    getDomainCodeFromLabel,
    getTacticNameFromLabel,
    getTechniqueNameFromLabel,
} from '@/assets/configuration/AttackFlowTemplates/TTPFrameworkConstants.ts';
import { getTacticOrder } from './TacticOrder';

interface Tactic {
    id: string,
    name: string,
    order: number,
    domain: string
}

interface Technique {
    id: string,
    descriptionLines: string[],
    titleLines: string[]
}

interface GroupedTechnique {
    tactic: Tactic
    techniques: Technique[]
}

const app = useApplicationStore();

const showTacticIds = ref(false);
const showTechniqueIds = ref(false);

const columnWidth = 200;
const techniqueHeight = 90;
const headerHeight = 40;
const headerTextHeightOffset = 5;
const gap = 3;
const textHeight = 15;
/** Maximum number of text lines in a technique block, after which text is truncated. */
const maxTechniqueLines = 5;

function getTechniqueTitleLines(techniqueId: string, techniqueName: string): string[] {
    let stringToWrap = techniqueName;
    if (showTechniqueIds.value) {
        stringToWrap =  `${techniqueId} - ${techniqueName}`;
    }

    return wrapText(stringToWrap, 30, 2);
}

function getTechniqueTranslation(techniqueIndex: number): string {
    return `translate(0, ${techniqueHeight * techniqueIndex + headerHeight + gap * (1 + techniqueIndex)})`;
}

function getTacticTranslation(tacticIndex: number): string {
    return `translate(${(columnWidth + gap) * tacticIndex}, 0)`;
}

function getHeaderLineY(tactic: Tactic, lineIndex: number) : number {
    let result : number = headerHeight / 2 + headerTextHeightOffset;
    const headerLines = headerLinesByTactic.value.get(tactic);
    if (!(headerLines && headerLines.length)) return result;

    result = headerHeight / (headerLines.length + 1) * (lineIndex + 1) + headerTextHeightOffset;

    return result;
}

function wrapText(text: string, maxCols: number, maxRows: number): string[] {
  // A naive approach to wrapping. It assumes that there will be
  // spaces in opportune places and never forces a line break.
  let startIdx = 0;
  let lastSpace = -1;
  let lines = [];

  // Break the string into multiple smaller strings, ideally at natural spaces.
  for (let endIdx = 0; endIdx < text.length; endIdx++) {
    if (/\s/.test(text.charAt(endIdx))) {
      lastSpace = endIdx;
    } else if (endIdx - startIdx >= maxCols) {
      if (lastSpace === -1) {
        lastSpace = endIdx // Break long strings even if there's no space.
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

const svgWidth = computed(() => {
    const tacticCount = groupedTechniques.value?.length ?? 0;
    return Math.max(
        columnWidth,
        tacticCount * columnWidth + Math.max(0, tacticCount - 1) * gap
    );
});

const svgHeight = computed(() => {
    const maxTechniqueCount = groupedTechniques.value?.reduce((max, tactic) => {
        return Math.max(max, tactic.techniques.length);
    }, 0) ?? 0;

    return Math.max(
        headerHeight,
        headerHeight + maxTechniqueCount * (techniqueHeight + gap)
    );
});

const headerLinesByTactic = computed<Map<Tactic, string[]>>(() => {
    const result = new Map<Tactic, string[]>();
    if (!groupedTechniques.value) return result;

    for (const gt of groupedTechniques.value) {
        let tacticText = gt.tactic.name;
        if (showTacticIds.value) {
            tacticText = `${gt.tactic.id} - ${gt.tactic.name}`;
        }

        result.set(gt.tactic, wrapText(tacticText, 30, 2));
    }

    return result;
});

const groupedTechniques = computed<GroupedTechnique[] | null>(() => {
    const blocks = app.activeEditor.file.canvas.blocks;
    const actionBlocks = blocks.filter(b => b.id === 'action');

    if (!actionBlocks.length) {
        return null
    };

    const grouped : { [key: string]: GroupedTechnique } = {};

    actionBlocks.forEach(block => {
        const ttp = block.properties.get("ttp", TTPTupleProperty);

        if (!ttp) return;

        const techniqueProp = ttp.value.get("technique") as StringProperty | undefined;

        if (!techniqueProp) return;

        const techniqueId = techniqueProp.value;

        if (!techniqueId) return;

        const tacticProp = ttp.value.get("tactic") as StringProperty | undefined;

        const tacticId = tacticProp?.value || "(NA)";
        const tacticLabel = tacticProp ? tacticProp.toString() : "None";
        const tacticName = tacticLabel === "None" ? "(Tactic Not Provided)" : getTacticNameFromLabel(tacticLabel);
        const tacticOrder = tacticLabel === "None" ? 99 : getTacticOrder(tacticName);
        const tactic = {
            id: tacticId,
            name: tacticName,
            order: tacticOrder,
            domain: tacticLabel === "None" ? "" : getDomainCodeFromLabel(tacticLabel),
        }

        if (!grouped[tacticId]) {
            grouped[tacticId] = {
            tactic,
            techniques: [],
            }
        }

        const techniqueLabel = techniqueProp.toString();
        const titleLines = getTechniqueTitleLines(techniqueId, getTechniqueNameFromLabel(techniqueLabel));
        const descriptionLines = wrapText(
                block.properties.get("description", StringProperty)?.value || "undefined",
                30, maxTechniqueLines - titleLines.length
            );

        grouped[tacticId].techniques.push({
            id: techniqueId,
            titleLines,
            descriptionLines
        });
    });

    const tacticGroups = new Array<GroupedTechnique>();
    for (const data of Object.values(grouped)) {
    tacticGroups.push({
        tactic: data.tactic,
        techniques: data.techniques,
    });
    }
    tacticGroups.sort((a,b) => a.tactic.order - b.tactic.order);

    return tacticGroups;
})

</script>
<style scoped>
    #matrix-vis-root {
        height: 100%;
        display: flex;
        flex-direction: column;
    }

    .svg-container {
        flex: 1;
        overflow: auto;
        background-color: var(--af-bg-color-secondary);
    }

    .matrix-toolbar {
        display: flex;
        gap: 8px;
        justify-content: end;
        padding: 3px 8px;
        background-color: var(--af-bg-color-tertiary);
        border: 1px solid var(--af-border-color-tertiary);
        color: var(--af-text-color-primary);
    }

    .matrix-toolbar label {
        display: flex;
        align-items: center;
    }

    .matrix-toolbar input {
        width: 15px;
        height: 15px;
    }

    svg {
        min-width: 100%;
        font-family: "Times", serif;
    }
</style>
