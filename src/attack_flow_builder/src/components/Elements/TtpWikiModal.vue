<template>
  <div
    v-if="visible"
    class="wiki-backdrop"
    @pointerdown.self="close"
  >
    <section
      class="wiki-modal"
      role="dialog"
      aria-modal="true"
      aria-label="TTP Wiki"
    >
      <header class="wiki-header">
        <div class="wiki-heading">
          <h2>TTP Wiki</h2>
          <p>Ctrl/Cmd + Shift + K</p>
        </div>
        <input
          ref="search"
          v-model="query"
          class="wiki-search"
          type="search"
          placeholder="Search TTPs, tactics, descriptions, or mitigations"
          @keydown.esc.stop="close"
          @keydown.stop
        >
        <button
          class="close-button"
          type="button"
          @click="close"
        >
          Close
        </button>
      </header>

      <div class="wiki-body">
        <aside class="wiki-sidebar">
          <div class="filter-section">
            <p class="filter-title">
              Model
            </p>
            <button
              :class="{ active: selectedModel === '' }"
              type="button"
              @click="selectedModel = ''"
            >
              All models
            </button>
            <button
              v-for="model in models"
              :key="model"
              :class="{ active: selectedModel === model }"
              type="button"
              @click="selectedModel = model"
            >
              {{ model }}
            </button>
          </div>

          <div class="filter-section tactics">
            <p class="filter-title">
              Tactics
            </p>
            <button
              :class="{ active: selectedTactic === '' }"
              type="button"
              @click="selectedTactic = ''"
            >
              All tactics
            </button>
            <button
              v-for="tactic in tactics"
              :key="tactic.id"
              :class="{ active: selectedTactic === tactic.id }"
              type="button"
              @click="selectedTactic = tactic.id"
            >
              <span>{{ tactic.name }}</span>
              <small>{{ tactic.id }}</small>
            </button>
          </div>
        </aside>

        <main class="wiki-content">
          <section class="result-list">
            <div class="result-count">
              {{ filteredEntries.length }} results
            </div>
            <button
              v-for="entry in visibleEntries"
              :key="entry.id"
              :class="{ active: selectedEntry?.id === entry.id }"
              class="result-item"
              type="button"
              @click="selectedId = entry.id"
            >
              <span class="result-meta">{{ entry.model }} - {{ entry.type }}</span>
              <strong>{{ entry.id }} {{ entry.name }}</strong>
              <span>{{ entry.tactics.map(t => t.name).join(", ") || "No tactic" }}</span>
            </button>
          </section>

          <article class="detail-panel">
            <template v-if="selectedEntry">
              <div class="detail-topline">
                <span>{{ selectedEntry.model }}</span>
                <span>{{ selectedEntry.type }}</span>
              </div>
              <h3>{{ selectedEntry.id }} {{ selectedEntry.name }}</h3>
              <p class="description">
                {{ selectedEntry.description || "No description available." }}
              </p>

              <div class="detail-actions">
                <button
                  type="button"
                  :disabled="!canApplySelected"
                  @click="applySelected"
                >
                  Use in selected action
                </button>
                <a
                  v-if="selectedEntry.url"
                  :href="selectedEntry.url"
                  target="_blank"
                  rel="noreferrer"
                >
                  Source
                </a>
                <span
                  v-if="statusMessage"
                  class="status-message"
                >
                  {{ statusMessage }}
                </span>
              </div>

              <div class="detail-grid">
                <section>
                  <h4>Tactics</h4>
                  <p>{{ selectedEntry.tactics.map(t => `${t.id} ${t.name}`).join(", ") || "None" }}</p>
                </section>
                <section>
                  <h4>Platforms</h4>
                  <p>{{ selectedEntry.platforms.join(", ") || "None" }}</p>
                </section>
                <section v-if="selectedEntry.parentTechniques.length">
                  <h4>Parent technique</h4>
                  <p>{{ selectedEntry.parentTechniques.map(t => `${t.id} ${t.name}`).join(", ") }}</p>
                </section>
                <section v-if="selectedEntry.externalReferences.length">
                  <h4>References</h4>
                  <p>{{ selectedEntry.externalReferences.map(r => r.id || r.source).filter(Boolean).join(", ") }}</p>
                </section>
              </div>

              <section class="mitigations">
                <h4>Countermeasures</h4>
                <div
                  v-if="selectedEntry.mitigations.length"
                  class="mitigation-list"
                >
                  <article
                    v-for="mitigation in selectedEntry.mitigations"
                    :key="mitigation.id"
                  >
                    <strong>{{ mitigation.id }} {{ mitigation.name }}</strong>
                    <p>{{ mitigation.description || "No description available." }}</p>
                  </article>
                </div>
                <p
                  v-else
                  class="empty-state"
                >
                  No countermeasures are mapped for this entry.
                </p>
              </section>
            </template>
            <div
              v-else
              class="empty-state"
            >
              No TTPs match the current filters.
            </div>
          </article>
        </main>
      </div>
    </section>
  </div>
</template>

<script lang="ts">
import Enums from "@/assets/configuration/AttackFlowTemplates/SourceWikiEnumeration";
import { GroupCommand } from "@OpenChart/DiagramEditor/Commands/index.commands";
import { setStringProperty, setTupleSubproperty } from "@OpenChart/DiagramEditor/Commands/Property";
import { StringProperty, TupleProperty } from "@OpenChart/DiagramModel";
import { defineComponent, ref } from "vue";
import { useApplicationStore } from "@/stores/ApplicationStore";
import type { PropType } from "vue";
import type { TtpWikiEntry, TtpWikiLink } from "@/assets/configuration/AttackFlowTemplates/SourceWikiEnumeration";

type TacticFilter = {
  id: string;
  name: string;
};

type ScoredEntry = {
  entry: TtpWikiEntry;
  score: number;
};

export default defineComponent({
  name: "TtpWikiModal",
  props: {
    visible: {
      type: Boolean,
      required: true
    },
    initialQuery: {
      type: String as PropType<string>,
      default: ""
    }
  },
  emits: {
    close: () => true
  },
  setup() {
    return {
      search: ref<HTMLInputElement | null>(null)
    };
  },
  data() {
    return {
      application: useApplicationStore(),
      query: this.initialQuery,
      selectedId: "",
      selectedModel: "",
      selectedTactic: "",
      statusMessage: ""
    };
  },
  computed: {
    entries(): TtpWikiEntry[] {
      return Enums.wiki;
    },

    models(): string[] {
      return [...new Set(this.entries.map(entry => entry.model))]
        .sort((a, b) => a.localeCompare(b));
    },

    tactics(): TacticFilter[] {
      const tactics = new Map<string, TacticFilter>();
      for (const entry of this.entries) {
        if (this.selectedModel && entry.model !== this.selectedModel) {
          continue;
        }
        if (entry.type === "countermeasure") {
          continue;
        }
        for (const tactic of entry.tactics) {
          tactics.set(tactic.id, { id: tactic.id, name: tactic.name });
        }
      }
      return [...tactics.values()].sort((a, b) => a.name.localeCompare(b.name));
    },

    filteredEntries(): TtpWikiEntry[] {
      const phrase = this.normalize(this.query).trim();
      const terms = phrase
        .split(/\s+/)
        .filter(Boolean);
      return this.entries.flatMap<ScoredEntry>(entry => {
        if (this.selectedModel && entry.model !== this.selectedModel) {
          return [];
        }
        if (
          this.selectedTactic
          && !entry.tactics.some(tactic => tactic.id === this.selectedTactic)
        ) {
          return [];
        }
        const score = this.scoreEntry(entry, terms, phrase);
        return score > 0 ? [{ entry, score }] : [];
      })
        .sort((a, b) => b.score - a.score || a.entry.label.localeCompare(b.entry.label))
        .map(result => result.entry);
    },

    visibleEntries(): TtpWikiEntry[] {
      return this.filteredEntries.slice(0, 200);
    },

    selectedEntry(): TtpWikiEntry | null {
      return this.filteredEntries.find(entry => entry.id === this.selectedId)
        ?? this.filteredEntries[0]
        ?? null;
    },

    selectedActionTtp(): TupleProperty | null {
      const action = this.application.getSelection.find(view => view.id === "action");
      const property = action?.properties.get("ttp");
      return property instanceof TupleProperty ? property : null;
    },

    canApplySelected(): boolean {
      return !!this.selectedEntry
        && this.selectedEntry.type !== "countermeasure"
        && !!this.selectedActionTtp;
    }
  },
  watch: {
    visible(isVisible: boolean) {
      if (!isVisible) {
        return;
      }
      this.activate();
    },

    initialQuery(query: string) {
      if (this.visible) {
        this.query = query;
      }
    },

    filteredEntries() {
      this.selectFirstResult();
    }
  },
  mounted() {
    if (this.visible) {
      this.activate();
    }
  },
  methods: {
    close() {
      this.$emit("close");
    },

    activate() {
      this.query = this.initialQuery;
      this.statusMessage = "";
      this.$nextTick(() => {
        this.search?.focus();
        this.selectFirstResult();
      });
    },

    normalize(value: string): string {
      return value.toLocaleLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "");
    },

    scoreEntry(entry: TtpWikiEntry, terms: string[], phrase: string): number {
      if (!terms.length) {
        return entry.type === "countermeasure" ? 0 : 1;
      }

      const identity = this.normalize(`${entry.id} ${entry.name} ${entry.label}`);
      const tacticText = this.normalize(entry.tactics.map(tactic => `${tactic.id} ${tactic.name}`).join(" "));
      const parentText = this.normalize(entry.parentTechniques.map(technique => `${technique.id} ${technique.name}`).join(" "));
      const mitigationText = this.normalize(entry.mitigations.map(mitigation => (
        `${mitigation.id} ${mitigation.name} ${mitigation.description ?? ""}`
      )).join(" "));
      const referenceText = this.normalize(entry.externalReferences.map(reference => (
        `${reference.id ?? ""} ${reference.source ?? ""}`
      )).join(" "));
      const description = this.normalize(entry.description);
      const haystack = [
        identity,
        description,
        this.normalize(entry.model),
        this.normalize(entry.type),
        tacticText,
        parentText,
        mitigationText,
        referenceText
      ].join(" ");

      if (!terms.every(term => haystack.includes(term))) {
        return 0;
      }

      let score = entry.type === "countermeasure" ? 1 : 20;
      if (this.normalize(entry.id) === phrase) score += 180;
      if (this.normalize(entry.name) === phrase) score += 160;
      if (identity.includes(phrase)) score += 120;
      if (tacticText.includes(phrase)) score += 60;
      if (parentText.includes(phrase)) score += 50;
      if (description.includes(phrase)) score += 35;
      if (mitigationText.includes(phrase)) score += 25;
      if (referenceText.includes(phrase)) score += 15;

      for (const term of terms) {
        if (identity.includes(term)) score += 12;
        if (tacticText.includes(term)) score += 6;
        if (parentText.includes(term)) score += 5;
        if (description.includes(term)) score += 3;
        if (mitigationText.includes(term)) score += 2;
      }

      return score;
    },

    selectFirstResult() {
      if (!this.filteredEntries.some(entry => entry.id === this.selectedId)) {
        this.selectedId = this.filteredEntries[0]?.id ?? "";
      }
    },

    applySelected() {
      const entry = this.selectedEntry;
      const ttp = this.selectedActionTtp;
      if (!entry || !ttp) {
        this.statusMessage = "Select an action card first.";
        return;
      }
      const tacticId = this.selectedTactic && entry.tactics.some(tactic => tactic.id === this.selectedTactic)
        ? this.selectedTactic
        : entry.tactics[0]?.id ?? null;
      const techniqueId = entry.type === "subtechnique"
        ? this.firstParentTechnique(entry)?.id ?? null
        : entry.id;
      const subtechniqueId = entry.type === "subtechnique" ? entry.id : null;
      const command = new GroupCommand();
      this.addTupleStringCommand(command, ttp, "tactic", tacticId);
      this.addTupleStringCommand(command, ttp, "technique", techniqueId);
      this.addTupleStringCommand(command, ttp, "subtechnique", subtechniqueId);
      if (command.isEmpty) {
        this.statusMessage = "The selected action cannot accept this mapping.";
        return;
      }
      this.application.execute(command);
      this.statusMessage = "Applied to selected action.";
    },

    firstParentTechnique(entry: TtpWikiEntry): TtpWikiLink | undefined {
      return entry.parentTechniques[0];
    },

    addTupleStringCommand(
      command: GroupCommand,
      tuple: TupleProperty,
      key: string,
      value: string | null
    ) {
      const property = tuple.value.get(key);
      if (!(property instanceof StringProperty)) {
        return;
      }
      command.do(setTupleSubproperty(
        tuple,
        setStringProperty(property, value)
      ));
    }
  }
});
</script>

<style scoped>
.wiki-backdrop {
  position: fixed;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  background: rgba(17, 17, 27, 0.72);
}

.wiki-modal {
  width: min(1180px, calc(100vw - 42px));
  height: min(760px, calc(100vh - 42px));
  display: flex;
  flex-direction: column;
  color: #cdd6f4;
  background: #181825;
  border: 1px solid #45475a;
  box-shadow: 0 24px 70px rgba(0, 0, 0, 0.42);
}

.wiki-header {
  display: grid;
  grid-template-columns: 190px minmax(0, 1fr) auto;
  gap: 14px;
  align-items: center;
  padding: 14px;
  border-bottom: 1px solid #313244;
}

.wiki-heading h2 {
  margin: 0;
  font-size: 14pt;
  font-weight: 700;
}

.wiki-heading p {
  color: #89b4fa;
  font-size: 8.5pt;
  margin-top: 2px;
}

.wiki-search {
  height: 36px;
  min-width: 0;
  color: #cdd6f4;
  background: #11111b;
  border: 1px solid #45475a;
  border-radius: 6px;
  padding: 0 12px;
  outline: none;
}

.wiki-search:focus {
  border-color: #89b4fa;
}

.close-button,
.detail-actions button,
.detail-actions a,
.wiki-sidebar button,
.result-item {
  color: #cdd6f4;
  background: #1e1e2e;
  border: 1px solid #313244;
  border-radius: 6px;
}

.close-button,
.detail-actions button,
.detail-actions a {
  height: 34px;
  padding: 0 12px;
}

.detail-actions a {
  display: inline-flex;
  align-items: center;
}

.detail-actions button:disabled {
  color: #6c7086;
  cursor: not-allowed;
}

.wiki-body {
  min-height: 0;
  flex: 1;
  display: grid;
  grid-template-columns: 230px minmax(0, 1fr);
}

.wiki-sidebar {
  min-height: 0;
  overflow: hidden;
  border-right: 1px solid #313244;
  background: #11111b;
}

.filter-section {
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 7px;
}

.filter-section.tactics {
  height: calc(100% - 180px);
  overflow: auto;
  border-top: 1px solid #313244;
}

.filter-title {
  color: #a6adc8;
  font-size: 8pt;
  font-weight: 700;
  text-transform: uppercase;
}

.wiki-sidebar button {
  min-height: 31px;
  padding: 7px 8px;
  text-align: left;
}

.wiki-sidebar button small {
  display: block;
  color: #89b4fa;
  margin-top: 2px;
}

.wiki-sidebar button.active,
.result-item.active {
  border-color: #89b4fa;
  background: #313244;
}

.wiki-content {
  min-width: 0;
  min-height: 0;
  display: grid;
  grid-template-columns: minmax(260px, 360px) minmax(0, 1fr);
}

.result-list {
  min-height: 0;
  overflow: auto;
  padding: 12px;
  border-right: 1px solid #313244;
}

.result-count {
  color: #a6adc8;
  font-size: 8.5pt;
  margin-bottom: 10px;
}

.result-item {
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 5px;
  padding: 10px;
  margin-bottom: 8px;
  text-align: left;
}

.result-item strong {
  font-size: 10pt;
}

.result-item span {
  color: #a6adc8;
  font-size: 8.5pt;
}

.result-meta {
  color: #89b4fa !important;
  text-transform: uppercase;
}

.detail-panel {
  min-width: 0;
  min-height: 0;
  overflow: auto;
  padding: 18px;
}

.detail-topline {
  display: flex;
  gap: 8px;
  color: #89b4fa;
  font-size: 8pt;
  font-weight: 700;
  text-transform: uppercase;
}

.detail-panel h3 {
  margin: 8px 0 12px;
  font-size: 18pt;
  line-height: 1.2;
}

.description {
  color: #cdd6f4;
  line-height: 1.55;
  white-space: pre-wrap;
}

.detail-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  margin: 18px 0;
}

.status-message {
  color: #a6e3a1;
  font-size: 9pt;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 18px;
}

.detail-grid section,
.mitigations article {
  padding: 12px;
  background: #11111b;
  border: 1px solid #313244;
  border-radius: 6px;
}

.detail-grid h4,
.mitigations h4 {
  color: #89b4fa;
  margin: 0 0 6px;
  font-size: 9pt;
  text-transform: uppercase;
}

.detail-grid p,
.mitigations p {
  color: #a6adc8;
  line-height: 1.45;
}

.mitigation-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.mitigation-list strong {
  display: block;
  margin-bottom: 6px;
}

.empty-state {
  color: #a6adc8;
}

@media (max-width: 860px) {
  .wiki-modal {
    width: 100vw;
    height: 100vh;
  }

  .wiki-header,
  .wiki-body,
  .wiki-content,
  .detail-grid {
    grid-template-columns: 1fr;
  }

  .wiki-sidebar,
  .result-list {
    border-right: none;
  }

  .filter-section.tactics {
    max-height: 180px;
  }
}
</style>
