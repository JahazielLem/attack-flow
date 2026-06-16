<template>
  <div class="app-title-bar-container">
    <TitleBar
      class="app-title-bar-element"
      :menus="menus"
      @select="onItemSelect"
    >
      <template #icon>
        <span class="logo">
          <img
            alt="Logo"
            title="Logo"
            :src="icon"
          >
        </span>
      </template>
    </TitleBar>
    <div class="wiki-search-shell">
      <input
        v-model="wikiSearch"
        class="wiki-search-input"
        type="search"
        placeholder="Search TTP wiki"
        title="Search TTP wiki"
        @input="onWikiSearchInput"
        @keydown.enter.stop="openWiki"
        @keydown.stop
      >
    </div>
    <div
      v-if="classificationMarking && classificationMarking.value"
      class="classification-marking"
      :data-value="classificationMarking.value"
    >
      {{ classificationMarking?.toString() }}
      <span v-if="classificationGroup?.value">:{{ classificationGroup.value }}</span>
    </div>
  </div>
</template>

<script lang="ts">
import Configuration from "@/assets/configuration/app.configuration";
// Dependencies
import { defineComponent } from "vue";
import { useApplicationStore } from "@/stores/ApplicationStore";
import { useContextMenuStore } from "@/stores/ContextMenuStore";
import type { CommandEmitter } from "@/assets/scripts/Application";
import type { ContextMenuSubmenu } from "@/assets/scripts/Browser";
// Components
import TitleBar from "@/components/Controls/TitleBar.vue";
import { EnumProperty, StringProperty, TupleProperty } from "@/assets/scripts/OpenChart/DiagramModel";

export default defineComponent({
  name: "AppTitleBar",
  data() {
    return {
      application: useApplicationStore(),
      contextMenus: useContextMenuStore(),
      icon: Configuration.application_icon,
      wikiSearch: ""
    };
  },
  emits: {
    openWiki: (query: string) => typeof query === "string"
  },
  computed: {

    /**
     * Returns the application's menus.
     * @returns
     *  The application's menus.
     */
    menus(): ContextMenuSubmenu<CommandEmitter>[] {
      return [
        this.contextMenus.fileMenu,
        this.contextMenus.editMenu,
        this.contextMenus.viewMenu,
        this.contextMenus.helpMenu
      ];
    },

    classificationMarking(): EnumProperty | undefined {
      const tup: TupleProperty | undefined = this.application.activeEditor.file.canvas.properties.get("classification");
      if (!tup) {
        return undefined;
      }
      const result: EnumProperty | undefined = tup?.value.get("marking") as EnumProperty;
      return result;
    },

    classificationGroup(): StringProperty | undefined {
      const tup: TupleProperty | undefined = this.application.activeEditor.file.canvas.properties.get("classification");
      if (!tup) {
        return undefined;
      }
      const result: StringProperty | undefined = tup?.value.get("group") as StringProperty;
      return result;
    }
  },
  methods: {
    openWiki() {
      this.$emit("openWiki", this.wikiSearch);
    },

    onWikiSearchInput(event: Event) {
      const target = event.target as HTMLInputElement;
      this.wikiSearch = target.value;
      if (this.wikiSearch.trim()) {
        this.$emit("openWiki", this.wikiSearch);
      }
    },

    /**
     * Menu item selection behavior.
     * @param emitter
     *  Menu item's command emitter.
     */
    async onItemSelect(emitter: CommandEmitter) {
      try {
        const cmd = emitter();
        if (cmd instanceof Promise) {
          this.application.execute(await cmd);
        } else {
          this.application.execute(cmd);
        }
      } catch (ex: unknown) {
        console.error(ex);
      }
    }
  },
  components: { TitleBar }
});
</script>

<style scoped>
/** === App Logo === */

.logo {
  margin: 5px 6px 0px 12px;
}

.logo img {
  height: 16px;
}

.app-title-bar-container {
  display: flex;
  align-items: center;
  position: relative;
  z-index: 2;
  /* Make sure find-dialog hides underneath title bar. */
}

.app-title-bar-element {
  min-width: 0;
  flex: 1;
}

.wiki-search-shell {
  width: min(280px, 32vw);
  padding-right: 10px;
  box-sizing: border-box;
}

.wiki-search-input {
  width: 100%;
  height: 22px;
  color: #cdd6f4;
  background: #11111b;
  border: 1px solid #313244;
  border-radius: 6px;
  padding: 0 8px;
  font-size: 9pt;
  outline: none;
}

.wiki-search-input:focus {
  border-color: #89b4fa;
}

/* Styling similar to classification markings in DiagramImage.ts. Change both together. */
.classification-marking {
  position: absolute;
  left: 50%;
  transform: translateX(-50%);
  height: 100%;
  display: flex;
  justify-content: center;
  align-items: center;
  font-weight: 600;
  padding: 0 5px 0 5px;
  color: white;
}

.classification-marking[data-value="tlp-red"] {
  background-color: black;
  color: #FF2B2B;
}

.classification-marking[data-value="tlp-amber"],
.classification-marking[data-value="tlp-amber-strict"] {
  background-color: black;
  color: #FFC000;
}

.classification-marking[data-value="tlp-green"] {
  background-color: black;
  color: #33FF00;
}

.classification-marking[data-value="tlp-clear"] {
  background-color: black;
  color: #FFFFFF;
}

.classification-marking[data-value="unclassified"] {
  background-color: black;
  color: #33FF00;
}
</style>
