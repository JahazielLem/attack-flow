<template>
  <div class="tuple-field-control">
    <table
      class="tuple-table"
      v-if="property.value.size"
    >
      <tr
        class="field-item"
        v-for="[key, value] in property.value"
        :key="key"
      >
        <td class="field-name">
          {{ toShortname(value.name) }}
        </td>
        <td>
          <component
            class="field-value"
            :is="getField(value)"
            :property="value"
            :featured-options="getFeaturedOptions(key)"
            :visible-options="getVisibleOptions(key)"
            @execute="execute"
          />
        </td>
      </tr>
    </table>
    <div
      class="no-properties"
      v-else
    >
      Tuple contains no properties.
    </div>
  </div>
</template>

<script lang="ts">
import * as EditorCommands from "@OpenChart/DiagramEditor/Commands";
// Dependencies
import { defineComponent, type PropType } from "vue";
import { 
  DateProperty, EnumProperty, FloatProperty, 
  IntProperty, StringProperty
} from "@OpenChart/DiagramModel";
import type { Property, TupleProperty } from "@OpenChart/DiagramModel";
import type { SynchronousEditorCommand } from "@OpenChart/DiagramEditor";
// Components
import TextField from "./TextField.vue";
import EnumField from "./EnumField.vue";
import NumberField from "./NumberField.vue";

export default defineComponent({
  name: "TupleField",
  props: {
    property: {
      type: Object as PropType<TupleProperty>,
      required: true
    },
    featuredOptionsMap: {
      type: Object as PropType<Map<string, ReadonlySet<string>>>,
      required: false
    },
    visibleOptionsMap: {
      type: Object as PropType<Map<string, ReadonlySet<string>>>,
      required: false
    }
  },
  data() {
    return {
      collapsed: true
    }
  },
  computed: {

  },
  methods: {

    /**
     * Executes an application command.
     * @param command
     *  The command to execute.
     */
    execute(command: SynchronousEditorCommand) {
      // Wrap edit commands
      const cmd = EditorCommands.setTupleSubproperty(this.property, command);
      this.$emit("execute", cmd);
    },

    /**
     * Converts a name to a short name 
     * @param name
     *  The name.
     * @returns
     *  The short name.
     */
    toShortname(str: string) {
      return `${str.substring(0, 4)}.`;
    },
    
    /**
     * Returns a field's component type.
     * @param type
     *  The type of field.
     * @returns
     *  The field's component type.
     */
    getField(type: Property): string | undefined {
      switch(type.constructor.name) {
        case StringProperty.name:
          return "TextField";
        case IntProperty.name:
        case FloatProperty.name:
          return "NumberField";
        case EnumProperty.name:
          return "EnumField";
        case DateProperty.name:
          throw new Error("Date properties cannot be rendered at this time.");
      }
    },

    /**
     * Returns a Set of featured options for a subkey, adapted for child fields.
     */
    getFeaturedOptions(key: string): Set<string> | undefined {
      const ro = this.featuredOptionsMap?.get(key) ?? this.property.validPropValues?.get(key);
      return ro ? new Set(ro) : undefined;
    },

    /**
     * Returns a Set of visible options for a subkey, used to filter displayed options.
     */
    getVisibleOptions(key: string): Set<string> | undefined {
      const ro = this.visibleOptionsMap?.get(key);
      return ro ? new Set(ro) : undefined;
    }

  },
  emits: {
    execute: (cmd: SynchronousEditorCommand) => cmd
  },
  components: {
    TextField,
    EnumField,
    NumberField
  }
});
</script>

<style scoped>

/** === Main Field === */

.tuple-field-control {
  max-width: 100%;
  display: flex;
  align-items: center;
}

/** === Table === */

.tuple-table {
  width: 100%;
  border-collapse: collapse;
  border: none;
  padding: 0px;
}

.tuple-table tr {
  border-bottom: solid 1px var(--af-bg-color-primary);
}

.tuple-table tr:last-child {
  border-bottom: none;
}

.tuple-table td {
  padding: 0px;
}

.tuple-table td.field-name {
  color: var(--af-text-color-secondary);
  font-size: 8.3pt;
  font-weight: 500;
  text-transform: uppercase;
  width: 0px;
  padding: 0px 8px;
  border-right: solid 1px var(--af-bg-color-primary);
}

/** === No Properties === */

.no-properties {
  color: #818181;
  font-size: 10pt;
  padding: 0px 12px;
}

</style>
