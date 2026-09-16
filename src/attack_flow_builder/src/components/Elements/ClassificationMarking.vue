<template>
  <div
    class="classification-marking"
    v-if="classificationMarking && classificationMarking.value"
    :style="{ color: classificationTextColor }"
  >
    {{ classificationMarking?.toString() }}
    <span v-if="classificationGroup?.value">:{{ classificationGroup.value }}</span>
  </div>
</template>
<script setup lang="ts">
import { getClassificationTextColor } from "@/assets/scripts/Application/Classification";
import { EnumProperty, StringProperty, TupleProperty } from "@/assets/scripts/OpenChart/DiagramModel";
import { useApplicationStore } from "@/stores/ApplicationStore";
import { computed } from "vue";

const application = useApplicationStore();

const classificationMarking = computed<EnumProperty | undefined>(() => {
    const tup : TupleProperty | undefined = application.activeEditor.file.canvas.properties.get("classification")
    if (!tup) {
        return undefined;
    }
    const result : EnumProperty | undefined = tup?.value.get("marking") as EnumProperty;
    return result
});

const classificationGroup = computed<StringProperty | undefined>( () => {
    const tup : TupleProperty | undefined = application.activeEditor.file.canvas.properties.get("classification")
    if (!tup) {
        return undefined;
    }
    const result : StringProperty | undefined = tup?.value.get("group") as StringProperty;
    return result
});

const classificationTextColor = computed<string>(() => {
    const markingText = classificationMarking.value?.toString();
    return markingText
        ? getClassificationTextColor(markingText)
        : "var(--af-text-color-primary)";
});

</script>
<style scoped>

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
    background-color: black;
}
</style>
