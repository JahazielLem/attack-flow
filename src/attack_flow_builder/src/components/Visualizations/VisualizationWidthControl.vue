<template>
  <div
    class="visualization-width-control visualization-export-ignore"
    role="group"
    :aria-label="ariaLabel"
  >
    <span>Width</span>
    <button
      type="button"
      title="Decrease Width"
      :disabled="clampedValue <= min"
      @click="decreaseWidth"
    >
      -
    </button>
    <span class="width-value">{{ clampedValue }}px</span>
    <button
      type="button"
      title="Increase Width"
      :disabled="clampedValue >= max"
      @click="increaseWidth"
    >
      +
    </button>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";

interface Props {
    modelValue: number;
    min: number;
    max: number;
    step?: number;
    ariaLabel?: string;
}

const props = withDefaults(defineProps<Props>(), {
    ariaLabel: "Visualization width",
    step: 200
});

const emit = defineEmits<{
    "update:modelValue": [value: number];
}>();

const clampedValue = computed(() => {
    return clampWidth(props.modelValue);
});

function decreaseWidth() {
    updateWidth(props.modelValue - props.step);
}

function increaseWidth() {
    updateWidth(props.modelValue + props.step);
}

function updateWidth(value: number) {
    emit("update:modelValue", clampWidth(value));
}

function clampWidth(value: number): number {
    return Math.min(props.max, Math.max(props.min, value));
}
</script>

<style scoped>
.visualization-width-control {
    align-items: center;
    color: #333;
    display: flex;
    font-size: 12px;
    gap: 6px;
    white-space: nowrap;
}

.visualization-width-control button {
    background: #fff;
    border: 1px solid #bbb;
    color: #333;
    cursor: pointer;
    font-size: 14px;
    height: 24px;
    line-height: 1;
    min-width: 24px;
    padding: 2px 6px;
}

.visualization-width-control button:disabled {
    cursor: default;
    opacity: 0.45;
}

.width-value {
    color: #555;
    min-width: 48px;
    text-align: center;
}
</style>
