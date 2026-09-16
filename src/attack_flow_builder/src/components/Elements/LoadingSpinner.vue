<template>
  <div
    class="loading-spinner"
    role="status"
    :aria-label="label"
  >
    <div class="loading-spinner-icon" />
  </div>
</template>

<script setup lang="ts">
interface LoadingSpinnerProps {
  /**
   * Accessible label applied to inner aria-label attribute.
   */
  label?: string;
}

const {
  label = "Loading"
} = defineProps<LoadingSpinnerProps>();
</script>

<style scoped>
.loading-spinner {
  display: flex;
  justify-content: center;
  align-items: center;
}

.loading-spinner-icon {
  width: 18px;
  height: 18px;
  border: solid 2px var(--af-border-color-secondary);
  border-top-color: var(--af-text-color-primary);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
</style>
