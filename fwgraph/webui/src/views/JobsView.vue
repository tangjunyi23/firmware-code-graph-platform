<template>
  <div class="jobs-chat">
    <WorkbenchView />
  </div>
</template>

<script setup>
import WorkbenchView from '../workbench/WorkbenchView.vue'

defineEmits(['open-functions', 'goto'])
</script>

<style scoped>
.jobs-chat { height: 100%; min-height: 0; display: flex; flex-direction: column; }
.jobs-chat :deep(.wb-root) { flex: 1; min-height: 0; }
</style>
