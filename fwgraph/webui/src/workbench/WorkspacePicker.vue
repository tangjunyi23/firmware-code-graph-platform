<template>
  <div v-if="open" class="pop" @keydown.escape="$emit('close')">
    <button
      v-for="job in jobs"
      :key="job.job_id"
      type="button"
      class="item"
      :class="{ on: selectedId === job.job_id }"
      @click="$emit('pick', job)"
    >
      <IconFolderOpen16 :size="14" />
      <span class="name">{{ job.firmware }}</span>
      <span class="meta">{{ STATUS_TEXT[job.status] || job.status }}</span>
    </button>
    <p v-if="!jobs.length" class="empty">{{ t('firmware.empty') }}</p>
  </div>
</template>

<script setup>
import { IconFolderOpen16 } from './icons.js'
import { t } from './locales.js'
import { STATUS_TEXT } from './pipeline.js'
defineProps({
  open: { type: Boolean, default: false },
  jobs: { type: Array, default: () => [] },
  selectedId: { type: String, default: '' }
})
defineEmits(['close', 'pick'])
</script>

<style scoped>
.pop {
  position: absolute;
  left: 20px;
  bottom: calc(100% + 6px);
  z-index: 12;
  min-width: 280px;
  max-width: 360px;
  max-height: 320px;
  overflow-y: auto;
  padding: 6px;
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 12px;
  background: var(--dsw-specific-menu);
  box-shadow: var(--dsw-shadow-lv3);
}
.item {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  height: 36px;
  padding: 0 10px;
  border: none;
  border-radius: 8px;
  background: transparent;
  color: var(--dsw-alias-label-primary);
  cursor: pointer;
  text-align: left;
  font-size: 13px;
}
.item:hover, .item.on { background: var(--dsw-alias-interactive-bg-hover); }
.name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.meta { color: var(--dsw-alias-label-tertiary); flex: none; }
.empty { margin: 8px; font-size: 12px; color: var(--dsw-alias-label-tertiary); }
</style>
