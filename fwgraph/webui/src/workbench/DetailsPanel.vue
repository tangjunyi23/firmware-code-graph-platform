<template>
  <div class="root">
    <div class="header">
      <span class="title">{{ node ? (node.name || t('details.title')) : t('details.title') }}</span>
      <button type="button" class="close" :aria-label="t('details.close')" @click="$emit('close')">
        <IconCloseOutline16 :size="16" />
      </button>
    </div>
    <div class="body">
      <p v-if="!node" class="empty">{{ t('details.empty') }}</p>
      <template v-else>
        <div v-if="node.argumentsText" class="section">
          <div class="label">{{ t('details.input') }}</div>
          <pre class="code">{{ pretty(node.argumentsText) }}</pre>
        </div>
        <div class="section">
          <div class="label">{{ t('details.output') }}</div>
          <pre class="code">{{ node.resultText || (node.status === 'running' ? t('details.running') : '') }}</pre>
        </div>
      </template>
    </div>
  </div>
</template>

<script setup>
import { IconCloseOutline16 } from './icons.js'
import { t } from './locales.js'

defineProps({ node: { type: Object, default: null } })
defineEmits(['close'])

function pretty (raw) {
  try { return JSON.stringify(JSON.parse(raw), null, 2) } catch { return raw }
}
</script>

<style scoped>
.root {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-width: 0;
  background: var(--dsw-alias-bg-base);
}
.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 14px 12px 12px;
  border-bottom: 1px solid var(--dsw-alias-border-l2);
}
.title {
  overflow: hidden;
  font-size: 14px;
  line-height: 20px;
  font-weight: 500;
  color: var(--dsw-alias-label-primary);
  text-overflow: ellipsis;
  white-space: nowrap;
}
.close {
  display: grid;
  flex: none;
  place-items: center;
  width: 28px;
  height: 28px;
  border: none;
  border-radius: 999px;
  background: transparent;
  color: var(--dsw-alias-label-secondary);
  cursor: pointer;
}
.close:hover { background: var(--dsw-alias-interactive-bg-hover); }
.body {
  flex: 1;
  min-height: 0;
  padding: 12px 16px;
  overflow-y: auto;
}
.empty {
  padding: 8px 0;
  font-size: 13px;
  line-height: 20px;
  color: var(--dsw-alias-label-tertiary);
}
.section { margin-bottom: 16px; }
.label {
  margin-bottom: 6px;
  font-size: 12px;
  line-height: 18px;
  font-weight: 500;
  color: var(--dsw-alias-label-secondary);
}
.code {
  margin: 0;
  padding: 16px;
  border-radius: 12px;
  background: var(--dsw-alias-markdown-code-block);
  font: var(--dsw-font-markdown-code-block);
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--dsw-alias-label-secondary);
}
</style>
