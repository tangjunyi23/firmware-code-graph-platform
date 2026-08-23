<template>
  <div class="mask" @click.self="$emit('close')">
    <div class="sheet">
      <div class="head">
        <span>{{ t('trajectory.title') }}</span>
        <button type="button" class="x" @click="$emit('close')">
          <IconCloseOutline16 :size="16" />
        </button>
      </div>
      <div class="list">
        <div v-for="node in session.state.nodes" :key="node.id" class="row">
          <span class="kind">{{ node.kind }}</span>
          <span class="sum">{{ line(node) }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { IconCloseOutline16 } from './icons.js'
import { t } from './locales.js'
const props = defineProps({ session: { type: Object, required: true } })
defineEmits(['close'])
function line (n) {
  if (n.kind === 'tool') return `${n.name || ''} ${n.status || ''}`
  return String(n.text || n.reason || '').replace(/\s+/g, ' ').slice(0, 120)
}
</script>

<style scoped>
.mask {
  position: absolute;
  inset: 0;
  z-index: 25;
  display: flex;
  justify-content: flex-end;
  background: var(--dsw-alias-bg-mask-2);
}
.sheet {
  width: min(420px, 100%);
  height: 100%;
  background: var(--dsw-alias-bg-layer-1);
  border-left: 1px solid var(--dsw-alias-border-l2);
  display: flex;
  flex-direction: column;
}
.head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 12px;
  border-bottom: 1px solid var(--dsw-alias-border-l2);
  font-weight: 500;
}
.x {
  width: 28px; height: 28px; border: none; border-radius: 999px;
  background: transparent; cursor: pointer; color: var(--dsw-alias-label-secondary);
}
.list { flex: 1; overflow-y: auto; padding: 8px 12px; }
.row {
  display: flex; gap: 8px; padding: 6px 0;
  font-size: 13px; border-bottom: 1px solid var(--dsw-alias-border-l1);
}
.kind { color: var(--dsw-alias-label-tertiary); flex: none; width: 72px; }
.sum { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
