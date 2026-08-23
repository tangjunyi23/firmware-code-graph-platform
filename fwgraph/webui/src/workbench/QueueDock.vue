<template>
  <div v-if="items.length" class="dock">
    <div class="panel">
      <button type="button" class="header" @click="open = !open">
        <span class="count">{{ t('queue.count', { n: items.length }) }}</span>
        <span class="chevron" :class="{ open }">
          <IconChevronDownOutline14 :size="12" />
        </span>
      </button>
      <ul v-if="open" class="list">
        <li v-for="(row, i) in items" :key="row.id || i" class="row">
          <span class="text">{{ rowText(row) }}</span>
          <button type="button" class="icon" :title="t('queue.remove')" @click="remove(row)">×</button>
        </li>
      </ul>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, ref } from 'vue'
import { IconChevronDownOutline14 } from './icons.js'
import { t } from './locales.js'
import { isInjectedHuntHint } from './dshClient.js'

const session = inject('wbSession')
const open = ref(true)

function rowText (row) {
  const msg = row.message || row
  if (typeof msg.text === 'string') return msg.text
  if (Array.isArray(msg.content)) {
    return msg.content.map((b) => b.text || '').join(' ')
  }
  return String(msg.content || msg.text || '')
}

const items = computed(() => (session?.state?.queue || []).filter((r) => {
  if (r.placement === 'steering') return false
  return !isInjectedHuntHint(rowText(r))
}))
function remove (row) {
  session.updateQueue({ action: 'remove', id: row.id })
}
</script>

<style scoped>
.dock {
  box-sizing: border-box;
  flex: none;
  width: calc(100% - 2 * var(--dsh-composer-side-clearance) - 2 * var(--dsh-composer-dock-inset));
  max-width: calc(var(--dsh-composer-card-max-width) - 2 * var(--dsh-composer-dock-inset));
  margin: 0 auto calc(0px - var(--dsh-composer-stack-gap, 6px) - 3px);
  padding: 0 var(--dsh-composer-dock-inset);
}
.panel {
  position: relative;
  overflow: hidden;
  width: 100%;
  padding: 2px 0;
  border-radius: 12px 12px 0 0;
  background: var(--dsw-specific-tip);
}
.panel::after {
  position: absolute;
  inset: 0;
  border: 1px solid var(--dsw-alias-border-l1);
  border-bottom: none;
  border-radius: inherit;
  content: '';
  pointer-events: none;
}
.header {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  height: 36px;
  padding: 4px 12px;
  border: none;
  background: transparent;
  color: var(--dsw-alias-label-primary);
  cursor: pointer;
  text-align: left;
}
.count {
  flex: 1;
  font-size: 13px;
  font-weight: 500;
  line-height: 24px;
}
.chevron { color: var(--dsw-alias-label-tertiary); display: grid; }
.chevron.open { transform: rotate(180deg); }
.list { margin: 0; padding: 0; list-style: none; max-height: 180px; overflow-y: auto; }
.row {
  display: flex;
  align-items: center;
  gap: 10px;
  height: 36px;
  padding: 4px 5px 4px 12px;
}
.text {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 13px;
}
.icon {
  border: none;
  background: transparent;
  color: var(--dsw-alias-label-tertiary);
  cursor: pointer;
  font-size: 16px;
}
</style>
