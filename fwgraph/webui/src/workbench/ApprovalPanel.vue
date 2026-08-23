<template>
  <div v-if="item" class="root">
    <div class="card">
      <div class="strip">
        <span class="dot" />
        <span>{{ t('approval.waiting') }}</span>
      </div>
      <div class="body">
        <div class="headline">{{ headline }}</div>
        <div v-if="detail" class="command">{{ detail }}</div>
        <div v-if="error" class="fail">{{ error }}</div>
      </div>
      <div class="actions">
        <button
          type="button"
          class="btn reject"
          :disabled="busy"
          @click.stop="respond('rejected')"
        >{{ t('approval.reject') }}</button>
        <button
          type="button"
          class="btn allow"
          :disabled="busy"
          @click.stop="respond('allowed-once')"
        >{{ t('approval.allowOnce') }}</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, ref } from 'vue'
import { t } from './locales.js'

const session = inject('wbSession')
const item = computed(() => (session?.state?.approvals || [])[0] || null)
const busy = ref(false)
const error = ref('')

const headline = computed(() => {
  const cur = item.value
  if (!cur) return ''
  return cur.reason || cur.justification || cur.toolName || '工具请求需要审批'
})
const detail = computed(() => {
  const cur = item.value
  if (!cur) return ''
  if (cur.command) return cur.command
  if (cur.toolName && cur.reason) return cur.toolName
  if (cur.arguments) {
    if (typeof cur.arguments === 'string') return cur.arguments
    try { return JSON.stringify(cur.arguments, null, 2) } catch { return String(cur.arguments) }
  }
  return cur.callId || ''
})

async function respond (outcome) {
  const cur = item.value
  if (!cur || busy.value) return
  busy.value = true
  error.value = ''
  try {
    await session.approve(cur, outcome)
  } catch (err) {
    error.value = err?.message || '审批失败'
  } finally {
    busy.value = false
  }
}
</script>

<style scoped>
.root {
  position: relative;
  z-index: 9;
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 8px calc(var(--dsh-composer-side-clearance) + 16px) 12px;
  pointer-events: auto;
}
.card {
  overflow: hidden;
  width: 100%;
  max-width: var(--dsh-chat-content-width);
  border: 1px solid var(--dsw-alias-state-warn-secondary);
  border-radius: 20px;
  background: var(--dsw-specific-input-major);
  box-shadow: var(--dsw-shadow-lv2);
  pointer-events: auto;
}
.strip {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 16px;
  background: var(--dsw-alias-state-warn-tertiary);
  color: var(--dsw-alias-state-warn-primary);
  font-size: 13px;
  line-height: 18px;
}
.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--dsw-alias-state-warn-primary);
}
.body {
  display: flex;
  flex-direction: column;
  gap: 6px;
  box-sizing: border-box;
  max-height: var(--dsh-composer-text-max-height);
  overflow-y: auto;
  padding: 12px 16px 0;
}
.headline {
  color: var(--dsw-alias-label-primary);
  font-size: 15px;
  line-height: 24px;
  font-weight: 500;
}
.command {
  color: var(--dsw-alias-label-tertiary);
  font-family: var(--ds-font-family-code);
  font-size: 13px;
  line-height: 20px;
  word-break: break-all;
}
.fail {
  color: var(--dsw-alias-state-error-primary);
  font-size: 12px;
  line-height: 18px;
}
.actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  padding: 14px 16px;
}
.btn {
  position: relative;
  z-index: 1;
  height: 32px;
  padding: 0 14px;
  border-radius: 16px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  pointer-events: auto;
}
.btn:disabled { opacity: 0.5; cursor: default; }
.reject {
  border: 1px solid var(--dsw-alias-border-l2);
  background: transparent;
  color: var(--dsw-alias-label-primary);
}
.reject:hover:not(:disabled) {
  background: var(--dsw-alias-interactive-bg-hover-danger);
  color: var(--dsw-alias-state-error-primary);
  border-color: transparent;
}
.allow {
  border: none;
  background: var(--dsw-alias-button-info-fill);
  color: #fff;
}
.allow:hover:not(:disabled) { background: var(--dsw-alias-button-info-hover); }
</style>
