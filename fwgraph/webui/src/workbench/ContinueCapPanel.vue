<template>
  <div v-if="visible" class="root">
    <div class="card">
      <div class="strip">
        <span class="dot" />
        <span>{{ t('cap.waiting') }}</span>
      </div>
      <div class="body">
        <div class="headline">{{ t('cap.headline', { turns, maxTurns }) }}</div>
        <div class="detail">{{ t('cap.detail') }}</div>
        <div v-if="error" class="fail">{{ error }}</div>
      </div>
      <div class="actions">
        <button
          type="button"
          class="btn reject"
          :disabled="busy"
          @click.stop="endHunt"
        >{{ t('cap.end') }}</button>
        <button
          type="button"
          class="btn allow"
          :disabled="busy"
          @click.stop="goOn"
        >{{ t('cap.continue') }}</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, ref } from 'vue'
import { t } from './locales.js'
import { HUNT_TURNS } from './pipeline.js'

const emit = defineEmits(['continued', 'ended'])
const session = inject('wbSession')
const visible = computed(() => {
  const st = session?.state
  if (!st) return false
  if (st.huntStatus === 'awaiting_continue') return true
  return st.huntStatus === 'done' && st.turns > 0 && st.turns >= (st.maxTurns || 0)
})
const turns = computed(() => session?.state?.turns || 0)
const maxTurns = computed(() => session?.state?.maxTurns || HUNT_TURNS)
const busy = ref(false)
const error = ref('')

async function goOn () {
  if (busy.value) return
  busy.value = true
  error.value = ''
  try {
    await session.continueHunt(HUNT_TURNS)
    emit('continued')
  } catch (err) {
    error.value = err?.message || '继续失败'
  } finally {
    busy.value = false
  }
}

function endHunt () {
  emit('ended')
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
  padding: 12px 16px 0;
}
.headline {
  color: var(--dsw-alias-label-primary);
  font-size: 15px;
  line-height: 24px;
  font-weight: 500;
}
.detail {
  color: var(--dsw-alias-label-tertiary);
  font-size: 13px;
  line-height: 20px;
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
  height: 32px;
  padding: 0 14px;
  border-radius: 16px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
}
.btn:disabled { opacity: 0.5; cursor: default; }
.reject {
  border: 1px solid var(--dsw-alias-border-l2);
  background: transparent;
  color: var(--dsw-alias-label-primary);
}
.allow {
  border: none;
  background: var(--dsw-alias-button-info-fill);
  color: #fff;
}
.allow:hover:not(:disabled) { background: var(--dsw-alias-button-info-hover); }
</style>
