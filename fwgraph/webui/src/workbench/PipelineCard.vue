<template>
  <div class="wrap">
    <div class="card">
      <div class="head">
        <span class="name">{{ job.firmware || '固件任务' }}</span>
        <span class="status" :data-kind="kind">{{ statusLabel }}</span>
      </div>
      <ol class="steps">
        <li
          v-for="(s, i) in PIPE_STEPS"
          :key="s.key"
          class="step"
          :data-state="stepState(i, job)"
        >
          <span class="dot">
            <span v-if="stepState(i, job) === 'ok'" class="tick">✓</span>
            <span v-else-if="stepState(i, job) === 'err'" class="tick">!</span>
          </span>
          <span class="lbl">{{ s.label }}</span>
        </li>
      </ol>
      <p v-if="job.error" class="err">{{ job.error }}</p>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { PIPE_STEPS, STATUS_TEXT, COMPLETE, stepState } from './pipeline.js'

const props = defineProps({ job: { type: Object, required: true } })

const statusLabel = computed(() => {
  if (props.job.status === 'uploading') return `上传 ${props.job.uploadPct || 0}%`
  return STATUS_TEXT[props.job.status] || props.job.status
})
const kind = computed(() => {
  if (props.job.status === 'failed') return 'err'
  if (COMPLETE.has(props.job.status)) return 'ok'
  return 'run'
})
</script>

<style scoped>
.wrap {
  max-width: var(--dsh-chat-content-width);
  width: 100%;
  margin: 16px auto 0;
  padding: 0 calc(var(--dsh-composer-side-clearance) + 16px);
}
.card {
  padding: 14px 16px 10px;
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 12px;
  background: var(--dsw-alias-bg-layer-1);
  box-shadow: var(--dsw-shadow-lv1);
}
.head {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 12px;
}
.name {
  font-size: 14px;
  font-weight: 500;
  color: var(--dsw-alias-label-primary);
}
.status {
  font-size: 12px;
  color: var(--dsw-alias-label-tertiary);
}
.status[data-kind='ok'] { color: var(--dsw-alias-state-success-primary); }
.status[data-kind='err'] { color: var(--dsw-alias-state-error-primary); }
.status[data-kind='run'] { color: var(--dsw-alias-state-business-primary); }
.steps {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 14px;
  margin: 0;
  padding: 0;
  list-style: none;
}
.step {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: var(--dsw-alias-label-caption);
  font-size: 12px;
  line-height: 18px;
}
.dot {
  width: 14px;
  height: 14px;
  border-radius: 50%;
  border: 1.5px solid var(--dsw-alias-border-l3);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 9px;
}
.step[data-state='ok'] { color: var(--dsw-alias-state-success-primary); }
.step[data-state='ok'] .dot {
  border-color: var(--dsw-alias-state-success-primary);
  background: var(--dsw-alias-state-success-primary);
  color: #fff;
}
.step[data-state='now'] { color: var(--dsw-alias-state-business-primary); }
.step[data-state='now'] .dot {
  border-color: var(--dsw-alias-state-business-primary);
  animation: pulse 1.2s ease-in-out infinite;
}
.step[data-state='err'] { color: var(--dsw-alias-state-error-primary); }
.step[data-state='err'] .dot {
  border-color: var(--dsw-alias-state-error-primary);
  background: var(--dsw-alias-state-error-primary);
  color: #fff;
}
@keyframes pulse {
  0%, 100% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--dsw-alias-state-business-primary) 40%, transparent); }
  50% { box-shadow: 0 0 0 4px color-mix(in srgb, var(--dsw-alias-state-business-primary) 0%, transparent); }
}
.err {
  margin: 8px 0 0;
  font-size: 12px;
  color: var(--dsw-alias-state-error-primary);
}
</style>
