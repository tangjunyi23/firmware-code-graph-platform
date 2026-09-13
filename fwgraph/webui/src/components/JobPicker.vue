<template>
  <el-select
    :model-value="modelValue"
    filterable
    placeholder="选择固件任务"
    class="job-picker"
    @update:model-value="onChange"
  >
    <el-option v-for="j in jobs" :key="j.job_id" :value="j.job_id" :label="j.firmware || j.job_id">
      <div class="jp-opt">
        <span class="jp-name">{{ j.firmware || j.job_id }}</span>
        <span class="jp-meta">
          <span class="jp-status" :data-state="stateOf(j.status)">{{ statusText(j.status) }}</span>
          <span class="jp-id">{{ j.job_id }}</span>
        </span>
      </div>
    </el-option>
  </el-select>
</template>

<script setup>
// 代码洞察四页共用的任务选择器：
// 固件名为主标签，状态汉化成徽章，按各页偏好状态自动选中第一个可用任务。
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { STATUS_TEXT } from '../workbench/pipeline.js'

const props = defineProps({
  modelValue: { type: String, default: '' },
  // 自动选中优先考虑的任务状态（如 ['routed','surfaced']）；空数组则不自动选中
  prefer: { type: Array, default: () => [] }
})
const emit = defineEmits(['update:modelValue', 'change'])

const jobs = ref([])

function statusText (s) { return STATUS_TEXT[s] || s || '—' }
function stateOf (s) {
  if (s === 'failed') return 'bad'
  if (['graphed', 'attacked', 'routed', 'surfaced', 'done'].includes(s)) return 'ok'
  return 'run'
}

function onChange (v) {
  emit('update:modelValue', v)
  emit('change', v)
}

async function refresh () {
  try {
    const list = await api('/jobs')
    jobs.value = Array.isArray(list) ? list : []
  } catch {
    jobs.value = []
  }
  if (!props.modelValue && props.prefer.length && jobs.value.length) {
    const hit = jobs.value.find((j) => props.prefer.includes(j.status))
    const picked = hit || null
    if (picked) onChange(picked.job_id)
  }
}

onMounted(refresh)
defineExpose({ refresh })
</script>

<style scoped>
.job-picker { width: 260px; }
.jp-opt {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  min-width: 0;
}
.jp-name {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.jp-meta { flex: none; display: flex; align-items: center; gap: 8px; }
.jp-status {
  padding: 0 7px;
  border-radius: 999px;
  font-size: 11px;
  line-height: 17px;
}
.jp-status[data-state='ok'] { color: var(--fw-ok); background: rgba(22, 163, 74, .1); }
.jp-status[data-state='run'] { color: var(--fw-warn); background: rgba(217, 119, 6, .12); }
.jp-status[data-state='bad'] { color: var(--fw-danger); background: rgba(225, 29, 72, .1); }
.jp-id {
  color: var(--fw-text-3);
  font-size: 11px;
  font-family: var(--fw-font-mono);
}
@media (max-width: 720px) {
  .job-picker { width: 100%; }
}
</style>
