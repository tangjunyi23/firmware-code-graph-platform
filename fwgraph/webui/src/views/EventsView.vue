<template>
  <div class="events-page">
    <el-card class="col-jobs" shadow="never">
      <template #header>
        <div class="row-between">
          <span>任务</span>
          <el-button size="small" text @click="loadJobs">刷新</el-button>
        </div>
      </template>
      <div
        v-for="j in jobs"
        :key="j.job_id"
        class="job-item"
        :class="{ on: j.job_id === jobId }"
        @click="selectJob(j)"
      >
        <div class="job-name">{{ j.firmware }}</div>
        <div class="job-meta">
          <el-tag size="small" :type="statusType(j.status)">{{ statusLabel(j.status) }}</el-tag>
          <span class="mono muted">{{ j.job_id }}</span>
        </div>
      </div>
      <el-empty v-if="!jobs.length" description="还没有任务，先去工作台上传固件" :image-size="70" />
    </el-card>

    <el-card class="col-stream" shadow="never">
      <template #header>
        <div class="row-between">
          <span>事件流
            <span v-if="jobId" class="mono muted">{{ jobId }}</span>
            <span v-if="running" class="live"><i></i>LIVE</span>
          </span>
          <span class="muted">流水线日志</span>
        </div>
      </template>

      <div v-if="job" class="pipe-mini">
        <span
          v-for="(s, i) in PIPE"
          :key="s"
          class="mini-step"
          :class="miniState(i)"
        >{{ s }}</span>
      </div>
      <p v-if="job && job.error" class="fail">{{ job.error }}</p>

      <div ref="logPane" class="log-pane">
        <div v-for="(line, i) in logLines" :key="i" class="log-line">{{ line }}</div>
        <div v-if="!logLines.length" class="muted pad">等待解包日志…</div>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import { api } from '../api'

const STORE_JOB = 'fwgraph_events_job'
const PIPE = ['解包', '解析', '反编译', '图谱', '攻击路径', '路由', '输入', '攻击面']
const STEP_INDEX = {
  uploading: 0, pending: 0, extracting: 0, parsing: 1, decompiling: 2,
  graphing: 3, attacking: 4, routing: 5, identifying: 6, surfacing: 7, surfaced: 7
}
const RUNNING = new Set([
  'pending', 'extracting', 'parsing', 'decompiling', 'graphing',
  'attacking', 'routing', 'identifying', 'surfacing'
])
const STATUS_TEXT = {
  pending: '排队', extracting: '解包中', parsing: '解析中', decompiling: '反编译',
  graphing: '建图', attacking: '攻击路径', routing: '路由', identifying: '输入识别',
  surfacing: '攻击面', graphed: '图谱完成', attacked: '路径完成', routed: '完成',
  surfaced: '完成', failed: '失败', done: '解包完成'
}

const jobs = ref([])
const jobId = ref('')
const job = ref(null)
const logLines = ref([])
const logPane = ref(null)
let pollTimer = null

const running = computed(() => job.value && RUNNING.has(job.value.status))

function statusType (s) {
  if (s === 'failed') return 'danger'
  if (RUNNING.has(s)) return 'warning'
  return 'success'
}
function statusLabel (s) { return STATUS_TEXT[s] || s }
function miniState (i) {
  const s = job.value?.status
  if (!s) return ''
  if (s === 'failed' && i === (STEP_INDEX[s] ?? 0)) return 'err'
  const idx = STEP_INDEX[s] ?? 0
  if (['graphed', 'attacked', 'routed', 'surfaced'].includes(s) || i < idx) return 'ok'
  if (i === idx) return 'now'
  return ''
}

async function loadJobs () {
  try { jobs.value = await api('/jobs') } catch { jobs.value = [] }
}

async function selectJob (row) {
  jobId.value = row.job_id
  try { localStorage.setItem(STORE_JOB, row.job_id) } catch { /* ignore */ }
  await refreshJob()
}

async function refreshJob () {
  if (!jobId.value) return
  try {
    job.value = await api(`/jobs/${jobId.value}`)
  } catch { return }
  try {
    const logs = await api(`/jobs/${jobId.value}/logs?lines=400`)
    logLines.value = logs.lines || []
    nextTick(() => {
      const el = logPane.value
      if (el) el.scrollTop = el.scrollHeight
    })
  } catch { /* ignore */ }
}

onMounted(async () => {
  await loadJobs()
  const saved = localStorage.getItem(STORE_JOB)
  const pick = jobs.value.find((j) => j.job_id === saved) || jobs.value[0]
  if (pick) await selectJob(pick)
  pollTimer = setInterval(async () => {
    await loadJobs()
    await refreshJob()
  }, 2000)
})
onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer)
})
</script>

<style scoped>
.events-page {
  display: grid;
  grid-template-columns: 280px 1fr;
  gap: 14px;
  min-height: calc(100vh - 110px);
}
.col-jobs, .col-stream { min-height: 0; }
.col-stream { display: flex; flex-direction: column; }
.col-stream :deep(.el-card__body) {
  flex: 1; min-height: 0; display: flex; flex-direction: column;
}
.row-between { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
.job-item {
  padding: 10px 8px; border-radius: 10px; cursor: pointer;
  border: 1px solid transparent;
  transition: background .15s ease, border-color .15s ease;
}
.job-item:hover { background: #f4f8fd; }
.job-item.on { background: #e9f2fd; border-color: #c0d4f8; }
.job-name { font-size: 13px; color: #1c2b3a; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.job-meta { display: flex; align-items: center; gap: 8px; margin-top: 4px; }
.mono { font-family: ui-monospace, Consolas, monospace; font-size: 11px; }
.muted { color: #64748f; }
.live {
  display: inline-flex; align-items: center; gap: 6px;
  color: #16a34a; font-size: 12px; font-weight: 650; margin-left: 8px;
}
.live i {
  width: 8px; height: 8px; border-radius: 50%; background: #16a34a;
  animation: pulse 1.2s ease-in-out infinite;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: .35; }
}
.pipe-mini {
  display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px;
}
.mini-step {
  font-size: 12px; padding: 3px 8px; border-radius: 999px;
  background: #f0f5fb; color: #9aa9bd;
}
.mini-step.ok { background: #ecf7f0; color: #16a34a; }
.mini-step.now { background: #e9f2fd; color: #2b6ce5; font-weight: 650; }
.mini-step.err { background: #fceeee; color: #dc2626; }
.fail {
  color: #b91c1c; background: #fceeee; border-radius: 8px;
  padding: 8px 10px; font-size: 13px; margin: 0 0 10px;
}
.log-pane {
  flex: 1; min-height: 280px; overflow: auto;
  background: #0f172a; color: #e2e8f0;
  border-radius: 10px; padding: 10px 12px;
  font-family: ui-monospace, Consolas, monospace; font-size: 12px;
  line-height: 1.5;
}
.log-line { white-space: pre-wrap; word-break: break-all; }
.pad { padding: 24px 8px; }
@media (max-width: 900px) {
  .events-page { grid-template-columns: 1fr; }
}
</style>
