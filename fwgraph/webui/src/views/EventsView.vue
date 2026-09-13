<template>
  <div class="events-page">
    <header class="ins-head">
      <div class="ins-head-row">
        <h1 class="ins-title"><span class="ins-ico"><component :is="NAV_ICONS.Tickets" :size="18" /></span>事件流</h1>
      </div>
      <p class="ins-sub">固件任务与挖掘会话的事件时间线。</p>
    </header>

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
        <div
          v-for="(row, i) in viewLines"
          :key="i"
          class="log-line"
          :data-lv="row.lv"
        >
          <span class="log-mark">{{ row.mark }}</span>
          <time v-if="row.time">{{ row.time }}</time>
          <span v-else class="log-time-gap" />
          <span class="log-msg">{{ row.msg }}</span>
        </div>
        <div v-if="!viewLines.length" class="muted pad">等待解包日志…</div>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { NAV_ICONS } from '../workbench/icons.js'
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import { api } from '../api'

const STORE_JOB = 'fwgraph_events_job'
const PIPE = ['解密', '解包', '解析', '反编译', '图谱', '攻击路径', '路由', '输入', '攻击面']
const STEP_INDEX = {
  uploading: 0, pending: 0, decrypting: 0, extracting: 1, parsing: 2, decompiling: 3,
  graphing: 4, attacking: 5, routing: 6, identifying: 7, surfacing: 8, surfaced: 8
}
const RUNNING = new Set([
  'pending', 'decrypting', 'extracting', 'parsing', 'decompiling', 'graphing',
  'attacking', 'routing', 'identifying', 'surfacing'
])
const STATUS_TEXT = {
  pending: '排队', decrypting: '解密中', extracting: '解包中', parsing: '解析中', decompiling: '反编译',
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

const MARK_LV = { '+': 'ok', '*': 'info', '!': 'warn', '✓': 'ok', '-': 'mute' }
const ZH = [
  [/EMBA finished analysis in default mode \(docker container\)\./i, 'EMBA 解包分析结束'],
  [/EMBA main container starting and detaching\./i, 'EMBA 主容器启动中'],
  [/Quest container .+ started and detached\./i, '辅助容器已启动'],
  [/EMBA main container .+ started and detached\./i, '主容器已启动'],
  [/Final cleanup started\./i, '开始收尾清理'],
  [/Pre-checking phase started on .+/i, '预检阶段开始'],
  [/Pre-checking phase ended on .+/i, '预检阶段结束'],
  [/Testing phase started on .+/i, '检测阶段开始'],
  [/Test ended on .+/i, '本阶段结束'],
  [/ not executed - blacklist triggered\s*$/i, '（策略跳过）'],
  [/ starting\s*$/i, ' 开始'],
  [/ finished\s*$/i, ' 完成'],
  [/Firmware binary path:/i, '固件路径：'],
  [/Firmware path:/i, '固件路径：'],
  [/Log directory:/i, '日志目录：'],
  [/Firmware tested:/i, '分析固件：'],
]

function zhMsg (s) {
  let out = s
  for (const [re, to] of ZH) out = out.replace(re, to)
  return out
}

function parseLogLine (line) {
  const raw = String(line || '')
  const m = raw.match(/^\[([+*!✓-])\]\s*(.*)$/)
  if (!m) return { lv: 'plain', mark: '', time: '', msg: raw }
  let rest = m[2]
  let time = ''
  const tm = rest.match(/^[A-Za-z]{3} [A-Za-z]{3} +\d{1,2} (\d{2}:\d{2}:\d{2}) UTC \d{4}(?: - )?(.*)$/)
  if (tm) {
    time = tm[1]
    rest = tm[2]
  }
  return { lv: MARK_LV[m[1]] || 'plain', mark: m[1], time, msg: zhMsg(rest) }
}

const viewLines = computed(() => logLines.value.map(parseLogLine))

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
.ins-head { grid-column: 1 / -1; margin-bottom: 2px; }
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
.job-item:hover { background: var(--fw-surface-2); }
.job-item.on { background: var(--fw-fill-strong); border-color: var(--fw-line-strong); }
.job-name { font-size: 13px; color: var(--fw-text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.job-meta { display: flex; align-items: center; gap: 8px; margin-top: 4px; }
.mono { font-family: ui-monospace, Consolas, monospace; font-size: 11px; }
.muted { color: var(--fw-text-3); }
.live {
  display: inline-flex; align-items: center; gap: 6px;
  color: #86efac; font-size: 12px; font-weight: 650; margin-left: 8px;
}
.live i {
  width: 8px; height: 8px; border-radius: 50%; background: #4ade80;
  animation: fx-pulse 1.6s ease-out infinite;
}
.pipe-mini {
  display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px;
}
.mini-step {
  font-size: 12px; padding: 3px 8px; border-radius: 999px;
  background: var(--fw-fill); color: var(--fw-text-3);
}
.mini-step.ok { background: #dcfce7; color: #166534; }
.mini-step.now { background: var(--fw-fill-strong); color: var(--fw-brand); font-weight: 650; }
.mini-step.err { background: #ffe4e6; color: #9f1239; }
.fail {
  color: var(--fw-danger); background: #ffe4e6; border-radius: 8px;
  padding: 8px 10px; font-size: 13px; margin: 0 0 10px;
}
.log-pane {
  flex: 1; min-height: 280px; overflow: auto;
  background: var(--fw-surface); color: var(--fw-text-2);
  border: 1px solid var(--fw-line);
  border-radius: 12px; padding: 10px 14px;
  font-family: var(--fw-font-mono); font-size: 12.5px;
  line-height: 1.65;
}
.log-line {
  display: grid;
  grid-template-columns: 18px 64px minmax(0, 1fr);
  column-gap: 10px;
  align-items: start;
  white-space: pre-wrap;
  word-break: break-word;
  padding: 1px 0;
}
.log-line[data-lv='plain'] {
  grid-template-columns: 1fr;
}
.log-line[data-lv='plain'] .log-mark,
.log-line[data-lv='plain'] .log-time-gap,
.log-line[data-lv='plain'] time { display: none; }
.log-mark {
  font-weight: 700;
  text-align: center;
}
.log-line[data-lv='ok'] .log-mark { color: var(--fw-ok); }
.log-line[data-lv='info'] .log-mark { color: var(--fw-brand); }
.log-line[data-lv='warn'] .log-mark { color: var(--fw-warn); }
.log-line[data-lv='mute'] .log-mark { color: var(--fw-text-3); }
time, .log-time-gap {
  color: var(--fw-text-3);
  font-variant-numeric: tabular-nums;
  font-size: 11px;
  padding-top: 2px;
}
.log-msg { min-width: 0; color: var(--fw-text); }
.pad { padding: 24px 8px; }
@media (max-width: 900px) {
  .events-page { grid-template-columns: 1fr; }
}
</style>
