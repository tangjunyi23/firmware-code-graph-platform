<template>
  <div class="prep">
    <aside class="rail">
      <button type="button" class="new-btn" data-tour="prepare-new" @click="reset">{{ t('prepare.new') }}</button>
      <div class="section"><span>{{ t('prepare.heading') }}</span><span>{{ jobs.length }}</span></div>
      <el-input v-model="taskQuery" class="prepare-task-search" placeholder="搜索固件任务" aria-label="搜索固件任务" clearable />
      <div class="task-status-tabs" aria-label="筛选分析任务状态">
        <button v-for="item in taskFilters" :key="item.key" type="button" :class="{ on: taskFilter === item.key }" :aria-pressed="taskFilter === item.key" @click="taskFilter = item.key">{{ item.label }} <span>{{ item.count }}</span></button>
      </div>
      <div class="list">
        <p v-if="!jobs.length" class="empty">{{ t('prepare.empty') }}</p>
        <button
          v-for="job in filteredJobs"
          :key="job.job_id"
          type="button"
          class="row"
          :class="{ on: current && current.job_id === job.job_id, fail: job.status === 'failed' }"
          :title="job.status === 'failed' ? (job.error || '分析失败') : job.firmware"
          @click="openJob(job)"
        >
          <span class="dot" :data-on="RUNNING.has(job.status) || undefined" />
          <span class="title" :title="job.firmware">{{ job.firmware }}</span>
          <span class="meta">{{ STATUS_TEXT[job.status] || job.status }}</span>
        </button>
        <p v-if="jobs.length && !filteredJobs.length" class="empty">无匹配任务</p>
      </div>
    </aside>
    <main class="stage" :class="{ 'create-stage': !current }">
      <div class="prepare-overview" aria-label="固件任务统计">
        <button v-for="item in taskFilters" :key="item.key" type="button" :class="{ on: taskFilter === item.key }" :aria-pressed="taskFilter === item.key" @click="taskFilter = item.key"><span>{{ item.key === 'all' ? '固件任务' : item.label }}</span><strong>{{ item.count }}</strong><i :data-status="item.key" /></button>
      </div>
      <header class="head">
        <div>
          <h1>{{ current ? (current.firmware || '固件任务') : '新建固件分析' }}</h1>
          <p v-if="current">{{ STATUS_TEXT[current.status] || current.status }}</p>
        </div>
        <div class="prepare-head-actions"><span v-if="current && RUNNING.has(current.status)" class="live"><i />分析进行中</span><button v-if="current" type="button" class="prepare-reset" @click="reset"><component :is="NAV_ICONS.Upload" :size="14" />新建任务</button></div>
      </header>

      <PipelineCard
        v-if="current"
        data-tour="prepare-board"
        :job="current"
        :decrypt="decrypt"
        :stats="stats"
        :lines="feed"
        :log-tail="current.log_tail || []"
        :retrying="retrying"
        @retry="retryFailed"
      />

      <p v-if="current && current.task" class="task">分析要求：{{ current.task }}</p>
      <p v-if="current && pipelineFinished(current)" class="hint">
        <a href="?page=jobs&mode=expert">进入安全工作台</a>
      </p>
      <p v-if="notice" class="notice" :class="{ error: notice.level === 'error' }">{{ notice.text }}</p>

      <div v-if="!current || !pipelineFinished(current)" class="composer-wrap">
        <button v-if="!current && !file" type="button" class="prepare-upload" data-tour="prepare-upload" @click="fileInput.click()">
          <span class="prepare-file-icon"><component :is="NAV_ICONS.Upload" :size="26" /></span><span><b>选择固件文件</b><small>BIN、IMG、TRX、CHK 等固件镜像</small></span>
        </button>
        <div v-if="file" class="prepare-selected-file">
          <span class="prepare-file-icon"><component :is="NAV_ICONS.Cpu" :size="22" /></span><div><strong>{{ file.name }}</strong><small>{{ fmtSize(file.size) }}</small></div>
          <button type="button" aria-label="移除固件文件" @click="file = null">×</button>
        </div>
        <label for="prepare-analysis-note" class="prepare-note-label">分析方向 <span class="muted">· 可选</span></label>
        <textarea id="prepare-analysis-note"
          v-model="draft"
          class="input"
          rows="3"
          :placeholder="t('placeholder.prepare')"
          :disabled="busy"
        />
        <div class="actions">
          <input ref="fileInput" type="file" class="hidden" :accept="FW_ACCEPT" @change="onPick" />
          <button
            type="button"
            class="send"
            data-tour="prepare-send"
            :disabled="busy || (!file && !current)"
            @click="onSend"
          >开始分析</button>
        </div>
      </div>
      <div v-if="uploadPct !== null" class="toast">正在上传固件… {{ uploadPct }}%</div>
    </main>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { api, uploadFirmware } from '../api.js'
import { loadJobs, rememberSelectedJob } from '../jobCatalog.js'
import PipelineCard from '../workbench/PipelineCard.vue'
import { t } from '../workbench/locales.js'
import { NAV_ICONS } from '../workbench/icons.js'
import {
  DEFAULT_PREPARE_TASK, FW_ACCEPT, RUNNING, STATUS_TEXT, pipelineFinished,
  announceSteps, failedStep, failedStepLabel, RETRYABLE_STEPS, fmtSize
} from '../workbench/pipeline.js'

const jobs = ref([])
const taskQuery = ref('')
const taskFilter = ref('all')
const taskFilters = computed(() => [
  { key: 'all', label: '全部', count: jobs.value.length },
  { key: 'ready', label: '已就绪', count: jobs.value.filter(job => job.status !== 'failed' && pipelineFinished(job)).length },
  { key: 'running', label: '进行中', count: jobs.value.filter(job => RUNNING.has(job.status)).length },
  { key: 'failed', label: '失败', count: jobs.value.filter(job => job.status === 'failed').length }
])
const filteredJobs = computed(() => {
  const query = taskQuery.value.trim().toLowerCase()
  const rows = jobs.value.filter(job => taskFilter.value === 'all' || (taskFilter.value === 'ready' ? job.status !== 'failed' && pipelineFinished(job) : taskFilter.value === 'failed' ? job.status === 'failed' : RUNNING.has(job.status)))
  return query ? rows.filter(job => `${job.firmware || ''} ${job.job_id || ''} ${STATUS_TEXT[job.status] || job.status}`.toLowerCase().includes(query)) : rows
})
const current = ref(null)
const draft = ref('')
const file = ref(null)
const fileInput = ref(null)
const notice = ref(null)
const uploadPct = ref(null)
const sending = ref(false)
const retrying = ref(false)
const decrypt = ref(null)
const stats = ref({})
const feed = ref([])
const busy = computed(() => sending.value || (current.value && RUNNING.has(current.value.status)))

let timer = null
let feedSeq = 0
let seenDecrypt = 0
let lastJob = null
let refreshPending = null
let disposed = false
let detailRevision = 0

function pushFeed (text, kind = 'info') {
  const line = String(text || '').trim()
  if (!line) return
  const last = feed.value[feed.value.length - 1]
  if (last && last.text === line) return
  feed.value.push({ id: ++feedSeq, ts: Date.now(), text: line, kind })
  if (feed.value.length > 80) feed.value = feed.value.slice(-80)
}

function noteJob (next) {
  const prev = lastJob
  for (const text of announceSteps(prev, next)) {
    const kind = text.includes('失败') ? 'err' : text.includes('完成') ? 'ok' : 'now'
    pushFeed(text, kind)
  }
  lastJob = next ? {
    job_id: next.job_id, status: next.status, firmware: next.firmware,
    error: next.error, failed_from: next.failed_from
  } : null
}

async function retryFailed () {
  const job = current.value
  if (!job || job.status !== 'failed' || retrying.value) return
  const step = failedStep(job)
  if (!step || !RETRYABLE_STEPS.has(step)) return
  retrying.value = true
  notice.value = null
  try {
    await api(`/jobs/${job.job_id}/${step}`, { method: 'POST' })
    pushFeed(`已重新发起「${failedStepLabel(job)}」阶段`, 'now')
    await refresh()
  } catch (err) {
    notice.value = { level: 'error', text: `重试发起失败：${err.message}` }
  } finally {
    retrying.value = false
  }
}

async function loadDetail (jobId) {
  const revision = ++detailRevision
  try {
    const detail = await api(`/jobs/${jobId}`)
    if (disposed || revision !== detailRevision || !current.value || current.value.job_id !== jobId) return
    current.value = { ...current.value, ...detail }
    stats.value = detail.manifest_summary || {}
    const packedN = detail.manifest_summary?.packed_binaries || 0
    if (packedN && !feed.value.some((l) => l.text.includes('加壳'))) {
      feed.value.push({
        at: new Date().toISOString(),
        kind: 'warn',
        text: `检测到 ${packedN} 个 UPX 加壳二进制：反编译与攻击面分析未覆盖（moria 标记），如需分析请先脱壳后重跑`,
      })
    }
    if (detail.manifest_summary?.total_binaries && !feed.value.some((l) => l.text.includes('个二进制'))) {
      pushFeed(
        `解出 ${detail.manifest_summary.extracted_files ?? '—'} 个文件，其中 ${detail.manifest_summary.total_binaries} 个二进制`,
        'ok'
      )
    }
  } catch { /* keep last */ }
  try {
    const dec = await api(`/jobs/${jobId}/decrypt`)
    if (disposed || revision !== detailRevision || !current.value || current.value.job_id !== jobId) return
    decrypt.value = dec
    const logs = dec.log || []
    for (const raw of logs.slice(seenDecrypt)) {
      const text = String(raw).replace(/^\S+\s+/, '')
      pushFeed(text, dec.status === 'failed' ? 'err' : 'info')
    }
    seenDecrypt = logs.length
  } catch {
    if (!disposed && revision === detailRevision && current.value?.job_id === jobId) decrypt.value = null
  }
}

function refresh () {
  if (refreshPending) return refreshPending
  refreshPending = refreshOnce().finally(() => { refreshPending = null })
  return refreshPending
}

async function refreshOnce () {
  try {
    const list = await loadJobs({ force: true })
    if (disposed) return
    jobs.value = Array.isArray(list) ? list : []
    if (current.value) {
      const fresh = jobs.value.find((j) => j.job_id === current.value.job_id)
      if (fresh) {
        const merged = { ...current.value, ...fresh }
        noteJob(merged)
        current.value = merged
        await loadDetail(fresh.job_id)
      }
    }
  } catch {
    /* keep last list */
  }
}

function reset () {
  detailRevision += 1
  current.value = null
  file.value = null
  draft.value = ''
  notice.value = null
  decrypt.value = null
  stats.value = {}
  feed.value = []
  seenDecrypt = 0
  lastJob = null
}

function openJob (job) {
  rememberSelectedJob(job.job_id)
  file.value = null
  draft.value = ''
  feed.value = []
  seenDecrypt = 0
  lastJob = null
  current.value = job
  notice.value = null
  noteJob(job)
  loadDetail(job.job_id)
}

function onPick (e) {
  const picked = e.target.files && e.target.files[0]
  if (picked) file.value = picked
  e.target.value = ''
}

async function onSend () {
  if (sending.value) return
  const task = draft.value.trim() || DEFAULT_PREPARE_TASK
  if (!file.value && !(current.value && RUNNING.has(current.value.status))) {
    notice.value = { level: 'error', text: '请先选择固件文件' }
    return
  }
  sending.value = true
  notice.value = null
  try {
    if (file.value) {
      uploadPct.value = 0
      pushFeed('开始上传固件', 'now')
      const fname = file.value.name
      const resp = await uploadFirmware(file.value, {
        auto: true,
        task,
        onProgress: (loaded, total) => {
          uploadPct.value = total ? Math.round((loaded / total) * 100) : 0
        }
      })
      file.value = null
      feed.value = []
      seenDecrypt = 0
      lastJob = null
      current.value = {
        job_id: resp.job_id,
        firmware: fname,
        status: resp.status || 'pending',
        task,
        uploadPct: 100
      }
      pushFeed(`上传完成，任务 ${resp.job_id}`, 'ok')
      noteJob(current.value)
    }
  } catch (err) {
    notice.value = { level: 'error', text: err.message || '上传失败' }
    pushFeed(err.message || '上传失败', 'err')
  } finally {
    uploadPct.value = null
    sending.value = false
    refresh()
  }
}

watch(uploadPct, (n) => {
  if (n == null) return
  if (n === 0 || n === 100 || n % 20 === 0) pushFeed(`正在上传固件 ${n}%`, 'now')
})

onMounted(() => {
  refresh()
  const poll = async () => {
    if (disposed) return
    if (!document.hidden) await refresh()
    if (!disposed) timer = setTimeout(poll, jobs.value.some(j => RUNNING.has(j.status)) ? 4000 : 20000)
  }
  timer = setTimeout(poll, 4000)
})
onBeforeUnmount(() => { disposed = true; detailRevision += 1; if (timer) clearTimeout(timer) })
</script>

<style scoped>
.prep {
  height: 100%;
  min-height: 0;
  display: grid;
  grid-template-columns: 260px minmax(0, 1fr);
  color: var(--fw-text);
  font-family: var(--fw-font, inherit);
}
.rail {
  display: flex;
  flex-direction: column;
  min-width: 0;
  padding: 12px;
  border-right: 1px solid var(--fw-line);
  background: var(--fw-surface);
}
.new-btn {
  height: 38px;
  margin-bottom: 8px;
  border: 1px solid var(--fw-line);
  border-radius: 12px;
  background: var(--fw-fill);
  color: var(--fw-text);
  font-weight: 500;
  cursor: pointer;
}
.new-btn:hover { background: var(--fw-fill-strong); }
.section { height: 28px; padding: 0 6px; font-size: 12px; color: var(--fw-text-3); }
.list { flex: 1; min-height: 0; overflow: auto; }
.empty { margin: 16px 8px; font-size: 13px; color: var(--fw-text-3); }
.row {
  display: flex; align-items: center; gap: 8px;
  width: 100%; height: 36px; padding: 0 8px;
  border: none; border-radius: 8px; background: transparent;
  cursor: pointer; text-align: left; font-family: inherit; color: inherit;
}
.row:hover, .row.on { background: var(--fw-fill); }
.dot { width: 6px; height: 6px; border-radius: 50%; background: #c8ccd3; flex: none; }
.dot[data-on] { background: var(--fw-ok); }
.row.fail .dot { background: var(--fw-danger); }
.row.fail .meta { color: var(--fw-danger); }
.title { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13.5px; }
.meta { font-size: 12px; color: var(--fw-text-3); flex: none; }
.stage { min-width: 0; overflow: auto; padding: 20px 22px 32px; }
.head { display: flex; justify-content: space-between; align-items: flex-end; gap: 12px; margin-bottom: 14px; }
.kicker { margin: 0 0 6px; color: var(--fw-brand); letter-spacing: .04em; font-size: 12px; font-weight: 600; }
h1 { margin: 0 0 4px; font-size: 24px; letter-spacing: -.03em; }
.head p { margin: 0; color: var(--fw-text-3); font-size: 13px; }
.live { display: inline-flex; align-items: center; gap: 6px; color: var(--fw-ok); font-size: 12px; }
.live i {
  width: 7px; height: 7px; border-radius: 50%; background: var(--fw-ok);
}
.task, .hint { font-size: 13px; color: var(--fw-text-2); line-height: 1.6; }
.notice { margin: 12px 0; font-size: 13px; }
.notice.error { color: var(--fw-danger); }
.composer-wrap {
  margin-top: 16px;
  padding: 12px 14px;
  border: 1px solid var(--fw-line);
  border-radius: 18px;
  background: var(--fw-surface);
}
.chip {
  display: inline-flex; align-items: center; gap: 8px;
  margin-bottom: 8px; padding: 4px 10px; border-radius: 999px;
  background: var(--fw-bg-2); font-size: 13px;
}
.chip button { border: none; background: none; cursor: pointer; color: inherit; }
.input {
  width: 100%; border: none; resize: none; outline: none;
  font: inherit; background: transparent; color: inherit;
}
.actions { display: flex; justify-content: space-between; align-items: center; margin-top: 8px; }
.hidden { display: none; }
.add, .send {
  height: 34px; padding: 0 14px; border-radius: 8px; border: none;
  cursor: pointer; font-weight: 500;
}
.add { background: var(--fw-bg-2); color: var(--fw-text-2); }
.send { background: var(--fw-brand); color: #fff; }
.send:disabled, .add:disabled { opacity: 0.5; cursor: default; }
.toast { margin-top: 12px; font-size: 13px; color: var(--fw-text-3); }
@media (max-width: 900px) {
  .prep { display: block; }
  .rail { height: 180px; border-right: none; border-bottom: 1px solid var(--fw-line); }
}
</style>
