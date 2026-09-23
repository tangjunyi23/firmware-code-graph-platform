<template>
  <div class="prep">
    <aside class="rail">
      <button type="button" class="new-btn" data-tour="prepare-new" @click="reset">{{ t('prepare.new') }}</button>
      <div class="section">{{ t('prepare.heading') }}</div>
      <div class="list">
        <p v-if="!jobs.length" class="empty">{{ t('prepare.empty') }}</p>
        <button
          v-for="job in jobs"
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
      </div>
    </aside>
    <main class="stage">
      <header class="head">
        <div>
          <p class="kicker">分析任务</p>
          <h1>{{ current ? (current.firmware || '固件任务') : '上传固件，九步自动推进' }}</h1>
          <p>{{ current ? (STATUS_TEXT[current.status] || current.status) : '解密、解包、反编译、图谱到攻击面，进度会在这里实时播报。' }}</p>
        </div>
        <span v-if="current && RUNNING.has(current.status)" class="live"><i />分析进行中</span>
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

      <p v-if="current && current.task" class="task">前置提示词：{{ current.task }}</p>
      <p v-if="current && pipelineFinished(current)" class="hint">
        分析任务已保存。到「新对话」选中该任务即可开始漏洞挖掘。
      </p>
      <p v-if="notice" class="notice" :class="{ error: notice.level === 'error' }">{{ notice.text }}</p>

      <div v-if="!current || !pipelineFinished(current)" class="composer-wrap">
        <div v-if="file" class="chip">
          <span>{{ file.name }}</span>
          <button type="button" @click="file = null">×</button>
        </div>
        <textarea
          v-model="draft"
          class="input"
          rows="3"
          :placeholder="t('placeholder.prepare')"
          :disabled="busy"
        />
        <div class="actions">
          <input ref="fileInput" type="file" class="hidden" :accept="FW_ACCEPT" @change="onPick" />
          <button type="button" class="add" data-tour="prepare-upload" :disabled="busy" @click="fileInput.click()">
            {{ t('input.upload') }}
          </button>
          <button
            type="button"
            class="send"
            data-tour="prepare-send"
            :disabled="busy || (!file && !current)"
            @click="onSend"
          >开始前置分析</button>
        </div>
      </div>
      <div v-if="uploadPct !== null" class="toast">正在上传固件… {{ uploadPct }}%</div>
    </main>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { api, uploadFirmware } from '../api.js'
import PipelineCard from '../workbench/PipelineCard.vue'
import { t } from '../workbench/locales.js'
import {
  DEFAULT_PREPARE_TASK, FW_ACCEPT, RUNNING, STATUS_TEXT, pipelineFinished,
  announceSteps, failedStep, failedStepLabel, RETRYABLE_STEPS
} from '../workbench/pipeline.js'

const jobs = ref([])
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
  try {
    const detail = await api(`/jobs/${jobId}`)
    if (!current.value || current.value.job_id !== jobId) return
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
    if (!current.value || current.value.job_id !== jobId) return
    decrypt.value = dec
    const logs = dec.log || []
    for (const raw of logs.slice(seenDecrypt)) {
      const text = String(raw).replace(/^\S+\s+/, '')
      pushFeed(text, dec.status === 'failed' ? 'err' : 'info')
    }
    seenDecrypt = logs.length
  } catch {
    decrypt.value = null
  }
}

async function refresh () {
  try {
    const list = await api('/jobs')
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
  timer = setInterval(refresh, 1500)
})
onBeforeUnmount(() => { if (timer) clearInterval(timer) })
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
