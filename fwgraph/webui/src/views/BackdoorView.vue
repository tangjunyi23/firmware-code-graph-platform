<template>
  <div>
    <header class="ins-head">
      <div class="ins-head-row">
        <h1 class="ins-title">
          <span class="ins-ico"><component :is="NAV_ICONS.ScanSearch" :size="18" /></span>
          后门检测
        </h1>
        <div class="ins-actions">
          <JobPicker v-model="jobId" :prefer="preferStatuses" />
        </div>
      </div>
      <p class="ins-sub">
        隐藏账户 · 植入密钥 · 启动链后门 · 可疑计划任务 · webshell ·
        已知蠕虫植入物 · 硬编码口令等专项规则检测。
      </p>
    </header>

    <el-card shadow="never" class="block">
      <template #header>
        <div class="row-between"><span>检测目标</span><span class="muted">{{ targetLabel }}</span></div>
      </template>

      <!-- 现场上传 -->
      <div
        class="drop"
        :class="{ over: dragOver, ready: !!uploadName }"
        @dragenter.prevent="dragOver = true"
        @dragover.prevent="dragOver = true"
        @dragleave.prevent="dragOver = false"
        @drop.prevent="onDrop"
        @click="fileInput.click()"
      >
        <input ref="fileInput" type="file" class="hidden" :accept="FW_ACCEPT" @change="onPick" />
        <strong>{{ uploadName || '把固件拖到这里现场检测，或点击选择' }}</strong>
        <span v-if="uploadPct != null">正在上传 {{ uploadPct }}%</span>
        <span v-else>{{ uploadName ? fmtSize(uploadSize) : '支持 bin / img / tar / zip / trx 等镜像，上传后自动解包' }}</span>
        <i v-if="uploadPct != null" class="drop-bar" :style="{ width: uploadPct + '%' }" />
      </div>
      <p v-if="extractionNote" class="ext-note" :class="{ err: extractionErr }">{{ extractionNote }}</p>

      <div class="actions">
        <el-button
          type="primary"
          :disabled="!ready || bdState === 'running'"
          :loading="bdState === 'running'"
          @click="runScan('backdoor')"
        >{{ bdState === 'running' ? '检测中…' : '开始后门检测' }}</el-button>
        <span class="muted hint">扫描在后台执行，完成自动刷新；固件越大耗时越长。</span>
      </div>
    </el-card>

    <!-- 后门检测结果 -->
    <el-card v-if="bd && bdState === 'done'" shadow="never" class="block">
      <template #header>
        <div class="row-between">
          <span>后门检测结果</span>
          <span class="muted">{{ fmtTime(bd.finished_at) }} · 扫描 {{ bd.result.files_scanned }} 个文件</span>
        </div>
      </template>
      <div class="verdict" :data-v="bd.result.verdict">
        <b>{{ bd.result.verdict_cn }}</b>
        <span>
          共 {{ bd.result.counts.total }} 条发现 ·
          严重 {{ bd.result.counts.critical }} / 高危 {{ bd.result.counts.high }} /
          中危 {{ bd.result.counts.medium }} / 低危 {{ bd.result.counts.low }}
        </span>
      </div>
      <div v-if="cats.length" class="cat-chips">
        <span v-for="c in cats" :key="c" class="stat-chip">{{ c }}</span>
      </div>
      <el-empty v-if="!bd.result.findings.length" description="九类规则未命中：未发现后门迹象" :image-size="70" />
      <div v-for="(f, i) in (bd.result.findings || [])" :key="i" class="fd-card" :data-sev="f.severity">
        <div class="fd-head">
          <span class="fd-sev">{{ sevCn(f.severity) }}</span>
          <span class="fd-cat">{{ f.category }}</span>
          <b class="fd-title">{{ f.title }}</b>
          <span class="fd-conf muted">置信 {{ Math.round(f.confidence * 100) }}%</span>
        </div>
        <p class="fd-target mono" :title="f.target">{{ f.target }}</p>
        <p class="fd-desc">{{ f.description }}</p>
        <p class="fd-fix">处置建议：{{ f.recommendation }}</p>
        <button v-if="f.evidence && f.evidence.length" type="button" class="fd-ev-toggle" @click="toggleEv(i)">
          {{ evOpen[i] ? '收起证据' : `证据（${f.evidence.length} 行）` }}
        </button>
        <pre v-if="evOpen[i]" class="fd-ev mono">{{ f.evidence.join('\n') }}</pre>
      </div>
    </el-card>

  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { api, uploadFirmware } from '../api'
import JobPicker from '../components/JobPicker.vue'
import { NAV_ICONS } from '../workbench/icons.js'
import { FW_ACCEPT, STATUS_TEXT, RUNNING } from '../workbench/pipeline.js'

const jobId = ref('')
const preferStatuses = ['done', 'routed', 'surfaced', 'graphed', 'attacked', 'decompiled']

const fileInput = ref(null)
const dragOver = ref(false)
const uploadName = ref('')
const uploadSize = ref(0)
const uploadPct = ref(null)
const uploadJob = ref('')
const extractionNote = ref('')
const extractionErr = ref(false)

const bd = ref(null)      // {status, result, error, finished_at}
const evOpen = ref({})
let timer = null

const ready = computed(() => !!jobId.value)
const targetLabel = computed(() => {
  if (!jobId.value) return '未选择'
  return uploadName.value || '已上传任务'
})

const cats = computed(() => Object.entries(bd.value?.result?.by_category || {})
  .map(([k, n]) => `${k} ${n}`))

function sevCn (s) {
  return { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' }[s] || s
}
function fmtTime (iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return isNaN(d) ? '' : d.toLocaleString('zh-CN', { hour12: false })
}
function fmtSize (n) {
  if (n > 1048576) return (n / 1048576).toFixed(1) + ' MB'
  if (n > 1024) return (n / 1024).toFixed(1) + ' KB'
  return n + ' B'
}
function toggleEv (i) { evOpen.value = { ...evOpen.value, [i]: !evOpen.value[i] } }

// ---- 上传 → 自动解包 → 可检测 ----
function onDrop (e) {
  dragOver.value = false
  const f = e.dataTransfer?.files?.[0]
  if (f) startUpload(f)
}
function onPick (e) {
  const f = e.target.files && e.target.files[0]
  if (f) startUpload(f)
  e.target.value = ''
}
async function startUpload (file) {
  uploadName.value = file.name
  uploadSize.value = file.size
  extractionNote.value = ''
  extractionErr.value = false
  try {
    uploadPct.value = 0
    const resp = await uploadFirmware(file, {
      auto: false,
      onProgress: (loaded, total) => { uploadPct.value = total ? Math.round((loaded / total) * 100) : 0 }
    })
    uploadJob.value = resp.job_id
    jobId.value = resp.job_id
    extractionNote.value = '上传完成，正在自动解包固件…'
  } catch (err) {
    extractionErr.value = true
    extractionNote.value = `上传失败：${err.message}`
    uploadPct.value = null
    uploadName.value = ''
  }
}

async function pollExtraction () {
  if (!uploadJob.value) return
  try {
    const list = await api('/jobs')
    const job = (list || []).find((j) => j.job_id === uploadJob.value)
    if (!job) return
    if (RUNNING.has(job.status)) {
      extractionNote.value = `正在解包（${STATUS_TEXT[job.status] || job.status}）…`
      return
    }
    if (job.status === 'failed') {
      extractionErr.value = true
      extractionNote.value = `解包失败：${job.error || '原因未知'}`
      return
    }
    extractionNote.value = `解包完成（${STATUS_TEXT[job.status] || job.status}），可以开始检测`
  } catch { /* 轮询失败忽略 */ }
}

// ---- 检测执行与轮询 ----
const bdState = computed(() => bd.value?.status || 'never')

async function runScan (kind) {
  if (!jobId.value) { ElMessage.warning('先选择或上传固件'); return }
  try {
    await api(`/jobs/${jobId.value}/${kind}`, { method: 'POST' })
    bd.value = { status: 'running' }
    ElMessage.success(kind === 'backdoor' ? '后门检测已开始' : 'SCA 扫描已开始')
  } catch (e) {
    ElMessage.error(e.message || '启动失败')
  }
}

async function refreshStates () {
  if (!jobId.value) return
  if (bd.value?.status === 'running' || !bd.value) {
    try {
      const st = await api(`/jobs/${jobId.value}/backdoor`)
      if (st.status !== 'never') bd.value = st
    } catch { /* keep */ }
  }
  pollExtraction()
}

watch(jobId, () => {
  bd.value = null
  evOpen.value = {}
  refreshStates()
})

onMounted(() => {
  timer = setInterval(refreshStates, 2000)
})
onBeforeUnmount(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
.block { margin-bottom: 14px; }
.row-between { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.muted { color: var(--fw-text-3); }
.mono { font-family: var(--fw-font-mono, ui-monospace, monospace); }
.hidden { display: none; }
.hint { font-size: 12px; }

.drop {
  position: relative;
  display: flex; flex-direction: column; align-items: center; gap: 6px;
  padding: 26px 16px; margin-bottom: 12px;
  border: 1.5px dashed var(--fw-line-strong); border-radius: 14px;
  background: var(--fw-fill); cursor: pointer; text-align: center;
  transition: border-color .2s ease, background .2s ease;
  overflow: hidden;
}
.drop:hover, .drop.over { border-color: var(--fw-brand); background: color-mix(in srgb, var(--fw-brand) 6%, transparent); }
.drop.ready { border-style: solid; border-color: color-mix(in srgb, var(--fw-ok) 55%, transparent); }
.drop strong { font-size: 14px; }
.drop span { font-size: 12px; color: var(--fw-text-3); }
.drop-bar { position: absolute; left: 0; bottom: 0; height: 3px; background: var(--fw-brand); transition: width .3s ease; }
.ext-note { margin: 0 0 10px; font-size: 12.5px; color: var(--fw-text-3); }
.ext-note.err { color: var(--fw-danger); }
.actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }

.verdict {
  display: flex; align-items: center; gap: 14px; flex-wrap: wrap;
  padding: 13px 16px; border-radius: 12px; margin-bottom: 12px;
  border: 1px solid var(--fw-line); background: var(--fw-fill);
}
.verdict b { font-size: 16px; }
.verdict span { font-size: 12.5px; color: var(--fw-text-3); }
.verdict[data-v='high'] { border-color: color-mix(in srgb, var(--fw-danger) 45%, transparent); background: color-mix(in srgb, var(--fw-danger) 8%, transparent); }
.verdict[data-v='high'] b { color: var(--fw-danger); }
.verdict[data-v='medium'] b { color: var(--fw-warn); }
.verdict[data-v='low'] b { color: var(--fw-text-2); }
.verdict[data-v='clean'] b { color: var(--fw-ok); }

.cat-chips { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
.stat-chip { padding: 3px 11px; border-radius: 999px; font-size: 12px; background: var(--fw-fill); color: var(--fw-text-2); border: 1px solid var(--fw-line); }
.stat-chip.warn b { color: var(--fw-danger); }
.as-stats { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }

.fd-card { border: 1px solid var(--fw-line); border-left: 3px solid var(--fw-text-3); border-radius: 10px; padding: 10px 13px; margin-bottom: 10px; }
.fd-card[data-sev='critical'] { border-left-color: #e11d48; }
.fd-card[data-sev='high'] { border-left-color: #ea580c; }
.fd-card[data-sev='medium'] { border-left-color: #d97706; }
.fd-card[data-sev='low'] { border-left-color: var(--fw-text-3); }
.fd-head { display: flex; align-items: center; gap: 9px; flex-wrap: wrap; }
.fd-sev { flex: none; padding: 0 8px; border-radius: 999px; font-size: 11px; line-height: 18px; font-weight: 600; }
.fd-sev[data-sev='critical'], .fd-sev { color: #e11d48; background: rgba(225, 29, 72, .12); }
.fd-sev[data-sev='high'] { color: #ea580c; background: rgba(234, 88, 12, .12); }
.fd-sev[data-sev='medium'] { color: #d97706; background: rgba(217, 119, 6, .14); }
.fd-sev[data-sev='low'], .fd-sev[data-sev='info'] { color: var(--fw-text-3); background: var(--fw-fill); }
.fd-cat { flex: none; font-size: 11.5px; color: var(--fw-brand); background: color-mix(in srgb, var(--fw-brand) 10%, transparent); padding: 0 8px; border-radius: 4px; line-height: 18px; }
.fd-title { font-size: 13.5px; }
.fd-conf { margin-left: auto; font-size: 11px; }
.fd-target { margin: 6px 0 0; font-size: 11.5px; color: var(--fw-text-3); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.fd-desc { margin: 6px 0 0; font-size: 12.5px; line-height: 1.65; color: var(--fw-text-2); }
.fd-fix { margin: 6px 0 0; font-size: 12.5px; line-height: 1.65; color: var(--fw-text); }
.fd-ev-toggle { margin: 8px 0 0; border: none; background: none; padding: 0; color: var(--fw-brand); font-size: 12px; cursor: pointer; }
.fd-ev { margin: 8px 0 0; padding: 9px 11px; background: var(--fw-surface-2); border: 1px solid var(--fw-line); border-radius: 8px; font-size: 11.5px; line-height: 1.6; color: var(--fw-text-2); max-height: 200px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; }
</style>
