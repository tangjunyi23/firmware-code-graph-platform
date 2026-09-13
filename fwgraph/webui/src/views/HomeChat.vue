<template>
  <div class="home-chat" :class="{ empty: !run && !messages.length }">
    <Transition name="pipe-in">
      <div v-if="run" class="pipe-wrap">
        <div class="pipe">
          <div class="pipe-head">
            <div class="pipe-title">
              <span class="pipe-name">{{ run.firmware || '固件任务' }}</span>
              <el-tag size="small" :type="statusTagType" effect="dark">{{ statusLabel }}</el-tag>
            </div>
            <span v-if="run.status === 'uploading'" class="pipe-pct">{{ run.uploadPct || 0 }}%</span>
            <span v-else-if="run.error" class="pipe-err">{{ run.error }}</span>
            <button type="button" class="icon-btn ghost" title="开启新项目" @click="newSession">
              <el-icon :size="16"><Plus /></el-icon>
              <span>新会话</span>
            </button>
          </div>
          <ol class="pipe-steps" aria-label="分析进度">
            <li
              v-for="(s, i) in PIPE_STEPS"
              :key="s.key"
              class="pipe-step"
              :class="stepState(i)"
            >
              <span class="dot">
                <span v-if="stepState(i) === 'ok'" class="tick">✓</span>
                <span v-else-if="stepState(i) === 'err'" class="tick">!</span>
              </span>
              <span class="lbl">{{ s.label }}</span>
            </li>
          </ol>
        </div>
      </div>
    </Transition>

    <Transition name="pipe-in">
      <div v-if="hunting || huntEvents.length" class="agent-hud-wrap">
        <div class="agent-hud">
          <div class="work-bar">
            <span class="work-dot" :class="{ on: hunting }"></span>
            <span class="work-state" :class="{ shimmer: hunting }">{{ hunting ? '工作中' : '挖掘结束' }}</span>
            <span class="work-meta">1 个智能体 · {{ huntElapsed }}</span>
          </div>
          <div v-if="huntFocus" class="work-focus">{{ huntFocus }}</div>
        </div>
      </div>
    </Transition>

    <div ref="scrollEl" class="chat-scroll">
      <div class="chat-inner">
        <div v-if="!messages.length && !run" class="hero">
          <div class="hero-mark"></div>
          <h1>分析固件，挖掘漏洞</h1>
          <p>上传一份固件，写下你想查的问题。平台会自动解包、建图并启动挖掘。</p>
          <div class="suggestions">
            <button
              v-for="s in SUGGESTS"
              :key="s"
              type="button"
              class="suggest"
              @click="draft = s"
            >{{ s }}</button>
          </div>
        </div>

        <TransitionGroup name="bubble" tag="div">
          <div v-for="m in messages" :key="m.id" class="row" :class="m.role">
            <div class="bubble">
              <div v-if="m.file" class="meta">
                <span class="chip">{{ m.file }}</span>
              </div>
              <div class="text">{{ m.text }}</div>
              <div v-if="m.jobId || m.sessionId" class="follow">
                <el-button
                  v-if="m.sessionId || m.jobId"
                  type="primary"
                  size="small"
                  round
                  @click="openReport(m.jobId, m.file, m.sessionId)"
                >
                  查看漏洞报告
                </el-button>
              </div>
            </div>
          </div>
        </TransitionGroup>

        <div v-if="huntEvents.length" class="dsh-trace">
          <div
            v-for="e in huntEvents"
            :key="e.key"
            class="dsh-card"
            :class="e.type"
            :data-running="e.running ? '1' : '0'"
          >
            <template v-if="e.type === 'thinking'">
              <button type="button" class="dsh-line" @click="e.open = !e.open">
                <span class="dsh-chev">{{ e.open ? '▾' : '▸' }}</span>
                <span class="dsh-title">思考</span>
                <span class="dsh-sep"></span>
                <span class="dsh-sum">{{ thinkSummary(e) }}</span>
              </button>
              <div v-if="e.open" class="dsh-think">{{ e.data.text }}</div>
            </template>
            <template v-else-if="e.type === 'tool_call'">
              <div class="dsh-line">
                <span class="dsh-title">{{ eventLabel(e) }}</span>
                <span class="dsh-sep"></span>
                <span class="dsh-sum">{{ toolFocus(e.data.input || {}) || (e.running ? '进行中' : '完成') }}</span>
              </div>
              <pre v-if="e.result && e.result.preview" class="dsh-body">{{ e.result.preview }}</pre>
            </template>
            <template v-else-if="e.type === 'text'">
              <div class="dsh-md">{{ e.data.text }}<span v-if="e.streaming" class="dsh-caret"></span></div>
            </template>
            <template v-else-if="e.type === 'error'">
              <div class="dsh-err">{{ e.data.message }}</div>
            </template>
          </div>
        </div>
      </div>
    </div>

    <div class="dock">
      <div class="recent">
        <button type="button" class="recent-chip new" title="开启新项目" @click="newSession">
          <el-icon :size="14"><Plus /></el-icon>
          <span class="recent-name">新会话</span>
        </button>
        <button
          v-for="j in recent"
          :key="j.job_id"
          type="button"
          class="recent-chip"
          :class="{ on: run && run.jobId === j.job_id }"
          @click="useJob(j)"
        >
          <span class="recent-name">{{ j.firmware }}</span>
        </button>
      </div>

      <div
        class="composer"
        :class="{ dragover }"
        @dragover.prevent="dragover = true"
        @dragleave="dragover = false"
        @drop.prevent="onDrop"
      >
        <Transition name="attach">
          <div v-if="file" class="attach">
            <el-icon><Document /></el-icon>
            <span class="attach-name">{{ file.name }}</span>
            <span class="muted">{{ fmtSize(file.size) }}</span>
            <button type="button" class="x" aria-label="移除附件" @click="file = null">×</button>
          </div>
        </Transition>
        <textarea
          v-model="draft"
          rows="2"
          :placeholder="placeholder"
          @keydown.enter.exact.prevent="send"
        />
        <div class="bar">
          <input
            ref="fileInput"
            type="file"
            class="hidden"
            accept=".bin,.img,.tar,.gz,.tgz,.zip,.trx,.chk,.fw"
            @change="onPick"
          />
          <button type="button" class="icon-btn" title="上传固件" @click="fileInput.click()">
            <el-icon :size="18"><Upload /></el-icon>
            <span>上传固件</span>
          </button>
          <span class="bar-spacer"></span>
          <button
            type="button"
            class="send-btn"
            :class="{ ready: canSend }"
            :disabled="!canSend || busy"
            title="发送"
            @click="send"
          >
            <el-icon v-if="!busy" :size="18"><Top /></el-icon>
            <span v-else class="spin"></span>
          </button>
        </div>
      </div>
      <p class="hint">将固件拖到输入框，或点击上传。Enter 发送，Shift+Enter 换行。</p>
    </div>

    <el-dialog v-model="reportVisible" :title="reportTitle" :width="isNarrow ? '96%' : '60%'" top="4vh">
      <div v-loading="reportLoading" class="report-body">
        <div v-if="reportHtml" class="md-body" v-html="reportHtml"></div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, getToken, uploadFirmware } from '../api'
import { renderMarkdown } from '../highlight.js'
import { useNarrowViewport } from '../useNarrowViewport'

const emit = defineEmits(['goto'])
const isNarrow = useNarrowViewport()

const STORE_KEY = 'fwgraph_home_run'
const SUGGESTS = ['快速扫描攻击面', '挖命令注入', '深度挖掘内存破坏']
const DEFAULT_TASK = '分析这个固件的攻击面并挖掘漏洞，优先命令注入和内存破坏。'
const PIPE_STEPS = [
  { key: 'decrypt', label: '固件解密' },
  { key: 'extract', label: '解包固件' },
  { key: 'parse', label: '解析文件' },
  { key: 'decompile', label: '反编译' },
  { key: 'graph', label: '代码图谱' },
  { key: 'attack', label: '攻击路径' },
  { key: 'routes', label: '路由识别' },
  { key: 'inputs', label: '输入识别' },
  { key: 'surfaces', label: '攻击面' }
]
const STEP_INDEX = {
  uploading: 0, pending: 0, decrypting: 0,
  extracting: 1,
  parsing: 2,
  decompiling: 3,
  ailifting: 4, graphing: 4,
  attacking: 5,
  routing: 6,
  identifying: 7,
  surfacing: 8, surfaced: 8
}
const RUNNING = new Set([
  'uploading', 'pending', 'decrypting', 'extracting', 'parsing', 'decompiling',
  'graphing', 'attacking', 'routing', 'identifying', 'surfacing'
])
const COMPLETE = new Set(['graphed', 'attacked', 'routed', 'surfaced'])
const STATUS_TEXT = {
  uploading: '正在上传固件', pending: '排队中', decrypting: '正在解密固件',
  extracting: '正在解包',
  parsing: '解析文件系统', decompiling: '反编译中', graphing: '构建图谱',
  attacking: '分析攻击路径', routing: '识别路由', identifying: '识别输入',
  surfacing: '导出攻击面', graphed: '图谱完成', attacked: '攻击路径完成',
  routed: '分析完成', surfaced: '分析完成', failed: '分析失败', done: '解包完成'
}

const placeholder = DEFAULT_TASK
const draft = ref('')
const file = ref(null)
const fileInput = ref(null)
const messages = ref([])
const busy = ref(false)
const dragover = ref(false)
const run = ref(null)
const recent = ref([])
const scrollEl = ref(null)
const huntEvents = ref([])
const hunting = ref(false)
const huntStartedAt = ref(0)
const nowTick = ref(Date.now())
let seq = 0
let pollTimer = null
let huntTimer = null
let huntCtrl = null
let stopped = false

const TOOL_LABEL = {
  fw_get_identification: '盘点外部输入',
  fw_list_surfaces: '列出攻击面',
  fw_get_surface: '读取攻击面',
  fw_attack_surface: '查询攻击路径',
  fw_get_manifest: '读取固件清单',
  fw_get_function_source: '读取伪代码',
  fw_routes: '查询路由',
  fw_trace_flow: '读取覆盖率轨迹',
  fw_call_trace: '追踪调用链',
  fw_get_cfg: '读取控制流图',
  fw_get_ast: '读取语法树',
  fw_compose_evidence: '拼接证据',
  record_finding: '记录漏洞',
  finish: '结束挖掘'
}

const canSend = computed(() => !busy.value && (!!file.value || !!(run.value && run.value.jobId)))
const pipeIndex = computed(() => {
  const status = run.value?.status || 'pending'
  if (status === 'failed') return STEP_INDEX[run.value?.lastOkStatus] ?? 0
  if (COMPLETE.has(status)) return PIPE_STEPS.length
  return STEP_INDEX[status] ?? 0
})
const statusLabel = computed(() => {
  const r = run.value
  if (!r) return ''
  if (r.status === 'uploading') return `上传 ${r.uploadPct || 0}%`
  return STATUS_TEXT[r.status] || r.status
})
const statusTagType = computed(() => {
  const s = run.value?.status
  if (s === 'failed') return 'danger'
  if (COMPLETE.has(s)) return 'success'
  return 'warning'
})
const huntElapsed = computed(() => {
  if (!huntStartedAt.value) return '0秒'
  const sec = Math.max(0, Math.floor((nowTick.value - huntStartedAt.value) / 1000))
  const m = Math.floor(sec / 60)
  const s = sec % 60
  if (m <= 0) return `${s}秒`
  return `${m}分${s.toString().padStart(2, '0')}秒`
})
const huntFocus = computed(() => {
  for (let i = huntEvents.value.length - 1; i >= 0; i--) {
    const e = huntEvents.value[i]
    if (e.type === 'tool_call') {
      const name = TOOL_LABEL[e.data.name] || e.data.name || '工具调用'
      const focus = toolFocus(e.data.input || {})
      return focus ? `${name}  ${focus}` : name
    }
    if (e.type === 'thinking' && e.data.text) {
      return `思考  ${String(e.data.text).replace(/\s+/g, ' ').slice(0, 80)}`
    }
  }
  return hunting.value ? '智能体正在分析攻击面…' : ''
})

function stepState (i) {
  const r = run.value
  if (!r) return 'wait'
  if (r.status === 'failed' && i === pipeIndex.value) return 'err'
  if (COMPLETE.has(r.status) || i < pipeIndex.value) return 'ok'
  if (i === pipeIndex.value) return 'now'
  return 'wait'
}

function toolFocus (input) {
  if (!input || typeof input !== 'object') return ''
  if (input.path) return input.path
  if (input.binary_path && input.addr) return `${input.binary_path} ${input.addr}`
  if (input.addr) return String(input.addr)
  if (input.route) return input.route
  if (input.title) return input.title
  if (input.md5) return String(input.md5)
  return ''
}

function eventLabel (e) {
  if (e.type === 'tool_call') return TOOL_LABEL[e.data.name] || `调用 ${e.data.name || ''}`
  if (e.type === 'tool_result') return `结果 ${TOOL_LABEL[e.data.name] || e.data.name || ''}`
  const map = {
    session_start: '会话开始', session_end: '会话结束', thinking: '思考',
    text: '输出', model_usage: '用量', error: '错误'
  }
  return map[e.type] || e.type
}

function thinkSummary (e) {
  const t = String(e?.data?.text || '').replace(/\s+/g, ' ').trim()
  if (!t) return e.running ? '正在推理…' : '思考完成'
  return t.slice(0, 72)
}

function fmtSize (n) {
  if (n == null) return ''
  if (n > 1048576) return (n / 1048576).toFixed(1) + ' MB'
  if (n > 1024) return (n / 1024).toFixed(1) + ' KB'
  return n + ' B'
}

function persist () {
  const payload = {
    run: run.value,
    messages: messages.value,
    seq
  }
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(payload))
  } catch { /* quota */ }
}

function restore () {
  try {
    const raw = localStorage.getItem(STORE_KEY)
    if (!raw) return
    const data = JSON.parse(raw)
    if (data.messages) messages.value = data.messages
    if (typeof data.seq === 'number') seq = data.seq
    if (data.run) run.value = data.run
  } catch { /* ignore */ }
}

watch([run, messages], persist, { deep: true })

function onPick (e) {
  const picked = e.target.files && e.target.files[0]
  if (picked) file.value = picked
  e.target.value = ''
}

function onDrop (e) {
  dragover.value = false
  const dropped = e.dataTransfer?.files?.[0]
  if (dropped) file.value = dropped
}

async function newSession () {
  if (run.value || messages.value.length || file.value) {
    try {
      await ElMessageBox.confirm(
        '将清空当前工作台对话并开始新项目。已有分析任务仍保留在近期列表，不会从服务器删除。',
        '开启新会话',
        { confirmButtonText: '开启', cancelButtonText: '取消', type: 'info' }
      )
    } catch {
      return
    }
  }
  stopPoll()
  stopHuntStream()
  hunting.value = false
  huntEvents.value = []
  huntStartedAt.value = 0
  run.value = null
  messages.value = []
  file.value = null
  draft.value = ''
  busy.value = false
  seq = 0
  try { localStorage.removeItem(STORE_KEY) } catch { /* ignore */ }
  ElMessage.success('已开启新会话，上传固件即可开始新项目')
}

function useJob (job) {
  run.value = {
    jobId: job.job_id,
    firmware: job.firmware,
    status: job.status,
    task: draft.value.trim() || DEFAULT_TASK,
    sessionId: run.value?.jobId === job.job_id ? run.value.sessionId : null,
    error: job.error || null
  }
  if (RUNNING.has(job.status) || job.status === 'done' || job.status === 'decompiled') {
    startPoll(job.job_id)
  }
}

async function loadRecent () {
  try {
    recent.value = ((await api('/jobs')) || []).slice(0, 8)
  } catch { /* ignore */ }
}

function push (msg) {
  seq += 1
  const row = { id: seq, ...msg }
  messages.value.push(row)
  nextTick(scrollBottom)
  return row
}

function scrollBottom () {
  const el = scrollEl.value
  if (el) el.scrollTop = el.scrollHeight
}

function sleep (ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function pipelineFinished (job) {
  if (!job) return false
  if (job.status === 'failed') return true
  if (RUNNING.has(job.status)) return false
  if (job.status === 'done' || job.status === 'decompiled' || job.status === 'ailifted') {
    return false
  }
  return COMPLETE.has(job.status)
}

function applyJob (job) {
  if (!run.value) {
    run.value = { jobId: job.job_id, firmware: job.firmware, status: job.status }
  }
  if (job.status !== 'failed') run.value.lastOkStatus = job.status
  run.value.jobId = job.job_id
  run.value.firmware = job.firmware || run.value.firmware
  run.value.status = job.status
  run.value.error = job.error || null
}

function stopPoll () {
  if (pollTimer) {
    clearTimeout(pollTimer)
    pollTimer = null
  }
}

function stopHuntStream () {
  if (huntCtrl) {
    huntCtrl.abort()
    huntCtrl = null
  }
  if (huntTimer) {
    clearInterval(huntTimer)
    huntTimer = null
  }
}

function handleRawEvent (raw) {
  let type = 'message'
  const dataLines = []
  for (const line of raw.split('\n')) {
    if (line.startsWith('event: ')) type = line.slice(7).trim()
    else if (line.startsWith('data: ')) dataLines.push(line.slice(6))
  }
  if (!dataLines.length) return
  let data = {}
  try { data = JSON.parse(dataLines.join('\n')) } catch { return }
  if (type === 'session_start' || type === 'model_usage') return
  if ((type === 'thinking' || type === 'text') && data.block != null) {
    const i = huntEvents.value.findIndex(
      (e) => e.type === type && e.data.block === data.block)
    if (i >= 0) {
      const prev = huntEvents.value[i]
      huntEvents.value[i] = {
        ...prev,
        data,
        streaming: !!data.stream,
        running: !!data.stream,
        open: type === 'thinking' ? (data.stream ? true : prev.open) : prev.open
      }
      nextTick(scrollBottom)
      return
    }
  }
  if (type === 'tool_result' && data.id) {
    const i = huntEvents.value.findIndex(
      (e) => e.type === 'tool_call' && e.data.id === data.id)
    if (i >= 0) {
      huntEvents.value[i].result = data
      huntEvents.value[i].running = false
      nextTick(scrollBottom)
      return
    }
  }
  huntEvents.value.push({
    key: `${type}-${data.seq || huntEvents.value.length}-${data.ts || Date.now()}`,
    type,
    data,
    streaming: !!data.stream,
    running: type === 'tool_call' || (type === 'thinking' && data.stream !== false),
    open: type === 'thinking',
    result: null
  })
  if (huntEvents.value.length > 400) huntEvents.value.splice(0, 80)
  if (type === 'session_end' || type === 'error') hunting.value = false
  nextTick(scrollBottom)
}

async function startHuntStream (sid) {
  if (!sid) return
  stopHuntStream()
  hunting.value = true
  if (!huntStartedAt.value) huntStartedAt.value = Date.now()
  huntTimer = setInterval(() => { nowTick.value = Date.now() }, 1000)
  const ctrl = new AbortController()
  huntCtrl = ctrl
  try {
    const resp = await fetch(`/vulnagent/sessions/${sid}/events?follow=1`, {
      headers: { Authorization: `Bearer ${getToken()}` },
      signal: ctrl.signal
    })
    if (!resp.ok || !resp.body) {
      hunting.value = false
      return
    }
    const reader = resp.body.getReader()
    const dec = new TextDecoder()
    let buf = ''
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      buf += dec.decode(value, { stream: true })
      let idx
      while ((idx = buf.indexOf('\n\n')) >= 0) {
        handleRawEvent(buf.slice(0, idx))
        buf = buf.slice(idx + 2)
      }
    }
  } catch (e) {
    if (e.name !== 'AbortError') {
      huntEvents.value.push({
        key: `err-${Date.now()}`,
        type: 'error',
        data: { message: `挖掘中断：${e.message}` }
      })
    }
  } finally {
    if (huntCtrl === ctrl) {
      hunting.value = false
      busy.value = false
    }
  }
}

function startPoll (jobId) {
  stopPoll()
  busy.value = true
  const tick = async () => {
    if (stopped) return
    try {
      const job = await api(`/jobs/${jobId}`)
      applyJob(job)
      if (job.status === 'failed') {
        busy.value = false
        push({ role: 'assistant', text: `分析失败：${job.error || '未知错误'}`, jobId })
        return
      }
      if (pipelineFinished(job)) {
        busy.value = false
        await onPipelineDone(job)
        return
      }
    } catch (e) {
      if (run.value) run.value.error = e.message
    }
    pollTimer = setTimeout(tick, 2000)
  }
  tick()
}

async function onPipelineDone (job) {
  const jobId = job.job_id
  const firmware = job.firmware || run.value?.firmware
  if (run.value?.sessionId) {
    push({
      role: 'assistant',
      text: `分析完成（${firmware}）。`,
      jobId,
      sessionId: run.value.sessionId,
      file: firmware
    })
    await loadRecent()
    return
  }
  const bubble = push({
    role: 'assistant',
    text: `分析完成（${firmware}）。正在启动漏洞挖掘…`,
    jobId,
    file: firmware
  })
  try {
    const sess = await api('/vulnagent/sessions', {
      method: 'POST',
      body: {
        task: (run.value && run.value.task) || DEFAULT_TASK,
        job_id: jobId,
        mode: 'static',
        max_turns: 32
      }
    })
    if (run.value) run.value.sessionId = sess.session_id
    bubble.sessionId = sess.session_id
    bubble.text = '分析完成，漏洞挖掘已在工作台启动。下方会实时显示思考、工具调用与输出。'
    busy.value = true
    startHuntStream(sess.session_id)
  } catch (e) {
    bubble.text = `分析完成，挖掘未启动：${e.message}`
    busy.value = false
  }
  await loadRecent()
}

async function send () {
  if (busy.value) return
  const text = draft.value.trim() || DEFAULT_TASK
  const attached = file.value
  const existingId = run.value?.jobId
  if (!attached && !existingId) {
    ElMessage.warning('请先上传固件，或点选上方一个已有任务')
    return
  }
  draft.value = ''
  file.value = null
  busy.value = true
  push({
    role: 'user',
    text,
    file: attached ? attached.name : run.value?.firmware
  })
  if (attached) {
    run.value = {
      jobId: null,
      firmware: attached.name,
      task: text,
      status: 'uploading',
      uploadPct: 0,
      sessionId: null,
      error: null
    }
    try {
      const r = await uploadFirmware(attached, {
        auto: true,
        onProgress (loaded, total) {
          if (run.value && run.value.status === 'uploading') {
            run.value.uploadPct = Math.round((loaded / total) * 100)
          }
        }
      })
      run.value.jobId = r.job_id
      run.value.status = r.status || 'pending'
      run.value.uploadPct = 100
      push({ role: 'assistant', text: '固件已上传，开始分析。流水线日志在「事件流」，挖掘过程会显示在本页。', jobId: r.job_id })
      try { localStorage.setItem('fwgraph_events_job', r.job_id) } catch { /* ignore */ }
      startPoll(r.job_id)
    } catch (e) {
      if (run.value) {
        run.value.status = 'failed'
        run.value.error = e.message
      }
      busy.value = false
      push({ role: 'assistant', text: '上传失败：' + e.message })
      ElMessage.error('上传失败: ' + e.message)
    }
    return
  }
  run.value.task = text
  try { localStorage.setItem('fwgraph_events_job', existingId) } catch { /* ignore */ }
  startPoll(existingId)
}

const reportVisible = ref(false)
const reportLoading = ref(false)
const reportTitle = ref('')
const reportHtml = ref('')

async function openReport (jobId, name, sessionId) {
  reportTitle.value = `${name || jobId} 漏洞分析报告`
  reportVisible.value = true
  reportLoading.value = true
  reportHtml.value = ''
  const sid = sessionId || run.value?.sessionId
  try {
    let md = ''
    if (sid) {
      try {
        md = await api(`/vulnagent/sessions/${sid}/report`)
      } catch (e) {
        if (e.status !== 404) throw e
      }
    }
    if (!md && jobId) {
      try {
        md = await api(`/jobs/${jobId}/report`)
      } catch (e) {
        if (e.status !== 404) throw e
        await api(`/jobs/${jobId}/report`, { method: 'POST' })
        md = await api(`/jobs/${jobId}/report`)
      }
    }
    if (!md) throw new Error('还没有生成报告（挖掘结束后才会写出 PoC 与调用链）')
    reportHtml.value = renderMarkdown(String(md))
  } catch (e) {
    reportVisible.value = false
    ElMessage.error('报告获取失败: ' + e.message)
  } finally {
    reportLoading.value = false
  }
}

onMounted(async () => {
  restore()
  await loadRecent()
  const jobId = run.value?.jobId
  if (!jobId) {
    if (run.value?.status === 'uploading') {
      run.value.status = 'failed'
      run.value.error = '刷新时上传尚未完成，请重新发送'
      busy.value = false
    }
    return
  }
  try {
    const job = await api(`/jobs/${jobId}`)
    applyJob(job)
    if (job.status === 'failed') {
      busy.value = false
      return
    }
    if (!pipelineFinished(job)) startPoll(jobId)
    else if (run.value?.sessionId) {
      busy.value = true
      startHuntStream(run.value.sessionId)
    } else busy.value = false
  } catch {
    /* job missing; keep restored transcript */
  }
})
onUnmounted(() => {
  stopped = true
  stopPoll()
  stopHuntStream()
})
</script>

<style scoped>
.home-chat {
  height: 100%;
  min-height: calc(100vh - 56px);
  display: flex;
  flex-direction: column;
}
.home-chat.empty {
  justify-content: center;
  padding-bottom: 14vh;
}
.home-chat.empty .chat-scroll {
  flex: 0 0 auto;
  overflow: visible;
}
.chat-scroll {
  flex: 1;
  min-height: 0;
  overflow: auto;
  padding: 12px 16px 8px;
}
.chat-inner { max-width: 740px; margin: 0 auto; }

.pipe-wrap {
  flex: none;
  padding: 14px 16px 0;
}
.pipe {
  max-width: 960px;
  margin: 0 auto;
  background: var(--fw-surface);
  border: 1px solid var(--fw-line);
  border-radius: 16px;
  padding: 14px 16px 10px;
  box-shadow: 0 8px 24px rgba(16, 42, 67, .06);
}
.pipe-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}
.pipe-title { display: flex; align-items: center; gap: 10px; min-width: 0; }
.pipe-name {
  font-weight: 650;
  color: var(--fw-text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.pipe-pct { font-variant-numeric: tabular-nums; color: var(--fw-brand); font-weight: 650; }
.pipe-err { color: #dc2626; font-size: 13px; }
.pipe-steps {
  list-style: none;
  display: flex;
  margin: 0;
  padding: 6px 0 2px;
  overflow-x: auto;
}
.pipe-step {
  position: relative;
  flex: 1;
  min-width: 72px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  color: var(--fw-text-3);
}
.pipe-step:not(:last-child)::after {
  content: '';
  position: absolute;
  top: 9px;
  left: calc(50% + 12px);
  right: calc(-50% + 12px);
  height: 2px;
  background: var(--fw-line);
  transition: background .3s ease;
}
.pipe-step.ok:not(:last-child)::after,
.pipe-step.now:not(:last-child)::after { background: var(--fw-brand); }
.pipe-step.err:not(:last-child)::after { background: #f5c6c6; }
.dot {
  width: 18px; height: 18px; border-radius: 50%;
  background: var(--fw-bg-2); border: 2px solid var(--fw-line);
  display: flex; align-items: center; justify-content: center;
  z-index: 1;
  transition: transform .25s ease, background .25s ease, border-color .25s ease, box-shadow .25s ease;
}
.tick { font-size: 11px; font-weight: 800; color: var(--fw-surface); line-height: 1; }
.lbl { font-size: 12px; text-align: center; line-height: 1.3; }
.pipe-step.ok .dot { background: #16a34a; border-color: #16a34a; }
.pipe-step.ok .lbl { color: #16a34a; }
.pipe-step.now .dot {
  background: var(--fw-brand); border-color: var(--fw-brand);
  box-shadow: 0 0 0 6px color-mix(in srgb, var(--fw-brand) 16%, transparent);
  animation: pulse-now 1.4s ease-in-out infinite;
}
.pipe-step.now .lbl { color: var(--fw-brand); font-weight: 650; }
.pipe-step.err .dot { background: #dc2626; border-color: #dc2626; }
.pipe-step.err .lbl { color: #dc2626; }
@keyframes pulse-now {
  0%, 100% { box-shadow: 0 0 0 4px color-mix(in srgb, var(--fw-brand) 16%, transparent); }
  50% { box-shadow: 0 0 0 8px color-mix(in srgb, var(--fw-brand) 08%, transparent); }
}
.pipe-in-enter-active { transition: opacity .35s ease, transform .35s ease; }
.pipe-in-enter-from { opacity: 0; transform: translateY(-8px); }

.hero { text-align: center; padding: 4px 8px 28px; }
.hero-mark {
  width: 16px; height: 16px; border-radius: 50%; margin: 0 auto 20px;
  background: radial-gradient(circle at 35% 35%, #7aa4f0, var(--fw-brand));
  box-shadow: 0 0 0 8px color-mix(in srgb, var(--fw-brand) 08%, transparent);
  animation: pulse-dot 2.4s ease-in-out infinite;
}
@keyframes pulse-dot {
  0%, 100% { box-shadow: 0 0 0 8px color-mix(in srgb, var(--fw-brand) 08%, transparent); }
  50% { box-shadow: 0 0 0 14px color-mix(in srgb, var(--fw-brand) 04%, transparent); }
}
.hero h1 {
  margin: 0;
  font-size: 30px;
  letter-spacing: 1.5px;
  color: var(--fw-text);
  font-weight: 650;
}
.hero p {
  margin: 12px auto 0;
  max-width: 28em;
  color: var(--fw-text-3);
  font-size: 14.5px;
  line-height: 1.65;
}
.suggestions {
  display: flex; flex-wrap: wrap; gap: 10px; justify-content: center;
  margin-top: 22px;
}
.suggest {
  border: 1px solid var(--fw-line);
  background: var(--fw-surface);
  color: var(--fw-text-2);
  border-radius: 999px;
  padding: 8px 14px;
  cursor: pointer;
  font-size: 13px;
  transition: transform .18s ease, box-shadow .18s ease, border-color .18s ease, color .18s ease, background .18s ease;
}
.suggest:hover {
  border-color: var(--fw-brand);
  color: var(--fw-brand);
  background: var(--fw-surface-2);
  transform: translateY(-2px);
  box-shadow: 0 6px 16px color-mix(in srgb, var(--fw-brand) 12%, transparent);
}
.suggest:active { transform: scale(.96); }

.row { display: flex; margin: 12px 0; }
.row.user { justify-content: flex-end; }
.row.assistant { justify-content: flex-start; }
.bubble {
  max-width: min(100%, 620px);
  padding: 12px 16px;
  border-radius: 16px;
  line-height: 1.58;
  font-size: 14.5px;
  color: var(--fw-text);
  white-space: pre-wrap;
  word-break: break-word;
}
.row.user .bubble {
  background: linear-gradient(180deg, #3b7aee, var(--fw-brand));
  color: var(--fw-surface);
  border-bottom-right-radius: 6px;
  box-shadow: 0 6px 16px color-mix(in srgb, var(--fw-brand) 22%, transparent);
}
.row.assistant .bubble {
  background: var(--fw-surface);
  border: 1px solid var(--fw-line);
  box-shadow: 0 4px 18px rgba(16, 42, 67, .06);
  border-bottom-left-radius: 6px;
}
.meta { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 8px; }
.chip {
  font-size: 11px; padding: 2px 8px; border-radius: 999px;
  background: rgba(255,255,255,.2); border: 1px solid rgba(255,255,255,.35);
}
.row.assistant .chip { background: var(--fw-fill); border-color: var(--fw-line); color: var(--fw-text-2); }
.follow { margin-top: 12px; display: flex; gap: 8px; flex-wrap: wrap; }

.bubble-enter-active {
  transition: opacity .38s cubic-bezier(.22, 1, .36, 1),
              transform .38s cubic-bezier(.22, 1, .36, 1);
}
.bubble-enter-from { opacity: 0; transform: translateY(12px) scale(.98); }
.bubble-move { transition: transform .3s ease; }

.dock { padding: 4px 16px 10vh; }
.home-chat.empty .dock { padding-bottom: 0; }
.recent {
  max-width: 740px; margin: 0 auto 10px;
  display: flex; gap: 8px; overflow-x: auto; padding-bottom: 4px;
}
.recent-chip {
  flex: none; display: inline-flex; align-items: center; gap: 8px;
  border: 1px solid var(--fw-line); background: var(--fw-surface); border-radius: 999px;
  padding: 6px 12px; cursor: pointer; color: var(--fw-text-2); font-size: 12px;
  transition: transform .18s ease, border-color .18s ease, color .18s ease, box-shadow .18s ease;
}
.recent-chip:hover {
  border-color: var(--fw-brand); color: var(--fw-brand);
  transform: translateY(-1px);
  box-shadow: 0 4px 12px color-mix(in srgb, var(--fw-brand) 1%, transparent);
}
.recent-chip:active { transform: scale(.96); }
.recent-chip.on {
  border-color: var(--fw-brand); color: var(--fw-brand); background: var(--fw-fill);
}
.recent-chip.new {
  border-style: dashed; color: var(--fw-brand);
}
.recent-name { max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.composer {
  max-width: 740px; margin: 0 auto;
  background: var(--fw-surface);
  border: 1px solid var(--fw-line);
  border-radius: 20px;
  box-shadow: 0 10px 32px rgba(16, 42, 67, .08);
  padding: 12px 14px 10px;
  transition: box-shadow .25s ease, border-color .25s ease, transform .25s ease;
}
.composer:focus-within {
  border-color: #a3c2f0;
  box-shadow: 0 14px 40px color-mix(in srgb, var(--fw-brand) 14%, transparent);
}
.composer.dragover {
  border-color: var(--fw-brand);
  transform: translateY(-3px);
  box-shadow: 0 16px 36px color-mix(in srgb, var(--fw-brand) 16%, transparent);
}
.attach {
  display: flex; align-items: center; gap: 8px;
  background: var(--fw-fill); border-radius: 10px; padding: 8px 10px; margin-bottom: 8px;
  font-size: 13px; color: var(--fw-text);
}
.attach-enter-active, .attach-leave-active { transition: opacity .2s ease, transform .2s ease; }
.attach-enter-from, .attach-leave-to { opacity: 0; transform: translateY(-6px); }
.attach-name { font-weight: 600; overflow: hidden; text-overflow: ellipsis; }
.x {
  margin-left: auto; border: 0; background: transparent; cursor: pointer;
  color: var(--fw-text-3); font-size: 18px; line-height: 1;
  width: 24px; height: 24px; border-radius: 50%;
  transition: background .15s ease, color .15s ease, transform .15s ease;
}
.x:hover { background: color-mix(in srgb, var(--fw-brand) 1%, transparent); color: var(--fw-text); }
.x:active { transform: scale(.9); }
.composer textarea {
  width: 100%; border: 0; resize: none; outline: none;
  font: inherit; color: var(--fw-text); background: transparent;
  min-height: 56px; max-height: 160px;
}
.bar {
  display: flex; align-items: center; gap: 8px;
  padding-top: 8px;
}
.bar-spacer { flex: 1; }
.icon-btn {
  display: inline-flex; align-items: center; gap: 6px;
  border: 1px solid var(--fw-line); background: var(--fw-surface); color: var(--fw-text-2);
  border-radius: 999px; padding: 7px 14px; cursor: pointer; font-size: 13px;
  transition: transform .18s ease, box-shadow .18s ease, border-color .18s ease, color .18s ease, background .18s ease;
}
.icon-btn:hover {
  border-color: var(--fw-brand); color: var(--fw-brand); background: var(--fw-surface-2);
  transform: translateY(-1px);
  box-shadow: 0 4px 12px color-mix(in srgb, var(--fw-brand) 1%, transparent);
}
.icon-btn:active { transform: scale(.96); }
.pipe-head .icon-btn.ghost { margin-left: 8px; flex: none; }
.send-btn {
  width: 38px; height: 38px; border: 0; border-radius: 50%;
  display: inline-flex; align-items: center; justify-content: center;
  background: var(--fw-line); color: var(--fw-surface); cursor: not-allowed;
  transition: transform .18s ease, background .2s ease, box-shadow .2s ease;
}
.send-btn.ready {
  background: var(--fw-brand); cursor: pointer;
  box-shadow: 0 4px 14px color-mix(in srgb, var(--fw-brand) 28%, transparent);
}
.send-btn.ready:hover { background: #2559c7; transform: translateY(-1px) scale(1.04); }
.send-btn.ready:active { transform: scale(.92); }
.send-btn:disabled:not(.ready) { opacity: .7; }
.spin {
  width: 16px; height: 16px; border: 2px solid rgba(255,255,255,.35);
  border-top-color: var(--fw-surface); border-radius: 50%;
  animation: spin .7s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
.hint {
  max-width: 740px; margin: 10px auto 0;
  text-align: center; color: var(--fw-text-3); font-size: 12px;
}
.hidden { display: none; }
.muted { color: var(--fw-text-3); font-size: 12px; }
.report-body { min-height: 200px; max-height: 72vh; overflow: auto; }

.agent-hud-wrap {
  flex: none;
  padding: 10px 16px 0;
}
.agent-hud {
  max-width: 960px;
  margin: 0 auto;
  background: #0f172a;
  color: #e2e8f0;
  border-radius: 14px;
  padding: 12px 16px 10px;
  box-shadow: 0 10px 28px rgba(15, 23, 42, .28);
}
.work-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 13px;
}
.work-dot {
  width: 9px; height: 9px; border-radius: 50%;
  background: #64748b;
}
.work-dot.on {
  background: #2ee6a6;
  box-shadow: 0 0 0 0 rgba(46, 230, 166, .55);
  animation: work-pulse 1.2s ease-in-out infinite;
}
@keyframes work-pulse {
  0% { box-shadow: 0 0 0 0 rgba(46, 230, 166, .5); opacity: 1; }
  70% { box-shadow: 0 0 0 10px rgba(46, 230, 166, 0); opacity: .85; }
  100% { box-shadow: 0 0 0 0 rgba(46, 230, 166, 0); opacity: 1; }
}
.work-state { font-weight: 700; letter-spacing: .04em; }
.work-state.shimmer {
  background: linear-gradient(90deg, #e2e8f0 0%, #e2e8f0 40%, #7dd3c7 50%, #e2e8f0 60%, #e2e8f0 100%);
  background-size: 250% 100%;
  background-position: 100% 0;
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
  -webkit-text-fill-color: transparent;
  animation: dsh-turn-status-shimmer 1.8s linear infinite;
}
@keyframes dsh-turn-status-shimmer { to { background-position: 0 0; } }
.work-meta { margin-left: auto; color: #94a3b8; font-variant-numeric: tabular-nums; }
.work-focus {
  margin-top: 8px;
  font-family: ui-monospace, Consolas, monospace;
  font-size: 12px;
  color: #7dd3c7;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.dsh-trace { margin: 16px 0 8px; display: flex; flex-direction: column; gap: 4px; }
.dsh-card { position: relative; overflow: hidden; padding: 4px 2px; }
.dsh-card[data-running='1']::after {
  content: '';
  position: absolute;
  inset-block: 0;
  left: 0;
  width: 280px;
  background: linear-gradient(90deg, transparent 0%, rgba(255,255,255,.65) 55%, transparent 100%);
  animation: dsh-row-sweep 2.6s ease-out infinite;
  pointer-events: none;
}
@keyframes dsh-row-sweep {
  0% { left: -280px; }
  90%, 100% { left: 100%; }
}
.dsh-line {
  display: flex;
  align-items: center;
  width: 100%;
  min-width: 0;
  gap: 0;
  padding: 2px 0;
  border: 0;
  background: none;
  font: inherit;
  color: inherit;
  text-align: left;
  cursor: default;
}
button.dsh-line { cursor: pointer; }
.dsh-chev { width: 16px; color: #94a3b8; font-size: 11px; flex: none; }
.dsh-title { font-size: 14px; line-height: 24px; color: var(--fw-text); flex: none; }
.dsh-sep {
  width: 2px; height: 2px; border-radius: 1px; margin: 0 8px;
  background: #94a3b8; flex: none;
}
.dsh-sum {
  min-width: 0; flex: 1;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  color: var(--fw-text-3); font-size: 14px; line-height: 24px;
}
.dsh-think {
  padding: 4px 0 8px 22px;
  color: var(--fw-text-3);
  font-size: 14px;
  line-height: 24px;
  white-space: pre-wrap;
  word-break: break-word;
}
.dsh-md {
  font-size: 15px;
  line-height: 24px;
  color: var(--fw-text);
  white-space: pre-wrap;
  word-break: break-word;
  padding: 6px 0;
}
.dsh-caret {
  display: inline-block; width: 7px; height: 1em; margin-left: 2px;
  background: var(--fw-brand); vertical-align: -2px;
  animation: dsh-caret 1s step-end infinite;
}
@keyframes dsh-caret { 50% { opacity: 0; } }
.dsh-body {
  margin: 4px 0 8px 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 12px;
  line-height: 1.5;
  color: #475569;
  max-height: 180px;
  overflow: auto;
}
.dsh-err { color: #b91c1c; font-size: 13px; padding: 6px 0; }
@media (prefers-reduced-motion: reduce) {
  .work-state.shimmer { animation: none; color: #e2e8f0; -webkit-text-fill-color: #e2e8f0; }
  .dsh-card[data-running='1']::after, .dsh-caret { animation: none; }
}

@media (max-width: 720px) {
  .hero h1 { font-size: 22px; }
  .home-chat.empty { padding-bottom: 8vh; }
  .dock { padding-bottom: 8vh; }
  .icon-btn span { display: none; }
  .pipe-step { min-width: 64px; }
  .lbl { font-size: 11px; }
}
</style>
