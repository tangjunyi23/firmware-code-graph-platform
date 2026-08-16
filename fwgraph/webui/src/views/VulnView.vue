<template>
  <div>
    <!-- launch card -->
    <el-card class="card" shadow="never">
      <template #header>
        <div class="row-between">
          <span class="card-title">漏洞挖掘 Agent</span>
          <span v-if="agent.agent" class="muted">
            {{ agent.agent.id }} · {{ agent.agent.model && agent.agent.model.name }} ·
            {{ (agent.agent.tools || []).length }} 工具 · 并发上限 {{ agent.max_parallel }}
          </span>
        </div>
      </template>
      <el-input v-model="task" type="textarea" :rows="3"
        placeholder="给漏洞挖掘 agent 的任务描述" />
      <div class="launch-row">
        <span class="muted">最大轮次</span>
        <el-input-number v-model="maxTurns" :min="1" :max="100" size="small" />
        <span class="mode-switch">
          <button class="mode-btn" :class="{ on: mode === 'static' }" @click="mode = 'static'">纯静态挖掘</button>
          <button class="mode-btn" :class="{ on: mode === 'dynamic' }" @click="mode = 'dynamic'">动静结合挖掘</button>
        </span>
        <el-button type="primary" :loading="launching" @click="launch">启动挖掘</el-button>
        <span class="muted">事件流实时展示 thinking / 工具调用 / 结果 / token 用量</span>
      </div>
    </el-card>

    <div class="cols">
      <!-- session list -->
      <el-card class="card col-sessions" shadow="never">
        <template #header>
          <div class="row-between">
            <span class="card-title">会话</span>
            <el-button size="small" text @click="loadSessions">刷新</el-button>
          </div>
        </template>
        <div v-for="s in sessions" :key="s.session_id" class="sess-item"
          :class="{ active: s.session_id === currentId }" @click="select(s)">
            <span v-if="s.mode" class="mode-tag" :class="s.mode">{{ s.mode === 'static' ? '静态' : '动静' }}</span>
          <div class="sess-head">
            <span class="mono sid">{{ s.session_id }}</span>
            <span>
              <el-tag v-if="reviewStatus(s.status)" size="small" effect="plain"
                :type="reviewStatus(s.status).type" class="review-tag">{{ reviewStatus(s.status).label }}</el-tag>
              <el-tag size="small" :type="statusType(s.status)">{{ statusLabel(s.status) }}</el-tag>
            </span>
          </div>
          <div class="muted sess-task">{{ s.task }}</div>
          <div class="muted">轮次 {{ s.turns }} · findings {{ (s.findings || []).length }} · {{ fmtTime(s.created_at) }}</div>
        </div>
        <el-empty v-if="!sessions.length" description="暂无会话" :image-size="60" />
      </el-card>

      <!-- event stream -->
      <el-card class="card col-events" shadow="never">
        <template #header>
          <div class="row-between">
            <span class="card-title">事件流
              <span v-if="currentId" class="mono muted">{{ currentId }}</span>
              <span v-if="currentRunning && currentId" class="live-badge"><i class="live-dot"></i>LIVE</span>
            </span>
            <div v-if="currentId">
              <el-button size="small" @click="showReport">报告</el-button>
              <el-button v-if="currentRunning" size="small" type="danger"
                :loading="stopping" @click="stop">停止</el-button>
            </div>
          </div>
        </template>
        <div class="ev-toolbar">
          <el-radio-group v-model="evFilter" size="small">
            <el-radio-button value="all">全部</el-radio-button>
            <el-radio-button value="thinking">思考</el-radio-button>
            <el-radio-button value="text">回复</el-radio-button>
            <el-radio-button value="tools">工具</el-radio-button>
            <el-radio-button value="usage">用量</el-radio-button>
            <el-radio-button value="error">错误</el-radio-button>
          </el-radio-group>
          <div class="ev-toolbar-right">
            <span class="muted">{{ shownEvents.length }} 条</span>
            <el-checkbox v-model="autoScroll" size="small">自动滚动</el-checkbox>
            <el-button size="small" text @click="clearEvents">清空</el-button>
          </div>
        </div>
        <div ref="eventPane" class="events">
          <!-- sticky live usage meter -->
          <div v-if="hasUsage" class="usage-strip">
            <Coins :size="13" class="usage-icon" />
            <span>tokens <b class="usage-num">{{ usageIn }}</b> in / <b class="usage-num">{{ usageOut }}</b> out</span>
            <span class="muted">累计</span>
          </div>
          <template v-for="e in shownEvents" :key="e.key ?? e.data.seq ?? e.type">
            <!-- session lifecycle markers -->
            <div v-if="isMarker(e.type)" class="ev-marker">
              <Play v-if="e.type === 'session_start'" :size="13" />
              <CircleCheck v-else-if="e.type === 'session_end'" :size="13" />
              <Flag v-else :size="13" />
              <span class="ev-marker-text">{{ markerText(e) }}</span>
              <time>{{ fmtClock(e.data.ts) }}</time>
            </div>

            <!-- thinking (streaming blocks update one card in place) -->
            <div v-else-if="e.type === 'thinking'" class="ev-card ev-thinking"
              :class="{ 'is-live': isStreaming(e) }">
              <div class="ev-head" :class="{ clickable: thinkingCollapsible(e) }" @click="toggleExpand(e)">
                <Brain :size="14" class="ev-icon" />
                <span class="ev-label">思考链</span>
                <i v-if="isStreaming(e)" class="live-dot"></i>
                <span class="ev-count muted">{{ (e.data.text || '').length }} 字</span>
                <span v-if="!thinkingBodyVisible(e)" class="ev-preview">{{ preview(e.data.text) }}</span>
                <time>{{ fmtClock(e.data.ts) }}</time>
                <ChevronRight v-if="thinkingCollapsible(e)" :size="13"
                  class="chev" :class="{ open: thinkingBodyVisible(e) }" />
              </div>
              <div v-if="thinkingBodyVisible(e)" class="ev-body">{{ e.data.text }}<span v-if="isStreaming(e)" class="stream-cursor">▌</span></div>
            </div>

            <!-- agent text (streaming blocks update one card in place) -->
            <div v-else-if="e.type === 'text'" class="ev-card ev-text"
              :class="{ 'is-live': isStreaming(e) }">
              <div class="ev-head">
                <MessageSquare :size="14" class="ev-icon" />
                <span class="ev-label">Agent 回复</span>
                <i v-if="isStreaming(e)" class="live-dot"></i>
                <time>{{ fmtClock(e.data.ts) }}</time>
              </div>
              <div class="ev-body">{{ e.data.text }}<span v-if="isStreaming(e)" class="stream-cursor">▌</span></div>
            </div>

            <!-- tool call -->
            <div v-else-if="e.type === 'tool_call'" class="ev-card ev-tool-call"
              :class="toolCallState(e)">
              <div class="ev-head" :class="{ clickable: argsLong(e.data.input) }" @click="toggleExpand(e)">
                <Wrench :size="14" class="ev-icon" />
                <span class="tool-name mono">{{ e.data.name }}</span>
                <i v-if="pendingToolIds.has(e.data.id)" class="tool-spinner"></i>
                <el-tag v-if="e.data.name === 'record_finding'" size="small" type="danger">finding</el-tag>
                <el-tag v-else-if="e.data.name === 'finish'" size="small" type="success">finish</el-tag>
                <span v-if="!bodyShown(e, argsText(e.data.input))" class="ev-preview mono">{{ preview(argsText(e.data.input)) }}</span>
                <time>{{ fmtClock(e.data.ts) }}</time>
                <ChevronRight v-if="argsLong(e.data.input)" :size="13"
                  class="chev" :class="{ open: bodyShown(e, argsText(e.data.input)) }" />
              </div>
              <pre v-if="bodyShown(e, argsText(e.data.input))" class="ev-code">{{ argsText(e.data.input) }}</pre>
            </div>

            <!-- tool result -->
            <div v-else-if="e.type === 'tool_result'" class="ev-card ev-tool-result"
              :class="{ 'is-error': e.data.is_error }">
              <div class="ev-head" :class="{ clickable: isLong(e.data.preview) }" @click="toggleExpand(e)">
                <Terminal :size="14" class="ev-icon" />
                <span class="tool-name mono">{{ e.data.name }}</span>
                <el-tag v-if="e.data.is_error" size="small" type="danger">ERROR</el-tag>
                <span v-if="!bodyShown(e, e.data.preview)" class="ev-preview">{{ preview(e.data.preview) }}</span>
                <time>{{ fmtClock(e.data.ts) }}</time>
                <ChevronRight v-if="isLong(e.data.preview)" :size="13"
                  class="chev" :class="{ open: bodyShown(e, e.data.preview) }" />
              </div>
              <div v-if="bodyShown(e, e.data.preview)" class="ev-body mono-sm">{{ e.data.preview }}</div>
            </div>

            <!-- model usage -->
            <div v-else-if="e.type === 'model_usage'" class="ev-usage">
              <Coins :size="12" />
              <span>+{{ e.data.input_tokens }} in / {{ e.data.output_tokens }} out</span>
              <span v-if="e.data.total_input != null" class="muted">累计 {{ e.data.total_input }} / {{ e.data.total_output }}</span>
              <time>{{ fmtClock(e.data.ts) }}</time>
            </div>

            <!-- error -->
            <div v-else-if="e.type === 'error'" class="ev-card ev-error">
              <div class="ev-head">
                <TriangleAlert :size="14" class="ev-icon" />
                <span class="ev-label">错误</span>
                <time>{{ fmtClock(e.data.ts) }}</time>
              </div>
              <div class="ev-body">{{ e.data.message }}</div>
            </div>

            <!-- anything else -->
            <div v-else class="ev-marker">
              <Flag :size="13" />
              <span class="ev-marker-text">[{{ e.type }}] {{ e.data.summary || e.data.reason || e.data.task || '' }}</span>
              <time>{{ fmtClock(e.data.ts) }}</time>
            </div>
          </template>
          <div v-if="!shownEvents.length" class="muted pad">选择左侧会话查看事件流</div>
        </div>
      </el-card>
    </div>

    <!-- findings -->
    <el-card class="card" shadow="never">
      <template #header>
        <div class="row-between">
          <span class="card-title">Findings</span>
          <el-radio-group v-model="findingScope" size="small">
            <el-radio-button value="session">本会话</el-radio-button>
            <el-radio-button value="all">全部</el-radio-button>
          </el-radio-group>
        </div>
      </template>
      <el-table :data="shownFindings" size="small" row-key="id">
        <el-table-column type="expand">
          <template #default="{ row }">
            <div class="finding-detail">
              <p><b>位置：</b>{{ row.binary_path || row.binary_md5 }} :: {{ row.function_name || '?' }} @ {{ row.function_addr }}</p>
              <p><b>摘要：</b>{{ row.summary }}</p>
              <p v-if="row.source_summary"><b>source：</b>{{ row.source_summary }}</p>
              <p v-if="row.sink_function"><b>sink：</b>{{ row.sink_function }}</p>
              <p v-if="row.sanitization"><b>消毒检查：</b>{{ row.sanitization }}</p>
              <p v-if="row.exploit_sketch"><b>利用思路：</b>{{ row.exploit_sketch }}</p>
              <p v-if="row.remediation"><b>修复建议：</b>{{ row.remediation }}</p>
              <div v-if="(row.evidence || []).length">
                <b>证据：</b>
                <ul><li v-for="(ev, i) in row.evidence" :key="i">{{ ev }}</li></ul>
              </div>
              <div v-if="(row.open_questions || []).length" class="oq-box">
                <b>待确认问题：</b>
                <ul><li v-for="(q, i) in row.open_questions" :key="i">{{ q }}</li></ul>
              </div>
              <div v-if="(row.errata || []).length" class="errata-box">
                <b>勘误：</b>
                <ul><li v-for="(er, i) in row.errata" :key="i">{{ er }}</li></ul>
              </div>
              <p v-if="(row.related_findings || []).length || row.supersedes">
                <b>关联记录：</b>
                <el-tag v-for="rid in row.related_findings || []" :key="rid" size="small" effect="plain" class="rel-tag">{{ rid }}</el-tag>
                <span v-if="row.supersedes" class="muted">替代 {{ row.supersedes }}</span>
              </p>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="严重度" width="90">
          <template #default="{ row }">
            <el-tag :type="sevType(row.severity)" size="small">{{ row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="标题" show-overflow-tooltip>
          <template #default="{ row }">
            <el-tag v-if="reviewStatus(row.status)" size="small" effect="dark"
              :type="reviewStatus(row.status).type" class="review-tag">{{ reviewStatus(row.status).label }}</el-tag>
            <span :class="{ struck: row.status === 'retracted' }">{{ row.title }}</span>
          </template>
        </el-table-column>
        <el-table-column label="类别" width="200" show-overflow-tooltip>
          <template #default="{ row }">
            {{ row.vuln_class }}
            <el-tag v-if="row.cwe" size="small" effect="plain" type="danger" class="cwe-tag">{{ row.cwe }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="置信度" width="80">
          <template #default="{ row }">{{ row.confidence }}</template>
        </el-table-column>
        <el-table-column prop="reachability" label="可达性" width="110" />
      </el-table>
      <el-empty v-if="!shownFindings.length" description="暂无 findings" :image-size="60" />
    </el-card>

    <el-dialog v-model="reportVisible" title="漏洞挖掘报告" width="780px">
      <pre class="report mono">{{ reportText }}</pre>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import {
  Brain, ChevronRight, CircleCheck, Coins, Flag, MessageSquare, Play,
  Terminal, TriangleAlert, Wrench
} from '@lucide/vue'
import { api, getToken } from '../api'

const DEFAULT_TASK = '对默认固件任务做漏洞挖掘：先取 verified 攻击路径，再看评分最高的未验证路径，逐条取伪代码深挖 source→sink 数据流。确认真实漏洞就 record_finding（每条都要有具体证据），完成后 finish 总结。'

const agent = ref({})
const task = ref(DEFAULT_TASK)
const maxTurns = ref(40)
const mode = ref('dynamic')
const launching = ref(false)
const stopping = ref(false)
const sessions = ref([])
const currentId = ref('')
const currentRunning = ref(false)
const events = ref([])
const eventPane = ref(null)
const findingScope = ref('session')
const sessionFindings = ref([])
const allFindings = ref([])
const reportVisible = ref(false)
const reportText = ref('')
const evFilter = ref('all')
const autoScroll = ref(true)
const expandedSeqs = ref(new Set())

let evtCtrl = null
let pollTimer = null

const LONG = 260

const shownFindings = computed(() =>
  findingScope.value === 'session' ? sessionFindings.value : allFindings.value)

const shownEvents = computed(() => {
  const f = evFilter.value
  if (f === 'all') return events.value
  if (f === 'tools') return events.value.filter(e => e.type === 'tool_call' || e.type === 'tool_result')
  if (f === 'usage') return events.value.filter(e => e.type === 'model_usage')
  if (f === 'error') return events.value.filter(e => e.type === 'error')
  return events.value.filter(e => e.type === f)
})

function statusType (s) {
  return { running: 'warning', done: 'success', error: 'danger', interrupted: 'info' }[s] || 'info'
}
function statusLabel (s) {
  return { running: '运行中', done: '完成', error: '错误', interrupted: '已中断' }[s] || s
}
function sevType (s) {
  return { critical: 'danger', high: 'danger', medium: 'warning', low: 'info', info: 'info' }[s] || 'info'
}
// 评审状态徽章（draft/verified/disputed/retracted）；字段不存在或取值不在
// 白名单内（如会话的运行态 running/done）时不渲染，保持向后兼容
const REVIEW_STATUS = {
  draft: { label: '草稿', type: 'info' },
  verified: { label: '已验证', type: 'success' },
  disputed: { label: '存疑', type: 'warning' },
  retracted: { label: '已撤回', type: 'danger' }
}
function reviewStatus (s) {
  return REVIEW_STATUS[s] || null
}
function fmtTime (iso) {
  return iso ? new Date(iso).toLocaleString() : ''
}
function fmtClock (iso) {
  return iso ? new Date(iso).toLocaleTimeString('zh-CN', { hour12: false }) : ''
}
function isMarker (type) {
  return type === 'session_start' || type === 'session_end' || type === 'session_idle'
}
function markerText (e) {
  if (e.type === 'session_start') return `会话开始 · ${e.data.task || ''}`
  if (e.type === 'session_end') return `会话结束 · ${e.data.summary || ''}`
  return `会话空闲 · ${e.data.reason || ''}`
}
function isLong (text) {
  return (text || '').length > LONG
}
function preview (text) {
  const first = String(text ?? '').split('\n')[0]
  return first.length > 110 ? first.slice(0, 110) + '…' : first
}
function argsText (input) {
  if (input === undefined || input === null) return ''
  try { return JSON.stringify(input, null, 2) } catch { return String(input) }
}
function argsLong (input) {
  return argsText(input).length > 140
}
function bodyShown (e, text) {
  if (!isLong(text) && e.type !== 'tool_call') return true
  if (e.type === 'tool_call' && !argsLong(e.data.input)) return true
  return expandedSeqs.value.has(e.data.seq)
}
function toggleExpand (e) {
  const seq = e.data.seq
  if (seq === undefined) return
  const next = new Set(expandedSeqs.value)
  if (next.has(seq)) next.delete(seq)
  else next.add(seq)
  expandedSeqs.value = next
}

/* ===== streaming event handling (dsh engine) =====
   thinking/text/tool_call snapshots carry a stable identity (block index or
   call id); each snapshot replaces the previous card in place instead of
   appending. Events without those fields (old builtin engine) append as
   before and are treated as final. */
const streamIndex = new Map() // render key -> position in events.value

function isStreaming (e) {
  return (e.type === 'thinking' || e.type === 'text') && e.data.stream === true
}
// expanded while streaming; once settled, long chains collapse behind the toggle
function thinkingBodyVisible (e) {
  if (isStreaming(e)) return true
  if (!isLong(e.data.text)) return true
  return expandedSeqs.value.has(e.data.seq)
}
function thinkingCollapsible (e) {
  return !isStreaming(e) && isLong(e.data.text)
}

// tool_call ids that have no matching tool_result yet
const pendingToolIds = computed(() => {
  const results = new Set()
  const calls = []
  for (const e of events.value) {
    if (e.type === 'tool_result' && e.data.id != null) results.add(e.data.id)
    else if (e.type === 'tool_call' && e.data.id != null) calls.push(e.data.id)
  }
  return new Set(calls.filter(id => !results.has(id)))
})
function toolCallState (e) {
  if (!pendingToolIds.value.has(e.data.id)) return {}
  return currentRunning.value ? { 'is-running': true } : { 'is-stale': true }
}

/* live usage meter: model_usage carries per-call deltas, accumulate locally
   (works for replay and for the old engine, whose events are deltas too) */
const usageIn = ref(0)
const usageOut = ref(0)
const hasUsage = ref(false)
const usageTarget = { in: 0, out: 0 }
let usageRaf = 0
function tweenUsage () {
  cancelAnimationFrame(usageRaf)
  const startIn = usageIn.value
  const startOut = usageOut.value
  const dIn = usageTarget.in - startIn
  const dOut = usageTarget.out - startOut
  const t0 = performance.now()
  const dur = 300
  const step = (t) => {
    const k = Math.min(1, (t - t0) / dur)
    const ease = 1 - (1 - k) ** 3
    usageIn.value = Math.round(startIn + dIn * ease)
    usageOut.value = Math.round(startOut + dOut * ease)
    if (k < 1) usageRaf = requestAnimationFrame(step)
  }
  usageRaf = requestAnimationFrame(step)
}

let scrollScheduled = false
function scrollToBottom () {
  if (!autoScroll.value || scrollScheduled) return
  scrollScheduled = true
  nextTick(() => {
    requestAnimationFrame(() => {
      scrollScheduled = false
      const el = eventPane.value
      if (el) el.scrollTop = el.scrollHeight
    })
  })
}

function upsertEvent (type, data) {
  let key = null
  if ((type === 'thinking' || type === 'text') && data.block != null) key = `${type}:${data.block}`
  else if (type === 'tool_call' && data.id != null) key = `call:${data.id}`
  if (key) {
    const idx = streamIndex.get(key)
    if (idx !== undefined && events.value[idx] && events.value[idx].key === key) {
      events.value[idx] = { type, data, key } // in-place replace, DOM node is patched not remounted
      return
    }
    events.value.push({ type, data, key })
    streamIndex.set(key, events.value.length - 1)
    return
  }
  events.value.push({ type, data })
}

function trimEvents () {
  if (events.value.length <= 800) return
  events.value.splice(0, events.value.length - 800)
  streamIndex.clear()
  events.value.forEach((e, i) => { if (e.key) streamIndex.set(e.key, i) })
}

function clearEvents () {
  events.value = []
  streamIndex.clear()
  usageTarget.in = 0
  usageTarget.out = 0
  usageIn.value = 0
  usageOut.value = 0
  hasUsage.value = false
}

async function loadAgent () {
  try { agent.value = await api('/vulnagent/agent') } catch { /* banner stays empty */ }
}

async function loadSessions () {
  try {
    sessions.value = await api('/vulnagent/sessions')
    // auto-open the newest session on first load so the live event stream
    // (thinking chain / tool cards) is visible without an extra click
    if (!currentId.value && sessions.value.length) select(sessions.value[0])
    const cur = sessions.value.find(s => s.session_id === currentId.value)
    currentRunning.value = Boolean(cur && cur.status === 'running')
    if (cur && cur.status === 'running') refreshSessionFindings()
  } catch { /* transient */ }
}

async function refreshSessionFindings () {
  if (!currentId.value) return
  try {
    const detail = await api(`/vulnagent/sessions/${currentId.value}`)
    const next = detail.finding_objects || []
    // keep array identity when unchanged so el-table preserves row expansion
    if (JSON.stringify(next) !== JSON.stringify(sessionFindings.value)) {
      sessionFindings.value = next
    }
  } catch { /* transient */ }
}

async function loadAllFindings () {
  try {
    const next = await api('/vulnagent/findings')
    if (JSON.stringify(next) !== JSON.stringify(allFindings.value)) {
      allFindings.value = next
    }
  } catch { /* transient */ }
}

async function launch () {
  if (!task.value.trim()) return
  launching.value = true
  try {
    const r = await api('/vulnagent/sessions', {
      method: 'POST',
      body: { task: task.value.trim(), max_turns: maxTurns.value, mode: mode.value }
    })
    await loadSessions()
    select({ session_id: r.session_id })
  } finally {
    launching.value = false
  }
}

async function stop () {
  stopping.value = true
  try {
    await api(`/vulnagent/sessions/${currentId.value}/stop`, { method: 'POST' })
    await loadSessions()
  } finally {
    stopping.value = false
  }
}

async function showReport () {
  try {
    reportText.value = await api(`/vulnagent/sessions/${currentId.value}/report`)
  } catch (e) {
    reportText.value = `（报告不可用：${e.message}）`
  }
  reportVisible.value = true
}

function select (s) {
  if (!s || s.session_id === currentId.value) return
  currentId.value = s.session_id
  sessionFindings.value = []
  expandedSeqs.value = new Set()
  refreshSessionFindings()
  streamEvents(s.session_id)
}

function handleRawEvent (raw) {
  let type = 'message'
  const dataLines = []
  for (const line of raw.split('\n')) {
    if (line.startsWith('event: ')) type = line.slice(7).trim()
    else if (line.startsWith('data: ')) dataLines.push(line.slice(6))
    // ': ping' heartbeats and blank lines are ignored
  }
  if (!dataLines.length) return
  let data = {}
  try { data = JSON.parse(dataLines.join('\n')) } catch { return }
  if (type === 'model_usage') {
    usageTarget.in += data.input_tokens || 0
    usageTarget.out += data.output_tokens || 0
    hasUsage.value = true
    tweenUsage()
  } else if (type === 'session_end' || type === 'error') {
    currentRunning.value = false
  }
  upsertEvent(type, data)
  trimEvents()
  scrollToBottom()
}

async function streamEvents (sid) {
  if (evtCtrl) evtCtrl.abort()
  const ctrl = new AbortController()
  evtCtrl = ctrl
  clearEvents()
  try {
    const resp = await fetch(`/vulnagent/sessions/${sid}/events?follow=1`, {
      headers: { Authorization: `Bearer ${getToken()}` },
      signal: ctrl.signal
    })
    if (!resp.ok || !resp.body) return
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
    if (buf.trim()) handleRawEvent(buf)
  } catch (e) {
    if (e.name !== 'AbortError') events.value.push({ type: 'error', data: { message: `事件流中断：${e.message}` } })
  }
}

onMounted(() => {
  loadAgent()
  loadSessions()
  loadAllFindings()
  pollTimer = setInterval(() => {
    loadSessions()
    if (findingScope.value === 'all') loadAllFindings()
  }, 3000)
})

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer)
  if (evtCtrl) evtCtrl.abort()
  cancelAnimationFrame(usageRaf)
})
</script>

<style scoped>
.card { margin-bottom: 12px; }
.card-title { font-weight: 600; letter-spacing: 1px; color: #2b6ce5; }
.row-between { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.launch-row { display: flex; align-items: center; gap: 10px; margin-top: 10px; }
.cols { display: flex; gap: 12px; align-items: stretch; }
.col-sessions { flex: 0 0 320px; }
.col-events { flex: 1 1 auto; min-width: 0; }
.sess-item { padding: 8px; border: 1px solid rgba(43, 108, 229, .22); border-radius: 6px; margin-bottom: 8px; cursor: pointer; }
.sess-item:hover { background: rgba(43, 108, 229, .08); }
.sess-item.active { border-color: #2b6ce5; background: rgba(43, 108, 229, .13); box-shadow: 0 0 10px rgba(43, 108, 229, .18); }
.sess-head { display: flex; justify-content: space-between; align-items: center; }
.sid { font-size: 12px; }
.sess-task { font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin: 4px 0; }

/* event stream */
.ev-toolbar { display: flex; justify-content: space-between; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }
.ev-toolbar-right { display: flex; align-items: center; gap: 10px; }
.events { height: 520px; overflow-y: auto; background: #f4f8fd; border: 1px solid rgba(43, 108, 229, .22); border-radius: 8px; padding: 10px; }
.events .pad { padding: 12px; text-align: center; }
.ev-card { background: #ffffff; border: 1px solid rgba(43, 108, 229, .22); border-left-width: 3px; border-radius: 8px; padding: 8px 10px; margin-bottom: 8px; }
.ev-head { display: flex; align-items: center; gap: 6px; min-height: 20px; }
.ev-head.clickable { cursor: pointer; user-select: none; }
.ev-head time, .ev-marker time, .ev-usage time { margin-left: auto; color: #8b9cb3; font-size: 11px; flex: none; }
.ev-icon { flex: none; }
.ev-label { font-size: 12px; font-weight: 600; }
.ev-preview { flex: 1 1 auto; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #64748f; font-size: 12px; }
.chev { flex: none; color: #8b9cb3; transition: transform 0.15s; }
.chev.open { transform: rotate(90deg); }
.ev-body { margin-top: 6px; font-size: 13px; line-height: 1.6; white-space: pre-wrap; word-break: break-word; }
.mono-sm { font-size: 12px; font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace; }
.ev-code { margin: 6px 0 0; background: #f4f8fd; color: #3d5470; border: 1px solid rgba(43, 108, 229, .18); border-radius: 6px; padding: 8px 10px; font-size: 12px; line-height: 1.5; overflow-x: auto; white-space: pre; }
.ev-thinking { border-left-color: #8b9cb3; }
.ev-thinking .ev-label { color: #64748f; }
.ev-thinking .ev-body { color: #64748f; font-style: italic; }
.ev-text { border-left-color: #2b6ce5; }
.ev-text .ev-label { color: #2b6ce5; }
.ev-tool-call { border-left-color: #b45309; }
.ev-tool-call .tool-name { color: #b45309; font-weight: 600; font-size: 12px; }
.ev-tool-result { border-left-color: #16a34a; }
.ev-tool-result .tool-name { color: #16a34a; font-weight: 600; font-size: 12px; }
.ev-tool-result.is-error { border-left-color: #dc2626; background: rgba(220, 38, 38, .10); }
.ev-tool-result.is-error .ev-body { color: #b91c1c; }
.ev-error { border-left-color: #dc2626; background: rgba(220, 38, 38, .10); }
.ev-error .ev-label { color: #dc2626; }
.ev-marker { display: flex; align-items: center; gap: 6px; color: #16a34a; font-size: 12px; padding: 2px 4px; margin-bottom: 8px; }
.ev-marker-text { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ev-usage { display: flex; align-items: center; gap: 6px; justify-content: flex-end; color: #64748f; font-size: 11px; margin-bottom: 8px; padding: 0 4px; }

/* findings */
.finding-detail { padding: 4px 16px; font-size: 13px; }
.finding-detail p { margin: 4px 0; }
.finding-detail ul { margin: 4px 0; padding-left: 20px; }
.errata-box { margin-top: 6px; padding: 8px 10px; background: rgba(180, 83, 9, .09); border: 1px solid rgba(180, 83, 9, .35); border-radius: 6px; color: #b45309; }
.oq-box { margin-top: 6px; padding: 8px 10px; background: rgba(43, 108, 229, .07); border: 1px solid rgba(43, 108, 229, .2); border-radius: 6px; color: #3d5470; }
.cwe-tag { margin-left: 6px; }
.review-tag { margin-right: 6px; }
.struck { text-decoration: line-through; color: #64748f; }
.rel-tag { margin-right: 6px; font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace; }
.report { max-height: 60vh; overflow: auto; white-space: pre-wrap; font-size: 12px; }

/* 挖掘模式切换 */
.mode-switch { display: inline-flex; gap: 6px; margin: 0 8px; }
.mode-btn {
  padding: 5px 14px; border-radius: 6px; cursor: pointer; font-size: 13px;
  background: #ffffff; border: 1px solid rgba(43, 108, 229, .22); color: #3d5470;
  transition: box-shadow .2s, border-color .2s, color .2s;
}
.mode-btn:hover { border-color: rgba(43, 108, 229, .55); }
.mode-btn.on {
  border-color: #2b6ce5; color: #2b6ce5;
  box-shadow: 0 0 10px rgba(43, 108, 229, .3), inset 0 0 6px rgba(43, 108, 229, .08);
}
.mode-tag {
  float: right; margin-left: 6px; padding: 0 6px; border-radius: 4px;
  font-size: 11px; line-height: 18px; border: 1px solid rgba(43, 108, 229, .35);
  color: #64748f;
}
.mode-tag.dynamic { color: #2b6ce5; border-color: rgba(43, 108, 229, .5); }

/* ===== 流式事件动效 ===== */
/* 事件流容器：自动滚动平滑推进，不再瞬跳 */
.events { scroll-behavior: smooth; }

/* 新卡片淡入上滑（仅挂载时播放一次；流式快照原地 patch 不会重触发） */
@keyframes ev-in {
  from { opacity: 0; transform: translateY(6px); }
  to { opacity: 1; transform: none; }
}
.ev-card, .ev-marker, .ev-usage {
  animation: ev-in .3s cubic-bezier(.22, .8, .36, 1);
  will-change: opacity, transform;
}

/* 脉冲青色小圆点：LIVE 徽标与流式卡片共用 */
.live-dot {
  width: 7px; height: 7px; border-radius: 50%; background: #2b6ce5; flex: none;
  display: inline-block; animation: live-pulse 1.2s ease-in-out infinite;
}
@keyframes live-pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(43, 108, 229, .5); opacity: 1; }
  50% { box-shadow: 0 0 0 5px rgba(43, 108, 229, 0); opacity: .55; }
}

/* 面板头部 LIVE 徽标 */
.live-badge {
  display: inline-flex; align-items: center; gap: 5px; margin-left: 10px;
  padding: 1px 8px; border-radius: 10px; vertical-align: 2px;
  background: rgba(220, 38, 38, .14); border: 1px solid rgba(220, 38, 38, .5);
  color: #dc2626; font-size: 11px; font-weight: 700; letter-spacing: 1.5px;
  animation: badge-pulse 1.2s ease-in-out infinite;
}
.live-badge .live-dot { background: #dc2626; animation: none; }
@keyframes badge-pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(220, 38, 38, .35); }
  50% { box-shadow: 0 0 10px 2px rgba(220, 38, 38, .25); }
}

/* 流式进行中的卡片：呼吸辉光边框 */
.ev-card.is-live {
  border-left-color: #2b6ce5;
  animation: ev-in .18s ease-out, live-glow 1.6s ease-in-out infinite;
}
@keyframes live-glow {
  0%, 100% { box-shadow: 0 0 4px rgba(43, 108, 229, .12); }
  50% { box-shadow: 0 0 14px rgba(43, 108, 229, .4); }
}

/* 流式文本光标 */
.stream-cursor { color: #2b6ce5; animation: blink .8s step-end infinite; }
/* 流式文本体：内容增长时柔和平滑（透明度/位移过渡） */
.ev-body, .ev-thinking-body, .ev-text-body, .ev-pre {
  transition: opacity .22s ease;
}
.ev-card.is-live .ev-body, .ev-card.is-live pre {
  transition: opacity .22s ease, transform .22s ease;
}
@keyframes blink { 50% { opacity: 0; } }

/* 工具调用 running/stale 状态 */
.tool-spinner {
  width: 12px; height: 12px; flex: none; border-radius: 50%;
  border: 2px solid rgba(180, 83, 9, .25); border-top-color: #b45309;
  animation: spin .8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
.ev-tool-call.is-running {
  border-left-color: #b45309;
  animation: ev-in .18s ease-out, tool-glow 1.6s ease-in-out infinite;
}
@keyframes tool-glow {
  0%, 100% { box-shadow: 0 0 4px rgba(180, 83, 9, .10); }
  50% { box-shadow: 0 0 12px rgba(180, 83, 9, .32); }
}
.ev-tool-call.is-stale { border-left-color: #b45309; opacity: .55; }
.ev-tool-call.is-stale .tool-spinner { animation: none; border-top-color: rgba(180, 83, 9, .4); }

/* 思考链字数 */
.ev-count { font-size: 11px; flex: none; }

/* sticky token 用量条 */
.usage-strip {
  position: sticky; top: -10px; z-index: 3;
  display: flex; align-items: center; gap: 8px;
  margin: -10px -10px 8px; padding: 6px 10px;
  background: rgba(255, 255, 255, .94); backdrop-filter: blur(4px);
  border-bottom: 1px solid rgba(43, 108, 229, .2);
  border-radius: 8px 8px 0 0; font-size: 12px; color: #3d5470;
}
.usage-icon { color: #2b6ce5; flex: none; }
.usage-num { font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace; color: #2b6ce5; font-weight: 600; }

@media (max-width: 900px) {
  .cols { flex-direction: column; }
  .col-sessions { flex: 1 1 auto; }
}
</style>
