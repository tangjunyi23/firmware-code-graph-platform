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
          <div class="sess-head">
            <span class="mono sid">{{ s.session_id }}</span>
            <el-tag size="small" :type="statusType(s.status)">{{ statusLabel(s.status) }}</el-tag>
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
            <el-button size="small" text @click="events = []">清空</el-button>
          </div>
        </div>
        <div ref="eventPane" class="events">
          <template v-for="e in shownEvents" :key="e.data.seq ?? e.type">
            <!-- session lifecycle markers -->
            <div v-if="isMarker(e.type)" class="ev-marker">
              <Play v-if="e.type === 'session_start'" :size="13" />
              <CircleCheck v-else-if="e.type === 'session_end'" :size="13" />
              <Flag v-else :size="13" />
              <span class="ev-marker-text">{{ markerText(e) }}</span>
              <time>{{ fmtClock(e.data.ts) }}</time>
            </div>

            <!-- thinking -->
            <div v-else-if="e.type === 'thinking'" class="ev-card ev-thinking">
              <div class="ev-head" :class="{ clickable: isLong(e.data.text) }" @click="toggleExpand(e)">
                <Brain :size="14" class="ev-icon" />
                <span class="ev-label">思考</span>
                <span v-if="!bodyShown(e, e.data.text)" class="ev-preview">{{ preview(e.data.text) }}</span>
                <time>{{ fmtClock(e.data.ts) }}</time>
                <ChevronRight v-if="isLong(e.data.text)" :size="13"
                  class="chev" :class="{ open: bodyShown(e, e.data.text) }" />
              </div>
              <div v-if="bodyShown(e, e.data.text)" class="ev-body">{{ e.data.text }}</div>
            </div>

            <!-- agent text -->
            <div v-else-if="e.type === 'text'" class="ev-card ev-text">
              <div class="ev-head">
                <MessageSquare :size="14" class="ev-icon" />
                <span class="ev-label">Agent 回复</span>
                <time>{{ fmtClock(e.data.ts) }}</time>
              </div>
              <div class="ev-body">{{ e.data.text }}</div>
            </div>

            <!-- tool call -->
            <div v-else-if="e.type === 'tool_call'" class="ev-card ev-tool-call">
              <div class="ev-head" :class="{ clickable: argsLong(e.data.input) }" @click="toggleExpand(e)">
                <Wrench :size="14" class="ev-icon" />
                <span class="tool-name mono">{{ e.data.name }}</span>
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
              <span class="muted">累计 {{ e.data.total_input }} / {{ e.data.total_output }}</span>
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
        <el-table-column prop="title" label="标题" show-overflow-tooltip />
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

async function loadAgent () {
  try { agent.value = await api('/vulnagent/agent') } catch { /* banner stays empty */ }
}

async function loadSessions () {
  try {
    sessions.value = await api('/vulnagent/sessions')
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
      body: { task: task.value.trim(), max_turns: maxTurns.value }
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
  events.value.push({ type, data })
  if (events.value.length > 800) events.value.splice(0, events.value.length - 800)
  if (autoScroll.value) {
    nextTick(() => {
      const el = eventPane.value
      if (el) el.scrollTop = el.scrollHeight
    })
  }
}

async function streamEvents (sid) {
  if (evtCtrl) evtCtrl.abort()
  const ctrl = new AbortController()
  evtCtrl = ctrl
  events.value = []
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
})
</script>

<style scoped>
.card { margin-bottom: 12px; }
.card-title { font-weight: 600; }
.row-between { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.launch-row { display: flex; align-items: center; gap: 10px; margin-top: 10px; }
.cols { display: flex; gap: 12px; align-items: stretch; }
.col-sessions { flex: 0 0 320px; }
.col-events { flex: 1 1 auto; min-width: 0; }
.sess-item { padding: 8px; border: 1px solid #ebeef5; border-radius: 6px; margin-bottom: 8px; cursor: pointer; }
.sess-item:hover { background: #f5f7fa; }
.sess-item.active { border-color: #409eff; background: #ecf5ff; }
.sess-head { display: flex; justify-content: space-between; align-items: center; }
.sid { font-size: 12px; }
.sess-task { font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin: 4px 0; }

/* event stream */
.ev-toolbar { display: flex; justify-content: space-between; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }
.ev-toolbar-right { display: flex; align-items: center; gap: 10px; }
.events { height: 520px; overflow-y: auto; background: #f7f8fb; border: 1px solid #ebeef5; border-radius: 8px; padding: 10px; }
.events .pad { padding: 12px; text-align: center; }
.ev-card { background: #fff; border: 1px solid #ebeef5; border-left-width: 3px; border-radius: 8px; padding: 8px 10px; margin-bottom: 8px; }
.ev-head { display: flex; align-items: center; gap: 6px; min-height: 20px; }
.ev-head.clickable { cursor: pointer; user-select: none; }
.ev-head time, .ev-marker time, .ev-usage time { margin-left: auto; color: #c0c4cc; font-size: 11px; flex: none; }
.ev-icon { flex: none; }
.ev-label { font-size: 12px; font-weight: 600; }
.ev-preview { flex: 1 1 auto; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #a8abb2; font-size: 12px; }
.chev { flex: none; color: #c0c4cc; transition: transform 0.15s; }
.chev.open { transform: rotate(90deg); }
.ev-body { margin-top: 6px; font-size: 13px; line-height: 1.6; white-space: pre-wrap; word-break: break-word; }
.mono-sm { font-size: 12px; font-family: 'JetBrains Mono', Consolas, monospace; }
.ev-code { margin: 6px 0 0; background: #282c34; color: #abb2bf; border-radius: 6px; padding: 8px 10px; font-size: 12px; line-height: 1.5; overflow-x: auto; white-space: pre; }
.ev-thinking { border-left-color: #c0c4cc; }
.ev-thinking .ev-label { color: #909399; }
.ev-thinking .ev-body { color: #909399; font-style: italic; }
.ev-text { border-left-color: #409eff; }
.ev-text .ev-label { color: #2563eb; }
.ev-tool-call { border-left-color: #e6a23c; }
.ev-tool-call .tool-name { color: #b45309; font-weight: 600; font-size: 12px; }
.ev-tool-result { border-left-color: #67c23a; }
.ev-tool-result .tool-name { color: #529b2e; font-weight: 600; font-size: 12px; }
.ev-tool-result.is-error { border-left-color: #f56c6c; background: #fef0f0; }
.ev-tool-result.is-error .ev-body { color: #c45656; }
.ev-error { border-left-color: #f56c6c; background: #fef0f0; }
.ev-error .ev-label { color: #f56c6c; }
.ev-marker { display: flex; align-items: center; gap: 6px; color: #67c23a; font-size: 12px; padding: 2px 4px; margin-bottom: 8px; }
.ev-marker-text { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ev-usage { display: flex; align-items: center; gap: 6px; justify-content: flex-end; color: #a8abb2; font-size: 11px; margin-bottom: 8px; padding: 0 4px; }

/* findings */
.finding-detail { padding: 4px 16px; font-size: 13px; }
.finding-detail p { margin: 4px 0; }
.finding-detail ul { margin: 4px 0; padding-left: 20px; }
.errata-box { margin-top: 6px; padding: 8px 10px; background: #fdf6ec; border: 1px solid #faecd8; border-radius: 6px; color: #b88230; }
.oq-box { margin-top: 6px; padding: 8px 10px; background: #f4f4f5; border: 1px solid #e9e9eb; border-radius: 6px; color: #606266; }
.cwe-tag { margin-left: 6px; }
.rel-tag { margin-right: 6px; font-family: 'JetBrains Mono', Consolas, monospace; }
.report { max-height: 60vh; overflow: auto; white-space: pre-wrap; font-size: 12px; }
@media (max-width: 900px) {
  .cols { flex-direction: column; }
  .col-sessions { flex: 1 1 auto; }
}
</style>
