<template>
  <div class="emul wb-root" :data-wb-theme="themePref">
    <header class="emul-heading">
      <div>
        <div class="heading-row">
          <h1>固件模拟</h1>
        </div>
      </div>
      <div class="heading-actions">
        <span class="refresh-note"><span class="refresh-dot" :class="{ offline: refreshError }" />{{ refreshError ? '同步暂不可用' : lastUpdated ? '更新于 ' + formatTime(lastUpdated) : '同步中…' }}</span>
        <button type="button" class="quiet-button" :disabled="refreshing" @click="refreshAll()"><RefreshCw :size="14" :class="{ spinning: refreshing }" />刷新</button>
      </div>
    </header>
    <p v-if="refreshError" class="sync-notice" role="status">{{ refreshError }}<button type="button" @click="refreshAll()">重试</button></p>

    <section v-if="loading" class="empty-state pane" role="status"><RefreshCw :size="26" class="spinning" /><h2>加载中…</h2></section>
    <section v-else-if="!hasActivity" class="empty-state pane" aria-label="暂无模拟任务">
      <div class="empty-icon"><Monitor :size="28" /></div><h2>暂无模拟任务</h2>
      <p>在安全工作台发起模拟测试。</p>
      <a href="?page=jobs&mode=expert" class="empty-link">前往安全工作台<ArrowRight :size="14" /></a>
    </section>

    <template v-else>
      <section class="overview pane" aria-label="模拟运行总览">
        <div class="overview-main">
          <div class="overview-label">{{ selectedSession ? '当前会话' : '任务总览' }}</div>
          <div class="overview-status" :data-status="selectedSession ? chipTone(selectedSession) : 'idle'"><span class="status-orb" :data-live="selectedSession?.status === 'running' && !isZombie(selectedSession) || undefined" /><strong>{{ overviewTitle }}</strong></div>
          <details v-if="currentGoal" class="goal-detail"><summary><span>验证目标</span><ChevronDown :size="14" /></summary><p>{{ currentGoal }}</p></details>
          <ol class="hero-steps"><li v-for="(s, i) in STEPS" :key="s" :data-st="heroStepState(i)"><i class="pt" /><span>{{ s }}</span></li></ol>
        </div>
        <div class="overview-env"><div class="overview-label"><Cpu :size="13" />运行环境</div><template v-if="activeEnv"><div class="env-title"><strong>{{ activeEnv.arch || '隔离环境' }}</strong><span class="env-badge" :data-status="activeEnv.status">{{ envText(activeEnv.status) }}</span></div><span class="env-id mono" :title="activeEnv.env_id">{{ activeEnv.env_id }}</span><div class="env-facts"><span>{{ activeEnv.iterations || 0 }} 轮迭代</span><span>{{ Math.round((activeEnv.disk_bytes || 0) / 1048576) }} MiB</span></div></template><span v-else class="dim">尚未创建运行环境</span></div>
      </section>

      <section class="metric-grid" aria-label="模拟指标">
        <article class="metric-card"><span class="metric-icon blue"><Activity :size="18" /></span><div><small>运行中会话</small><b>{{ runningSessions.length }}</b></div></article>
        <article class="metric-card"><span class="metric-icon amber"><Clock3 :size="18" /></span><div><small>待处理请求</small><b>{{ queuedRequests.length }}</b></div></article>
        <article class="metric-card"><span class="metric-icon green"><CheckCircle2 :size="18" /></span><div><small>就绪环境</small><b>{{ readyEnvs.length }}</b></div></article>
        <article class="metric-card"><span class="metric-icon violet"><History :size="18" /></span><div><small>历史会话</small><b>{{ completedSessions.length }}</b><em>其中 {{ errorSessions.length }} 个异常会话</em></div></article>
      </section>

      <section class="session-section" aria-label="模拟会话">
        <div class="section-head"><div><h2>模拟会话</h2></div><span class="section-count">{{ filteredSessions.length }} / {{ chipSessions.length }} 个会话</span></div>
        <div class="session-toolbar">
          <div class="session-filters" aria-label="会话状态筛选"><button v-for="option in SESSION_FILTERS" :key="option.value" type="button" :class="{ on: sessionFilter === option.value }" :aria-pressed="sessionFilter === option.value" @click="sessionFilter = option.value">{{ option.label }}</button></div>
          <label class="session-search"><Search :size="15" /><input v-model="sessionSearch" aria-label="搜索模拟会话" placeholder="搜索验证目标、固件或会话编号" /><button v-if="sessionSearch" type="button" aria-label="清空会话搜索" @click="sessionSearch = ''"><X :size="14" /></button></label>
        </div>
        <div class="session-grid">
          <article v-for="s in filteredSessions" :key="s.session_id" class="session-card" :data-status="chipTone(s)" :class="{ selected: s.session_id === selected, live: s.status === 'running' && !isZombie(s), zombie: isZombie(s) }">
            <button type="button" class="session-select" :aria-pressed="s.session_id === selected" :title="chipTitle(s)" @click="select(s.session_id)">
              <span class="session-top"><i class="session-dot" /><span>{{ chipStatus(s) }}</span><Check v-if="s.session_id === selected" :size="14" class="selected-check" /></span>
              <strong>{{ chipLabel(s) }}</strong><span class="session-id mono">{{ s.job_id ? '固件 ' + s.job_id : s.session_id }}</span><span class="session-time">{{ formatDate(s.created_at) }}</span>
            </button>
            <button v-if="isZombie(s)" type="button" class="session-stop" :disabled="stopping === s.session_id" @click="stopZombie(s.session_id)">{{ stopping === s.session_id ? '归档中…' : '停止失联会话' }}</button>
          </article>
        </div>
        <div v-if="!filteredSessions.length" class="filter-empty"><Search :size="22" /><span>{{ chipSessions.length ? '没有符合条件的会话' : '请求已进入队列，等待创建模拟会话' }}</span><button v-if="sessionSearch || sessionFilter !== 'all'" type="button" class="quiet-button" @click="sessionSearch = ''; sessionFilter = 'all'">清空筛选</button></div>
      </section>

      <div v-if="selected" class="detail-shell"><div class="detail-titlebar"><div><h2>{{ chipLabel(selectedSession || {}) }}</h2></div><span class="live-pill" :data-status="selectedSession ? chipTone(selectedSession) : 'idle'" :data-running="selectedSession?.status === 'running' && !isZombie(selectedSession) || undefined"><i />{{ selectedSession ? chipStatus(selectedSession) : '会话' }}</span></div>
        <div class="detail-grid"><section ref="flowEl" class="pane flow"><header class="pane-h"><div><h2>执行记录</h2></div><span class="pane-hint">{{ selectedSession?.status === 'running' ? '实时更新' : '历史回放' }}</span></header><p v-if="dsh.state.lastError" class="empty" role="status">执行记录暂不可用：{{ dsh.state.lastError }}</p><MessageList :session="dsh" @inspect="onInspect" /></section>
          <aside class="rail"><section class="pane service-pane"><header class="pane-h"><div><h2>运行服务</h2></div><span class="pane-hint">{{ activeEnv?.services?.length || 0 }} 项</span></header><ul v-if="activeEnv?.services?.length" class="svc-rows"><li v-for="sv in activeEnv.services" :key="sv.name"><button type="button" :class="{ on: logService === sv.name }" :aria-pressed="logService === sv.name" :title="logService === sv.name ? '点击取消过滤' : '点击查看该服务日志'" @click="logService = logService === sv.name ? '' : sv.name"><span><b class="service-name mono">{{ sv.name }}</b><small class="mono dim">{{ sv.guest_port ?? '—' }} → {{ sv.host_port ?? '—' }}</small></span><strong :data-st="sv.status"><i />{{ svcText(sv.status) }}</strong></button></li></ul><p v-else class="empty">{{ activeEnv ? '当前环境尚未启动服务' : '尚无运行环境' }}</p></section>
            <section class="pane log-pane"><header class="pane-h"><div><h2>服务日志</h2></div><button v-if="logService" type="button" class="filter-pill" aria-label="取消服务日志筛选" @click="logService = ''">{{ logService }}<X :size="12" /></button></header><p v-if="consoleError" class="empty" role="status">{{ consoleError }}</p><pre ref="consoleEl" class="console" @scroll="onConsoleScroll">{{ consoleText || (activeEnv ? '暂无服务输出' : '等待运行环境创建…') }}</pre></section></aside>
        </div>
      </div>

      <el-drawer v-model="inspectOpen" append-to-body title="调用详情" size="min(520px, 100%)" direction="rtl"><div v-if="inspectNode" class="inspect-body"><p class="inspect-title">{{ toolTitle(inspectNode.name) }} <span class="mono-name">{{ inspectNode.name }}</span></p><p class="dim">{{ inspectNode.status === 'running' ? '运行中' : inspectNode.status === 'error' ? '失败' : inspectNode.status === 'stopped' ? '已停止' : '已完成' }}<template v-if="inspectNode.finishedTs || inspectNode.ts"> · {{ fmtTs(inspectNode.finishedTs || inspectNode.ts) }}</template></p><h4>输入</h4><pre class="inspect-pre">{{ prettyJson(inspectNode.argumentsText) || '（无）' }}</pre><h4>输出</h4><pre class="inspect-pre" :data-error="inspectNode.status === 'error' || undefined">{{ inspectNode.resultText || (inspectNode.error ? JSON.stringify(inspectNode.error, null, 2) : '') || '（无输出）' }}</pre></div></el-drawer>
    </template>
  </div>
</template>

<script setup>
// 模拟观察台：会话筛选、执行证据和服务日志；沿用现有模拟 API。
import { computed, nextTick, onBeforeUnmount, onMounted, provide, ref, watch } from 'vue'
import { Activity, ArrowRight, Check, CheckCircle2, ChevronDown, Clock3, Cpu, History, Monitor, RefreshCw, Search, X } from '@lucide/vue'
import { api } from '../api.js'
import { themePref } from '../themePrefs'
import MessageList from '../workbench/MessageList.vue'
import { createDshSession, summarizeTool, toolTitle } from '../workbench/dshClient.js'

const STEPS = ['构建环境', '启动服务', '探活诊断', '验证发布']
const SESSION_FILTERS = [{ value: 'all', label: '全部' }, { value: 'running', label: '运行中' }, { value: 'done', label: '已完成' }, { value: 'error', label: '异常' }]
const sessionSearch = ref('')
const sessionFilter = ref('all')
const loading = ref(true)
const refreshing = ref(false)
const lastUpdated = ref(null)
const refreshError = ref('')
const consoleError = ref('')
const stopping = ref('')
let consoleRevision = 0

const selected = ref('')
const sessions = ref([])
const envs = ref([])
const requests = ref([])
const consoleText = ref('')
const logService = ref('')
const consoleEl = ref(null)
let consoleFollow = true

const dsh = createDshSession('/emulagent')
provide('wbSession', dsh)
const flowEl = ref(null)
let timer = null
let consoleTimer = null

// 执行流跟随最新进展：回填完成时直接到底；之后节点变化只在用户
// 贴近底部时跟随（上滚浏览历史时不打扰）
async function scrollFlowBottom(force = false) {
  await nextTick()
  const el = flowEl.value?.querySelector('.root')
  if (!el) return
  if (!force) {
    const nearBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 120
    if (!nearBottom) return
  }
  el.scrollTop = el.scrollHeight
}
watch(() => dsh.state.nodes.length, () => scrollFlowBottom())
watch(() => dsh.state.loadingHistory, (v, old) => { if (old && !v) scrollFlowBottom(true) })

// 运行中置顶，其余按时间倒序
const chipSessions = computed(() => {
  const live = sessions.value.filter(s => s.status === 'running')
  const past = sessions.value.filter(s => s.status !== 'running')
    .sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')))
  return [...live, ...past]
})
const runningSessions = computed(() => sessions.value.filter(s => s.status === 'running' && !isZombie(s)))
const completedSessions = computed(() => sessions.value.filter(s => s.status !== 'running'))
const readyEnvs = computed(() => envs.value.filter(e => e.status === 'ready'))
const errorSessions = computed(() => sessions.value.filter(s => ['error', 'failed'].includes(s.status) || isZombie(s)))
const queuedRequests = computed(() => requests.value.filter(r => r.status === 'pending' || (r.status === 'working' && !r.emul_session)))
const filteredSessions = computed(() => {
  const query = sessionSearch.value.trim().toLowerCase()
  return chipSessions.value.filter(s => {
    const statusMatches = sessionFilter.value === 'all'
      || (sessionFilter.value === 'running' ? s.status === 'running' && !isZombie(s)
        : sessionFilter.value === 'error' ? ['error', 'failed'].includes(s.status) || isZombie(s)
        : s.status === sessionFilter.value)
    return statusMatches && (!query || [chipLabel(s), s.task, s.session_id, s.job_id].join(' ').toLowerCase().includes(query))
  })
})
const hasActivity = computed(() =>
  sessions.value.length > 0 || requests.value.length > 0 || envs.value.length > 0)
const selectedSession = computed(() =>
  sessions.value.find(s => s.session_id === selected.value))
const envsOf = sid => envs.value.filter(e => e.session_id === sid)
const activeEnv = computed(() => {
  const mine = envsOf(selected.value)
  return mine.find(e => e.status === 'ready')
    || mine.find(e => ['booting', 'degraded', 'built'].includes(e.status))
    || mine[mine.length - 1]
})

// 会话 chips：任务摘要代替裸 ID；失联（宿主已死仍标 running）单独标识
const isZombie = s => s.status === 'running' && s.host_alive === false
function taskGoal(s) {
  const task = String(s?.task || '')
  const goal = task.match(/(?:^|\n)目标[：:]\s*([\s\S]*?)(?=\n(?:要求|结构化上下文)[：:]|$)/)?.[1]
  return (goal || task.replace(/^\[模拟请求[^\]]*\][^\n]*\n?/, '')).trim()
}
function chipLabel(s) {
  const goal = taskGoal(s)
  const firstTarget = goal.match(/(?:^|\n)\s*1\)\s*([^\n]+)/)?.[1]
  return String(firstTarget || goal || (s.job_id ? '固件 ' + s.job_id : '模拟会话'))
    .replace(/（(?:firmware\/|usr\/)[^）]*）/g, '').replace(/\s+/g, ' ').trim().slice(0, 100)
}
const chipTone = s => isZombie(s) || ['error', 'failed'].includes(s.status) ? 'error' : s.status
const chipStatus = s => (isZombie(s) ? '失联' : statusText(s.status))
const chipTitle = s => [chipLabel(s), s.session_id, formatDate(s.created_at)].filter(Boolean).join('\n')
async function stopZombie(sid) {
  if (stopping.value) return
  stopping.value = sid
  try {
    await api(`/emulagent/sessions/${sid}/stop`, { method: 'POST' })
    await refreshAll()
  } catch { refreshError.value = '停止会话未成功，请稍后重试。' }
  finally { stopping.value = '' }
}

// 当前目标：优先本会话关联的请求（多会话并行时目标行不串台）
const sessionRequests = computed(() => {
  const sid = selected.value
  if (!sid) return requests.value
  const mine = requests.value.filter(r =>
    r.from_session === sid || r.emul_session === sid)
  return mine
})
const pendingRequests = computed(() =>
  sessionRequests.value.filter(x => ['pending', 'working'].includes(x.status)))
const currentGoal = computed(() => {
  const r = pendingRequests.value[0] || sessionRequests.value[0]
  return r?.goal || taskGoal(selectedSession.value) || ''
})
const overviewTitle = computed(() => {
  const session = selectedSession.value
  if (session) {
    if (isZombie(session)) return '宿主连接已中断'
    if (session.status === 'running') return currentAction.value
    return { done: '模拟执行已完成', error: '模拟执行失败', failed: '模拟执行失败', stopped: '模拟执行已停止', purged: '会话已清理' }[session.status] || statusText(session.status)
  }
  return queuedRequests.value.length ? '等待创建模拟会话' : '请选择一个模拟会话'
})

// 正在做什么：优先「正在运行的工具」，其次流式思考；都不是才看最后一步
function digestText(text) {
  return String(text || '')
    .replace(/[#*`>_~]+/g, ' ').replace(/\s+/g, ' ').trim()
    .slice(0, 80)
}
const currentAction = computed(() => {
  const nodes = [...(dsh.state?.nodes || [])].reverse()
  const runTool = nodes.find(n => n.kind === 'tool' && n.status === 'running' && n.name)
  if (runTool) return `${toolTitle(runTool.name)}：${summarizeTool(runTool)}`
  if (nodes.some(n => n.kind === 'reasoning' && n.streaming)) return '思考中'
  if (dsh.state?.running) {
    const lastText = nodes.find(n => n.kind === 'text')
    const lastTool = nodes.find(n => n.kind === 'tool' && n.name)
    if (lastText?.streaming) return digestText(lastText.text) || '输出中'
    if (lastTool) {
      return lastTool.status === 'running'
        ? `${toolTitle(lastTool.name)}：${summarizeTool(lastTool)}`
        : `刚完成「${toolTitle(lastTool.name)}」，继续分析中`
    }
    if (lastText) return digestText(lastText.text) || '等待模型输出'
    return nodes.length ? '等待下一步' : '等待模型响应'
  }
  return nodes.length ? '回合间隙 · 等待下一步' : '等待开始'
})

function statusText(s) {
  return { running: '运行中', done: '已完成', error: '失败', failed: '失败', stopped: '已停止',
           pending: '待处理', unknown: '状态未知', purged: '已清理' }[s] || s || '状态未知'
}
function envText(s) {
  return { ready: '就绪', built: '已构建', booting: '启动中', degraded: '待修复', stopped: '已停止', failed: '失败', purged: '已清理' }[s] || s || '待创建'
}
function formatDate(value) {
  if (!value) return '创建时间未记录'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '创建时间未记录'
  return date.toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
}
function formatTime(value) {
  return new Date(value).toLocaleTimeString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false })
}
function svcText(s) {
  return { ok: '正常', degraded: '待修复', stopped: '已停止',
           booting: '启动中', purged: '已清理' }[s] || s
}
function heroStepState(i) {
  const env = activeEnv.value
  const st = env?.status
  const svcOk = (env?.services || []).some(s => s.status === 'ok')
  if (!env) return selectedSession.value?.status === 'running' && !isZombie(selectedSession.value) && i === 0 ? 'now' : 'todo'
  if (st === 'ready') return 'ok'
  // 已停止/失败的环境不再伪装成「正在进行」：要么已走到的步骤记 ok，要么留空
  if (st === 'stopped' || st === 'failed') {
    if (i === 0) return 'ok'
    if (i === 1) return svcOk ? 'ok' : 'todo'
    return 'todo'
  }
  if (i === 0) return ['built', 'booting', 'degraded', 'ready'].includes(st) ? 'ok' : 'now'
  if (i === 1) return st === 'booting' ? 'now' : ['degraded', 'ready'].includes(st) ? 'ok' : 'todo'
  if (i === 2) return st === 'degraded' ? (svcOk ? 'ok' : 'now') : 'todo'
  return 'todo'
}

async function refreshAll() {
  if (refreshing.value) return
  refreshing.value = true
  try {
    const [sessionRows, envRows, requestRows] = await Promise.all([api('/emulagent/sessions'), api('/emul/envs'), api('/emul/requests')])
    sessions.value = Array.isArray(sessionRows) ? sessionRows : []
    envs.value = Array.isArray(envRows) ? envRows : []
    requests.value = Array.isArray(requestRows) ? requestRows : []
    lastUpdated.value = Date.now()
    refreshError.value = ''
  } catch { refreshError.value = '暂时无法同步模拟状态，已保留最近一次数据。' }
  finally { loading.value = false; refreshing.value = false }
  if (selected.value && !selectedSession.value) {
    selected.value = ''
    dsh.detach()
    consoleRevision += 1
    consoleText.value = ''
  }
  if (!selected.value && chipSessions.value.length) {
    select(chipSessions.value[0].session_id)
  }
  if (selected.value && dsh.state.sid !== selected.value) {
    dsh.attach(selected.value, { expectRunning: selectedSession.value?.status === 'running' })
      .catch(() => {})
  }
}

async function refreshConsole() {
  const revision = ++consoleRevision
  const env = activeEnv.value
  consoleError.value = ''
  if (!env) { consoleText.value = ''; return }
  try {
    const out = await api(`/emul/envs/${env.env_id}/console`, {
      method: 'POST', body: { service: logService.value || null, tail: 100 },
    })
    if (revision !== consoleRevision) return
    consoleText.value = Object.entries(out || {})
      .map(([name, v]) => `── ${name} ──\n${v.console || ''}`)
      .join('\n')
  } catch { if (revision === consoleRevision) consoleError.value = '日志读取暂不可用，将自动重试。' }
}

// 日志面板：默认跟随到底，用户上滚即暂停跟随
function onConsoleScroll() {
  const el = consoleEl.value
  if (!el) return
  consoleFollow = el.scrollTop + el.clientHeight >= el.scrollHeight - 24
}
watch(consoleText, async () => {
  if (!consoleFollow) return
  await nextTick()
  const el = consoleEl.value
  if (el) el.scrollTop = el.scrollHeight
})

function select(sid) {
  if (selected.value === sid && dsh.state.sid === sid) return
  selected.value = sid
  consoleText.value = ''
  logService.value = ''
  consoleFollow = true
  const s = sessions.value.find(x => x.session_id === sid)
  dsh.attach(sid, { expectRunning: s?.status === 'running' })
    .then(() => scrollFlowBottom(true)).catch(() => {})
  refreshConsole()
}

// 「查看」调用详情
const inspectOpen = ref(false)
const inspectNode = ref(null)
function onInspect(node) {
  inspectNode.value = node
  inspectOpen.value = true
}
function prettyJson(raw) {
  try { return JSON.stringify(JSON.parse(raw), null, 2) } catch { return raw || '' }
}
function fmtTs(ts) {
  const d = new Date(Number(ts))
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString()
}

watch(logService, () => { consoleFollow = true; refreshConsole() })
watch(() => activeEnv.value?.env_id, () => { consoleText.value = ''; consoleFollow = true; refreshConsole() })

onMounted(() => {
  refreshAll()
  timer = setInterval(refreshAll, 6000)
  consoleTimer = setInterval(refreshConsole, 5000)
})
onBeforeUnmount(() => {
  consoleRevision += 1
  if (timer) clearInterval(timer)
  if (consoleTimer) clearInterval(consoleTimer)
  dsh.detach()
})
</script>

<style scoped>
@import '../workbench/tokens.css';
.emul { min-height: 100%; max-width: 1540px; margin: 0 auto; padding: 30px 38px 52px; display: flex; flex-direction: column; gap: 22px; color: var(--fw-text); }
.emul-heading { display: flex; align-items: flex-end; justify-content: space-between; gap: 20px; }
.kicker, .section-eyebrow, .pane-eyebrow { margin: 0 0 8px; color: var(--fw-text-3); font-size: 10px; letter-spacing: .16em; text-transform: uppercase; font-weight: 650; }
.heading-row { display: flex; align-items: center; gap: 18px; }
.emul h1 { margin: 0; font-size: 28px; line-height: 1.15; letter-spacing: -.02em; }
.sub { margin: 8px 0 0; color: var(--fw-text-2); font-size: 13px; }
.readonly-badge, .live-pill { display: inline-flex; align-items: center; gap: 7px; border: 1px solid var(--fw-line); border-radius: 999px; padding: 6px 10px; color: var(--fw-text-2); font-size: 11px; white-space: nowrap; }
.readonly-badge i, .live-pill i { width: 7px; height: 7px; display: inline-block; border-radius: 50%; background: var(--fw-text-3); }
.live-pill[data-running] { color: var(--fw-ok); border-color: color-mix(in srgb, var(--fw-ok) 45%, var(--fw-line)); }
.live-pill[data-running] i { background: var(--fw-ok); box-shadow: 0 0 0 4px color-mix(in srgb, var(--fw-ok) 14%, transparent); }
.refresh-note { color: var(--fw-text-3); font-size: 11px; white-space: nowrap; }
.refresh-dot { display: inline-block; width: 6px; height: 6px; margin-right: 5px; border-radius: 50%; background: var(--fw-brand); }
.pane { background: var(--fw-surface); border: 1px solid var(--fw-line); border-radius: 14px; overflow: hidden; }
.empty-state { min-height: 360px; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; padding: 40px; }
.empty-icon { width: 54px; height: 54px; display: grid; place-items: center; border-radius: 16px; background: var(--fw-fill); color: var(--fw-brand); font-size: 30px; }
.empty-state h2 { margin: 18px 0 6px; font-size: 18px; }
.empty-state p { max-width: 460px; margin: 0; color: var(--fw-text-3); font-size: 12px; line-height: 1.8; }
.overview { display: grid; grid-template-columns: minmax(0, 1.7fr) minmax(250px, .7fr); padding: 24px 26px; gap: 30px; background: linear-gradient(120deg, color-mix(in srgb, var(--fw-brand) 7%, var(--fw-surface)), var(--fw-surface)); }
.overview-label { margin-bottom: 10px; color: var(--fw-text-3); font-size: 11px; }
.overview-status { display: flex; align-items: center; gap: 10px; font-size: 18px; }
.status-orb { width: 10px; height: 10px; border-radius: 50%; background: var(--fw-text-3); }
.status-orb[data-live] { background: var(--fw-ok); box-shadow: 0 0 0 5px color-mix(in srgb, var(--fw-ok) 15%, transparent); }
.overview-goal { display: flex; gap: 12px; margin: 14px 0 20px; color: var(--fw-text-2); font-size: 12px; line-height: 1.6; }
.overview-goal span { flex: none; color: var(--fw-text-3); }
.overview-env { display: flex; flex-direction: column; justify-content: center; padding-left: 26px; border-left: 1px solid var(--fw-line); }
.overview-env strong { font-size: 15px; }
.env-id { margin-top: 8px; color: var(--fw-text-3); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.env-facts { display: flex; gap: 14px; margin-top: 18px; color: var(--fw-text-2); font-size: 11px; }
.hero-steps { display: flex; gap: 0; margin: 0; padding: 0; list-style: none; }
.hero-steps li { display: flex; align-items: center; gap: 7px; flex: 1; color: var(--fw-text-3); font-size: 11px; white-space: nowrap; }
.hero-steps li:not(:last-child)::after { content: ''; height: 2px; flex: 1; margin: 0 10px; border-radius: 2px; background: var(--fw-line); }
.hero-steps li[data-st=ok] { color: var(--fw-ok); } .hero-steps li[data-st=ok] .pt { background: var(--fw-ok); } .hero-steps li[data-st=ok]:not(:last-child)::after { background: var(--fw-ok); }
.hero-steps li[data-st=now] { color: var(--fw-warn); font-weight: 650; } .hero-steps li[data-st=now] .pt { background: var(--fw-warn); box-shadow: 0 0 0 4px color-mix(in srgb, var(--fw-warn) 14%, transparent); }
.pt { width: 8px; height: 8px; flex: none; border-radius: 50%; background: var(--fw-line-strong); }
.metric-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
.metric-card { display: flex; align-items: center; gap: 12px; min-height: 86px; padding: 17px 18px; background: var(--fw-surface); border: 1px solid var(--fw-line); border-radius: 12px; }
.metric-icon { width: 30px; height: 30px; display: grid; place-items: center; border-radius: 9px; font-size: 15px; }
.metric-icon.blue { color: #75a8ff; background: rgba(71,126,235,.14); } .metric-icon.amber { color: #e6ad58; background: rgba(220,148,35,.14); } .metric-icon.green { color: #5ed2a0; background: rgba(45,177,121,.14); } .metric-icon.violet { color: #b19aff; background: rgba(126,93,229,.14); }
.metric-card div { min-width: 0; display: flex; flex-direction: column; gap: 3px; } .metric-card small { color: var(--fw-text-3); font-size: 11px; } .metric-card b { font-size: 22px; line-height: 1; font-variant-numeric: tabular-nums; } .metric-card em { color: var(--fw-text-3); font-size: 10px; font-style: normal; }
.section-head, .detail-titlebar { display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; }
.section-head h2, .detail-titlebar h2 { margin: 0; font-size: 18px; letter-spacing: -.01em; } .section-count, .pane-hint { color: var(--fw-text-3); font-size: 11px; }
.session-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 10px; margin-top: 12px; }
.session-card { min-width: 0; display: flex; flex-direction: column; align-items: flex-start; gap: 7px; padding: 15px 16px; border: 1px solid var(--fw-line); border-radius: 11px; background: var(--fw-surface); color: inherit; text-align: left; cursor: pointer; transition: border-color .18s, box-shadow .18s, transform .18s; }
.session-card:hover { border-color: var(--fw-line-strong); transform: translateY(-1px); } .session-card.selected { border-color: var(--fw-brand); box-shadow: 0 0 0 1px color-mix(in srgb, var(--fw-brand) 55%, transparent) inset; }
.session-top { width: 100%; display: flex; align-items: center; gap: 6px; color: var(--fw-text-3); font-size: 10px; } .session-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--fw-text-3); } .session-card.live .session-dot { background: var(--fw-warn); animation: emulp 1.4s ease-in-out infinite; } .session-card.zombie .session-dot { background: var(--fw-danger); }
.session-card strong { overflow: hidden; max-width: 100%; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; } .session-id { max-width: 100%; overflow: hidden; color: var(--fw-text-3); text-overflow: ellipsis; } .session-time { color: var(--fw-text-3); font-size: 10px; } .session-stop { margin-left: auto; color: var(--fw-danger); }
.detail-shell { display: flex; flex-direction: column; gap: 13px; } .detail-titlebar { align-items: center; padding-top: 4px; }
.detail-grid { display: grid; grid-template-columns: minmax(0, 1.55fr) minmax(300px, .85fr); gap: 14px; align-items: start; }
.pane-h { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 14px 17px; border-bottom: 1px solid var(--fw-line); } .pane-h h2 { margin: 0; font-size: 13px; } .pane-eyebrow { margin: 0 0 4px; font-size: 9px; }
.flow { display: flex; flex-direction: column; min-height: 470px; } .flow :deep(.root) { flex: 1; overflow-y: auto; max-height: clamp(380px, calc(100vh - 465px), 760px); } .flow :deep(.user-row .actions) { display: none; }
.rail { display: flex; flex-direction: column; gap: 14px; } .svc-rows { list-style: none; margin: 0; padding: 7px; display: flex; flex-direction: column; gap: 2px; } .svc-rows li { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 10px 9px; border-radius: 8px; cursor: pointer; } .svc-rows li:hover, .svc-rows li.on { background: var(--fw-fill); } .svc-rows li > span { min-width: 0; display: flex; flex-direction: column; gap: 5px; } .service-name { overflow: hidden; text-overflow: ellipsis; } .svc-rows strong { display: inline-flex; align-items: center; gap: 5px; color: var(--fw-text-2); font-size: 10px; font-weight: 550; } .svc-rows strong i { width: 6px; height: 6px; border-radius: 50%; background: var(--fw-text-3); } .svc-rows strong[data-st=ok] { color: var(--fw-ok); } .svc-rows strong[data-st=ok] i { background: var(--fw-ok); } .svc-rows strong[data-st=degraded] { color: var(--fw-danger); } .svc-rows strong[data-st=degraded] i { background: var(--fw-danger); }
.empty { margin: 15px 17px; color: var(--fw-text-3); font-size: 12px; } .filter-pill { max-width: 130px; overflow: hidden; padding: 3px 8px; border-radius: 5px; background: var(--fw-fill); color: var(--fw-text-2); font-family: var(--fw-font-mono); font-size: 10px; text-overflow: ellipsis; white-space: nowrap; } .console { margin: 0; min-height: 210px; max-height: 300px; padding: 15px 17px; overflow: auto; background: var(--fw-surface-2); color: var(--fw-text-2); font-family: var(--fw-font-mono); font-size: 10.5px; line-height: 1.7; white-space: pre-wrap; }
.inspect-body { display: flex; flex-direction: column; gap: 10px; } .inspect-title { margin: 0; font-size: 15px; font-weight: 600; } .inspect-title .mono-name { margin-left: 8px; color: var(--fw-text-3); font-family: var(--fw-font-mono); font-size: 12px; font-weight: 400; } .inspect-body h4 { margin: 6px 0 0; color: var(--fw-text-3); font-size: 12px; } .inspect-pre { max-height: 320px; margin: 0; padding: 10px 12px; overflow: auto; border: 1px solid var(--fw-line); border-radius: 9px; background: var(--fw-surface-2); color: var(--fw-text-2); font-family: var(--fw-font-mono); font-size: 11px; line-height: 18px; white-space: pre-wrap; word-break: break-word; } .inspect-pre[data-error] { color: var(--fw-danger); } .dim { color: var(--fw-text-3); font-size: 12px; } .mono { font-family: var(--fw-font-mono); font-size: 11px; }
@keyframes emulp { 0%, 100% { opacity: 1 } 50% { opacity: .28 } }
@media (max-width: 1100px) { .emul { padding: 26px 24px 44px; } .overview { grid-template-columns: 1fr; } .overview-env { padding: 18px 0 0; border-top: 1px solid var(--fw-line); border-left: 0; } .detail-grid { grid-template-columns: 1fr; } }
@media (max-width: 700px) { .emul { padding: 22px 16px 36px; gap: 18px; } .emul-heading { align-items: flex-start; flex-direction: column; gap: 12px; } .heading-row { align-items: flex-start; flex-direction: column; gap: 10px; } .emul h1 { font-size: 25px; } .refresh-note { align-self: flex-end; } .overview { min-width: 0; padding: 20px 18px; } .overview-main, .overview-env { min-width: 0; } .overview-status strong { min-width: 0; overflow-wrap: anywhere; } .overview-goal { min-width: 0; overflow-wrap: anywhere; } .hero-steps { overflow-x: auto; padding-bottom: 4px; } .hero-steps li { min-width: 105px; } .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } .metric-card { min-width: 0; min-height: 74px; padding: 13px; } .metric-card b { font-size: 19px; } .session-grid { grid-template-columns: 1fr; } .detail-titlebar { align-items: flex-start; flex-direction: column; } .flow { min-height: 380px; } .flow :deep(.root) { max-height: 520px; } }
.heading-actions { display: flex; align-items: center; gap: 12px; }
.quiet-button { display: inline-flex; align-items: center; justify-content: center; gap: 7px; border: 1px solid var(--fw-line); border-radius: 7px; padding: 8px 11px; background: var(--fw-surface); color: var(--fw-text-2); font: inherit; font-size: 12px; cursor: pointer; }
.quiet-button:hover { border-color: var(--fw-brand); color: var(--fw-brand); }
.quiet-button:disabled { opacity: .6; cursor: wait; }
.spinning { animation: emul-spin 1.2s linear infinite; }
.refresh-dot.offline { background: var(--fw-warn); }
.sync-notice { display: flex; align-items: center; justify-content: space-between; gap: 14px; margin: 0; padding: 12px 16px; border: 1px solid color-mix(in srgb,var(--fw-warn) 30%,var(--fw-line)); border-radius: 8px; background: var(--fw-surface); color: var(--fw-text-2); font-size: 12px; }
.sync-notice button { flex: none; border: 0; background: transparent; color: var(--fw-brand); cursor: pointer; }
.overview-main, .overview-env, .detail-titlebar > div, .flow, .rail { min-width: 0; }
.overview-status { line-height: 1.6; }
.status-orb { flex: none; }
.overview-status strong { min-width: 0; overflow-wrap: anywhere; }
.overview-status[data-status='error'] { color: var(--fw-danger); }
.overview-status[data-status='error'] .status-orb { background: var(--fw-danger); }
.overview-status[data-status='done'] .status-orb { background: var(--fw-ok); }
.goal-detail { margin: 13px 0 18px; padding: 10px 12px; border: 1px solid var(--fw-line); border-radius: 7px; }
.goal-detail summary { display: flex; align-items: center; justify-content: space-between; gap: 10px; cursor: pointer; list-style: none; color: var(--fw-text-2); font-size: 12px; }
.goal-detail summary::-webkit-details-marker { display: none; }
.goal-detail[open] summary svg { transform: rotate(180deg); }
.goal-detail p { margin: 12px 0 0; color: var(--fw-text-2); font-size: 12px; line-height: 1.85; white-space: pre-wrap; overflow-wrap: anywhere; }
.overview-env .overview-label { display: flex; align-items: center; gap: 6px; }
.env-title { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.env-badge { font-size: 11px; color: var(--fw-text-3); }
.env-badge[data-status='ready'] { color: var(--fw-ok); }
.env-badge:is([data-status='failed'],[data-status='degraded']) { color: var(--fw-warn); }
.metric-icon { flex: none; width: 34px; height: 34px; }
.metric-card { min-height: 94px; }
.metric-card small { font-size: 12px; }
.metric-card em { line-height: 1.6; font-size: 11px; }
.metric-card b { font-size: 25px; padding: 2px 0; }
.section-description { margin: 7px 0 0; color: var(--fw-text-3); font-size: 12px; }
.session-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin: 16px 0 12px; }
.session-filters { display: flex; gap: 3px; padding: 4px; border: 1px solid var(--fw-line); border-radius: 8px; background: var(--fw-surface); }
.session-filters button { padding: 7px 13px; border: 0; border-radius: 5px; background: transparent; color: var(--fw-text-3); font: inherit; font-size: 12px; cursor: pointer; }
.session-filters button.on { background: var(--fw-fill); color: var(--fw-brand); }
.session-search { display: flex; align-items: center; gap: 8px; width: min(360px, 45%); min-width: 0; padding: 9px 11px; border: 1px solid var(--fw-line); border-radius: 7px; background: var(--fw-surface); color: var(--fw-text-3); }
.session-search input { width: 100%; min-width: 0; border: 0; outline: 0; background: transparent; color: var(--fw-text); font: inherit; font-size: 12px; }
.session-search input::placeholder { color: var(--fw-text-3); }
.session-search button { display: grid; place-items: center; border: 0; background: transparent; color: var(--fw-text-3); cursor: pointer; }
.session-search:focus-within { border-color: var(--fw-brand); }
.session-card { display: block; padding: 0; position: relative; cursor: default; }
.session-select { display: flex; flex-direction: column; align-items: flex-start; gap: 9px; width: 100%; min-width: 0; padding: 16px; border: 0; border-radius: inherit; background: transparent; color: inherit; text-align: left; cursor: pointer; font: inherit; }
.session-card strong { display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 2; min-height: 40px; line-height: 1.6; white-space: normal; overflow-wrap: anywhere; }
.session-top, .session-time, .session-id { font-size: 11px; }
.selected-check { margin-left: auto; color: var(--fw-brand); }
.session-card[data-status='error'] .session-dot { background: var(--fw-danger); }
.session-card[data-status='error'] .session-top { color: var(--fw-danger); }
.session-card[data-status='done'] .session-dot { background: var(--fw-ok); }
.session-stop { display: block; margin: 0 16px 12px; padding: 5px 0; border: 0; background: transparent; font: inherit; font-size: 11px; cursor: pointer; }
.filter-empty { display: flex; flex-direction: column; align-items: center; gap: 14px; padding: 36px 20px; color: var(--fw-text-3); border: 1px dashed var(--fw-line); border-radius: 10px; font-size: 13px; }
.detail-titlebar h2 { font-size: 16px; line-height: 1.7; overflow-wrap: anywhere; }
.live-pill[data-status='error'] { color: var(--fw-danger); }
.live-pill[data-status='error'] i { background: var(--fw-danger); }
.svc-rows li { display: block; padding: 0; cursor: default; }
.svc-rows li:hover { background: transparent; }
.svc-rows button { display: flex; justify-content: space-between; align-items: center; gap: 10px; width: 100%; padding: 12px 9px; border: 0; border-radius: 7px; background: transparent; color: inherit; text-align: left; cursor: pointer; }
.svc-rows button:hover, .svc-rows button.on { background: var(--fw-fill); }
.svc-rows button > span { display: flex; flex-direction: column; gap: 6px; min-width: 0; }
.svc-rows strong { flex: none; font-size: 11px; }
.service-name { font-size: 12px; white-space: nowrap; }
.filter-pill { display: inline-flex; align-items: center; gap: 6px; border: 0; cursor: pointer; }
.console { line-height: 1.8; overflow-wrap: anywhere; border-radius: 0; }
.empty-link { display: inline-flex; align-items: center; gap: 8px; margin-top: 22px; padding: 10px 16px; border-radius: 7px; background: #326dd6; color: white; text-decoration: none; font-size: 12px; }
.empty-process { display: flex; align-items: center; gap: 14px; margin-top: 30px; color: var(--fw-text-3); font-size: 11px; }
.emul :is(button,a,summary):focus-visible { outline: 2px solid var(--fw-brand); outline-offset: 3px; }
@keyframes emul-spin { to { transform: rotate(360deg); } }
@media (max-width: 1100px) { .overview, .detail-grid { grid-template-columns: minmax(0,1fr); } }
@media (max-width: 700px) {
  .heading-actions { width: 100%; justify-content: space-between; }
  .session-toolbar { flex-direction: column; align-items: stretch; gap: 10px; }
  .session-search { width: 100%; }
  .session-filters { justify-content: space-between; }
  .session-filters button { flex: 1; padding: 7px 3px; }
  .session-grid { grid-template-columns: minmax(0,1fr); max-height: 390px; overflow: auto; padding: 3px; }
  .hero-steps { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap: 14px; overflow: visible; }
  .hero-steps li { min-width: 0; }
  .hero-steps li::after { display: none; }
  .metric-card { align-items: flex-start; gap: 9px; }
  .metric-card em { font-size: 10px; }
  .section-head { align-items: flex-start; }
  .section-count { flex: none; }
  .empty-state { padding: 28px 18px; }
  .empty-process { gap: 8px; }
}
@media (prefers-reduced-motion: reduce) { .spinning, .session-card.live .session-dot { animation: none; } .session-card { transition: none; } }
</style>
