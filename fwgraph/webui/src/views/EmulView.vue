<template>
  <div class="emul wb-root" :data-wb-theme="themePref">
    <header class="ins-head">
      <div>
        <p class="kicker">固件工具</p>
        <h1>固件模拟</h1>
        <p class="sub">由漏洞挖掘 agent 自动发起 · 全程只读观察</p>
      </div>
    </header>

    <!-- 默认状态：暂无模拟 -->
    <p v-if="!hasActivity" class="idle">当前没有固件模拟。挖掘 agent 完成静态结论后会自动发起，届时此处实时展示进度。</p>

    <template v-else>
      <!-- 当前进度：用户一眼看到模拟走到哪一步 -->
      <section class="hero" aria-label="模拟进度">
        <ol class="hero-steps">
          <li v-for="(s, i) in STEPS" :key="s" :data-st="heroStepState(i)">
            <i class="pt" />{{ s }}
          </li>
        </ol>
        <div class="hero-now">
          <template v-if="selectedSession && selectedSession.status === 'running'">
            <span class="pulse" />进行中 · {{ currentAction }}
          </template>
          <template v-else-if="pendingRequests.length">
            <span class="pulse" />排队中 · 等待模拟 agent 接单（{{ pendingRequests[0].goal.slice(0, 50) }}）
          </template>
          <template v-else-if="selectedSession">
            已结束 · {{ statusText(selectedSession.status) }}
          </template>
          <template v-else-if="chipSessions.length">选择一个会话查看</template>
          <template v-else>暂无会话</template>
        </div>
        <div v-if="activeEnv" class="hero-meta">
          <span>第 {{ activeEnv.iterations }} 轮迭代</span>
          <span v-if="activeEnv.arch">{{ activeEnv.arch }}</span>
          <span>{{ Math.round((activeEnv.disk_bytes || 0) / 1048576) }}MiB</span>
          <span class="mono">{{ activeEnv.env_id }}</span>
        </div>
        <p v-if="currentGoal" class="hero-goal">目标：{{ currentGoal }}</p>
      </section>

      <!-- 会话切换：紧凑横条 -->
      <nav class="chips" aria-label="模拟会话">
        <button v-for="s in chipSessions" :key="s.session_id" type="button"
                class="chip" :class="{ sel: s.session_id === selected, live: s.status === 'running' && !isZombie(s) }"
                :title="chipTitle(s)"
                @click="select(s.session_id)">
          <i v-if="s.status === 'running'" class="dot" :data-zombie="isZombie(s) || undefined" />
          <span class="chip-label">{{ chipLabel(s) }}</span>
          <span class="dim" :data-zombie="isZombie(s) || undefined">{{ chipStatus(s) }}</span>
          <span v-if="isZombie(s)" class="chip-stop"
                title="宿主进程已失联，停止并归档该会话（释放并发额度）"
                @click.stop="stopZombie(s.session_id)">停止</span>
        </button>
      </nav>

      <!-- 执行流 + 服务日志 -->
      <div v-if="selected" class="detail-grid">
        <section ref="flowEl" class="pane flow">
          <header class="pane-h"><h2>AI 执行流</h2></header>
          <MessageList :session="dsh" @inspect="onInspect" />
        </section>

        <aside class="rail">
          <section class="pane">
            <header class="pane-h"><h2>服务</h2></header>
            <ul v-if="activeEnv" class="svc-rows">
              <li v-for="sv in activeEnv.services" :key="sv.name"
                  :class="{ on: logService === sv.name }"
                  :title="logService === sv.name ? '点击取消过滤，显示全部服务日志' : '点击只看该服务日志'"
                  @click="logService = logService === sv.name ? '' : sv.name">
                <span class="mono">{{ sv.name }}</span>
                <span class="mono dim">{{ sv.guest_port }}→{{ sv.host_port }}</span>
                <b :data-st="sv.status">{{ svcText(sv.status) }}</b>
              </li>
            </ul>
            <p v-else class="empty">尚无环境</p>
          </section>

          <section class="pane">
            <header class="pane-h">
              <h2>日志</h2>
              <span v-if="logService" class="dim">仅 {{ logService }}</span>
            </header>
            <pre ref="consoleEl" class="console" @scroll="onConsoleScroll">{{ consoleText || '（暂无输出）' }}</pre>
          </section>
        </aside>
      </div>

      <!-- 调用详情抽屉：执行流里「查看」的落点 -->
      <el-drawer v-model="inspectOpen" title="调用详情" size="520px" direction="rtl">
        <div v-if="inspectNode" class="inspect-body">
          <p class="inspect-title">
            {{ toolTitle(inspectNode.name) }}
            <span class="mono-name">{{ inspectNode.name }}</span>
          </p>
          <p class="dim">
            {{ inspectNode.status === 'running' ? '运行中' : inspectNode.status === 'error' ? '失败' : inspectNode.status === 'stopped' ? '已停止' : '已完成' }}
            <template v-if="inspectNode.finishedTs || inspectNode.ts">
              · {{ fmtTs(inspectNode.finishedTs || inspectNode.ts) }}
            </template>
          </p>
          <h4>输入</h4>
          <pre class="inspect-pre">{{ prettyJson(inspectNode.argumentsText) || '（无）' }}</pre>
          <h4>输出</h4>
          <pre class="inspect-pre" :data-error="inspectNode.status === 'error' || undefined">{{
            inspectNode.resultText
            || (inspectNode.error ? JSON.stringify(inspectNode.error, null, 2) : '')
            || '（无输出）' }}</pre>
        </div>
      </el-drawer>
    </template>
  </div>
</template>

<script setup>
// 固件模拟（纯观察台）：进度大卡（走到哪一步 / 正在做什么 / 目标）
// + AI 执行流（思考与工具都回放）+ 服务/日志。无任何用户操作入口。
import { computed, nextTick, onBeforeUnmount, onMounted, provide, ref, watch } from 'vue'
import { api } from '../api.js'
import { themePref } from '../themePrefs'
import MessageList from '../workbench/MessageList.vue'
import { createDshSession, summarizeTool, toolTitle } from '../workbench/dshClient.js'

const STEPS = ['底座', '启动服务', '探活诊断', '就绪发布']

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
const chipLabel = s =>
  String(s.task || '').replace(/\s+/g, ' ').trim().slice(0, 18)
  || s.session_id.slice(2, 12)
const chipStatus = s => (isZombie(s) ? '失联' : statusText(s.status))
const chipTitle = s => [s.task, s.created_at].filter(Boolean).join('\n')
async function stopZombie(sid) {
  try {
    await api(`/emulagent/sessions/${sid}/stop`, { method: 'POST' })
  } catch { /* 轮询会兜底刷新 */ }
  refreshAll()
}

// 当前目标：优先本会话关联的请求（多会话并行时目标行不串台）
const sessionRequests = computed(() => {
  const sid = selected.value
  if (!sid) return requests.value
  const mine = requests.value.filter(r =>
    r.from_session === sid || r.emul_session === sid)
  return mine.length ? mine : requests.value
})
const pendingRequests = computed(() =>
  sessionRequests.value.filter(x => ['pending', 'working'].includes(x.status)))
const currentGoal = computed(() => {
  const r = pendingRequests.value[0] || sessionRequests.value[0]
  return r?.goal || ''
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
  return { running: '运行中', done: '已完成', error: '出错',
           purged: '已自动清理' }[s] || s || ''
}
function svcText(s) {
  return { ok: '正常', degraded: '待修复', stopped: '已停止',
           booting: '启动中', purged: '已清理' }[s] || s
}
function heroStepState(i) {
  const env = activeEnv.value
  const st = env?.status
  const svcOk = (env?.services || []).some(s => s.status === 'ok')
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
  try {
    sessions.value = await api('/emulagent/sessions')
    envs.value = await api('/emul/envs')
    requests.value = await api('/emul/requests')
  } catch { /* 轮询失败静默 */ }
  if (!selected.value && chipSessions.value.length) {
    select(chipSessions.value[0].session_id)
  }
  if (selected.value && dsh.state.sid !== selected.value) {
    dsh.attach(selected.value, { expectRunning: selectedSession.value?.status === 'running' })
      .catch(() => {})
  }
}

async function refreshConsole() {
  const env = activeEnv.value
  if (!env) { consoleText.value = ''; return }
  try {
    const out = await api(`/emul/envs/${env.env_id}/console`, {
      method: 'POST', body: { service: logService.value || null, tail: 100 },
    })
    consoleText.value = Object.entries(out || {})
      .map(([name, v]) => `── ${name} ──\n${v.console || ''}`)
      .join('\n')
  } catch { /* 静默 */ }
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
  selected.value = sid
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

onMounted(() => {
  refreshAll()
  timer = setInterval(refreshAll, 6000)
  consoleTimer = setInterval(refreshConsole, 5000)
})
onBeforeUnmount(() => {
  if (timer) clearInterval(timer)
  if (consoleTimer) clearInterval(consoleTimer)
  dsh.detach()
})
</script>

<style scoped>
@import '../workbench/tokens.css';

.emul { min-height: 100%; padding: 22px 26px 42px; display: flex; flex-direction: column; gap: 14px; }
.ins-head h1 { margin: 0; font-size: 22px; }
.kicker { margin: 0 0 4px; font-size: 12px; letter-spacing: .18em; color: var(--fw-text-3); text-transform: uppercase; }
.sub { margin: 6px 0 0; color: var(--fw-text-2); font-size: 13px; }
.dim { color: var(--fw-text-3); font-size: 12px; }
.mono { font-family: var(--fw-font-mono); font-size: 12px; }
.idle { margin: 48px auto; color: var(--fw-text-3); font-size: 13px; max-width: 520px; text-align: center; }

/* 进度大卡 */
.hero { background: var(--fw-surface); border: 1px solid var(--fw-line); border-radius: 14px; padding: 18px 20px; display: flex; flex-direction: column; gap: 12px; }
.hero-steps { list-style: none; display: flex; margin: 0; padding: 0; gap: 0; }
.hero-steps li { flex: 1; display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--fw-text-2); position: relative; padding: 6px 0; }
.hero-steps li:not(:last-child)::after { content: ''; flex: 1; height: 2px; background: var(--fw-line); margin: 0 12px; border-radius: 1px; }
.hero-steps li[data-st='ok'] { color: var(--fw-ok); font-weight: 600; }
.hero-steps li[data-st='ok'] .pt { background: var(--fw-ok); }
.hero-steps li[data-st='ok']:not(:last-child)::after { background: var(--fw-ok); }
.hero-steps li[data-st='now'] { color: var(--fw-warn); font-weight: 600; }
.hero-steps li[data-st='now'] .pt { background: var(--fw-warn); box-shadow: 0 0 0 4px rgba(217, 119, 6, .18); }
.pt { width: 10px; height: 10px; border-radius: 50%; background: var(--fw-line); flex: none; }
.hero-now { display: flex; align-items: center; gap: 8px; font-size: 13.5px; font-weight: 600; }
.pulse { width: 8px; height: 8px; border-radius: 50%; background: var(--fw-warn); animation: emulp 1.4s ease-in-out infinite; flex: none; }
@keyframes emulp { 0%, 100% { opacity: 1 } 50% { opacity: .25 } }
.hero-meta { display: flex; gap: 16px; color: var(--fw-text-2); font-size: 12px; flex-wrap: wrap; }
.hero-goal { margin: 0; font-size: 12.5px; color: var(--fw-text-2); }

/* 会话 chips */
.chips { display: flex; gap: 8px; flex-wrap: wrap; }
.chip { display: inline-flex; align-items: center; gap: 7px; border: 1px solid var(--fw-line); background: var(--fw-surface); border-radius: 999px; padding: 5px 12px; cursor: pointer; color: inherit; font-size: 12px; }
.chip:hover { border-color: var(--fw-accent, #2f6bff); }
.chip.sel { border-color: var(--fw-accent, #2f6bff); box-shadow: 0 0 0 1px var(--fw-accent, #2f6bff) inset; }
.chip.live .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--fw-warn); animation: emulp 1.4s ease-in-out infinite; }
.chip .dot[data-zombie] { background: var(--fw-text-3); animation: none; }
.chip-label { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.chip .dim[data-zombie] { color: var(--fw-warn); }
.chip-stop { flex: none; border: 1px solid var(--fw-line); border-radius: 999px; padding: 1px 8px; font-size: 11px; color: var(--fw-danger); cursor: pointer; }
.chip-stop:hover { border-color: var(--fw-danger); background: color-mix(in srgb, var(--fw-danger) 12%, transparent); }

/* 调用详情抽屉 */
.inspect-body { display: flex; flex-direction: column; gap: 10px; }
.inspect-title { margin: 0; font-size: 15px; font-weight: 600; }
.inspect-title .mono-name { margin-left: 8px; font-family: var(--fw-font-mono); font-size: 12px; color: var(--fw-text-3); font-weight: 400; }
.inspect-body h4 { margin: 6px 0 0; font-size: 12px; color: var(--fw-text-3); }
.inspect-pre { margin: 0; padding: 10px 12px; background: var(--fw-surface-2); border: 1px solid var(--fw-line); border-radius: 10px; font-family: var(--fw-font-mono); font-size: 11.5px; line-height: 18px; white-space: pre-wrap; word-break: break-word; max-height: 320px; overflow: auto; color: var(--fw-text-2); }
.inspect-pre[data-error] { color: var(--fw-danger); }

/* 详情 */
.detail-grid { display: grid; grid-template-columns: minmax(0, 1.7fr) minmax(300px, 1fr); gap: 14px; align-items: start; }
@media (max-width: 1100px) { .detail-grid { grid-template-columns: 1fr; } }
.pane { background: var(--fw-surface); border: 1px solid var(--fw-line); border-radius: 14px; overflow: hidden; }
.pane-h { display: flex; align-items: center; gap: 10px; padding: 10px 14px; border-bottom: 1px solid var(--fw-line); }
.pane-h h2 { margin: 0; font-size: 13.5px; }
.flow { display: flex; flex-direction: column; min-height: 420px; }
/* 跟随视口预算：不与页面级滚动叠加（hero+chips 约占 330px） */
.flow :deep(.root) { flex: 1; overflow-y: auto; max-height: clamp(360px, calc(100vh - 400px), 760px); }
.flow :deep(.user-row .actions) { display: none; }
.rail { display: flex; flex-direction: column; gap: 14px; }
.empty { margin: 12px 14px; color: var(--fw-text-3); font-size: 12px; }

.svc-rows { list-style: none; margin: 0; padding: 6px; display: flex; flex-direction: column; gap: 2px; }
.svc-rows li { display: flex; justify-content: space-between; gap: 8px; align-items: center; font-size: 12px; padding: 5px 8px; border-radius: 7px; cursor: pointer; }
.svc-rows li.on { background: var(--fw-line); }
.svc-rows b { font-size: 11px; }
.svc-rows b[data-st='ok'] { color: var(--fw-ok); }
.svc-rows b[data-st='degraded'] { color: var(--fw-danger); }
.svc-rows b[data-st='stopped'] { color: var(--fw-text-3); }

.console { margin: 0; padding: 12px 14px; max-height: 260px; overflow: auto; font-family: var(--fw-font-mono); font-size: 11px; white-space: pre-wrap; background: var(--fw-surface-2); color: var(--fw-text-2); }
</style>
