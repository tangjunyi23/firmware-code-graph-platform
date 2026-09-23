<template>
  <div
    ref="frameRef"
    class="wb-root"
    :data-wb-theme="theme"
    :data-details-collapsed="!detailsOpen || undefined"
    :data-dragging="dragging || undefined"
  >
    <div
      class="wb-body"
      :style="bodyGrid"
    >
    <div v-if="isNarrow && railOpen" class="rail-mask" aria-hidden="true" @click="railOpen = false" />
    <aside class="wb-rail" :class="{ open: isNarrow && railOpen }">
      <SidebarJobs
        :active-sid="activeSid"
        :job-id="currentJobId"
        @select="onSelectSession"
        @select-job="onSelectJob"
        @new-session="onNewSession"
        @stop="onStopSession"
        @archive="onArchiveSession"
        @unarchive="onUnarchiveSession"
        @purge-archived="onPurgeArchived"
      />
    </aside>
    <main class="wb-main">
      <header class="stage-bar">
        <button
          v-if="isNarrow"
          type="button"
          class="rail-toggle"
          aria-label="打开对话列表"
          @click="railOpen = true"
        >
          <IconPanelLeftOutline16 :size="16" />
        </button>
        <span class="stage-title">{{ firmwareLabel || 'FWGraph' }}</span>
        <button
          v-if="activeSid"
          type="button"
          class="traj-btn"
          title="对话轨迹与工具调用统计 / 导出会话"
          @click="trajectoryOpen = true"
        >
          <IconChartColumn16 :size="15" />
          <span>统计</span>
          <span
            v-if="tokBadge"
            class="tok-badge"
            :title="`累计 ${tokBadge.total} tokens（输入 ${tokBadge.in} · 输出 ${tokBadge.out} · 缓存 ${tokBadge.cache}）· ${tokBadge.calls} 次调用`"
          >{{ tokBadge.total }}</span>
        </button>
      </header>
      <div class="conv" :data-phase="phase">
        <div class="scroll-wrap" v-show="phase === 'active'">
          <div
            ref="scrollEl"
            class="scroll-body"
            data-conversation-scroll
            @scroll="onScroll"
          >
            <MessageList
              v-if="activeSid"
              :session="session"
              @inspect="onInspect"
              @fork="onFork"
            />
          </div>
          <button
            v-if="showToBottom"
            type="button"
            class="to-bottom"
            :title="t('chat.toBottom')"
            @click="scrollToBottom"
          >
            <IconChevronDownOutline14 :size="16" />
          </button>
        </div>
        <div ref="seatRef" class="composer-seat" data-composer-seat>
          <div class="composer-stack" :class="{ 'composer-hero': phase === 'hero' }">
            <div v-if="phase === 'hero'" class="hero-copy">
              <h1>今天挖哪一块固件？</h1>
              <p>选一个已完成的分析任务，直接描述入口或漏洞类型。</p>
            </div>
            <div v-if="phase === 'hero'" class="hero-workspace-row">
              <button
                ref="chipRef"
                type="button"
                class="workspace"
                data-tour="wb-workspace"
                :aria-expanded="pickerOpen"
                :aria-label="t('hero.chooseWorkspace')"
                @click="pickerOpen = !pickerOpen"
              >
                <IconFolderClose16 v-if="!firmwareLabel" :size="16" class="folder" />
                <IconFolderOpen16 v-else :size="16" class="folder" />
                <span class="workspace-label">{{ firmwareLabel || t('hero.chooseWorkspace') }}</span>
                <IconChevronDownOutline14 :size="12" class="chevron" />
              </button>
              <WorkspacePicker
                :open="pickerOpen"
                :jobs="readyJobs"
                :selected-id="currentJobId"
                :anchor="chipRef"
                @close="pickerOpen = false"
                @pick="onPickJob"
              />
            </div>
            <QueueDock />
            <ApprovalPanel />
            <ContinueCapPanel @continued="catalog.refresh()" @ended="onStopCurrent" />
            <div class="end-cards-row">
              <EmulationOfferCard @answered="catalog.refresh()" />
              <SessionEndCard @new-hunt="onNewSession" />
            </div>
            <Composer
              :variant="phase === 'hero' ? 'hero' : 'composer'"
              :draft="draft"
              :job-id="currentJobId"
              :firmware-label="firmwareLabel"
              :running="session.state.running"
              :locked="sending"
              :notice="notice"
              @update:draft="draft = $event"
              @send="onSend"
              @stop="onInterruptCurrent"
              @steer="session.steerAll()"
              @request-workspace="pickerOpen = true"
            />
          </div>
        </div>
      </div>
    </main>

    <aside class="wb-details" v-show="detailsOpen">
      <DetailsPanel :node="inspected" @close="detailsOpen = false" />
    </aside>

    <div
      v-if="detailsOpen && cols.details > 0"
      class="handle"
      data-side="details"
      :style="{ left: (RAIL + cols.center) + 'px' }"
      :data-dragging="dragging === 'details' || undefined"
      @pointerdown="startDrag('details', $event)"
    />
    </div>

    <div class="overlay-layer" data-shell-overlay>
      <TrajectoryView v-if="trajectoryOpen" :session="session" @close="trajectoryOpen = false" />
      <SettingsOverlay
        v-if="settingsOpen"
        :session="session"
        :theme="theme"
        @update:theme="setTheme"
        @close="settingsOpen = false"
      />
    </div>
  </div>
</template>

<script setup>
import { computed, inject, nextTick, onBeforeUnmount, onMounted, provide, reactive, ref, watch } from 'vue'
import './tokens.css'
import SidebarJobs from './SidebarJobs.vue'
import MessageList from './MessageList.vue'
import Composer from './Composer.vue'
import QueueDock from './QueueDock.vue'
import EmulationOfferCard from './EmulationOfferCard.vue'
import SessionEndCard from './SessionEndCard.vue'
import ApprovalPanel from './ApprovalPanel.vue'
import ContinueCapPanel from './ContinueCapPanel.vue'
import DetailsPanel from './DetailsPanel.vue'
import TrajectoryView from './TrajectoryView.vue'
import SettingsOverlay from './SettingsOverlay.vue'
import WorkspacePicker from './WorkspacePicker.vue'
import { createDshSession } from './dshClient.js'
import { createCatalog } from './catalog.js'
import { api } from '../api.js'
import { t } from './locales.js'
import {
  DEFAULT_TASK, HUNT_TURNS, pipelineFinished
} from './pipeline.js'
import { IconFolderClose16, IconFolderOpen16, IconChevronDownOutline14, IconPanelLeftOutline16, IconChartColumn16 } from './icons.js'

const RAIL = 260

// ≤900px：会话栏转抽屉，主区单列
const isNarrow = ref(false)
const railOpen = ref(false)
let narrowMq = null
function onNarrowMq (e) {
  isNarrow.value = e.matches
  if (!e.matches) railOpen.value = false
}


const DETAILS_MIN = 300
const DETAILS_MAX = 520
const DETAILS_DEFAULT = 360
const CENTER_MIN = 640

function clampWidth (px, min, max) {
  return Math.min(max, Math.max(min, Math.round(px)))
}
function computeColumns (viewport, details) {
  const available = Math.max(0, viewport - RAIL)
  const d0 = details === 0 ? 0 : clampWidth(details, DETAILS_MIN, DETAILS_MAX)
  if (d0 + CENTER_MIN <= available) return { center: available - d0, details: d0 }
  if (DETAILS_MIN + CENTER_MIN <= available) {
    return { center: CENTER_MIN, details: Math.max(DETAILS_MIN, available - CENTER_MIN) }
  }
  return { center: available, details: 0 }
}

const theme = ref(localStorage.getItem('fwgraph_wb_theme') || 'light')
function setTheme (v) {
  theme.value = v
  localStorage.setItem('fwgraph_wb_theme', v)
}

const detailsPref = ref(DETAILS_DEFAULT)
const detailsOpen = ref(false)
const viewport = ref(typeof window !== 'undefined' ? window.innerWidth : 1280)
const dragging = ref(null)

const cols = computed(() => computeColumns(
  viewport.value,
  detailsOpen.value ? detailsPref.value : 0
))
const bodyGrid = computed(() => ({
  gridTemplateColumns: isNarrow.value
    ? 'minmax(0, 1fr)'
    : `${RAIL}px minmax(0, 1fr) ${cols.value.details}px`
}))

const frameRef = ref(null)
const scrollEl = ref(null)
const seatRef = ref(null)
const chipRef = ref(null)

function onResize () {
  const el = frameRef.value
  const w = el ? el.getBoundingClientRect().width : window.innerWidth
  if (w > 0) viewport.value = w
}

const session = createDshSession()
const catalog = createCatalog()
provide('wbSession', session)
provide('wbCatalog', catalog)
provide('wbTheme', theme)
provide('wbOpenSettings', () => { settingsOpen.value = true })
provide('wbOpenTrajectory', () => { trajectoryOpen.value = true })
provide('wbAccount', inject('wbAccount', ref(null)))


const trajectoryOpen = ref(false)
const settingsOpen = ref(false)
const pickerOpen = ref(false)
const inspected = ref(null)
const activeSid = ref(null)
const currentJobId = ref('')
const firmwareLabel = ref('')
const draft = ref('')
const sending = ref(false)
const notice = ref(null)
const sessionJobMap = reactive({})
const showToBottom = ref(false)

// token 实时徽章（dshClient usageTotals：每步 assistant/message 累加，
// 流式过程中随事件跳动）
function fmtBadge (n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M'
  if (n >= 1e3) return (n / 1e3).toFixed(0) + 'K'
  return String(n)
}
const tokBadge = computed(() => {
  const u = session.state.usageTotals
  if (!u || !u.calls) return null
  const total = u.input + u.output + u.cacheRead + u.cacheWrite
  return {
    total: fmtBadge(total),
    in: fmtBadge(u.input), out: fmtBadge(u.output),
    cache: fmtBadge(u.cacheRead + u.cacheWrite), calls: u.calls,
  }
})

const readyJobs = computed(() =>
  (catalog.state.jobs || []).filter((j) => pipelineFinished(j))
)
const phase = computed(() => (activeSid.value ? 'active' : 'hero'))

function writeSidQuery (sid) {
  const url = new URL(window.location.href)
  if (sid) url.searchParams.set('sid', sid)
  else url.searchParams.delete('sid')
  window.history.replaceState(null, '', url)
  try {
    if (sid) sessionStorage.setItem('fwgraph_wb_sid', sid)
    else sessionStorage.removeItem('fwgraph_wb_sid')
  } catch { /* private mode */ }
}

function restoreSid () {
  let sid = ''
  try {
    sid = new URL(window.location.href).searchParams.get('sid')
      || sessionStorage.getItem('fwgraph_wb_sid')
      || ''
  } catch {
    sid = ''
  }
  sid = String(sid || '').trim()
  if (!sid) return
  const sess = (catalog.state.sessions || []).find((s) => s.session_id === sid)
  onSelectSession({
    sid,
    jobId: sess?.job_id || sessionJobMap[sid] || ''
  })
}

function onSelectSession ({ sid, jobId, expectRunning = false }) {
  railOpen.value = false
  pickerOpen.value = false
  if (jobId) {
    currentJobId.value = jobId
    sessionJobMap[sid] = jobId
    const job = catalog.jobById(jobId)
    if (job) firmwareLabel.value = job.firmware
  }
  if (activeSid.value === sid) {
    if (expectRunning) session.state.running = true
    writeSidQuery(sid)
    return
  }
  session.detach()
  activeSid.value = sid
  writeSidQuery(sid)
  if (sid) session.attach(sid, { expectRunning })
}

function onSelectJob (job) {
  onPickJob(job)
}

function onPickJob (job) {
  pickerOpen.value = false
  if (!pipelineFinished(job)) {
    notice.value = { level: 'error', text: '该分析任务尚未完成，请到「分析任务」页等待或新建。' }
    return
  }
  notice.value = null
  currentJobId.value = job.job_id
  firmwareLabel.value = job.firmware
}

function onNewSession () {
  session.detach()
  activeSid.value = null
  writeSidQuery('')
  firmwareLabel.value = ''
  draft.value = ''
  notice.value = null
  pickerOpen.value = false
  inspected.value = null
  detailsOpen.value = false
}


async function onStopSession ({ sid }) {
  if (!sid) return
  try {
    await api(`/vulnagent/sessions/${sid}/stop`, { method: 'POST' })
    if (session.state.sid === sid) {
      try { await session.cancel() } catch { /* host may already be gone */ }
      session.state.running = false
    }
    catalog.refresh()
  } catch (err) {
    notice.value = { level: 'error', text: err.message || '停止失败' }
  }
}

function onInterruptCurrent () {
  session.cancel().catch(() => {})
  session.state.running = false
}

function onStopCurrent () {
  const sid = activeSid.value || session.state.sid
  if (sid) onStopSession({ sid })
  else session.cancel().catch(() => {})
}

async function onArchiveSession ({ sid }) {
  if (!sid) return
  try {
    await api(`/vulnagent/sessions/${sid}`, {
      method: 'PATCH', body: { archived: true }
    })
    if (session.state.sid === sid) session.state.running = false
    catalog.refresh()
  } catch (err) {
    notice.value = { level: 'error', text: err.message || '归档失败' }
  }
}

async function onUnarchiveSession ({ sid }) {
  if (!sid) return
  try {
    await api(`/vulnagent/sessions/${sid}`, {
      method: 'PATCH', body: { archived: false }
    })
    catalog.refresh()
  } catch (err) {
    notice.value = { level: 'error', text: err.message || '取消归档失败' }
  }
}

async function onPurgeArchived () {
  if (!window.confirm(t('session.purgeConfirm'))) return
  const archived = (catalog.state.sessions || []).filter((s) => s.archived)
  if (archived.some((s) => s.session_id === activeSid.value)) {
    session.detach()
    activeSid.value = null
    writeSidQuery('')
    draft.value = ''
    inspected.value = null
    detailsOpen.value = false
  }
  try {
    await api('/vulnagent/sessions/purge-archived', { method: 'POST' })
    catalog.refresh()
  } catch (err) {
    notice.value = { level: 'error', text: err.message || '删除已归档失败' }
  }
}

function onInspect (node) {
  inspected.value = node
  detailsOpen.value = true
}
function onFork (node) {
  if (node?.seq) session.fork(node.seq)
}

async function startHunt (job, userText) {
  const jobId = job.job_id
  const task = (userText || '').trim() || DEFAULT_TASK
  notice.value = { level: 'info', text: '正在进入对话…' }
  try {
    const sess = await api('/vulnagent/sessions', {
      method: 'POST',
      body: { task, job_id: jobId, mode: 'dynamic', max_turns: HUNT_TURNS }
    })
    currentJobId.value = jobId
    firmwareLabel.value = job.firmware
    sessionJobMap[sess.session_id] = jobId
    draft.value = ''
    notice.value = null
    if (!(catalog.state.sessions || []).some((s) => s.session_id === sess.session_id)) {
      catalog.state.sessions.unshift({
        session_id: sess.session_id,
        task,
        status: 'running',
        job_id: jobId,
        findings: [],
        archived: false
      })
    }
    onSelectSession({ sid: sess.session_id, jobId, expectRunning: true })
    catalog.refresh()
  } catch (err) {
    notice.value = { level: 'error', text: err.message || '挖掘未启动' }
  }
}

async function onSend () {
  if (sending.value) return
  const text = draft.value.trim() || DEFAULT_TASK
  const jobId = currentJobId.value
  if (!jobId) {
    notice.value = { level: 'error', text: t('placeholder.workspace') }
    pickerOpen.value = true
    return
  }
  notice.value = null
  if (activeSid.value && session.state.sid) {
    // 乐观上屏：发送瞬间插入本地用户消息（真实事件到达后确认复用），
    // 消除"点发送后卡一下才显示"（2026-09-23 用户反馈）
    session.pushLocalUser(text)
    sending.value = true
    try {
      if (session.state.huntStatus === 'awaiting_continue') {
        await session.continueHunt(HUNT_TURNS, text)
      } else if (['done', 'error', 'interrupted'].includes(session.state.huntStatus)) {
        await session.resumeHunt(text)
      } else {
        await session.prompt(text, 'queue')
      }
      draft.value = ''
    } catch (err) {
      notice.value = { level: 'error', text: err.message }
      if (session.state.huntStatus === 'awaiting_continue') {
        /* banner stays */
      }
    } finally {
      sending.value = false
    }
    return
  }
  const job = catalog.jobById(jobId)
  if (!job || !pipelineFinished(job)) {
    notice.value = { level: 'error', text: '请选择已完成的分析任务后再发送。' }
    return
  }
  sending.value = true
  try {
    await startHunt(job, text)
  } finally {
    sending.value = false
  }
}

// stick-to-bottom（2026-09-23 用户要求）：默认跟随 AI 进度滚动；
// 用户上滚即脱离（自由查看）；点"回到底部"或滚回底部即恢复跟随。
const followTail = ref(true)

function onScroll () {
  const el = scrollEl.value
  if (!el) return
  const gap = el.scrollHeight - el.scrollTop - el.clientHeight
  showToBottom.value = gap > 48
  // 程序滚动期间（scrollAnim 活跃）不判定脱离
  if (!scrollAnim) followTail.value = gap <= 48
}

function onContentGrow () {
  if (!followTail.value) return
  const el = scrollEl.value
  if (el) el.scrollTop = el.scrollHeight
}

let scrollAnim = 0
function animateScrollTo (el, top, ms = 320) {
  if (scrollAnim) cancelAnimationFrame(scrollAnim)
  const from = el.scrollTop
  const to = Math.max(0, top)
  if (Math.abs(to - from) < 2) {
    el.scrollTop = to
    onScroll()
    return
  }
  const t0 = performance.now()
  const ease = (t) => 1 - (1 - t) ** 3
  const step = (now) => {
    const p = Math.min(1, (now - t0) / ms)
    el.scrollTop = from + (to - from) * ease(p)
    if (p < 1) scrollAnim = requestAnimationFrame(step)
    else {
      scrollAnim = 0
      onScroll()
    }
  }
  scrollAnim = requestAnimationFrame(step)
}
function scrollToBottom () {
  const el = scrollEl.value
  if (!el) return
  followTail.value = true
  animateScrollTo(el, el.scrollHeight)
}
function jumpToBottom () {
  if (!el) return
  el.scrollTop = el.scrollHeight
  onScroll()
}

watch([activeSid, () => session.state.loadingHistory], async ([sid, loading]) => {
  if (!sid || loading) return
  await nextTick()
  jumpToBottom()
})


// 内容增长（AI 流式输出/新节点）时若处于跟随态则贴底
watch(() => session.state.rev, async () => {
  if (!followTail.value) return
  await nextTick()
  onContentGrow()
})
let seatObs = null
watch(seatRef, (seat) => {
  if (seatObs) { seatObs.disconnect(); seatObs = null }
  if (!seat || !scrollEl.value) return
  seatObs = new ResizeObserver(() => {
    scrollEl.value.style.setProperty('--dsh-composer-height', `${seat.offsetHeight}px`)
  })
  seatObs.observe(seat)
})

function startDrag (which, ev) {
  ev.preventDefault()
  ev.currentTarget.setPointerCapture?.(ev.pointerId)
  dragging.value = which
  const origin = ev.clientX
  const base = cols.value.details
  const onMove = (e) => {
    const dx = e.clientX - origin
    detailsPref.value = clampWidth(base - dx, DETAILS_MIN, DETAILS_MAX)
  }
  const onUp = () => {
    dragging.value = null
    window.removeEventListener('pointermove', onMove)
    window.removeEventListener('pointerup', onUp)
  }
  window.addEventListener('pointermove', onMove)
  window.addEventListener('pointerup', onUp)
}

let catalogTimer = null
let frameRo = null
onMounted(() => {
  narrowMq = window.matchMedia('(max-width: 900px)')
  onNarrowMq(narrowMq)
  narrowMq.addEventListener('change', onNarrowMq)
  const el = frameRef.value
  let raf = null
  if (el) {
    frameRo = new ResizeObserver(() => {
      raf ??= requestAnimationFrame(() => {
        raf = null
        onResize()
      })
    })
    frameRo.observe(el)
  }
  onResize()
  catalog.refresh().then(() => restoreSid())
  catalogTimer = setInterval(() => {
    if (typeof document !== 'undefined' && document.hidden) return
    catalog.refresh({ silent: true })
  }, 20000)
})
onBeforeUnmount(() => {
  session.detach()
  if (catalogTimer) clearInterval(catalogTimer)
  if (frameRo) frameRo.disconnect()
  if (seatObs) seatObs.disconnect()
  if (scrollAnim) cancelAnimationFrame(scrollAnim)
  if (narrowMq) narrowMq.removeEventListener('change', onNarrowMq)
})
</script>

<style scoped>
.wb-root {
  position: relative;
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  overflow: hidden;
  background: transparent;
  color: var(--dsw-alias-label-primary);
  font-family: var(--dsw-font-family);
}

.wb-rail {
  min-width: 0;
  overflow: hidden;
  background: var(--dsw-specific-sidebar-fill);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border-right: 1px solid var(--fw-line);
}
.rail-toggle {
  display: grid;
  place-items: center;
  width: 32px;
  height: 32px;
  flex: none;
  border: none;
  border-radius: 8px;
  background: transparent;
  color: var(--dsw-alias-label-secondary);
  cursor: pointer;
}
.rail-toggle:hover { background: var(--dsw-alias-interactive-bg-hover); color: var(--dsw-alias-label-primary); }
.rail-mask {
  position: fixed;
  inset: 0;
  z-index: 950;
  background: rgba(19, 18, 18, .42);
}
@media (max-width: 900px) {
  .wb-rail {
    position: fixed;
    inset: 0 auto 0 0;
    z-index: 960;
    width: min(300px, 84vw);
    transform: translateX(-102%);
    transition: transform .22s ease;
  }
  .wb-rail.open { transform: translateX(0); box-shadow: var(--fw-shadow-lg); }
}
.wb-body {
  position: relative;
  display: grid;
  flex: 1;
  min-height: 0;
  overflow: hidden;
  transition: grid-template-columns var(--ds-transition-duration-slow) var(--ds-ease-in-out);
}
.wb-root[data-dragging] .wb-body { transition: none; }
@media (prefers-reduced-motion: reduce) {
  .wb-body { transition: none; }
}
.wb-main {
  min-width: 0;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.stage-bar {
  flex: none;
  display: flex;
  align-items: center;
  height: 48px;
  padding: 0 20px;
}
.tok-badge {
  margin-left: 2px; padding: 1px 7px;
  border-radius: 999px; font-size: 11px; font-weight: 600;
  color: var(--fw-brand, #5b8cff);
  background: rgba(91, 140, 255, .12);
  font-variant-numeric: tabular-nums;
}
.stage-title {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 14px;
  font-weight: 600;
  color: var(--dsw-alias-label-primary);
}
.traj-btn {
  display: inline-flex; align-items: center; gap: 5px;
  margin-left: 12px; padding: 4px 10px;
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 8px; background: transparent;
  color: inherit; font-size: 12px; cursor: pointer;
}
.traj-btn:hover { background: var(--dsw-alias-interactive-bg-hover); }
.hero-copy {
  padding: 0 20px 8px;
  text-align: left;
}
.hero-copy h1 {
  margin: 0 0 8px;
  font-size: 28px;
  font-weight: 650;
  letter-spacing: -0.04em;
  color: var(--dsw-alias-label-primary);
}
.hero-copy p {
  margin: 0;
  font-size: 14px;
  color: var(--dsw-alias-label-tertiary);
}
.wb-details {
  min-width: 0;
  overflow: hidden;
  border-left: 1px solid var(--dsw-alias-border-l2);
}
.wb-root[data-details-collapsed] .wb-details { border-left: none; }

.conv {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-width: 0;
  background: transparent;
  /* 2026-09-23：748px 的旧覆盖是"对话窄"的真凶——tokens 层的值一直被
     它压住。按用户要求拉满：留少量页边距的近全宽（大屏自动到顶）。 */
  --dsh-chat-content-width: min(1760px, calc(100% - 24px));
  --dsh-composer-card-max-width: calc(var(--dsh-chat-content-width) + 32px);
  --dsh-composer-side-clearance: 12px;
  --dsh-composer-dock-inset: 8px;
  --dsh-composer-stack-gap: 6px;
  --dsh-composer-text-max-height: 336px;
}

.end-cards-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
  max-width: var(--dsh-chat-content-width);
  margin: 0 auto;
  width: 100%;
}
.end-cards-row > :deep(.emu-card),
.end-cards-row > :deep(.end-card) {
  margin: 0;
  max-width: none;
  width: 100%;
}
@media (max-width: 900px) {
  .end-cards-row { grid-template-columns: 1fr; }
}
.scroll-body {
  display: flex;
  flex: 1;
  flex-direction: column;
  min-height: 0;
  overflow-y: auto;
  overflow-x: hidden;
  scrollbar-gutter: stable;
}
.scroll-wrap {
  position: relative;
  display: none;
  flex: 1 1 auto;
  min-height: 0;
}
.conv[data-phase='active'] .scroll-wrap {
  display: flex;
  flex-direction: column;
}
.conv[data-phase='hero'] { justify-content: center; }
.conv[data-phase='active'] { overflow: hidden; }

.composer-seat {
  display: flex;
  flex: none;
  flex-direction: column;
  z-index: 7;
}
.conv[data-phase='active'] .composer-seat {
  background: linear-gradient(
    180deg,
    color-mix(in srgb, var(--dsw-alias-bg-base) 0%, transparent) 0px,
    var(--dsw-alias-bg-base) 28px
  );
}
.composer-stack {
  display: flex;
  flex-direction: column;
  gap: var(--dsh-composer-stack-gap);
}
.composer-hero {
  position: relative;
  align-self: center;
  gap: 8px;
  padding-bottom: 32px;
  width: min(calc(var(--dsh-composer-card-max-width) + 2 * var(--dsh-composer-side-clearance)), 100%);
  z-index: 1;
}
.hero-workspace-row {
  position: relative;
  display: flex;
  align-items: center;
  gap: 2px;
  min-width: 0;
  margin-top: 4px;
  padding-left: 20px;
  z-index: 10;
}
.workspace {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  max-width: min(100%, 360px);
  min-height: 28px;
  padding: 0 8px;
  border: none;
  border-radius: 16px;
  background: transparent;
  color: var(--dsw-alias-label-primary);
  font-size: 13px;
  line-height: 20px;
  font-weight: 500;
  cursor: pointer;
}
.workspace:hover,
.workspace[aria-expanded='true'] { background: var(--dsw-alias-interactive-bg-hover); }
.folder { flex: none; }
.workspace-label {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.chevron { flex: none; color: var(--dsw-alias-label-caption); }

.to-bottom {
  position: absolute;
  right: max(16px, calc((100% - var(--dsh-chat-content-width)) / 2));
  bottom: 16px;
  z-index: 8;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 34px;
  height: 34px;
  padding: 0;
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 100px;
  color: var(--dsw-alias-label-primary);
  background: var(--dsw-alias-button-floating-fill);
  box-shadow: var(--dsw-shadow-lv2);
  cursor: pointer;
  transition: transform .18s ease, opacity .18s ease;
}
.to-bottom:hover { background: var(--dsw-alias-button-floating-hover); }

.handle {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 8px;
  margin-left: -4px;
  cursor: col-resize;
  z-index: 2;
  touch-action: none;
  transition: left var(--ds-transition-duration-slow) var(--ds-ease-in-out);
}
.wb-root[data-dragging] .handle { transition: none; }
.handle[data-side='details']::after {
  content: '';
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 12px;
  height: 32px;
  border-radius: 10px;
  box-sizing: border-box;
  background: var(--dsw-alias-button-floating-fill);
  border: 1px solid var(--dsw-alias-border-l2-darkmode-thin);
  opacity: 0;
  transition: opacity var(--ds-transition-duration-slow) var(--ds-ease-in-out),
    background var(--ds-transition-duration-slow) var(--ds-ease-in-out);
}
.wb-details:hover ~ .handle[data-side='details']::after,
.handle[data-side='details']:hover::after,
.handle[data-side='details'][data-dragging]::after { opacity: 1; }
.handle[data-side='details']:hover::after,
.handle[data-side='details'][data-dragging]::after {
  background: var(--dsw-alias-button-floating-hover);
  border-color: var(--dsw-alias-border-l3);
}

.overlay-layer {
  position: absolute;
  inset: 0;
  z-index: 20;
  pointer-events: none;
}
.overlay-layer > * { pointer-events: auto; }

.wb-upload-toast {
  position: absolute;
  bottom: 24px;
  left: 50%;
  transform: translateX(-50%);
  padding: 8px 16px;
  border-radius: 999px;
  background: var(--dsw-alias-label-primary);
  color: var(--dsw-alias-bg-base);
  font-size: 13px;
  box-shadow: var(--dsw-shadow-lv2);
  z-index: 30;
}
</style>
