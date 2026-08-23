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
      :style="{ gridTemplateColumns: `${RAIL}px minmax(0, 1fr) ${cols.details}px` }"
    >
    <aside class="wb-rail">
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
            <div v-if="phase === 'hero'" class="hero-workspace-row">
              <button
                ref="chipRef"
                type="button"
                class="workspace"
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
                @close="pickerOpen = false"
                @pick="onPickJob"
              />
            </div>
            <QueueDock />
            <ApprovalPanel />
            <ContinueCapPanel @continued="catalog.refresh()" @ended="onStopCurrent" />
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
import { computed, onBeforeUnmount, onMounted, provide, reactive, ref, watch } from 'vue'
import './tokens.css'
import SidebarJobs from './SidebarJobs.vue'
import MessageList from './MessageList.vue'
import Composer from './Composer.vue'
import QueueDock from './QueueDock.vue'
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
import { IconFolderClose16, IconFolderOpen16, IconChevronDownOutline14 } from './icons.js'

const RAIL = 280
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

const readyJobs = computed(() =>
  (catalog.state.jobs || []).filter((j) => pipelineFinished(j))
)
const phase = computed(() => (activeSid.value ? 'active' : 'hero'))

function onSelectSession ({ sid, jobId, expectRunning = false }) {
  pickerOpen.value = false
  if (jobId) {
    currentJobId.value = jobId
    sessionJobMap[sid] = jobId
    const job = catalog.jobById(jobId)
    if (job) firmwareLabel.value = job.firmware
  }
  if (activeSid.value === sid) {
    if (expectRunning) session.state.running = true
    return
  }
  session.detach()
  activeSid.value = sid
  if (sid) session.attach(sid, { expectRunning })
}

function onSelectJob (job) {
  onPickJob(job)
}

function onPickJob (job) {
  pickerOpen.value = false
  if (!pipelineFinished(job)) {
    notice.value = { level: 'error', text: '该前置任务尚未完成，请到「前置任务」页等待或新建。' }
    return
  }
  notice.value = null
  currentJobId.value = job.job_id
  firmwareLabel.value = job.firmware
}

function onNewSession () {
  session.detach()
  activeSid.value = null
  currentJobId.value = ''
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
    notice.value = { level: 'error', text: '请选择已完成的前置任务后再发送。' }
    return
  }
  sending.value = true
  try {
    await startHunt(job, text)
  } finally {
    sending.value = false
  }
}

const follow = ref(true)
function onScroll () {
  const el = scrollEl.value
  if (!el) return
  const gap = el.scrollHeight - el.scrollTop - el.clientHeight
  follow.value = gap <= 24
  showToBottom.value = gap > 48
}
function scrollToBottom () {
  const el = scrollEl.value
  if (!el) return
  el.scrollTop = el.scrollHeight
  follow.value = true
  showToBottom.value = false
}
let scrollRaf = 0
watch(() => session.state.rev, () => {
  if (!follow.value) return
  if (scrollRaf) return
  scrollRaf = requestAnimationFrame(() => {
    scrollRaf = 0
    scrollToBottom()
  })
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
  catalog.refresh()
  catalogTimer = setInterval(() => catalog.refresh(), 5000)
})
onBeforeUnmount(() => {
  session.detach()
  if (catalogTimer) clearInterval(catalogTimer)
  if (frameRo) frameRo.disconnect()
  if (seatObs) seatObs.disconnect()
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
  background: var(--dsw-alias-bg-base);
  color: var(--dsw-alias-label-primary);
  font-family: var(--dsw-font-family);
}
.wb-rail {
  min-width: 0;
  overflow: hidden;
  background: var(--dsw-specific-sidebar-fill);
  border-right: 1px solid var(--dsw-alias-border-l1);
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
  background: var(--dsw-alias-bg-base);
  --dsh-chat-content-width: 748px;
  --dsh-composer-card-max-width: calc(var(--dsh-chat-content-width) + 32px);
  --dsh-composer-side-clearance: 16px;
  --dsh-composer-dock-inset: 8px;
  --dsh-composer-stack-gap: 6px;
  --dsh-composer-text-max-height: 336px;
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
