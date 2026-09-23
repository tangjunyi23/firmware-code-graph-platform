<template>
  <div class="root">
    <div class="column">
      <button
        v-if="session.state.hasMoreHistory"
        type="button"
        class="older"
        @click="session.backfill(400)"
      >{{ t('chat.loadOlder') }}</button>
      <div v-if="session.state.loadingHistory" class="turn-status" role="status">加载对话…</div>
      <button
        v-if="hiddenCount > 0"
        type="button"
        class="older"
        @click="revealMore"
      >显示更早 {{ hiddenCount }} 条</button>

      <div
        v-for="node in timelineNodes"
        :key="node.id"
        class="flow-item"
        :data-chat-anchor-key="node.id"
      >
        <div v-if="node.kind === 'user'" class="user-row" data-time-hover-root>
          <div class="bubble">{{ displayText(node.text) }}</div>
          <div class="actions">
            <button
              type="button"
              class="action"
              :title="t('message.branch') || '分支'"
              @click="$emit('fork', node)"
            >
              <IconBranchOutline16 :size="16" />
            </button>
          </div>
        </div>

        <div
          v-else-if="node.kind === 'reasoning'"
          class="think"
          :data-state="node.streaming ? 'running' : 'ok'"
        >
          <button type="button" class="disc-row" @click="toggle(node.id)">
            <span class="leading" :class="{ open: open[node.id] }">
              <IconChevronDownOutline14 :size="14" />
            </span>
            <span class="disc-title" :class="{ 'think-glow': node.streaming }"><template v-if="node.streaming"><span class="tk-dot" /><span class="tk-dot" /><span class="tk-dot" /></template>{{ node.streaming ? '思考中' : '思考过程' }}</span>
            <template v-if="!open[node.id] && thinkPreview(node)">
              <span class="sep" />
              <span class="summary think-preview" v-html="hl(thinkPreview(node))" />
            </template>
            <span v-if="node.ts" class="row-time">{{ fmtTime(node.ts) }}</span>
          </button>
          <div v-if="open[node.id]" class="think-body"><span v-html="hl(node.text)" /><span v-if="node.streaming" class="caret" /></div>
        </div>

        <div
          v-else-if="node.kind === 'tool'"
          class="tool"
          :data-state="node.status === 'running' ? 'running' : node.status === 'error' ? 'error' : 'ok'"
        >
          <button type="button" class="disc-row" @click="toggle(node.id)">
            <span v-if="node.status === 'running'" class="leading">
              <span class="fx-dot" />
            </span>
            <span v-else class="leading chev" :class="{ open: open[node.id] }">
              <IconChevronDownOutline14 :size="14" />
            </span>
            <span v-if="node.status && node.status !== 'running'" class="st-dot" :data-st="node.status" />
            <span class="disc-title">{{ toolTitle(node.name) }}</span>
            <span class="tool-name mono-name">{{ node.name }}</span>
            <span class="sep" />
            <span
              class="summary"
              :class="{ error: node.status === 'error' }"
            >{{ toolSummary(node) }}</span>
            <span v-if="node.status === 'running'" class="row-time">运行中</span>
            <span v-else-if="node.finishedTs" class="row-time">{{ fmtTime(node.finishedTs) }}</span>
            <span v-else-if="node.ts" class="row-time">{{ fmtTime(node.ts) }}</span>
          </button>
          <div v-if="open[node.id]" class="tool-body">
            <div class="io-card">
              <div v-if="node.argumentsText" class="io-section">
                <span class="io-label">IN</span>
                <pre class="io-text">{{ pretty(node.argumentsText) }}</pre>
              </div>
              <div v-if="node.argumentsText && node.resultText" class="io-div" />
              <div v-if="node.resultText || node.error" class="io-section">
                <span class="io-label">OUT</span>
                <pre class="io-text" :data-error="node.status === 'error' || undefined">
{{ node.resultText || JSON.stringify(node.error, null, 2) }}</pre>
              </div>
            </div>
            <button type="button" class="inspect" @click="$emit('inspect', node)">
              <IconInspectOutline12 :size="12" />
              {{ t('inspect') }}
            </button>
          </div>
        </div>

        <div v-else-if="node.kind === 'text'" class="assistant">
          <span
            v-if="node.streaming"
            class="assistant-raw"
            :ref="(el) => session.bindStreamEl(node.id, el)"
          /><span v-if="node.streaming" class="caret" />
          <MarkdownText v-else :text="node.text" />
        </div>

        <div v-else-if="node.kind === 'todo'" class="todo">
          <div
            v-for="(item, i) in node.todos"
            :key="i"
            class="todo-item"
            :data-status="item.status"
          >{{ item.content || item.text || item }}</div>
        </div>

        <div v-else-if="node.kind === 'turn-end'" class="turn-div">
          <span v-if="node.reason === 'interrupted'" class="stopped">已停止</span>
          <span v-else-if="node.reason === 'error'" class="turn-err">
            本轮中断 · {{ turnError(node) }}<template v-if="node.ts"> · {{ fmtTime(node.ts) }}</template>
          </span>
          <template v-else>
            <i class="turn-line" />
            <span class="turn-label">第 {{ turnNo(node) }} 轮完成<template v-if="node.ts"> · {{ fmtTime(node.ts) }}</template></span>
            <i class="turn-line" />
          </template>
        </div>
      </div>

      <div
        v-if="liveThink"
        class="think think-dock"
        data-state="running"
        role="status"
      >
        <span class="tk-dot" aria-hidden="true" /><span class="tk-dot" aria-hidden="true" /><span class="tk-dot" aria-hidden="true" />
        <span class="disc-title think-glow">思考中</span>
        <span class="sep" />
        <span
          class="summary think-preview"
          :ref="(el) => session.bindStreamEl(liveThink.id, el)"
        />
        <span class="caret" />
      </div>
      <div
        v-else-if="session.state.running && !session.state.loadingHistory"
        class="think think-dock"
        data-state="running"
        role="status"
      >
        <span class="tk-dot" aria-hidden="true" /><span class="tk-dot" aria-hidden="true" /><span class="tk-dot" aria-hidden="true" />
        <span class="disc-title think-glow">思考中</span>
      </div>

      <div v-if="session.state.lastError" class="open-error">{{ session.state.lastError }}</div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, reactive, ref } from 'vue'
import MarkdownText from './MarkdownText.vue'
import {
  IconChevronDownOutline14, IconInspectOutline12, IconBranchOutline16
} from './icons.js'
import { t } from './locales.js'
import { lastLine, toolTitle, summarizeTool } from './dshClient.js'
import { highlightText } from '../highlight.js'

defineProps({ session: { type: Object, required: true } })
defineEmits(['inspect', 'fork'])

const session = inject('wbSession')
const open = reactive({})
function toggle (id) { open[id] = !open[id] }

// 折叠行时间：只显示 时:分:秒（观察台关心的是相对节奏，不是日期）
function fmtTime (ts) {
  const d = new Date(Number(ts))
  if (Number.isNaN(d.getTime())) return ''
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}
// turn-end 分隔线上的轮数：第几个 completed 回合
function turnNo (node) {
  const nodes = allNodes.value
  let n = 0
  for (const x of nodes) {
    if (x.kind !== 'turn-end') continue
    n++
    if (x.id === node.id) break
  }
  return n
}

function turnError (node) {
  // turn/end 的 error reason：dsh 侧 message（截断），网关 401 之类如实透出
  const raw = String(node.error || node.errorMessage || '')
  if (raw) return raw.slice(0, 120)
  return '模型调用失败（详见会话状态）'
}

// 「显示更早」分批放行：一次只多放一批，避免大会话瞬间渲染上千节点
const BATCH = 80
const reveal = ref(0)
const showAll = computed(() => reveal.value >= 9999)
const allNodes = computed(() => {
  void session.state.rev
  return session.state.loadingHistory ? [] : session.state.nodes
})
const visibleCount = computed(() => BATCH + reveal.value * BATCH)
const hiddenCount = computed(() => {
  if (showAll.value) return 0
  return Math.max(0, allNodes.value.length - visibleCount.value)
})
const visibleNodes = computed(() => {
  const nodes = allNodes.value
  if (showAll.value || nodes.length <= visibleCount.value) return nodes
  return nodes.slice(-visibleCount.value)
})
function revealMore () { reveal.value++ }

const liveThink = computed(() => {
  const nodes = allNodes.value
  for (let i = nodes.length - 1; i >= 0; i--) {
    if (nodes[i].kind === 'reasoning' && nodes[i].streaming) return nodes[i]
  }
  if (session.state.running) {
    for (let i = nodes.length - 1; i >= 0; i--) {
      if (nodes[i].kind === 'reasoning') return nodes[i]
    }
  }
  return null
})

const timelineNodes = computed(() => {
  const live = liveThink.value
  const nodes = visibleNodes.value
  if (!live) return nodes
  return nodes.filter((n) => n.id !== live.id)
})

function displayText (text) {
  // 剥离编排注入的交互纪律前缀（只给模型看，不进用户气泡；旧会话
  // 的首条消息带着前缀——2026-09-23 用户反馈）
  return String(text || '').replace(
    /【交互纪律（必须遵守）】[\s\S]*?\n\n/, '').trim()
}

function thinkPreview (node) {
  return lastLine(node.text).trim()
}
function hl (text) {
  return highlightText(text)
}

function toolSummary (node) {
  return summarizeTool(node)
}

function pretty (raw) {
  try { return JSON.stringify(JSON.parse(raw), null, 2) } catch { return raw }
}
</script>

<style scoped>
.root { min-width: 0; }
.column {
  max-width: var(--dsh-chat-content-width);
  width: 100%;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 16px;
  padding: 16px calc(var(--dsh-composer-side-clearance) + 16px) 24px;
}
.flow-item {
  min-width: 0;
  contain: content;
}
.flow-item:empty { display: none; }

.user-row {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 6px;
}
.bubble {
  max-width: min(1200px, 94%);
  background: var(--dsw-specific-bubble);
  border-radius: 22px;
  padding: 10px 16px;
  font-size: 15px;
  line-height: 24px;
  letter-spacing: -0.011em;
  color: var(--dsw-alias-label-primary);
  white-space: pre-wrap;
  word-break: break-word;
}
.actions {
  display: flex;
  align-items: center;
  gap: 10px;
  height: 28px;
}
.action {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border: none;
  border-radius: 28px;
  background: transparent;
  color: var(--dsw-alias-label-tertiary);
  cursor: pointer;
}
.action:hover {
  background: var(--dsw-alias-interactive-bg-hover);
  color: var(--dsw-alias-label-secondary);
}

.disc-row {
  display: flex;
  align-items: center;
  width: 100%;
  height: 24px;
  min-width: 0;
  padding: 0;
  border: none;
  background: none;
  color: inherit;
  font: inherit;
  text-align: left;
  cursor: pointer;
  position: relative;
  overflow: hidden;
}
.leading {
  flex: none;
  width: 16px;
  height: 16px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  margin-right: 6px;
  color: var(--dsw-alias-label-tertiary);
  transition: transform .18s ease;
}
.leading.open { transform: rotate(0deg); }
.think .leading:not(.open) { transform: rotate(-90deg); }
.tool .chev:not(.open) { transform: rotate(-90deg); }
/* 工具行状态点：完成绿 / 失败红 / 停止灰，折叠态也能扫出健康度 */
.st-dot {
  flex: none;
  width: 7px;
  height: 7px;
  border-radius: 50%;
  margin-right: 6px;
}
.st-dot[data-st='ok'] { background: var(--fw-ok, #22c55e); opacity: .75; }
.st-dot[data-st='error'] { background: var(--dsw-alias-state-error-primary, #ef4444); }
.st-dot[data-st='stopped'] { background: var(--dsw-alias-label-caption, #94a3b8); }
/* 折叠行右侧时间：与折叠条同行，灰字不抢焦点 */
.row-time {
  flex: none;
  margin-left: 10px;
  font-size: 11px;
  line-height: 24px;
  font-variant-numeric: tabular-nums;
  color: var(--dsw-alias-label-caption);
  opacity: .85;
}
/* 工具行标题后跟原始工具名（等宽小字），折叠即可分辨具体调用 */
.mono-name {
  flex: none;
  margin-left: 6px;
  font-family: var(--fw-font-mono, ui-monospace, monospace);
  font-size: 11px;
  color: var(--dsw-alias-label-caption);
}
/* 回合分隔线：把长执行流切成一段段可呼吸的回合 */
.turn-div {
  display: flex;
  align-items: center;
  gap: 10px;
  min-height: 18px;
}
.turn-line {
  flex: 1;
  height: 1px;
  background: var(--dsw-alias-border-l2, var(--fw-line));
  opacity: .6;
}
.turn-label {
  flex: none;
  font-size: 11px;
  color: var(--dsw-alias-label-caption);
  font-variant-numeric: tabular-nums;
}
.turn-err {
  flex: none;
  font-size: 11.5px;
  color: #e11d48;
  background: rgba(225, 29, 72, .1);
  padding: 2px 10px;
  border-radius: 999px;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.disc-title {
  flex: none;
  font-size: 14px;
  line-height: 24px;
  color: var(--dsw-alias-label-secondary);
  font-weight: 400;
}
.sep {
  flex: none;
  width: 2px;
  height: 2px;
  margin: 0 8px;
  border-radius: 1px;
  background: var(--dsw-alias-label-caption);
}
.summary {
  min-width: 0;
  overflow: hidden;
  flex: 1 1 auto;
  color: var(--dsw-alias-label-tertiary);
  font-size: 14px;
  line-height: 24px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.summary.error { color: var(--dsw-alias-state-error-primary); }
.think-preview { color: var(--dsw-alias-label-tertiary); }

.think[data-state='running'] .disc-row::after,
.tool[data-state='running'] .disc-row::after {
  content: '';
  position: absolute;
  inset-block: 0;
  left: 0;
  width: 300px;
  background: linear-gradient(
    90deg,
    transparent 0%,
    color-mix(in srgb, var(--dsw-alias-bg-base) 60%, transparent) 55%,
    transparent 100%
  );
  animation: sweep 2.6s ease-out infinite;
  pointer-events: none;
}
@keyframes sweep {
  0% { left: -300px; }
  90%, 100% { left: 100%; }
}
@media (prefers-reduced-motion: reduce) {
  .think[data-state='running'] .disc-row::after,
  .tool[data-state='running'] .disc-row::after { animation: none; }
}

.think-dock {
  align-self: stretch;
  display: flex;
  align-items: center;
  min-width: 0;
  height: 24px;
}
.think-dock .fx-dot { margin-right: 8px; }
.think-glow {
  color: #7dd3fc;
  animation: fx-glow 1.6s ease-in-out infinite;
}
@media (prefers-reduced-motion: reduce) {
  .think-glow,
  .tk-dot,
  .caret,
  .think[data-state='running'] .disc-row::before { animation: none; }
}
.think-body {
  /* 思考体同样卡片化（弱一层的底色），缩进对齐折叠条 */
  margin: 4px 0 0 22px;
  padding: 10px 14px;
  background: var(--fw-surface-2);
  border: 1px solid var(--fw-line);
  border-radius: 12px;
  color: var(--dsw-alias-label-tertiary);
  font-size: 14px;
  line-height: 24px;
  white-space: pre-wrap;
  word-break: break-word;
}
.io-card {
  display: flex;
  flex-direction: column;
  margin: 4px 0 4px 4px;
  border: 1px solid var(--dsw-alias-border-l1);
  border-radius: 12px;
  background: var(--dsw-alias-markdown-code-block);
  font: var(--dsw-font-markdown-code-block-small);
}
.io-section {
  display: grid;
  grid-template-columns: max-content 1fr;
  column-gap: 14px;
  align-items: baseline;
  padding: 12px 16px;
  max-height: 150px;
  overflow-y: auto;
}
.io-label {
  position: sticky;
  top: 0;
  align-self: start;
  color: var(--dsw-alias-label-caption);
}
.io-div { height: 1px; background: var(--dsw-alias-border-l2); }
.io-text {
  min-width: 0;
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--dsw-alias-label-secondary);
  font: inherit;
}
.io-text[data-error] { color: var(--dsw-alias-state-error-primary); }
.inspect {
  display: inline-flex;
  align-self: flex-start;
  align-items: center;
  gap: 4px;
  margin: 4px 0 2px 4px;
  padding: 2px 8px;
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 999px;
  background: var(--dsw-alias-bg-base);
  color: var(--dsw-alias-label-secondary);
  font-size: 11px;
  line-height: 16px;
  cursor: pointer;
  opacity: 0;
  transition: opacity 100ms ease;
}
.tool:hover .inspect { opacity: 1; }
.inspect:hover {
  background: var(--dsw-alias-interactive-bg-hover-solid);
  color: var(--dsw-alias-label-primary);
}

.assistant {
  font-size: 15px;
  line-height: 26px;
  letter-spacing: -0.011em;
  color: var(--dsw-alias-label-primary);
  /* 卡片化：AI 正文不再裸排——圆角面板包裹 + 宽度约束，
     长 markdown（表格/代码块）在卡内横向滚动不撑破布局 */
  background: var(--fw-surface-2);
  border: 1px solid var(--fw-line);
  border-radius: 14px;
  padding: 12px 16px;
  max-width: 100%;
  overflow-wrap: anywhere;
}
.assistant :deep(pre),
.assistant :deep(table) {
  max-width: 100%;
  overflow-x: auto;
  white-space: pre;
}
.assistant-raw { white-space: pre-wrap; word-break: break-word; }
.caret {
  display: inline-block;
  width: 7px;
  height: 15px;
  margin-left: 3px;
  border-radius: 1.5px;
  background: var(--fw-brand);
  box-shadow: 0 0 10px rgba(34, 211, 238, .8);
  animation: caret-pulse 1s ease-in-out infinite;
  vertical-align: text-bottom;
}
@keyframes caret-pulse {
  /* 2026-09-23：柔和化（用户反馈"一直在抖动"）——只做透明度缓变，
     去掉光晕尺寸跳变 */
  0%, 100% { opacity: .95; }
  50% { opacity: .4; }
}
.tk-dot {
  display: inline-block;
  width: 4px;
  height: 4px;
  margin-right: 3px;
  border-radius: 50%;
  background: #7dd3fc;
  vertical-align: 1px;
  /* 柔和化：纯透明度波浪，无位移（translateY 会造成"抖动"观感） */
  animation: tk-wave 1.6s ease-in-out infinite;
}
.tk-dot:nth-child(2) { animation-delay: .2s; }
.tk-dot:nth-child(3) { animation-delay: .4s; }
.think-dock .tk-dot:nth-child(3) { margin-right: 8px; }
@keyframes tk-wave {
  0%, 60%, 100% { opacity: .4; }
  30% { opacity: 1; }
}
.think[data-state='running'] .disc-row,
.think-dock { position: relative; }
.think[data-state='running'] .disc-row::before,
.think-dock::before {
  content: '';
  position: absolute;
  left: 0;
  top: 2px;
  bottom: 2px;
  width: 2px;
  border-radius: 2px;
  background: linear-gradient(180deg, transparent, #22d3ee, #a78bfa, transparent);
  background-size: 100% 200%;
  animation: think-flow 1.4s linear infinite;
  box-shadow: 0 0 6px rgba(34, 211, 238, .55);
}
@keyframes think-flow {
  0% { background-position: 0 -100%; }
  100% { background-position: 0 100%; }
}

.stopped {
  align-self: flex-start;
  padding: 0 6px;
  border-radius: 6px;
  background: var(--dsw-alias-interactive-bg-hover);
  color: var(--dsw-alias-label-tertiary);
  font-size: 11px;
  line-height: 18px;
}

.todo-item {
  font-size: 14px;
  line-height: 22px;
  color: var(--dsw-alias-label-secondary);
}

.turn-status {
  align-self: flex-start;
  display: inline-flex;
  align-items: center;
  height: 26px;
  font: var(--dsw-font-s-strong-14);
  white-space: nowrap;
  background: linear-gradient(
    90deg,
    var(--dsw-static-deepseek-500) 0%,
    var(--dsw-static-deepseek-500) 40%,
    var(--dsw-static-deepseek-200) 50%,
    var(--dsw-static-deepseek-500) 60%,
    var(--dsw-static-deepseek-500) 100%
  );
  background-position: 100% 0;
  background-size: 250% 100%;
  background-clip: text;
  color: transparent;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  animation: shimmer 1.8s linear infinite;
}
.clock {
  margin-left: 8px;
  font: var(--dsw-font-xs-13);
  font-weight: 400;
  font-variant-numeric: tabular-nums;
  color: var(--dsw-alias-label-caption);
  -webkit-text-fill-color: var(--dsw-alias-label-caption);
}
@keyframes shimmer { to { background-position: 0 0; } }
@media (prefers-reduced-motion: reduce) {
  .turn-status { animation: none; background-size: 100% 100%; }
}

.open-error {
  color: var(--dsw-alias-state-error-primary);
  font-size: 12px;
  line-height: 18px;
}
.older {
  align-self: center;
  border: none;
  border-radius: 14px;
  padding: 4px 12px;
  font-size: 12px;
  color: var(--dsw-alias-label-secondary);
  background: var(--dsw-alias-interactive-bg-hover-solid);
  cursor: pointer;
}
</style>
