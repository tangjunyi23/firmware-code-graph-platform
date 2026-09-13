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
        @click="showAll = true"
      >显示更早 {{ hiddenCount }} 条</button>

      <div
        v-for="node in timelineNodes"
        :key="node.id"
        class="flow-item"
        :data-chat-anchor-key="node.id"
      >
        <div v-if="node.kind === 'user'" class="user-row" data-time-hover-root>
          <div class="bubble">{{ node.text }}</div>
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
            <span class="disc-title">思考中</span>
            <template v-if="!open[node.id] && thinkPreview(node)">
              <span class="sep" />
              <span class="summary think-preview" v-html="hl(thinkPreview(node))" />
            </template>
          </button>
          <div v-if="open[node.id]" class="think-body"><span v-html="hl(node.text)" /><span v-if="node.streaming" class="caret" /></div>
        </div>

        <div
          v-else-if="node.kind === 'tool'"
          class="tool"
          :data-state="node.status === 'running' ? 'running' : node.status === 'error' ? 'error' : 'ok'"
        >
          <button type="button" class="disc-row" @click="toggle(node.id)">
            <span v-if="node.status === 'running' || open[node.id]" class="leading">
              <span v-if="node.status === 'running'" class="fx-dot" />
              <IconChevronDownOutline14 v-else :size="14" />
            </span>
            <span class="disc-title">{{ toolTitle(node.name) }}</span>
            <span class="sep" />
            <span
              class="summary"
              :class="{ error: node.status === 'error' }"
            >{{ toolSummary(node) }}</span>
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

        <div v-else-if="node.kind === 'turn-end' && node.reason === 'interrupted'" class="stopped">
          已停止
        </div>
      </div>

      <div
        v-if="liveThink"
        class="think think-dock"
        data-state="running"
        role="status"
      >
        <span class="fx-dot" aria-hidden="true" />
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
        <span class="fx-dot" aria-hidden="true" />
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
import { lastLine, toolTitle } from './dshClient.js'
import { highlightText } from '../highlight.js'

defineProps({ session: { type: Object, required: true } })
defineEmits(['inspect', 'fork'])

const session = inject('wbSession')
const open = reactive({})
function toggle (id) { open[id] = !open[id] }

const WINDOW = 80
const showAll = ref(false)
const allNodes = computed(() => {
  void session.state.rev
  return session.state.loadingHistory ? [] : session.state.nodes
})
const hiddenCount = computed(() => {
  if (showAll.value) return 0
  return Math.max(0, allNodes.value.length - WINDOW)
})
const visibleNodes = computed(() => {
  const nodes = allNodes.value
  if (showAll.value || nodes.length <= WINDOW) return nodes
  return nodes.slice(-WINDOW)
})

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

function thinkPreview (node) {
  return lastLine(node.text).trim()
}
function hl (text) {
  return highlightText(text)
}

function toolSummary (node) {
  if (node.status === 'error') {
    return String(node.error?.message || node.resultText || t('row.failed')).split('\n')[0]
  }
  const args = node.argumentsText || ''
  try {
    const obj = JSON.parse(args)
    return obj.path || obj.binary_path || obj.addr || obj.title || obj.name || node.name || ''
  } catch {
    return String(args || node.name || '').replace(/\s+/g, ' ').slice(0, 80)
  }
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
  max-width: min(525px, 82%);
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
  .think-glow { animation: none; }
}
.think-body {
  padding: 4px 0 4px 22px;
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
}
.assistant-raw { white-space: pre-wrap; word-break: break-word; }
.caret {
  display: inline-block;
  width: 2px;
  height: 1em;
  margin-left: 2px;
  background: var(--fw-brand);
  box-shadow: 0 0 8px rgba(34, 211, 238, .7);
  animation: blink 1s step-end infinite;
  vertical-align: text-bottom;
}
@keyframes blink { 50% { opacity: 0; } }

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
