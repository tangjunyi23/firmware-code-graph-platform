<template>
  <div class="root" :class="{ hero: variant === 'hero' }">
    <div
      v-if="dragActive"
      class="drop-overlay"
      :class="{ blocked: !canDrop }"
    >
      <strong>{{ canDrop ? '将固件拖到此处即可添加' : '当前无法添加固件' }}</strong>
    </div>
    <div
      v-if="notice"
      class="notice"
      :class="{ error: notice.level === 'error' }"
      role="status"
    >{{ notice.text }}</div>

    <div
      class="card"
      :class="{ trigger: workspaceTrigger }"
      data-composer-card
      data-tour="wb-composer"
      @click="workspaceTrigger && $emit('request-workspace')"
    >
      <div v-if="file" class="attach-rail">
        <div class="chip">
          <span class="chip-name">{{ file.name }}</span>
          <span class="chip-size">{{ fmtSize(file.size) }}</span>
          <button type="button" class="chip-x" aria-label="移除附件" @click.stop="$emit('clear-file')">×</button>
        </div>
      </div>

      <div ref="scrollRef" class="scroll" data-input-scroll>
        <textarea
          ref="inputRef"
          class="input"
          :value="draft"
          :disabled="textareaDisabled"
          :readonly="workspaceTrigger"
          :placeholder="resolvedPlaceholder"
          :aria-label="workspaceTrigger ? t('hero.chooseWorkspace') : undefined"
          rows="2"
          @input="onInput"
          @keydown="onKeyDown"
        />
      </div>


      <div class="row">
        <div class="tools">
          <div
            class="policy"
            role="radiogroup"
            :aria-label="t('approval.policy')"
            @click.stop
          >
            <button
              type="button"
              class="policy-btn"
              :class="{ on: policy === 'auto' }"
              :aria-checked="policy === 'auto' ? 'true' : 'false'"
              :title="t('approval.auto')"
              role="radio"
              @mousedown.prevent="keepFocus"
              @click="setPolicy('auto')"
            >{{ t('approval.auto') }}</button>
            <button
              type="button"
              class="policy-btn"
              :class="{ on: policy === 'ask' }"
              :aria-checked="policy === 'ask' ? 'true' : 'false'"
              :title="t('approval.ask')"
              role="radio"
              @mousedown.prevent="keepFocus"
              @click="setPolicy('ask')"
            >{{ t('approval.ask') }}</button>
          </div>
          <input
            v-if="allowUpload"
            ref="fileInput"
            type="file"
            class="hidden"
            :accept="FW_ACCEPT"
            @change="onPick"
          />
          <button
            v-if="allowUpload"
            type="button"
            class="add"
            :aria-label="t('input.upload')"
            :title="t('input.upload')"
            :disabled="locked"
            @mousedown.prevent="keepFocus"
            @click="fileInput.click()"
          >
            <IconPlusOutline16 :size="14" />
          </button>
        </div>
        <div class="trailing">
          <button
            type="button"
            class="primary"
            :aria-label="primaryLabel"
            :title="primaryLabel"
            :disabled="primaryDisabled"
            @mousedown.prevent="keepFocus"
            @click="onPrimary"
          >
            <IconStop v-if="running" :size="16" />
            <IconSend v-else :size="16" />
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, inject, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { IconPlusOutline16, IconSend, IconStop } from './icons.js'
import { t } from './locales.js'
import { FW_ACCEPT, fmtSize, isFirmwareFile } from './pipeline.js'

const props = defineProps({
  variant: { type: String, default: 'composer' },
  draft: { type: String, default: '' },
  file: { type: Object, default: null },
  jobId: { type: String, default: '' },
  firmwareLabel: { type: String, default: '' },
  mode: { type: String, default: 'dynamic' },
  allowUpload: { type: Boolean, default: false },
  running: { type: Boolean, default: false },
  locked: { type: Boolean, default: false },
  notice: { type: Object, default: null }
})
const emit = defineEmits([
  'update:draft', 'update:mode', 'send', 'stop', 'pick-file', 'clear-file',
  'request-workspace', 'steer'
])

const session = inject('wbSession', null)
const running = computed(() => props.running || !!session?.state?.running)
const policy = computed(() => session?.state?.approvalPolicy === 'auto' ? 'auto' : 'ask')
function setPolicy (next) {
  session?.setApprovalPolicy(next)
}

const workspaceTrigger = computed(() => !props.jobId && !props.file && !props.locked)
const empty = computed(() => !props.draft.trim() && !props.file)
const canSteer = computed(() => running.value && empty.value && (session?.state?.queue || []).length)
const textareaDisabled = computed(() => props.locked && !workspaceTrigger.value)
const canDrop = computed(() => !props.locked)
const primaryLabel = computed(() => running.value ? t('input.stop') : t('input.send'))
const primaryDisabled = computed(() => {
  if (running.value) return false
  if (props.locked) return true
  if (!props.jobId && !props.file) return true
  return empty.value && !props.jobId
})
const resolvedPlaceholder = computed(() => {
  if (workspaceTrigger.value) return t('placeholder.workspace')
  if (props.locked) return t('placeholder.unavailable')
  if (canSteer.value) return t('placeholder.steerQueue')
  if (props.variant === 'hero') return t('placeholder.hero')
  return t('placeholder.default')
})

const inputRef = ref(null)
const scrollRef = ref(null)
const fileInput = ref(null)
const composing = ref(false)

// 2026-09-23：示例建议 chips 移除（用户反馈堆积历史输入无法清理）
function applySuggestion (text) {
  emit('update:draft', text)
  nextTick(() => { inputRef.value?.focus({ preventScroll: true }); resize() })
}

function keepFocus () {
  inputRef.value?.focus({ preventScroll: true })
}
function onInput (e) {
  if (props.locked || workspaceTrigger.value) return
  emit('update:draft', e.target.value)
  resize()
}
function resize () {
  const el = inputRef.value
  if (!el) return
  el.style.height = 'auto'
  const max = 336
  const min = props.variant === 'hero' ? 52 : 48
  el.style.height = Math.min(max, Math.max(min, el.scrollHeight)) + 'px'
}
watch(() => props.draft, () => nextTick(resize))
watch(() => props.variant, () => nextTick(resize))

function onKeyDown (e) {
  if (workspaceTrigger.value) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      emit('request-workspace')
    }
    return
  }
  if (e.key === 'Enter' && e.shiftKey) return
  if (e.isComposing || composing.value || e.keyCode === 229) {
    if (e.type === 'compositionstart') composing.value = true
    return
  }
  if (e.key === 'Enter') {
    e.preventDefault()
    if (e.repeat) return
    if ((e.metaKey || e.ctrlKey) && canSteer.value) {
      emit('steer')
      return
    }
    if (!primaryDisabled.value && !running.value) emit('send')
    else if (running.value && !empty.value) emit('send')
  }
}

function onPick (e) {
  const picked = e.target.files && e.target.files[0]
  if (picked) emit('pick-file', picked)
  e.target.value = ''
}

function onPrimary () {
  if (running.value) {
    emit('stop')
    return
  }
  if (!primaryDisabled.value) emit('send')
}

const dragActive = ref(false)
let dragDepth = 0
function hasFiles (event) {
  return event.dataTransfer?.types?.includes('Files')
}
function onDragEnter (event) {
  if (!hasFiles(event)) return
  event.preventDefault()
  dragDepth += 1
  dragActive.value = true
}
function onDragOver (event) {
  if (!hasFiles(event) || !event.dataTransfer) return
  event.preventDefault()
  event.dataTransfer.dropEffect = canDrop.value ? 'copy' : 'none'
}
function onDragLeave (event) {
  if (!hasFiles(event)) return
  dragDepth = Math.max(0, dragDepth - 1)
  if (dragDepth === 0) dragActive.value = false
}
function onDrop (event) {
  if (!hasFiles(event)) return
  event.preventDefault()
  dragDepth = 0
  dragActive.value = false
  if (!canDrop.value) return
  const file = event.dataTransfer?.files?.[0]
  if (file && isFirmwareFile(file)) emit('pick-file', file)
}

onMounted(() => {
  document.addEventListener('dragenter', onDragEnter)
  document.addEventListener('dragover', onDragOver)
  document.addEventListener('dragleave', onDragLeave)
  document.addEventListener('drop', onDrop)
  nextTick(resize)
  if (!props.locked) inputRef.value?.focus({ preventScroll: true })
})
onUnmounted(() => {
  document.removeEventListener('dragenter', onDragEnter)
  document.removeEventListener('dragover', onDragOver)
  document.removeEventListener('dragleave', onDragLeave)
  document.removeEventListener('drop', onDrop)
})
</script>

<style scoped>
.root {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 0 var(--dsh-composer-side-clearance) 8px;
  position: relative;
}
.root.hero { padding: 0 var(--dsh-composer-side-clearance); }

.notice {
  width: 100%;
  max-width: var(--dsh-composer-card-max-width);
  margin-bottom: 6px;
  padding: 4px 8px;
  border-radius: 8px;
  background: var(--dsw-alias-interactive-bg-hover);
  color: var(--dsw-alias-label-secondary);
  font-size: 12px;
  line-height: 18px;
}
.notice.error {
  background: var(--dsw-alias-interactive-bg-hover-danger);
  color: var(--dsw-alias-state-error-primary);
}

.card {
  box-sizing: border-box;
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 12px;
  width: 100%;
  max-width: var(--dsh-composer-card-max-width);
  padding-top: 10px;
  border: 1px solid var(--dsw-alias-border-l2-darkmode-thin);
  border-radius: 22px;
  background: var(--dsw-specific-input-major);
  box-shadow:
    var(--dsw-shadow-lv2),
    0 0 0 1px rgba(19, 76, 255, .04),
    0 18px 40px rgba(19, 76, 255, .06);
  font-size: 15px;
  line-height: 24px;
  letter-spacing: -0.011em;
  --dsh-scrollbar-thumb: var(--dsw-alias-scrollbar-bg-l2);
  --dsh-scrollbar-thumb-hover: var(--dsw-alias-scrollbar-hover-l2);
}
.card.trigger {
  border-color: transparent;
  cursor: pointer;
}
.card.trigger::after {
  content: '';
  position: absolute;
  inset: -1px;
  border-radius: 22px;
  background: var(--dsw-alias-border-l4);
  pointer-events: none;
  -webkit-mask: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'%3E%3Crect width='100%25' height='100%25' fill='none' rx='22' ry='22' stroke='black' stroke-width='2' stroke-dasharray='4 4'/%3E%3C/svg%3E");
  mask: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'%3E%3Crect width='100%25' height='100%25' fill='none' rx='22' ry='22' stroke='black' stroke-width='2' stroke-dasharray='4 4'/%3E%3C/svg%3E");
}
.card.trigger:hover::after { background: var(--dsw-alias-state-business-primary); }
.card.trigger :disabled { pointer-events: none; }

.attach-rail { min-width: 0; padding: 4px 12px 0; }
.chip {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  max-width: 100%;
  height: 32px;
  padding: 0 8px 0 12px;
  border-radius: 10px;
  background: var(--dsw-alias-interactive-bg-hover);
  font-size: 13px;
}
.chip-name {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.chip-size { color: var(--dsw-alias-label-tertiary); }
.chip-x {
  border: none;
  background: transparent;
  color: var(--dsw-alias-label-secondary);
  cursor: pointer;
  font-size: 16px;
  line-height: 1;
}

.scroll { max-height: var(--dsh-composer-text-max-height); overflow-y: auto; }

.suggest-row {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  padding: 0 12px 0 16px;
}
.suggest-chip {
  height: 26px;
  padding: 0 12px;
  border: 1px solid var(--dsw-alias-border-l2-darkmode-thin);
  border-radius: 999px;
  background: transparent;
  color: var(--dsw-alias-label-secondary);
  font-size: 12px;
  line-height: 24px;
  cursor: pointer;
  font-family: inherit;
}
.suggest-chip:hover {
  background: var(--dsw-alias-interactive-bg-hover);
  color: var(--dsw-alias-label-primary);
  border-color: var(--dsw-alias-border-l4, transparent);
}
.input {
  display: block;
  box-sizing: border-box;
  width: 100%;
  min-height: 48px;
  resize: none;
  overflow: hidden;
  border: none;
  outline: none;
  background: transparent;
  color: var(--dsw-alias-label-primary);
  caret-color: var(--dsw-alias-state-business-primary);
  padding: 4px 12px 0 16px;
  font-family: var(--dsw-font-family);
  font-size: inherit;
  line-height: inherit;
}
.hero .input { min-height: 52px; }
.input::placeholder {
  color: var(--dsw-alias-label-caption);
  user-select: none;
}
.input:disabled {
  color: var(--dsw-alias-label-tertiary);
  cursor: not-allowed;
}
.card.trigger .input { cursor: pointer; }

.row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 2px 8px 6px;
  min-width: 0;
}
.tools, .modes, .trailing {
  display: flex;
  align-items: center;
  min-width: 0;
}
.tools { gap: 10px; }
.modes { gap: 12px; }
.trailing { flex: none; gap: 12px; }

.policy {
  display: inline-flex;
  align-items: center;
  height: 28px;
  padding: 2px;
  border-radius: 999px;
  background: var(--dsw-specific-selector);
}
.policy-btn {
  height: 24px;
  padding: 0 10px;
  border: none;
  border-radius: 999px;
  background: transparent;
  color: var(--dsw-alias-label-tertiary);
  font-size: 12px;
  line-height: 24px;
  font-weight: 500;
  cursor: pointer;
  font-family: inherit;
}
.policy-btn.on {
  background: var(--dsw-alias-bg-base);
  color: var(--dsw-alias-label-primary);
  box-shadow: var(--dsw-shadow-lv1, none);
}
.policy-btn:hover:not(.on) { color: var(--dsw-alias-label-secondary); }

.add {
  display: grid;
  place-items: center;
  flex: none;
  width: 28px;
  height: 28px;
  border: none;
  border-radius: 999px;
  background: var(--dsw-specific-selector);
  color: var(--dsw-alias-label-primary);
  cursor: pointer;
}
.add:hover:not(:disabled) { background: var(--dsw-alias-interactive-bg-hover-solid); }
.add:disabled { opacity: 0.5; cursor: default; }

.mode-chip {
  height: 28px;
  padding: 0 10px;
  border: none;
  border-radius: 24px;
  background: transparent;
  color: var(--dsw-alias-label-secondary);
  font-size: 13px;
  line-height: 20px;
  font-weight: 500;
  cursor: pointer;
}
.mode-chip:hover:not(:disabled) { background: var(--dsw-alias-interactive-bg-hover); }
.mode-chip:disabled { opacity: 0.5; cursor: default; }

.primary {
  display: grid;
  place-items: center;
  flex: none;
  width: 36px;
  height: 36px;
  border: none;
  border-radius: 999px;
  background: var(--fw-brand, #134cff);
  color: #fff;
  cursor: pointer;
  box-shadow: 0 8px 18px rgba(19, 76, 255, .28);
  transition: background-color 120ms ease, transform 120ms ease, box-shadow 120ms ease;
}
.primary:hover:not(:disabled) {
  background: var(--fw-brand-hover, #3363ff);
  transform: translateY(-1px);
  box-shadow: 0 10px 22px rgba(19, 76, 255, .34);
}
.primary:disabled { opacity: 0.4; cursor: default; box-shadow: none; transform: none; }

.hidden { display: none; }

.drop-overlay {
  position: absolute;
  inset: 0;
  z-index: 5;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 22px;
  background: var(--dsw-alias-bg-mask-drop);
  color: var(--dsw-alias-label-primary);
  pointer-events: none;
}
.drop-overlay.blocked { color: var(--dsw-alias-label-tertiary); }
</style>
