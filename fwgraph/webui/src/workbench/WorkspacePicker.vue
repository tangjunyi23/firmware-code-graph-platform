<template>
  <Teleport to="body">
    <div
      v-if="open"
      class="wb-root picker-root"
      :data-wb-theme="theme"
    >
      <div
        ref="popRef"
        class="pop"
        role="listbox"
        :aria-label="t('hero.chooseWorkspace')"
        :style="popStyle"
      >
        <button
          v-for="job in jobs"
          :key="job.job_id"
          type="button"
          class="item"
          role="option"
          :class="{ on: selectedId === job.job_id }"
          :aria-selected="selectedId === job.job_id ? 'true' : 'false'"
          @click="$emit('pick', job)"
        >
          <IconFolderOpen16 :size="14" />
          <span class="name">{{ job.firmware }}</span>
          <span class="meta">{{ STATUS_TEXT[job.status] || job.status }}</span>
        </button>
        <p v-if="!jobs.length" class="empty">{{ t('firmware.empty') }}</p>
      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { inject, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import './tokens.css'
import { IconFolderOpen16 } from './icons.js'
import { t } from './locales.js'
import { STATUS_TEXT } from './pipeline.js'

const props = defineProps({
  open: { type: Boolean, default: false },
  jobs: { type: Array, default: () => [] },
  selectedId: { type: String, default: '' },
  anchor: { type: Object, default: null }
})
const emit = defineEmits(['close', 'pick'])

const theme = inject('wbTheme', ref('light'))
const popRef = ref(null)
const popStyle = ref({})

const GAP = 6
const MARGIN = 8
const MAX_H = 420

function place () {
  const el = props.anchor
  if (!el || typeof el.getBoundingClientRect !== 'function') {
    popStyle.value = { top: '72px', left: '300px', maxHeight: '360px' }
    return
  }
  const r = el.getBoundingClientRect()
  const vw = window.innerWidth
  const vh = window.innerHeight
  const above = Math.max(0, r.top - MARGIN)
  const below = Math.max(0, vh - r.bottom - MARGIN)
  const openDown = below >= 180 || below >= above
  const maxHeight = Math.max(120, Math.min(MAX_H, openDown ? below - GAP : above - GAP))
  const width = Math.min(360, Math.max(280, r.width + 80, vw - MARGIN * 2))
  let left = r.left
  if (left + width > vw - MARGIN) left = vw - MARGIN - width
  if (left < MARGIN) left = MARGIN
  const style = {
    left: Math.round(left) + 'px',
    maxHeight: Math.round(maxHeight) + 'px',
    width: Math.round(width) + 'px'
  }
  if (openDown) style.top = Math.round(r.bottom + GAP) + 'px'
  else style.top = Math.round(r.top - GAP - maxHeight) + 'px'
  popStyle.value = style
}

function onDocClick (ev) {
  const pop = popRef.value
  if (pop && pop.contains(ev.target)) return
  const anchor = props.anchor
  if (anchor && (anchor === ev.target || anchor.contains?.(ev.target))) return
  emit('close')
}

function onKey (ev) {
  if (ev.key === 'Escape') emit('close')
}

let listenTimer = 0
function detachDoc () {
  document.removeEventListener('mousedown', onDocClick, true)
  window.removeEventListener('resize', place)
  window.removeEventListener('keydown', onKey)
  if (listenTimer) {
    window.clearTimeout(listenTimer)
    listenTimer = 0
  }
}
watch(() => props.open, async (open) => {
  detachDoc()
  if (!open) return
  await nextTick()
  place()
  window.addEventListener('resize', place)
  window.addEventListener('keydown', onKey)
  // 等打开这次点击结束再监听，避免立刻关掉
  listenTimer = window.setTimeout(() => {
    listenTimer = 0
    if (props.open) document.addEventListener('mousedown', onDocClick, true)
  }, 0)
})
watch(() => props.jobs.length, () => { if (props.open) nextTick(place) })

onBeforeUnmount(detachDoc)
</script>

<style scoped>
.picker-root {
  position: fixed;
  inset: 0;
  z-index: 80;
  width: auto;
  height: auto;
  overflow: visible;
  pointer-events: none;
  background: transparent;
}
.pop {
  position: fixed;
  z-index: 81;
  box-sizing: border-box;
  overflow-x: hidden;
  overflow-y: auto;
  padding: 6px;
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 12px;
  background: var(--dsw-specific-menu);
  box-shadow: var(--dsw-shadow-lv3);
  pointer-events: auto;
}
.item {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  min-height: 36px;
  padding: 0 10px;
  border: none;
  border-radius: 8px;
  background: transparent;
  color: var(--dsw-alias-label-primary);
  cursor: pointer;
  text-align: left;
  font-size: 13px;
  font-family: inherit;
}
.item:hover, .item.on { background: var(--dsw-alias-interactive-bg-hover); }
.name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.meta { color: var(--dsw-alias-label-tertiary); flex: none; }
.empty { margin: 8px; font-size: 12px; color: var(--dsw-alias-label-tertiary); }
</style>
