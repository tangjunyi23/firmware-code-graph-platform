<template>
  <span class="count" :class="{ run: playing, pop: popped }">{{ shown }}</span>
</template>

<script setup>
import { onBeforeUnmount, ref, watch } from 'vue'

const props = defineProps({
  value: { type: [Number, String], default: 0 },
  ms: { type: Number, default: 1100 }
})

const shown = ref(format(props.value, 1))
const playing = ref(false)
const popped = ref(false)
let raf = 0

function parse (raw) {
  const text = String(raw ?? '')
  if (text === '—' || text === '-' || text === '') return { n: null, suffix: text, prefix: '' }
  const m = text.match(/^([^0-9.-]*)(-?\d+(?:\.\d+)?)(.*)$/)
  if (!m) return { n: null, suffix: text, prefix: '' }
  return { n: Number(m[2]), prefix: m[1], suffix: m[3] }
}
function format (raw, t) {
  const { n, prefix, suffix } = parse(raw)
  if (n == null || Number.isNaN(n)) return String(raw ?? '')
  const cur = n * t
  const digits = String(n).includes('.') ? 1 : 0
  return `${prefix}${cur.toFixed(digits)}${suffix}`
}

function play (next) {
  const { n } = parse(next)
  if (n == null || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    shown.value = format(next, 1)
    playing.value = false
    return
  }
  playing.value = true
  popped.value = false
  const t0 = performance.now()
  const step = (now) => {
    const p = Math.min(1, (now - t0) / props.ms)
    const ease = 1 - (1 - p) ** 3
    shown.value = format(next, ease)
    if (p < 1) raf = requestAnimationFrame(step)
    else {
      playing.value = false
      popped.value = true
      setTimeout(() => { popped.value = false }, 420)
    }
  }
  if (raf) cancelAnimationFrame(raf)
  raf = requestAnimationFrame(step)
}

watch(() => props.value, (v) => play(v), { immediate: true })
onBeforeUnmount(() => { if (raf) cancelAnimationFrame(raf) })
</script>

<style scoped>
.count {
  font-variant-numeric: tabular-nums;
  display: inline-block;
}
.count.run { color: var(--fw-brand); }
.count.pop { color: var(--fw-text); }
</style>
