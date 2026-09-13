<template>
  <div class="line" @mousemove="onMove" @mouseleave="active = -1">
    <svg :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="none" role="img" :aria-label="title">
      <defs>
        <linearGradient v-for="s in painted" :key="s.name" :id="s.gradId" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" :stop-color="s.color" stop-opacity="0.32" />
          <stop offset="100%" :stop-color="s.color" stop-opacity="0" />
        </linearGradient>
      </defs>
      <line
        v-for="tick in yTicks"
        :key="tick.y"
        class="grid"
        :x1="PAD.l"
        :x2="W - PAD.r"
        :y1="tick.y"
        :y2="tick.y"
      />
      <text
        v-for="tick in yTicks"
        :key="'yl' + tick.y"
        class="axis"
        :x="PAD.l - 8"
        :y="tick.y + 3"
        text-anchor="end"
      >{{ tick.label }}</text>
      <text
        v-for="(lab, i) in xLabs"
        :key="'xl' + i"
        class="axis"
        :x="xAt(lab.i)"
        :y="H - 8"
        text-anchor="middle"
      >{{ lab.text }}</text>
      <path
        v-for="s in painted"
        :key="s.name + '-a'"
        :d="s.area"
        :fill="`url(#${s.gradId})`"
      />
      <path
        v-for="s in painted"
        :key="s.name + '-l'"
        :d="s.line"
        fill="none"
        :stroke="s.color"
        stroke-width="2.2"
        stroke-linejoin="round"
        stroke-linecap="round"
      />
      <g v-if="active >= 0">
        <line class="rule" :x1="xAt(active)" :x2="xAt(active)" :y1="PAD.t" :y2="H - PAD.b" />
        <circle
          v-for="s in painted"
          :key="s.name + '-d'"
          :cx="xAt(active)"
          :cy="yAt(s.values[active] || 0)"
          r="4"
          :fill="s.color"
        />
      </g>
    </svg>
    <div v-if="active >= 0" class="tip" :style="tipStyle">
      <div class="tip-day">{{ labels[active] }}</div>
      <div v-for="s in painted" :key="s.name" class="tip-row">
        <i :style="{ background: s.color }" />
        {{ s.name }}
        <b>{{ s.values[active] || 0 }}</b>
      </div>
    </div>
    <div class="keys">
      <span v-for="s in painted" :key="s.name">
        <i :style="{ background: s.color }" />{{ s.name }}
      </span>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'

const props = defineProps({
  title: { type: String, default: '趋势' },
  labels: { type: Array, default: () => [] },
  series: { type: Array, default: () => [] }
})

const W = 720
const H = 240
const PAD = { t: 16, r: 12, b: 28, l: 36 }
const active = ref(-1)

const maxY = computed(() => {
  let m = 0
  for (const s of props.series) {
    for (const v of s.values || []) m = Math.max(m, Number(v) || 0)
  }
  if (m <= 4) return 4
  const step = Math.ceil(m / 4)
  return step * 4
})

const yTicks = computed(() => {
  const max = maxY.value
  const out = []
  for (let i = 0; i <= 4; i++) {
    const val = (max / 4) * i
    const y = PAD.t + (1 - i / 4) * (H - PAD.t - PAD.b)
    out.push({ y, label: String(Math.round(val)) })
  }
  return out
})

const n = computed(() => Math.max(props.labels.length, 2))

function xAt (i) {
  const span = W - PAD.l - PAD.r
  if (n.value <= 1) return PAD.l + span / 2
  return PAD.l + (span * i) / (n.value - 1)
}
function yAt (v) {
  const max = maxY.value || 1
  return PAD.t + (1 - (Number(v) || 0) / max) * (H - PAD.t - PAD.b)
}

const painted = computed(() => props.series.map((s, idx) => {
  const values = props.labels.map((_, i) => Number(s.values?.[i]) || 0)
  const pts = values.map((v, i) => `${xAt(i)},${yAt(v)}`)
  const line = pts.length ? `M ${pts.join(' L ')}` : ''
  const lastX = xAt(Math.max(0, values.length - 1))
  const base = H - PAD.b
  const area = pts.length
    ? `M ${xAt(0)},${base} L ${pts.join(' L ')} L ${lastX},${base} Z`
    : ''
  return {
    name: s.name,
    color: s.color,
    values,
    line,
    area,
    gradId: `lg-${idx}`
  }
}))

const xLabs = computed(() => {
  const labs = props.labels || []
  if (labs.length <= 7) {
    return labs.map((text, i) => ({ i, text: shortDay(text) }))
  }
  const pick = [0, Math.floor((labs.length - 1) / 2), labs.length - 1]
  return [...new Set(pick)].map((i) => ({ i, text: shortDay(labs[i]) }))
})

function shortDay (iso) {
  const s = String(iso || '')
  return s.length >= 10 ? s.slice(5) : s
}

function onMove (ev) {
  const box = ev.currentTarget.getBoundingClientRect()
  const x = ev.clientX - box.left
  const inner = box.width - 8
  const t = Math.min(1, Math.max(0, x / inner))
  active.value = Math.round(t * (n.value - 1))
}

const tipStyle = computed(() => {
  if (active.value < 0) return {}
  const pct = n.value <= 1 ? 50 : (active.value / (n.value - 1)) * 100
  return { left: `clamp(72px, ${pct}%, calc(100% - 72px))` }
})
</script>

<style scoped>
.line { position: relative; min-width: 0; }
svg { width: 100%; height: 240px; display: block; }
.grid { stroke: var(--fw-line); stroke-width: 1; }
.axis { fill: var(--fw-text-3); font-size: 10px; }
.rule { stroke: rgba(91, 140, 255, .5); stroke-dasharray: 3 3; }
.tip {
  position: absolute;
  top: 8px;
  transform: translateX(-50%);
  min-width: 120px;
  padding: 8px 10px;
  border-radius: 10px;
  background: var(--fw-surface-2);
  border: 1px solid var(--fw-line-strong);
  color: var(--fw-text);
  font-size: 12px;
  pointer-events: none;
  box-shadow: var(--fw-shadow-lg);
}
.tip-day { color: var(--fw-text-3); margin-bottom: 4px; }
.tip-row { display: flex; align-items: center; gap: 6px; }
.tip-row b { margin-left: auto; font-variant-numeric: tabular-nums; }
.tip i, .keys i {
  width: 8px; height: 8px; border-radius: 99px; display: inline-block;
}
.keys {
  display: flex;
  gap: 14px;
  margin-top: 6px;
  color: var(--fw-text-3);
  font-size: 12px;
}
.keys span { display: inline-flex; align-items: center; gap: 6px; }
</style>
