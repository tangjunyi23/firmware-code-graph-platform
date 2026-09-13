<template>
  <svg :viewBox="`0 0 ${S} ${S}`" class="radar" role="img" :aria-label="title">
    <polygon
      v-for="ring in rings"
      :key="ring"
      class="grid"
      :points="poly(axes.map(() => ring))"
    />
    <line
      v-for="(a, i) in axes"
      :key="a.key"
      class="axis"
      :x1="cx"
      :y1="cy"
      :x2="pt(i, 1).x"
      :y2="pt(i, 1).y"
    />
    <polygon class="area" :points="poly(values)" />
    <circle
      v-for="(a, i) in axes"
      :key="a.key + 'd'"
      class="dot"
      :cx="pt(i, values[i]).x"
      :cy="pt(i, values[i]).y"
      r="3.2"
    />
    <text
      v-for="(a, i) in axes"
      :key="a.key + 'l'"
      class="lab"
      :x="pt(i, 1.18).x"
      :y="pt(i, 1.18).y"
      text-anchor="middle"
    >{{ a.label }}</text>
  </svg>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  title: { type: String, default: '威胁雷达' },
  axes: { type: Array, default: () => [] },
  scores: { type: Array, default: () => [] }
})

const S = 280
const cx = 140
const cy = 148
const R = 88
const n = computed(() => Math.max(props.axes.length, 3))
const values = computed(() =>
  props.axes.map((_, i) => Math.max(0, Math.min(1, Number(props.scores[i]) || 0)))
)
const rings = [0.33, 0.66, 1]

function pt (i, mag) {
  const ang = (-Math.PI / 2) + (i * 2 * Math.PI) / n.value
  return { x: cx + Math.cos(ang) * R * mag, y: cy + Math.sin(ang) * R * mag }
}
function poly (mags) {
  return mags.map((m, i) => {
    const p = pt(i, m)
    return `${p.x.toFixed(1)},${p.y.toFixed(1)}`
  }).join(' ')
}
</script>

<style scoped>
.radar { width: 100%; height: 260px; display: block; }
.grid { fill: none; stroke: var(--fw-line); }
.axis { stroke: var(--fw-line-strong); }
.area {
  fill: rgba(91, 140, 255, .14);
  stroke: var(--fw-brand);
  stroke-width: 1.6;
}
.dot { fill: var(--fw-brand); }
.lab { fill: var(--fw-text-3); font-size: 11px; }
</style>
