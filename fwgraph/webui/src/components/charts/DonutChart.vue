<template>
  <div class="donut">
    <svg
      :viewBox="`0 0 ${box} ${box}`"
      :width="size"
      :height="size"
      role="img"
      :aria-label="title"
    >
      <defs>
        <filter :id="glowId" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="2.2" result="b" />
          <feMerge>
            <feMergeNode in="b" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
      <circle
        class="track"
        :cx="cx"
        :cy="cy"
        :r="radius"
        fill="none"
        :stroke-width="thickness"
      />
      <circle
        v-for="(slice, i) in slices"
        :key="slice.key"
        fill="none"
        :cx="cx"
        :cy="cy"
        :r="radius"
        :stroke="slice.color"
        :stroke-width="hover === i ? thickness + 3 : thickness"
        stroke-linecap="butt"
        :stroke-dasharray="slice.dash"
        :stroke-dashoffset="slice.offset"
        :filter="hover === i ? `url(#${glowId})` : null"
        :opacity="hover < 0 || hover === i ? 1 : 0.38"
        :transform="`rotate(-90 ${cx} ${cy})`"
        @mouseenter="hover = i"
        @mouseleave="hover = -1"
      />
      <text :x="cx" :y="cy - 6" class="center-num">{{ centerValue }}</text>
      <text :x="cx" :y="cy + 14" class="center-sub">{{ hoverLabel || sub }}</text>
    </svg>
    <ul class="legend">
      <li
        v-for="(slice, i) in slices"
        :key="slice.key"
        :class="{ on: hover === i }"
        @mouseenter="hover = i"
        @mouseleave="hover = -1"
      >
        <i :style="{ background: slice.color }" />
        <span class="name">{{ slice.label }}</span>
        <b>{{ slice.value }}</b>
      </li>
    </ul>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'

const props = defineProps({
  items: { type: Array, default: () => [] },
  title: { type: String, default: '分布' },
  sub: { type: String, default: '' },
  size: { type: Number, default: 196 },
  thickness: { type: Number, default: 22 }
})

const hover = ref(-1)
const glowId = `glow-${Math.random().toString(36).slice(2, 8)}`
const box = 220
const cx = 110
const cy = 110
const radius = computed(() => 78)

const total = computed(() =>
  props.items.reduce((sum, item) => sum + (Number(item.value) || 0), 0)
)
const centerValue = computed(() => {
  if (hover.value >= 0 && slices.value[hover.value]) {
    return slices.value[hover.value].value
  }
  return total.value
})
const hoverLabel = computed(() => {
  if (hover.value >= 0 && slices.value[hover.value]) {
    return slices.value[hover.value].label
  }
  return ''
})

const slices = computed(() => {
  const circ = 2 * Math.PI * radius.value
  const sum = total.value
  let acc = 0
  return props.items
    .filter((item) => (Number(item.value) || 0) > 0)
    .map((item) => {
      const value = Number(item.value) || 0
      const frac = sum ? value / sum : 0
      const dash = `${frac * circ} ${circ}`
      const offset = -acc * circ
      acc += frac
      return {
        key: item.key,
        label: item.label,
        value,
        color: item.color,
        dash,
        offset
      }
    })
})
</script>

<style scoped>
.donut {
  display: flex;
  align-items: center;
  gap: 18px;
  min-width: 0;
}
svg { flex: none; overflow: visible; display: block; }
.track { stroke: var(--fw-line); }
circle[stroke] { cursor: pointer; transition: stroke-width .18s ease, opacity .18s ease; }
.center-num {
  fill: var(--fw-text);
  font-size: 28px;
  font-weight: 650;
  text-anchor: middle;
  font-variant-numeric: tabular-nums;
  letter-spacing: -0.04em;
}
.center-sub {
  fill: var(--fw-text-3);
  font-size: 11px;
  text-anchor: middle;
}
.legend {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 8px;
  min-width: 0;
  flex: 1;
}
.legend li {
  display: grid;
  grid-template-columns: 8px 1fr auto;
  gap: 8px;
  align-items: center;
  color: var(--fw-text-2);
  font-size: 12px;
  cursor: pointer;
}
.legend li.on { color: var(--fw-text); }
.legend i {
  width: 8px;
  height: 8px;
  border-radius: 99px;
}
.legend .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.legend b {
  font-variant-numeric: tabular-nums;
  color: var(--fw-text);
  font-weight: 600;
}
@media (max-width: 720px) {
  .donut { flex-direction: column; align-items: stretch; }
  svg { margin: 0 auto; }
}
</style>
