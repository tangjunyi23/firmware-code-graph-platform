<template>
  <div class="ring">
    <svg :viewBox="`0 0 ${box} ${box}`" :width="size" :height="size" role="img" :aria-label="label">
      <circle class="track" :cx="c" :cy="c" :r="r" fill="none" :stroke-width="stroke" />
      <circle
        class="bar"
        :cx="c"
        :cy="c"
        :r="r"
        fill="none"
        :stroke-width="stroke"
        stroke-linecap="round"
        :stroke-dasharray="circ"
        :stroke-dashoffset="offset"
        :transform="`rotate(-90 ${c} ${c})`"
      />
      <text :x="c" :y="c - 4" class="num">{{ shown }}%</text>
      <text :x="c" :y="c + 16" class="cap">{{ label }}</text>
    </svg>
    <p v-if="sub" class="sub">{{ sub }}</p>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  value: { type: Number, default: 0 },
  label: { type: String, default: '进度' },
  sub: { type: String, default: '' },
  size: { type: Number, default: 168 }
})

const box = 180
const c = 90
const stroke = 12
const r = 72
const circ = 2 * Math.PI * r
const shown = computed(() => Math.max(0, Math.min(100, Math.round(props.value || 0))))
const offset = computed(() => circ * (1 - shown.value / 100))
</script>

<style scoped>
.ring { display: flex; flex-direction: column; align-items: center; }
svg { display: block; overflow: visible; }
.track { stroke: rgba(148, 197, 255, .12); }
.bar {
  stroke: var(--fw-brand);
  filter: drop-shadow(0 0 10px rgba(56, 189, 248, .35));
  transition: stroke-dashoffset .6s ease;
}
.num {
  fill: var(--fw-text);
  font-size: 32px;
  font-weight: 650;
  text-anchor: middle;
  font-variant-numeric: tabular-nums;
  letter-spacing: -0.04em;
}
.cap { fill: var(--fw-text-3); font-size: 11px; text-anchor: middle; }
.sub { margin: 8px 0 0; color: var(--fw-text-2); font-size: 12px; text-align: center; }
</style>
