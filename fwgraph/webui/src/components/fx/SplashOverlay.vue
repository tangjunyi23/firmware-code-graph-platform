<template>
  <div v-if="open" class="splash" @click="skip">
    <div class="veil" />
    <div class="scan" />
    <div class="beam" />
    <div class="inner">
      <p class="kicker">FWGRAPH // BOOT SEQUENCE</p>
      <h2 class="glitch" data-text="链路校准">链路校准</h2>
      <p class="pct">{{ pct }}%</p>
      <ol>
        <li :class="{ on: step >= 0 }">01  同步固件图谱节点</li>
        <li :class="{ on: step >= 1 }">02  装载动态验证通道</li>
        <li :class="{ on: step >= 2 }">03  进入威胁驾驶舱</li>
      </ol>
      <div class="bar"><i :style="{ width: pct + '%' }" /></div>
      <span class="hint">点击任意处跳过</span>
    </div>
  </div>
</template>

<script setup>
import { onBeforeUnmount, onMounted, ref } from 'vue'

const emit = defineEmits(['done'])
const open = ref(true)
const step = ref(-1)
const pct = ref(0)
let timers = []

function finish () {
  if (!open.value) return
  open.value = false
  emit('done')
}
function skip () { finish() }

onMounted(() => {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    finish()
    return
  }
  timers = [
    setTimeout(() => { step.value = 0; pct.value = 22 }, 220),
    setTimeout(() => { step.value = 1; pct.value = 58 }, 900),
    setTimeout(() => { step.value = 2; pct.value = 100 }, 1680),
    setTimeout(finish, 2600)
  ]
})
onBeforeUnmount(() => timers.forEach(clearTimeout))
</script>

<style scoped>
.splash {
  position: fixed;
  inset: 0;
  z-index: 6000;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
}
.veil {
  position: absolute;
  inset: 0;
  background:
    radial-gradient(ellipse at 50% 28%, rgba(34,211,238,.28), transparent 46%),
    radial-gradient(ellipse at 80% 80%, rgba(244,114,182,.18), transparent 42%),
    #03050b;
}
.scan {
  position: absolute;
  inset: 0;
  background: repeating-linear-gradient(
    to bottom,
    transparent 0 3px,
    rgba(0,0,0,.28) 3px 4px
  );
  mix-blend-mode: overlay;
  pointer-events: none;
}
.beam {
  position: absolute;
  left: 0; right: 0; height: 18%;
  background: linear-gradient(to bottom, transparent, rgba(34,211,238,.22), transparent);
  animation: drop 1.4s linear infinite;
  pointer-events: none;
}
@keyframes drop {
  from { top: -20%; }
  to { top: 110%; }
}
.inner { position: relative; width: min(520px, 88vw); }
.kicker {
  margin: 0 0 10px;
  color: #67e8f9;
  letter-spacing: .28em;
  font-size: 13px;
  text-shadow: 0 0 18px rgba(34,211,238,.8);
}
.glitch {
  margin: 0;
  font-size: 52px;
  letter-spacing: -.05em;
  color: #f4f7ff;
  position: relative;
  text-shadow: 0 0 24px rgba(34,211,238,.55);
  animation: shake .18s steps(2) infinite;
}
.glitch::before,
.glitch::after {
  content: attr(data-text);
  position: absolute;
  inset: 0;
}
.glitch::before { color: #22d3ee; transform: translate(3px, -2px); mix-blend-mode: screen; }
.glitch::after { color: #f472b6; transform: translate(-3px, 2px); mix-blend-mode: screen; }
@keyframes shake {
  0% { transform: translate(0, 0); }
  50% { transform: translate(1px, -1px); }
}
.pct {
  margin: 4px 0 16px;
  font-size: 28px;
  color: #22d3ee;
  font-variant-numeric: tabular-nums;
  text-shadow: 0 0 16px rgba(34,211,238,.9);
}
ol { margin: 0 0 18px; padding: 0; list-style: none; }
li {
  padding: 8px 0;
  color: #334155;
  font-size: 15px;
  letter-spacing: .04em;
  transition: color .2s ease, text-shadow .2s ease;
}
li.on { color: #e8eef8; text-shadow: 0 0 12px rgba(34,211,238,.45); }
.bar {
  height: 6px;
  border-radius: 99px;
  background: rgba(255,255,255,.1);
  overflow: hidden;
  box-shadow: inset 0 0 12px rgba(34,211,238,.2);
}
.bar i {
  display: block;
  height: 100%;
  background: linear-gradient(90deg, #22d3ee, #f472b6 70%, #fff);
  box-shadow: 0 0 18px #22d3ee;
  transition: width .4s ease;
}
.hint { display: block; margin-top: 12px; color: #94a3b8; font-size: 12px; }
@media (prefers-reduced-motion: reduce) {
  .scan, .beam, .glitch { animation: none; }
}
</style>
