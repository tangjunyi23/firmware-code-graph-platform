<template>
  <div class="threat-radar">
    <div class="tr-stage" :style="{ '--tr-period': period + 's' }">
      <!-- 刻度盘：同心环 + 度数刻度 + 十字线 -->
      <svg viewBox="0 0 440 440" class="tr-plate" aria-hidden="true">
        <circle v-for="r in [70, 112, 154, 196]" :key="r" class="ring" :r="r"
                :cx="220" :cy="220"
                :class="{ dashed: r === 112, dim: r === 70 }" />
        <g class="ticks">
          <line v-for="t in minorTicks" :key="'mi' + t" v-bind="tickLine(t, 189, 194)" />
        </g>
        <g class="ticks major">
          <line v-for="t in majorTicks" :key="'ma' + t" v-bind="tickLine(t, 184, 196)" />
        </g>
        <text v-for="d in [0, 90, 180, 270]" :key="'dg' + d" class="deg" v-bind="degText(d)">
          {{ String(d).padStart(3, '0') }}
        </text>
        <line class="cross" x1="220" y1="28" x2="220" y2="412" />
        <line class="cross" x1="28" y1="220" x2="412" y2="220" />
        <circle class="hub" r="3" cx="220" cy="220" />
      </svg>

      <!-- 旋转波束：拖尾扇面 + 锐利前沿 -->
      <div class="tr-beam" aria-hidden="true" />

      <!-- 环绕尘埃：不同轨道半径/周期/方向的小光点，围绕刻度盘缓慢公转 -->
      <span
        v-for="(m, i) in motes"
        :key="'m' + i"
        class="tr-orbit"
        :style="m.orbit"
        aria-hidden="true"
      >
        <i class="tr-mote" :style="m.dot" />
      </span>

      <!-- 目标光点：绑定真实漏洞条目，悬停显示漏洞名；highlight-id 联动外部列表 -->
      <span
        v-for="b in blips"
        :key="b.id"
        class="tr-blip"
        :class="['sev-' + b.key, { hl: b.id === hoverId || b.id === props.highlightId }]"
        :style="b.style"
        tabindex="0"
        @mouseenter="hoverId = b.id"
        @mouseleave="hoverId = ''"
        @focus="hoverId = b.id"
        @blur="hoverId = ''"
      >
        <i class="core" /><i class="ping" />
      </span>

      <!-- 悬停信息卡：漏洞名 / 编号 / CWE / 置信度 / 函数 -->
      <transition name="tr-tip">
        <div v-if="hoverBlip" class="tr-tip" :style="hoverBlip.tipStyle" aria-live="polite">
          <span class="tr-tip-row">
            <i class="tr-tip-sev" :style="{ background: hoverBlip.color }" />
            <em>{{ hoverBlip.sevLabel }}</em>
            <b v-if="hoverBlip.meta.confidence" class="tr-tip-conf">置信度 {{ hoverBlip.meta.confidence }}</b>
          </span>
          <p class="tr-tip-title">{{ hoverBlip.title }}</p>
          <span class="tr-tip-meta">{{ hoverBlip.meta.id }}<template v-if="hoverBlip.meta.cwe"> · {{ hoverBlip.meta.cwe }}</template><template v-if="hoverBlip.meta.cls"> · {{ hoverBlip.meta.cls }}</template></span>
          <span v-if="hoverBlip.meta.fn" class="tr-tip-meta mono">{{ hoverBlip.meta.fn }}</span>
        </div>
      </transition>

      <!-- 中心读数 -->
      <div class="tr-core">
        <b><CountUp :value="index" /></b>
        <span>威胁指数</span>
        <em v-if="sub">{{ sub }}</em>
      </div>
    </div>

    <ul class="tr-legend">
      <li v-for="it in items" :key="it.key">
        <i :style="{ background: it.color, '--blip': it.color }" />
        <span>{{ it.label }}</span>
        <b>{{ it.value }}</b>
      </li>
      <li v-if="!items.length"><span class="tr-empty">暂无威胁数据</span></li>
    </ul>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import CountUp from '../fx/CountUp.vue'

const props = defineProps({
  // [{key,label,value,color}] —— 严重度分布，角度按类别扇区展开
  items: { type: Array, default: () => [] },
  // 真实漏洞条目（/vulnagent/findings）：提供时光点逐条绑定，悬停显示漏洞名
  findings: { type: Array, default: () => [] },
  // 外部联动高亮的光点 id（如“最新发现”列表悬停时定位到雷达上的点）
  highlightId: { type: String, default: '' },
  index: { type: Number, default: 0 },
  sub: { type: String, default: '' },
  period: { type: Number, default: 5 } // 波束扫描一圈的秒数
})

const hoverId = ref('')

// 光点大小 / 悬停信息卡的严重度文案与颜色
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const BLIP_SIZE = { critical: 11, high: 10, medium: 9, low: 8, info: 7 }
const sevMeta = (key) => {
  const it = props.items.find((x) => x.key === key)
  return { label: it?.label || key, color: it?.color || '#64748b' }
}

const majorTicks = Array.from({ length: 12 }, (_, i) => i * 30)
const minorTicks = Array.from({ length: 60 }, (_, i) => i * 6)
  .filter((d) => d % 30 !== 0)

function tickLine (deg, r1, r2) {
  const rad = ((deg - 90) * Math.PI) / 180
  return {
    x1: 220 + Math.cos(rad) * r1, y1: 220 + Math.sin(rad) * r1,
    x2: 220 + Math.cos(rad) * r2, y2: 220 + Math.sin(rad) * r2
  }
}
function degText (deg) {
  const rad = ((deg - 90) * Math.PI) / 180
  return {
    x: 220 + Math.cos(rad) * 212,
    y: 220 + Math.sin(rad) * 212 + 4,
    'text-anchor': 'middle'
  }
}

// 确定性伪随机：同一数据每次渲染位置一致，不做 hydration 跳变
function hash (n) {
  const x = Math.sin(n * 127.1 + 311.7) * 43758.5453
  return x - Math.floor(x)
}

// 环绕尘埃轨道：半径（inset）/周期/方向/相位/大小都错开
const motes = computed(() =>
  Array.from({ length: 9 }, (_, i) => {
    const h1 = hash(i * 13 + 5)
    const h2 = hash(i * 29 + 11)
    const h3 = hash(i * 47 + 17)
    const inset = Math.round(6 + h1 * 38) // 轨道半径：6%~44% 内圈到外圈
    const dur = (10 + h2 * 18).toFixed(1) // 10s ~ 28s
    return {
      orbit: {
        inset: inset + '%',
        animationDuration: dur + 's',
        animationDirection: i % 3 === 0 ? 'reverse' : 'normal',
        animationDelay: '-' + (h3 * Number(dur)).toFixed(1) + 's'
      },
      dot: {
        '--msize': (2 + Math.round(h2 * 2)) + 'px',
        '--mcolor': i % 2 ? 'var(--fw-accent)' : 'var(--fw-brand)'
      }
    }
  })
)

// 光点布局：每个严重度类别占一个扇区。有 findings 时光点逐条对应真实漏洞
// （每类最多 8 个，index 顺序即新旧序），否则按聚合计数布点。位置用确定性
// 伪随机，同一数据每次渲染一致。
function place (si, k, nSectors) {
  const base = (si / nSectors) * 360 + 180 / nSectors
  const angle = (base + (hash(si * 31 + k * 7 + 1) - 0.5) * (360 / nSectors) * 0.8 + 360) % 360
  const radius = 0.42 + hash(si * 17 + k * 53 + 2) * 0.44
  const rad = ((angle - 90) * Math.PI) / 180
  return {
    angle,
    lx: 50 + Math.cos(rad) * radius * 47,
    ty: 50 + Math.sin(rad) * radius * 47
  }
}

function blipStyle (key, lx, ty, angle) {
  return {
    left: lx.toFixed(2) + '%',
    top: ty.toFixed(2) + '%',
    '--blip-size': (BLIP_SIZE[key] || 8) + 'px',
    // 波束周期对齐：光点在波束扫过它的那一刻起脉冲
    animationDelay: (angle / 360) * props.period + 's'
  }
}

const blips = computed(() => {
  const out = []

  if (props.findings.length) {
    const groups = new Map(SEV_ORDER.map((k) => [k, []]))
    for (const f of props.findings) {
      const k = SEV_ORDER.includes(f.severity) ? f.severity : 'info'
      if (groups.get(k).length < 8) groups.get(k).push(f)
    }
    const live = SEV_ORDER.filter((k) => groups.get(k).length)
    const n = Math.max(live.length, 1)
    live.forEach((k, si) => {
      groups.get(k).forEach((f, kk) => {
        const { angle, lx, ty } = place(si, kk, n)
        out.push({
          id: f.id || k + '-' + kk,
          key: k,
          title: f.title || f.id || '未命名漏洞',
          meta: {
            id: f.id || '',
            cwe: f.cwe || '',
            cls: f.vuln_class || '',
            fn: f.function_name || '',
            confidence: f.confidence || ''
          },
          lx, ty,
          style: blipStyle(k, lx, ty, angle)
        })
      })
    })
    return out
  }

  // 聚合兜底：没有单条数据时按各类计数布点
  const live = props.items.filter((it) => (it.value || 0) > 0)
  const n = Math.max(live.length, 1)
  live.forEach((it, si) => {
    const count = Math.min(8, Math.max(1, Math.round(it.value)))
    for (let k = 0; k < count; k++) {
      const { angle, lx, ty } = place(si, k, n)
      out.push({
        id: it.key + '-' + k,
        key: it.key,
        title: `${it.label} ×${it.value}`,
        meta: { id: '', cwe: '', cls: '', fn: '', confidence: '' },
        lx, ty,
        style: { ...blipStyle(it.key, lx, ty, angle), '--blip': it.color }
      })
    }
  })
  return out
})

// 悬停中的光点（含外部联动）：合并严重度文案/颜色，并计算信息卡位置
// （水平收边防溢出；靠上边缘的光点把卡片放下方）
const hoverBlip = computed(() => {
  const wanted = hoverId.value || props.highlightId
  const b = blips.value.find((x) => x.id === wanted)
  if (!b) return null
  const meta = sevMeta(b.key)
  const above = b.ty > 30
  return {
    ...b,
    color: b.style['--blip'] || meta.color,
    sevLabel: meta.label,
    tipStyle: {
      left: Math.min(84, Math.max(16, b.lx)).toFixed(2) + '%',
      top: b.ty.toFixed(2) + '%',
      transform: above
        ? 'translate(-50%, calc(-100% - 16px))'
        : 'translate(-50%, 18px)'
    }
  }
})
</script>

<style scoped>
.threat-radar {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
  width: 100%;
}
.tr-stage {
  position: relative;
  width: min(100%, 430px);
  aspect-ratio: 1;
  flex: none;
}
.tr-plate { position: absolute; inset: 0; width: 100%; height: 100%; }
.tr-plate .ring {
  fill: none;
  stroke: var(--fw-brand);
  stroke-opacity: .16;
}
.tr-plate .ring.dashed { stroke-dasharray: 3 6; stroke-opacity: .12; }
.tr-plate .ring.dim { stroke-opacity: .09; }
.tr-plate .ticks line { stroke: var(--fw-brand); stroke-opacity: .18; }
.tr-plate .ticks.major line { stroke-opacity: .34; }
.tr-plate .deg {
  fill: var(--fw-text-3);
  font-size: 11px;
  font-family: var(--fw-font-mono);
  opacity: .8;
}
.tr-plate .cross { stroke: var(--fw-brand); stroke-opacity: .10; }
.tr-plate .hub { fill: var(--fw-brand); fill-opacity: .5; }

/* 波束：conic 拖尾（头部最亮向后渐隐）+ 硬边前沿细线 */
.tr-beam {
  position: absolute;
  inset: 4.2%;
  border-radius: 50%;
  background:
    conic-gradient(from 0deg,
      rgba(110, 155, 255, .30), rgba(110, 155, 255, .10) 16%,
      transparent 26%, transparent 100%),
    conic-gradient(from 0deg,
      rgba(147, 180, 255, .55) 0deg, transparent 1.4deg, transparent 100%);
  mask-image: radial-gradient(circle, #000 0 99%, transparent 100%);
  -webkit-mask-image: radial-gradient(circle, #000 0 99%, transparent 100%);
  animation: tr-rotate var(--tr-period) linear infinite;
  pointer-events: none;
}
@keyframes tr-rotate { to { transform: rotate(360deg); } }

/* 环绕尘埃：轨道环旋转，光点在轨道顶点，随公转明暗闪烁 */
.tr-orbit {
  position: absolute;
  border-radius: 50%;
  pointer-events: none;
  animation: tr-orbit-spin 1s linear infinite; /* duration/direction/delay 由内联样式给 */
}
.tr-mote {
  position: absolute;
  left: 50%;
  top: calc(var(--msize, 2px) / -2);
  margin-left: calc(var(--msize, 2px) / -2);
  width: var(--msize, 2px);
  height: var(--msize, 2px);
  border-radius: 50%;
  background: var(--mcolor, var(--fw-brand));
  box-shadow: 0 0 6px var(--mcolor, var(--fw-brand));
  animation: tr-mote-twinkle 3.4s ease-in-out infinite;
}
@keyframes tr-orbit-spin { to { transform: rotate(360deg); } }
@keyframes tr-mote-twinkle {
  0%, 100% { opacity: .16; }
  50% { opacity: .72; }
}

/* 目标光点：实心核 + 扫描脉冲环；命中区放大到 22px 方便悬停 */
.tr-blip {
  position: absolute;
  width: 22px;
  height: 22px;
  margin: -11px;
  display: grid;
  place-items: center;
  border-radius: 50%;
  cursor: pointer;
  outline: none;
  z-index: 3;
}
.tr-blip:focus-visible .core { box-shadow: 0 0 0 3px rgba(91, 140, 255, .35); }
.tr-blip.sev-critical { --blip: #f26076; }
.tr-blip.sev-high { --blip: #f59e5c; }
.tr-blip.sev-medium { --blip: #e5c04b; }
.tr-blip.sev-low { --blip: #3ecf8e; }
.tr-blip.sev-info { --blip: #5b6b85; }
.tr-blip .core {
  position: relative;
  width: var(--blip-size, 9px);
  height: var(--blip-size, 9px);
  border-radius: 50%;
  background: var(--blip, var(--fw-brand));
  box-shadow: 0 0 8px var(--blip, var(--fw-brand)), 0 0 2px #fff inset;
  transition: transform .15s ease;
}
.tr-blip:hover .core, .tr-blip:focus-visible .core, .tr-blip.hl .core { transform: scale(1.4); }
.tr-blip.hl .ping { animation: none; opacity: .5; transform: scale(1.9); }
.tr-blip .ping {
  position: absolute;
  inset: 0;
  border-radius: 50%;
  border: 1.5px solid var(--blip, var(--fw-brand));
  opacity: 0;
  animation: tr-ping var(--tr-period) cubic-bezier(.16, .84, .44, 1) infinite;
}
@keyframes tr-ping {
  0% { transform: scale(.5); opacity: .95; }
  14% { transform: scale(1.7); opacity: 0; }
  100% { transform: scale(1.7); opacity: 0; }
}
.tr-blip.sev-critical .core { animation: tr-breathe 2.2s ease-in-out infinite; }
@keyframes tr-breathe {
  0%, 100% { box-shadow: 0 0 6px var(--blip); }
  50% { box-shadow: 0 0 14px var(--blip), 0 0 4px var(--blip); }
}

/* 悬停信息卡：漏洞名 + 编号/CWE/类型 + 函数 */
.tr-tip {
  position: absolute;
  z-index: 20;
  width: max-content;
  max-width: 236px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 9px 11px;
  border-radius: 10px;
  border: 1px solid var(--fw-line-strong);
  background: var(--fw-surface);
  box-shadow: 0 12px 32px -8px rgba(2, 6, 23, .45);
  pointer-events: none;
}
.tr-tip-row { display: flex; align-items: center; gap: 6px; }
.tr-tip-sev { width: 8px; height: 8px; border-radius: 99px; flex: none; }
.tr-tip-row em { font-style: normal; font-size: 11px; color: var(--fw-text-3); letter-spacing: .04em; }
.tr-tip-conf {
  margin-left: auto;
  font-style: normal;
  font-size: 10.5px;
  color: var(--fw-brand);
  background: var(--fw-fill);
  border-radius: 99px;
  padding: 1px 7px;
}
.tr-tip-title {
  margin: 0;
  font-size: 12.5px;
  font-weight: 650;
  line-height: 1.45;
  color: var(--fw-text);
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
.tr-tip-meta {
  font-size: 10.5px;
  color: var(--fw-text-3);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.tr-tip-enter-active, .tr-tip-leave-active { transition: opacity .12s ease, transform .12s ease; }
.tr-tip-enter-from, .tr-tip-leave-to { opacity: 0; }

/* 中心读数 */
.tr-core {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 2px;
  text-align: center;
  pointer-events: none;
}
.tr-core::before {
  content: '';
  position: absolute;
  width: 132px;
  height: 132px;
  border-radius: 50%;
  background: var(--fw-surface);
  border: 1px solid var(--fw-line);
  box-shadow: 0 0 0 10px var(--fw-surface), 0 8px 32px -8px rgba(15, 23, 42, .18);
  z-index: -1;
}
.tr-core b {
  font-size: 40px;
  font-weight: 750;
  letter-spacing: -0.04em;
  line-height: 1;
  color: var(--fw-text);
  font-variant-numeric: tabular-nums;
}
.tr-core span {
  font-size: 11px;
  letter-spacing: .18em;
  color: var(--fw-text-3);
}
.tr-core em {
  font-style: normal;
  font-size: 11px;
  color: var(--fw-text-2);
  margin-top: 3px;
}

.tr-legend {
  list-style: none;
  margin: 10px 0 0;
  padding: 0;
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
  justify-content: center;
}
.tr-legend li {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--fw-text-2);
}
.tr-legend i {
  width: 8px;
  height: 8px;
  border-radius: 99px;
  flex: none;
  background: var(--blip);
}
.tr-legend b { color: var(--fw-text); font-variant-numeric: tabular-nums; }
.tr-empty { color: var(--fw-text-3); }

@media (prefers-reduced-motion: reduce) {
  .tr-beam, .tr-blip .ping, .tr-blip .core { animation: none !important; }
  .tr-blip .ping { opacity: .4; transform: scale(1.8); }
  .tr-orbit, .tr-mote { animation: none !important; }
  .tr-mote { opacity: .4; }
}
</style>
