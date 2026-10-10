<template>
  <div ref="wrap" class="rs-wrap">
    <canvas ref="cv" class="rs-canvas" role="img" aria-label="威胁雷达，按漏洞类别与严重度展示目标；点击目标查看详情" />
    <div ref="tip" class="rs-tip">
      <div v-if="hover" class="rt-name">
        {{ hover.full || hover.name }}<span v-if="hover.cwe" class="cwe">{{ hover.cwe }}</span>
      </div>
      <div v-if="hover" class="rt-row">
        <span class="sev" :class="'sev-' + hover.sev">{{ SEV[hover.sev]?.label || hover.sev }}</span>
        {{ hover.sector }}
        <span v-if="hover.ver" class="rt-ver">✓ 已验证</span>
        <span v-else class="rt-pend">待验证</span>
      </div>
      <div v-if="hover" class="rt-row dim">{{ hover.reach }} · 置信 {{ hover.conf }}</div>
    </div>
  </div>
</template>

<script setup>
/* 威胁雷达（Canvas）：按态势大屏 demo 移植 —— 扫描余晖波束、严重度色带、
   扇区标签、杂波噪点、攻击链、悬停下钻。数据来自 /vulnagent/findings。 */
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'

const props = defineProps({
  // 扇区名（攻击面/类别）
  sectors: { type: Array, default: () => [] },
  // 目标: {sector, sev, name, cwe, ver, reach, conf, n}
  targets: { type: Array, default: () => [] },
  centerValue: { type: [String, Number], default: '' },
  centerLabel: { type: String, default: '攻击面总数' },
  period: { type: Number, default: 5.5 } // 秒/圈
})

const wrap = ref(null)
const cv = ref(null)
const tip = ref(null)
const hover = ref(null)

const SEV = {
  crit: { label: '严重', color: '#F43F5E', band: [0.23, 0.36] },
  high: { label: '高危', color: '#FB923C', band: [0.40, 0.59] },
  med: { label: '中危', color: '#FACC15', band: [0.63, 0.80] },
  low: { label: '低危', color: '#34D399', band: [0.84, 0.97] }
}
const MONO = '"Cascadia Code","JetBrains Mono",Consolas,monospace'
const REDUCED = typeof window !== 'undefined' &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches

function hexA (hex, a) {
  const n = parseInt(hex.slice(1), 16)
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`
}

let ctx = null
let w = 0; let h = 0; let cx = 0; let cy = 0; let R = 0
let beam = -Math.PI / 2; let prevBeam = beam; let last = 0
let sweeps = 0; let sweepIdx = 0
let blips = []
let chains = []
let clutter = []
let raf = 0
let ro = null

function rebuild () {
  const nSec = Math.max(props.sectors.length, 1)
  const secIdx = new Map(props.sectors.map((s, i) => [s, i]))
  // 确定性伪随机（同数据同布局）
  let seed = 42
  const rnd = () => {
    seed = (seed * 16807) % 2147483647
    return (seed - 1) / 2147483646
  }
  const placed = []
  blips = props.targets.map((t, i) => {
    const s = secIdx.has(t.sector) ? secIdx.get(t.sector) : (i % nSec)
    const sectorAngle = Math.PI * 2 / nSec
    const start = -Math.PI / 2 + sectorAngle * s
    const sev = SEV[t.sev] ? t.sev : 'low'
    const band = SEV[sev].band
    let best = null; let bestDistance = -1
    // Keep dots in their category/risk ring, choosing room away from existing dots.
    for (let candidate = 0; candidate < 36; candidate++) {
      const a = start + sectorAngle * (.12 + rnd() * .76)
      const d = band[0] + rnd() * (band[1] - band[0])
      const point = { a, d, nx: Math.cos(a) * d, ny: Math.sin(a) * d }
      const distance = placed.length ? Math.min(...placed.map(p => Math.hypot(p.nx - point.nx, p.ny - point.ny))) : Infinity
      if (distance > bestDistance) { best = point; bestDistance = distance }
    }
    placed.push(best)
    return { ...t, ...best, sev, s, size: 3.5 + Math.sqrt(t.n || 1) * 2.2, glow: 0, seed: rnd(), x: 0, y: 0 }
  })
  // 攻击链：每个扇区第一条 严重/高危 → 同扇区下一条
  chains = []
  for (let s = 0; s < nSec; s++) {
    const group = blips.filter((b) => b.s === s)
    if (group.length >= 2) chains.push([blips.indexOf(group[0]), blips.indexOf(group[1])])
  }
  clutter = Array.from({ length: 48 }, () => ({
    a: rnd() * Math.PI * 2, d: 0.16 + rnd() * 0.82, p: 0, s: 0.6 + rnd()
  }))
}

function resize () {
  if (!wrap.value || !cv.value) return
  const r = wrap.value.getBoundingClientRect()
  if (r.width < 60 || r.height < 60) return
  w = r.width; h = r.height
  const dpr = window.devicePixelRatio || 1
  cv.value.width = w * dpr; cv.value.height = h * dpr
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  cx = w / 2; cy = h / 2 + 4
  R = Math.min(w, h) / 2 - 30
}

function draw (ts) {
  raf = requestAnimationFrame(draw)
  if (!ctx || R <= 10) return
  try {
    const dt = Math.min(64, ts - (last || ts)); last = ts
    const speed = (Math.PI * 2) / (props.period * 1000)
    if (!REDUCED) { prevBeam = beam; beam += dt * speed } else { prevBeam = beam }
    const step = (beam - prevBeam + Math.PI * 2) % (Math.PI * 2)
    const idx = Math.floor((beam + Math.PI / 2) / (Math.PI * 2))
    if (idx > sweepIdx) { sweepIdx = idx; sweeps = idx }
    for (const b of blips) {
      const fwd = (b.a - prevBeam + Math.PI * 2) % (Math.PI * 2)
      if (fwd <= step + 0.001) b.glow = 1
      b.glow *= Math.pow(0.994, dt / 16.7)
      b.x = cx + Math.cos(b.a) * b.d * R
      b.y = cy + Math.sin(b.a) * b.d * R
    }
    ctx.clearRect(0, 0, w, h)
    // 标签保留区：目标名称不得压盖扇区标签 / 严重度标签 / 四角 HUD
    const reserved = [
      { x: 0, y: 0, w: 150, h: 24 }, { x: w - 150, y: 0, w: 150, h: 24 },
      { x: 0, y: h - 24, w: 200, h: 24 }, { x: w - 110, y: h - 24, w: 110, h: 24 }
    ]

    // 严重度色带（分层填充）
    for (const k of ['low', 'med', 'high', 'crit']) {
      ctx.fillStyle = hexA(SEV[k].color, k === 'crit' ? 0.045 : 0.025)
      ctx.beginPath(); ctx.arc(cx, cy, R * SEV[k].band[1], 0, Math.PI * 2); ctx.fill()
    }
    // 细网格：细环 + 辐条
    ctx.save()
    ctx.strokeStyle = 'rgba(148,163,184,.045)'; ctx.lineWidth = 1
    for (let i = 1; i <= 8; i++) { ctx.beginPath(); ctx.arc(cx, cy, R * i / 9, 0, Math.PI * 2); ctx.stroke() }
    ctx.strokeStyle = 'rgba(148,163,184,.035)'
    for (let i = 0; i < 24; i++) {
      const a = i / 24 * Math.PI * 2
      ctx.beginPath()
      ctx.moveTo(cx + Math.cos(a) * R * 0.16, cy + Math.sin(a) * R * 0.16)
      ctx.lineTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R); ctx.stroke()
    }
    ctx.restore()

    // 刻度环
    ctx.save()
    for (let i = 0; i < 60; i++) {
      const a = i / 60 * Math.PI * 2; const long = i % 5 === 0
      ctx.strokeStyle = hexA('#22D3EE', long ? 0.28 : 0.12); ctx.lineWidth = 1
      ctx.beginPath()
      ctx.moveTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R)
      ctx.lineTo(cx + Math.cos(a) * (R + (long ? 7 : 4)), cy + Math.sin(a) * (R + (long ? 7 : 4)))
      ctx.stroke()
    }
    // 严重度环 + 标签
    ctx.font = '10px ' + MONO; ctx.textAlign = 'left'
    for (const k in SEV) {
      const v = SEV[k]
      ctx.strokeStyle = hexA(v.color, 0.24); ctx.lineWidth = 1
      ctx.beginPath(); ctx.arc(cx, cy, R * v.band[1], 0, Math.PI * 2); ctx.stroke()
      ctx.fillStyle = hexA(v.color, 0.82)
      ctx.fillText(v.label, cx + 3, cy - R * v.band[1] + 11)
      reserved.push({ x: cx + 1, y: cy - R * v.band[1] + 2, w: ctx.measureText(v.label).width + 6, h: 12 })
    }
    // 扇区分隔 + 标签
    const nSec = Math.max(props.sectors.length, 1)
    const secStep = 360 / nSec
    const secCount = props.sectors.map((_, i) => blips.filter((b) => b.s === i).length)
    ctx.textAlign = 'center'
    for (let i = 0; i < props.sectors.length; i++) {
      const a = (-90 + secStep * i) * Math.PI / 180
      ctx.strokeStyle = 'rgba(148,163,184,.10)'
      ctx.beginPath(); ctx.moveTo(cx, cy)
      ctx.lineTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R); ctx.stroke()
      const m = (-90 + secStep * i + secStep / 2) * Math.PI / 180
      ctx.fillStyle = hover.value && hover.value.s === i ? '#ECF4FF' : '#A7BBD5'
      ctx.font = '10.5px sans-serif'
      const label = `${props.sectors[i]} · ${secCount[i]}`
      const lw = ctx.measureText(label).width
      let sx = cx + Math.cos(m) * (R + 24)
      sx = Math.max(lw / 2 + 6, Math.min(w - lw / 2 - 6, sx))
      // 纵向同样钳制：正上/正下扇区的标签会越出画布被裁切
      const sy = Math.max(14, Math.min(h - 8, cy + Math.sin(m) * (R + 24) + 4))
      ctx.fillText(label, sx, sy)
      reserved.push({ x: sx - lw / 2 - 3, y: sy - 9, w: lw + 6, h: 15 })
    }
    ctx.restore()

    // 杂波噪点
    ctx.save(); ctx.globalCompositeOperation = 'lighter'
    for (const c of clutter) {
      const fwd = (c.a - prevBeam + Math.PI * 2) % (Math.PI * 2)
      if (fwd <= step + 0.001) c.p = 1
      c.p *= Math.pow(0.988, dt / 16.7)
      const x = cx + Math.cos(c.a) * c.d * R; const y = cy + Math.sin(c.a) * c.d * R
      ctx.fillStyle = `rgba(125,211,252,${0.05 + c.p * 0.28})`
      ctx.beginPath(); ctx.arc(x, y, 0.8 * c.s, 0, Math.PI * 2); ctx.fill()
    }
    ctx.restore()

    // 攻击链（流动虚线）
    ctx.save()
    ctx.lineWidth = 1; ctx.setLineDash([5, 4])
    ctx.lineDashOffset = -(ts * 0.012) % 9
    for (const [ai, bi] of chains) {
      const A = blips[ai]; const B = blips[bi]
      if (!A || !B) continue
      const mx = (A.x + B.x) / 2 - (A.y - B.y) * 0.14
      const my = (A.y + B.y) / 2 + (A.x - B.x) * 0.14
      ctx.strokeStyle = hexA('#F43F5E', 0.15 + 0.28 * Math.max(A.glow, B.glow))
      ctx.beginPath(); ctx.moveTo(A.x, A.y); ctx.quadraticCurveTo(mx, my, B.x, B.y); ctx.stroke()
      ctx.fillStyle = hexA('#F43F5E', 0.35 + 0.4 * B.glow)
      ctx.beginPath(); ctx.arc(B.x, B.y, 1.6, 0, Math.PI * 2); ctx.fill()
    }
    ctx.restore()

    // 目标核心 + 悬停十字（按用户要求去掉辉光/脉冲环，只留实心点）
    const hov = hover.value
    for (const b of blips) {
      const c = SEV[b.sev].color
      ctx.fillStyle = c
      ctx.beginPath(); ctx.arc(b.x, b.y, b.size * 0.62, 0, Math.PI * 2); ctx.fill()
      ctx.fillStyle = 'rgba(255,255,255,.9)'
      ctx.beginPath(); ctx.arc(b.x, b.y, Math.max(1.4, b.size * 0.24), 0, Math.PI * 2); ctx.fill()
      if (b === hov) {
        ctx.strokeStyle = hexA(c, 0.5); ctx.setLineDash([4, 4]); ctx.lineWidth = 1
        ctx.beginPath()
        ctx.moveTo(b.x, b.y - b.size - 14); ctx.lineTo(b.x, b.y + b.size + 14)
        ctx.moveTo(b.x - b.size - 14, b.y); ctx.lineTo(b.x + b.size + 14, b.y)
        ctx.stroke(); ctx.setLineDash([])
      }
    }
    // 扫描波束
    if (!REDUCED) {
      ctx.save(); ctx.globalCompositeOperation = 'lighter'
      if (ctx.createConicGradient) {
        const trail = 1.9; const start = beam - trail
        const g = ctx.createConicGradient(start, cx, cy)
        const span = trail / (Math.PI * 2)
        g.addColorStop(0, 'rgba(91,124,250,0)')
        g.addColorStop(Math.max(0, span - 0.004), 'rgba(91,124,250,0)')
        g.addColorStop(span, 'rgba(125,211,252,.12)')
        g.addColorStop(Math.min(1, span + 0.005), 'rgba(125,211,252,0)')
        g.addColorStop(1, 'rgba(91,124,250,0)')
        ctx.fillStyle = g
        ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.fill()
      }
      const lg = ctx.createLinearGradient(cx, cy, cx + Math.cos(beam) * R, cy + Math.sin(beam) * R)
      lg.addColorStop(0, 'rgba(125,211,252,0)')
      lg.addColorStop(0.7, 'rgba(125,211,252,.50)')
      lg.addColorStop(1, 'rgba(125,211,252,.72)')
      ctx.strokeStyle = lg; ctx.lineWidth = 2
      ctx.shadowColor = '#22D3EE'; ctx.shadowBlur = 5
      ctx.beginPath(); ctx.moveTo(cx, cy)
      ctx.lineTo(cx + Math.cos(beam) * R, cy + Math.sin(beam) * R); ctx.stroke()
      ctx.restore()
    }

    // Keep the original canvas; reserve space for the center, dots and fixed annotations.
    ctx.font = '10.5px system-ui, sans-serif'
    ctx.textBaseline = 'middle'
    const placedLabels = []
    const centerRadius = Math.max(20, R * .16)
    reserved.push({ x: cx - centerRadius - 3, y: cy - centerRadius - 3, w: centerRadius * 2 + 6, h: centerRadius * 2 + 6 })
    for (const b of blips) reserved.push({ x: b.x - 5, y: b.y - 5, w: 10, h: 10 })
    const cands = blips.filter(b => b === hov || b.sev === 'crit' || (b.sev === 'high' && b.glow > .15))
      .sort((a, b) => (a === hov ? -1 : b === hov ? 1 : 0) ||
        (b.sev === 'crit' ? 1 : 0) - (a.sev === 'crit' ? 1 : 0) || a.s - b.s)
    const maxLabels = w < 240 ? 2 : 4
    const collides = rect => [...reserved, ...placedLabels].some(p =>
      rect.x < p.x + p.w && p.x < rect.x + rect.w && rect.y < p.y + p.h && p.y < rect.y + rect.h)
    for (const b of cands) {
      if (placedLabels.length >= maxLabels && b !== hov) break
      const sourceName = String(b.name || '')
      const limit = w < 240 ? 10 : 14
      const name = sourceName.length > limit ? sourceName.slice(0, limit - 1) + '…' : sourceName
      const tw = ctx.measureText(name).width
      if (tw < 2) continue
      let box = null
      // Try both sides and vertical offsets; suppress a label if no clear space remains.
      for (const dy of [0, -17, 17, -32, 32]) {
        for (const side of [Math.cos(b.a) >= 0 ? 1 : -1, Math.cos(b.a) >= 0 ? -1 : 1]) {
          const left = side > 0 ? b.x + 10 : b.x - tw - 14
          const rect = { x: left - 3, y: b.y + dy - 8, w: tw + 6, h: 16 }
          if (rect.x < 4 || rect.x + rect.w > w - 4 || rect.y < 26 || rect.y + rect.h > h - 26 || collides(rect)) continue
          box = rect; break
        }
        if (box) break
      }
      if (!box) continue
      placedLabels.push(box)
      ctx.fillStyle = 'rgba(9,17,30,.9)'
      ctx.fillRect(box.x, box.y, box.w, box.h)
      ctx.textAlign = 'left'
      ctx.fillStyle = hexA(SEV[b.sev].color, b === hov ? 1 : .9)
      ctx.fillText(name, box.x + 3, box.y + 8)
    }
    ctx.textBaseline = 'alphabetic'

    // 中心信息
    ctx.save()
    ctx.fillStyle = 'rgba(10,16,30,.95)'
    ctx.beginPath(); ctx.arc(cx, cy, Math.max(20, R * 0.16), 0, Math.PI * 2); ctx.fill()
    ctx.strokeStyle = 'rgba(148,163,184,.18)'; ctx.stroke()
    ctx.textAlign = 'center'
    ctx.fillStyle = '#E6EDF7'; ctx.font = '700 22px ' + MONO
    ctx.fillText(String(props.centerValue), cx, cy - 2)
    ctx.fillStyle = '#AABDD6'; ctx.font = '9.5px sans-serif'
    ctx.fillText(props.centerLabel, cx, cy + 14)
    ctx.restore()

    // 四角 HUD
    ctx.font = '10px ' + MONO
    ctx.fillStyle = 'rgba(162,203,233,.75)'
    ctx.textAlign = 'left'
    ctx.fillText('MODE · DEEP-SCAN', 14, 18)
    ctx.fillText(`SWEEP ${String(sweeps % 1000).padStart(3, '0')} · ${props.period}s/rev`, 14, h - 12)
    ctx.textAlign = 'right'
    ctx.fillText('TARGETS ' + blips.length, w - 14, 18)
    ctx.fillText('LIVE', w - 14, h - 12)
  } catch (e) { /* 单帧绘制异常，下一帧自动恢复 */ }
}

const emit = defineEmits(['select'])

function hitTarget (event) {
  if (!cv.value) return null
  const rect = cv.value.getBoundingClientRect()
  const x = event.clientX - rect.left; const y = event.clientY - rect.top
  let best = null; let bestDistance = Infinity
  for (const point of blips) {
    const distance = Math.hypot(point.x - x, point.y - y)
    if (distance <= Math.max(10, point.size + 3) && distance < bestDistance) { best = point; bestDistance = distance }
  }
  return best
}
function onClick (event) {
  const target = hitTarget(event)
  if (target) emit('select', target)
}
function onMove (event) {
  const best = hitTarget(event)
  hover.value = best
  if (best && tip.value) {
    tip.value.style.display = 'block'
    const tw = tip.value.offsetWidth; const th = tip.value.offsetHeight
    let x = event.clientX + 16
    if (x + tw > window.innerWidth - 8) x = event.clientX - tw - 16
    const y = Math.max(8, Math.min(window.innerHeight - th - 8, event.clientY - th / 2))
    tip.value.style.left = Math.max(8, x) + 'px'
    tip.value.style.top = y + 'px'
    cv.value.style.cursor = 'pointer'
  } else {
    if (tip.value) tip.value.style.display = 'none'
    if (cv.value) cv.value.style.cursor = 'crosshair'
  }
}
function onLeave () {
  hover.value = null
  if (tip.value) tip.value.style.display = 'none'
}

watch(() => [props.sectors, props.targets], rebuild, { deep: true })

onMounted(() => {
  ctx = cv.value.getContext('2d')
  rebuild()
  resize()
  ro = new ResizeObserver(resize)
  ro.observe(wrap.value)
  cv.value.addEventListener('pointermove', onMove)
  cv.value.addEventListener('pointerleave', onLeave)
  cv.value.addEventListener('click', onClick)
  raf = requestAnimationFrame(draw)
})
onBeforeUnmount(() => {
  if (raf) cancelAnimationFrame(raf)
  if (ro) ro.disconnect()
  if (cv.value) {
    cv.value.removeEventListener('pointermove', onMove)
    cv.value.removeEventListener('pointerleave', onLeave)
    cv.value.removeEventListener('click', onClick)
  }
})
</script>

<style scoped>
.rs-wrap { position: relative; width: 100%; height: 100%; min-height: 0; }
.rs-canvas { width: 100%; height: 100%; display: block; cursor: crosshair; }
.rs-tip {
  position: fixed;
  z-index: 1200;
  pointer-events: none;
  display: none;
  width: min(320px, calc(100vw - 24px));
  box-sizing: border-box;
  background: rgba(10, 16, 30, .96);
  border: 1px solid rgba(91, 124, 250, .4);
  border-radius: 10px;
  padding: 10px 12px;
  box-shadow: 0 10px 34px rgba(0, 0, 0, .55), 0 0 24px rgba(91, 124, 250, .12);
  backdrop-filter: blur(6px);
  color: #E6EDF7;
}
.rt-name { overflow-wrap: anywhere; font-size: 12.5px; font-weight: 600; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.rt-name .cwe {
  font: 10.5px var(--fw-font-mono, monospace);
  color: #7DA2FF;
  background: rgba(91, 124, 250, .14);
  padding: 1px 6px;
  border-radius: 4px;
}
.rt-row { margin-top: 7px; font-size: 11px; color: #98A3BC; display: flex; align-items: center; gap: 8px; }
.rt-row.dim { color: #A2B4CF; font-size: 10.5px; }
.rt-ver { color: #34D399; font-size: 10.5px; }
.rt-pend { color: #8A94AD; font-size: 10.5px; }
.sev { flex: none; font-size: 10px; padding: 1px 6px; border-radius: 4px; font-weight: 600; }
.sev-crit { color: #FF8FA5; background: rgba(244, 63, 94, .15); }
.sev-high { color: #FB923C; background: rgba(251, 146, 60, .14); }
.sev-med { color: #FACC15; background: rgba(250, 204, 21, .12); }
.sev-low { color: #34D399; background: rgba(52, 211, 153, .12); }
</style>
